#![deny(unsafe_op_in_unsafe_fn)]

use std::ffi::{OsStr, OsString};
use std::io as StdIo;
use std::io::{stderr, stdout, Write};
use std::mem;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::io::{FromRawFd, RawFd};
use std::sync::Arc;

use anyhow::{bail, format_err, Error};
use nix::sys::socket::SockAddr;

#[macro_use]
mod macros;

pub mod apparmor;
pub mod capability;
pub mod error;
pub mod fork;
pub mod io;
pub mod nsfd;
pub mod poll_fn;
pub mod process;
pub mod seccomp;
pub mod sys_mknod;
pub mod sys_quotactl;
pub mod syscall;
pub mod tools;

use crate::io::seq_packet::{SeqPacketListener, SeqPacketSocket};
use crate::syscall::{Syscall, SyscallStatus};
use crate::tools::Fd;

fn usage(status: i32, program: &OsStr, out: &mut dyn Write) -> ! {
    let _ = out.write_all("usage: ".as_bytes());
    let _ = out.write_all(program.as_bytes());
    let _ = out.write_all(
        concat!(
            "[options] SOCKET_PATH\n",
            "options:\n",
            "    -h, --help      show this help message\n",
            "    --system        \
                     run as systemd daemon (use sd_notify() when ready to accept connections)\n",
        )
        .as_bytes(),
    );
    std::process::exit(status);
}

fn main() {
    let mut args = std::env::args_os();
    let program = args.next().unwrap(); // program name always exists

    let mut use_sd_notify = false;
    let mut path = None;

    let mut nonopt_arg = |arg: OsString| {
        if path.is_some() {
            let _ = stderr().write_all(b"unexpected extra parameter: ");
            let _ = stderr().write_all(arg.as_bytes());
            let _ = stderr().write_all(b"\n");
            usage(1, &program, &mut stderr());
        }

        path = Some(arg);
    };

    for arg in &mut args {
        if arg == "-h" || arg == "--help" {
            usage(0, &program, &mut stdout());
        }

        if arg == "--" {
            break;
        } else if arg == "--system" {
            use_sd_notify = true;
        } else {
            if arg.as_bytes().starts_with(b"-") {
                let _ = stderr().write_all(b"unexpected option: ");
                let _ = stderr().write_all(arg.as_bytes());
                let _ = stderr().write_all(b"\n");
                usage(1, &program, &mut stderr());
            }

            nonopt_arg(arg);
        }
    }

    for arg in &mut args {
        nonopt_arg(arg);
    }

    let path = match path {
        Some(path) => path,
        None => {
            eprintln!("missing path");
            usage(1, &program, &mut stderr());
        }
    };

    let rt = tokio::runtime::Runtime::new().expect("failed to spawn tokio runtime");

    if let Err(err) = rt.block_on(do_main(use_sd_notify, path)) {
        eprintln!("error: {}", err);
        std::process::exit(1);
    }
}

async fn do_main(use_sd_notify: bool, socket_path: OsString) -> Result<(), Error> {
    match std::fs::remove_file(&socket_path) {
        Ok(_) => (),
        Err(ref e) if e.kind() == StdIo::ErrorKind::NotFound => (), // Ok
        Err(e) => bail!("failed to remove previous socket: {}", e),
    }

    let address =
        SockAddr::new_unix(socket_path.as_os_str()).expect("cannot create struct sockaddr_un?");

    let mut listener = SeqPacketListener::bind(&address)
        .map_err(|e| format_err!("failed to create listening socket: {}", e))?;

    if use_sd_notify {
        notify_systemd()?;
    }

    loop {
        let client = listener.accept().await?;
        tokio::spawn(handle_client(client));
    }
}

async fn handle_client(socket: SeqPacketSocket) {
    match client_main(socket).await {
        Ok(()) => (),
        Err(err) => eprintln!("client error, disconnecting: {}", err),
    }
}

async fn client_main(socket: SeqPacketSocket) -> std::io::Result<()> {
    use std::io::IoSliceMut;

    // We expect the cookie and 1 seccomp fd per packet.
    let mut fd_buf = io::cmsg::buffer::<[RawFd; 1]>();
    let mut cookie = [0u8; 16];
    loop {
        let (datalen, cmsglen) = socket
            .recvmsg_vectored(&mut [IoSliceMut::new(&mut cookie)], &mut fd_buf)
            .await?;

        // sanitize
        let datalen = datalen.min(cookie.len());

        // extract PVE vmid if any
        // FIXME: s/0/continue/ in final PVE version:
        let vmid: u64 = match cookie[..datalen].strip_prefix(b"PVE:") {
            Some(vmid) => match std::str::from_utf8(vmid) {
                Ok(vmid) => match vmid.parse() {
                    Ok(vmid) => vmid,
                    Err(_) => 0, // invalid format
                },
                Err(_) => 0, // also invalid format
            },
            None => 0, // not a pve container
        };

        for cmsg in io::cmsg::iter(&fd_buf[..cmsglen]) {
            if cmsg.cmsg_level != libc::SOL_SOCKET || cmsg.cmsg_type != libc::SCM_RIGHTS {
                continue;
            }

            for fd in cmsg
                .data
                .chunks_exact(mem::size_of::<RawFd>())
                .map(|chunk| unsafe {
                    Fd::from_raw_fd(std::ptr::read_unaligned(chunk.as_ptr() as _))
                })
            {
                match seccomp::SeccompNotifyFd::new(fd) {
                    Ok(fd) => {
                        tokio::spawn(handle_container(vmid, fd));
                    }
                    Err(err) => eprintln!("failed to register seccomp fd with reactor: {}", err),
                }
            }
        }
    }
}

async fn handle_container(vmid: u64, fd: seccomp::SeccompNotifyFd) {
    match container_main(vmid, fd).await {
        Ok(()) => (),
        Err(err) => eprintln!("container ({}) error: {}", vmid, err),
    }
}

async fn container_main(vmid: u64, fd: seccomp::SeccompNotifyFd) -> Result<(), Error> {
    let fd = Arc::new(fd);
    while let Some(msg) = fd.next().await? {
        tokio::spawn(handle_notification(vmid, msg));
    }
    Ok(())
}

async fn handle_notification(vmid: u64, msg: seccomp::Notification) {
    match handle_notification_do(vmid, msg).await {
        Ok(()) => (),
        Err(err) => eprintln!("error handling syscall for container {}: {}", vmid, err),
    }
}

async fn handle_notification_do(vmid: u64, msg: seccomp::Notification) -> Result<(), Error> {
    let result = match handle_syscall(vmid, &msg).await {
        Ok(r) => r,
        Err(err) => {
            // we use 'nix' and 'std' stuff, so system errors can be:
            // * std::io::Error
            // * nix::Error::Sys(errno)
            // * nix::Errno
            //
            // Any other error types indicate errors inside our handler code, in which case we bail
            // out. The `Notification`'s Drop handler will send a "default" response of `ENOSYS` in
            // this case *shrug*.
            if let Some(errno) = err.downcast_ref::<nix::errno::Errno>() {
                SyscallStatus::Err(*errno as _)
            } else if let Some(nix::Error::Sys(errno)) = err.downcast_ref::<nix::Error>() {
                SyscallStatus::Err(*errno as _)
            } else if let Some(ioerr) = err.downcast_ref::<std::io::Error>() {
                if let Some(errno) = ioerr.raw_os_error() {
                    SyscallStatus::Err(errno)
                } else {
                    return Err(err);
                }
            } else {
                return Err(err);
            }
        }
    };

    match result {
        SyscallStatus::Ok(val) => msg.respond(val, 0, 0),
        SyscallStatus::Err(err) => msg.respond(-1, -err, 0),
    }
}

async fn handle_syscall(vmid: u64, msg: &seccomp::Notification) -> Result<SyscallStatus, Error> {
    let _ = vmid; // we currently don't care actually

    let (arch, sysnr) = (msg.notif.data.arch, msg.notif.data.nr);

    let syscall_nr = match syscall::translate_syscall(arch, sysnr) {
        Some(nr) => nr,
        None => return Ok(nix::errno::Errno::ENOSYS.into()),
    };

    match syscall_nr {
        Syscall::Mknod => sys_mknod::mknod(msg).await,
        Syscall::MknodAt => sys_mknod::mknodat(msg).await,
        Syscall::Quotactl => sys_quotactl::quotactl(msg).await,
    }
}

#[link(name = "systemd")]
extern "C" {
    fn sd_notify(unset_environment: libc::c_int, state: *const libc::c_char) -> libc::c_int;
}

fn notify_systemd() -> StdIo::Result<()> {
    let err = unsafe { sd_notify(0, c_str!("READY=1\n").as_ptr()) };
    if err >= 0 {
        Ok(())
    } else {
        Err(StdIo::Error::from_raw_os_error(-err))
    }
}
