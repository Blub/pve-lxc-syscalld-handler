//! Low level seccomp module
//!
//! Mostly provides data structures.

use std::ffi::CString;
use std::os::raw::{c_int, c_uint};
use std::os::unix::fs::FileExt;
use std::os::unix::io::{AsRawFd, RawFd};
use std::sync::Arc;
use std::{io, mem};

use anyhow::{bail, Error};
use nix::errno::Errno;
use once_cell::sync::OnceCell as SyncOnceCell;
use tokio::io::unix::AsyncFd;

use crate::process::PidFd;
use crate::tools::{vec, Fd};

/// Contains syscall data.
#[repr(C)]
pub struct SeccompData {
    pub nr: c_int,
    pub arch: u32,
    pub instruction_pointer: u64,
    pub args: [u64; 6],
}

/// Seccomp syscall notification data.
///
/// Sent by the kernel when a seccomp filter returns `SECCOMP_RET_USER_NOTIF` for a syscall.
#[repr(C)]
pub struct SeccompNotif {
    pub id: u64,
    pub pid: u32,
    pub flags: u32,
    pub data: SeccompData,
}

/// Seccomp syscall response data.
///
/// This is sent as a reply to `SeccompNotif`.
#[repr(C)]
pub struct SeccompNotifResp {
    pub id: u64,
    pub val: i64,
    pub error: i32,
    pub flags: u32,
}

/// Information about the actual sizes of `SeccompNotif`, and `SeccompNotifResp` and `SeccompData`.
///
/// If the sizes mismatch it is likely that the kernel has an incompatible view of these data
/// structures.
#[derive(Clone)]
#[repr(C)]
pub struct SeccompNotifSizes {
    pub notif: u16,
    pub notif_resp: u16,
    pub data: u16,
}

impl SeccompNotifSizes {
    /// Query the kernel for its data structure sizes.
    pub fn get() -> io::Result<Self> {
        const SECCOMP_GET_NOTIF_SIZES: c_int = 3;

        let mut this = Self {
            notif: 0,
            notif_resp: 0,
            data: 0,
        };

        let rc = unsafe {
            libc::syscall(
                libc::SYS_seccomp,
                SECCOMP_GET_NOTIF_SIZES,
                0,
                &mut this as *mut _,
            )
        };
        if rc == 0 {
            Ok(this)
        } else {
            Err(io::Error::last_os_error())
        }
    }

    /// Check whether the kernel's data structure sizes match the one this
    /// crate was compiled with.
    pub fn check(&self) -> io::Result<()> {
        if usize::from(self.notif) != mem::size_of::<SeccompNotif>()
            || usize::from(self.notif_resp) != mem::size_of::<SeccompNotifResp>()
            || usize::from(self.data) != mem::size_of::<SeccompData>()
        {
            Err(io::Error::new(
                io::ErrorKind::Other,
                "seccomp data structure size mismatch",
            ))
        } else {
            Ok(())
        }
    }

    /// Query the kernel for its data structure sizes and check whether they
    /// match this ones this crate was compiled with.
    pub fn get_checked() -> io::Result<Self> {
        let this = Self::get()?;
        this.check()?;
        Ok(this)
    }
}

/// Represents a seccomp syscall request and provides a `respond` method to respond to it.
///
/// This also `Deref`'s directly to the contained `data` for convenience.
///
/// Note that if `respond` is not called, it will respond with a default of `ENOSYS`.
pub struct Notification {
    /// The actual data.
    pub data: NotificationData,

    /// Removed when responding, otherwise Drop will respond.
    fd: Option<Arc<SeccompNotifyFd>>,
}

impl std::ops::Deref for Notification {
    type Target = NotificationData;

    fn deref(&self) -> &NotificationData {
        &self.data
    }
}

impl Notification {
    /// Respond to this syscall.
    pub fn respond(mut self, value: i64, error: i32, flags: u32) -> Result<(), Error> {
        self.respond_do(value, error, flags)
    }

    fn respond_do(&mut self, val: i64, error: i32, flags: u32) -> Result<(), Error> {
        match self.fd.take() {
            Some(notify) => unsafe {
                notify.respond(&mut SeccompNotifResp {
                    id: self.notif.id,
                    val,
                    error,
                    flags,
                })?
            },
            None => bail!("double response"),
        }
        Ok(())
    }

    fn new(fd: &Arc<SeccompNotifyFd>, notif: SeccompNotif) -> Option<Self> {
        let pid_fd = match PidFd::open(notif.pid as libc::pid_t) {
            Ok(pid_fd) => pid_fd,
            Err(err) => {
                eprintln!(
                    "failed to open pid fd (process vanished, or insufficient privileges): {}",
                    err
                );
                return None;
            }
        };

        if unsafe { seccomp_notif_id_valid(fd.fd.as_raw_fd(), notif.id) }.is_err() {
            // request was cancelled, pidfd is likely the wrong process
            drop(pid_fd); // let's be explicit here
            return None;
        }

        Some(Self {
            fd: Some(Arc::clone(fd)),
            data: NotificationData {
                notif,
                pid_fd,
                mem_fd: SyncOnceCell::new(),
            },
        })
    }
}

impl Drop for Notification {
    fn drop(&mut self) {
        let _ = self.respond_do(-1, libc::ENOSYS, 0);
    }
}

/// Provides access to the notifiation data for syscall arguments, methods to access them as
/// various types, the pid and memfd.
pub struct NotificationData {
    pid_fd: PidFd,
    mem_fd: SyncOnceCell<std::fs::File>,
    pub notif: SeccompNotif,
}

impl NotificationData {
    fn open_mem_fd<'a>(
        pid_fd: &'_ PidFd,
        file: &'a SyncOnceCell<std::fs::File>,
    ) -> io::Result<&'a std::fs::File> {
        file.get_or_try_init(move || {
            pid_fd.open_file(c_str!("mem"), libc::O_RDONLY | libc::O_CLOEXEC, 0)
        })
    }

    /// Read a C string from the program at an offset.
    ///
    /// The string can be a maximum of 4k in length, otherwise it will be considered an error.
    pub fn get_c_string(&self, offset: u64) -> Result<CString, Error> {
        let mut data = unsafe { vec::uninitialized(4096) };
        let got = Self::open_mem_fd(&self.pid_fd, &self.mem_fd)?.read_at(&mut data, offset)?;

        let len = unsafe { libc::strnlen(data.as_ptr() as *const _, got) };
        if len >= got {
            Err(nix::Error::Sys(Errno::EINVAL).into())
        } else {
            unsafe {
                data.set_len(len);
            }
            // We used strlen, so the only Error in CString::new() cannot happen at this point:
            Ok(CString::new(data).unwrap())
        }
    }

    /// Get the process' pidfd.
    ///
    /// Note that the message must be valid, otherwise this panics!
    pub fn pid_fd(&self) -> &PidFd {
        &self.pid_fd
    }

    /// Shortcut to get a parameter value.
    #[inline]
    pub fn arg(&self, arg: u32) -> Result<u64, Error> {
        self.notif
            .data
            .args
            .get(arg as usize)
            .copied()
            .ok_or_else(|| Errno::ERANGE.into())
    }

    /// Get a parameter as C String where the pointer may be `NULL`.
    ///
    /// Strings are limited to 4k bytes currently.
    #[inline]
    pub fn arg_opt_c_string(&self, arg: u32) -> Result<Option<CString>, Error> {
        let offset = self.arg(arg)?;
        if offset == 0 {
            Ok(None)
        } else {
            Ok(Some(self.get_c_string(offset)?))
        }
    }

    /// Checked way to get a `mode_t` argument.
    #[inline]
    pub fn arg_mode_t(&self, arg: u32) -> Result<nix::sys::stat::mode_t, Error> {
        nix::sys::stat::mode_t::try_from(self.arg(arg)?).map_err(|_| Error::from(Errno::EINVAL))
    }

    /// Checked way to get a `dev_t` argument.
    #[inline]
    pub fn arg_dev_t(&self, arg: u32) -> Result<nix::sys::stat::dev_t, Error> {
        self.arg(arg)
    }

    /// Get a parameter as C String.
    ///
    /// Strings are limited to 4k bytes currently.
    #[inline]
    pub fn arg_c_string(&self, arg: u32) -> Result<CString, Error> {
        self.arg_opt_c_string(arg)?
            .ok_or_else(|| Errno::EINVAL.into())
    }

    /// Checked way to get a file descriptor argument.
    #[inline]
    pub fn arg_fd(&self, arg: u32, flags: c_int) -> Result<Fd, Error> {
        let fd = self.arg(arg)? as RawFd;

        // we pass negative ones 'as-is', others get opened via the pidfd
        if fd == libc::AT_FDCWD {
            // NOTE: we could pass this one through, but let's be explicit here, in the future we
            // might want to reuse this one?
            Ok(self.pid_fd().fd_cwd()?)
        } else if fd < 0 {
            return Ok(Fd(fd));
        } else {
            Ok(self.pid_fd.fd_num(fd, flags)?)
        }
    }

    /// Checked way to get a c_uint argument.
    #[inline]
    pub fn arg_uint(&self, arg: u32) -> Result<c_uint, Error> {
        c_uint::try_from(self.arg(arg)?).map_err(|_| Errno::EINVAL.into())
    }

    /// Checked way to get a c_int argument.
    #[inline]
    pub fn arg_int(&self, arg: u32) -> Result<c_int, Error> {
        self.arg_uint(arg).map(|u| u as c_int)
    }

    /// Checked way to get a `caddr_t` argument.
    #[inline]
    pub fn arg_caddr_t(&self, arg: u32) -> Result<*mut i8, Error> {
        Ok(self.arg(arg)? as *mut i8)
    }

    /// Checked way to get a raw pointer argument
    #[inline]
    pub fn arg_pointer(&self, arg: u32) -> Result<*const u8, Error> {
        Ok(self.arg(arg)? as usize as *const u8)
    }

    /// Checked way to get a raw char pointer.
    #[inline]
    pub fn arg_char_ptr(&self, arg: u32) -> Result<*const libc::c_char, Error> {
        Ok(self.arg(arg)? as usize as *const libc::c_char)
    }

    /// Write data to the process.
    #[inline]
    pub fn mem_write_struct<T>(&self, offset: u64, data: &T) -> io::Result<()> {
        let slice = unsafe {
            std::slice::from_raw_parts(data as *const T as *const u8, mem::size_of::<T>())
        };
        let put = Self::open_mem_fd(&self.pid_fd, &self.mem_fd)?.write_at(slice, offset)?;
        if put != mem::size_of::<T>() {
            Err(Errno::EINVAL.into())
        } else {
            Ok(())
        }
    }

    /// Read a user space pointer parameter.
    #[inline]
    pub fn arg_struct_by_ptr<T>(&self, arg: u32) -> Result<T, Error> {
        let offset = self.arg(arg)?;
        let mut data: T = unsafe { mem::zeroed() };
        let slice = unsafe {
            std::slice::from_raw_parts_mut(&mut data as *mut _ as *mut u8, mem::size_of::<T>())
        };
        let got = Self::open_mem_fd(&self.pid_fd, &self.mem_fd)?.read_at(slice, offset)?;
        if got != mem::size_of::<T>() {
            Err(Errno::EINVAL.into())
        } else {
            Ok(data)
        }
    }
}

/// A tokio-driven seccomp notify file descriptor.
///
/// Behaves like an `AsyncIterator` over [`Notifcation`s](Notification).
pub struct SeccompNotifyFd {
    fd: AsyncFd<Fd>,
}

nix::ioctl_readwrite!(seccomp_notif_recv, b'!', 0, SeccompNotif);
nix::ioctl_readwrite!(seccomp_notif_send, b'!', 1, SeccompNotifResp);
nix::ioctl_write_int!(seccomp_notif_id_valid, b'!', 2);

impl SeccompNotifyFd {
    /// Attempt to register the provided `Fd` with the `tokio` runtime.
    pub fn new(fd: Fd) -> Result<Self, Error> {
        Ok(Self {
            fd: AsyncFd::new(fd)?,
        })
    }

    /// Wait for the next syscall event.
    pub async fn next(self: &Arc<Self>) -> io::Result<Option<Notification>> {
        loop {
            let mut guard = self.fd.readable().await?;

            let mut buf = mem::MaybeUninit::<SeccompNotif>::uninit();

            let result = match guard.try_io(|fd| {
                unsafe { seccomp_notif_recv(fd.as_raw_fd(), buf.as_mut_ptr()) }
                    .map_err(crate::error::nix_to_io)
            }) {
                Err(_would_block) => continue,
                Ok(result) => result,
            };

            return match result {
                Ok(_) => match Notification::new(self, unsafe { buf.assume_init() }) {
                    Some(notif) => Ok(Some(notif)),
                    None => continue, // request was cancelled
                },
                Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
                Err(err) => Err(crate::error::io_err_other(err)),
            };
        }
    }

    /// Respond to a syscall.
    ///
    /// Prefer to use [`Notification::respond`].
    pub unsafe fn respond(&self, response: &mut SeccompNotifResp) -> nix::Result<()> {
        unsafe { seccomp_notif_send(self.fd.as_raw_fd(), response).map(drop) }
    }
}
