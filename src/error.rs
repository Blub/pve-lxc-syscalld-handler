use std::io;

pub fn io_err_other<E: ToString>(e: E) -> io::Error {
    io::Error::new(io::ErrorKind::Other, e.to_string())
}

pub fn nix_to_io(err: nix::Error) -> io::Error {
    match err {
        nix::Error::Sys(raw) => io::Error::from_raw_os_error(raw as _),
        other => io::Error::new(io::ErrorKind::Other, other.to_string()),
    }
}
