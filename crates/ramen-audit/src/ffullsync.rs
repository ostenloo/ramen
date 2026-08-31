#![allow(unsafe_code)]
//! The single module in this crate allowed to touch `unsafe`.
//!
//! Two syscalls:
//! - `fcntl(F_FULLFSYNC)` — macOS's durable-sync barrier (`02-audit.md` §5:
//!   "the writer issues one `F_FULLFSYNC` per drain cycle").
//! - `flock(LOCK_EX | LOCK_NB)` — single-writer lock for the audit file
//!   (`02-audit.md` §5: "flock on the file, fail loud if held").
//!
//! Everything else in the crate is `unsafe_code`-free (crate-level
//! `deny(unsafe_code)`).

use std::fs::File;
use std::io;

/// Issue `fcntl(fd, F_FULLFSYNC)` on macOS; on other platforms a plain
/// `fsync` (via [`File::sync_all`]) is the best available barrier, so this is
/// a no-op there.
pub fn full_fsync(file: &File) -> io::Result<()> {
    #[cfg(target_os = "macos")]
    {
        use std::os::unix::io::AsRawFd;
        let ret = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_FULLFSYNC) };
        if ret == -1 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = file;
        Ok(())
    }
}

/// Take an exclusive, non-blocking `flock` on `file`.
///
/// The lock is tied to the open file description: it is held for as long as
/// `file` is open and released automatically when it is dropped (or the
/// process dies).
///
/// Returns `Err(io::Error)` with `kind == WouldBlock` if another process
/// holds the lock.
pub fn lock_exclusive(file: &File) -> io::Result<()> {
    use std::os::unix::io::AsRawFd;
    let ret = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if ret == 0 {
        return Ok(());
    }
    let err = io::Error::last_os_error();
    // flock reports EWOULDBLOCK (== EAGAIN) when the lock is held.
    if err.raw_os_error() == Some(libc::EWOULDBLOCK) {
        return Err(io::Error::new(io::ErrorKind::WouldBlock, err));
    }
    Err(err)
}
