//! Effect primitives pinned to an open parent-directory fd (`05-operations.md` M6).
//!
//! A `FileWrite` effect must not resolve the target path independently for
//! every syscall. Each path-string resolution is a window in which an agent
//! with write access to an intermediate directory can swap a path component
//! (rename a directory, plant a symlink) and steer the write away from the
//! directory that was checked. `pin_parent` resolves the parent **once**,
//! proves the opened fd references that directory (the pre-open `lstat` and
//! the post-open `fstat` must agree on device + inode), and every subsequent
//! syscall of the effect runs `*at`-relative to that fd, naming the target
//! by its bare final component only. One resolution for the whole effect.
//!
//! What the pin guarantees: a swap that lands **after** the pin cannot
//! affect the effect at all — the fd outlives the path string. A swap that
//! lands **before** the pin changes what the path resolves to, and the
//! configured-prefix check runs against the pinned resolution, so the
//! supervisor's outer bound (`05-operations.md` M6 step 3) is enforced
//! against the directory that is actually written, not against an
//! earlier, stale resolution.
//!
//! All `unsafe` in this module wraps a single system call: `open(2)`,
//! `fstat(2)`, `openat(2)`, `renameat(2)`, `unlinkat(2)`, `fclonefileat(2)`.
// Sole additional `unsafe` module alongside `platform::darwin` (crate root
// is `deny(unsafe_code)`, `00-overview.md` Unsafe policy).
#![allow(unsafe_code)]

use std::ffi::CString;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

/// A parent directory pinned for the duration of one effect.
///
/// `canon_parent` is the fully symlink-resolved parent; `canon_target` is
/// `canon_parent` joined with the target's final component — the canonical
/// target used in responses and audit strings. `fd` is the directory the
/// effect actually operates on, verified to be `canon_parent`.
#[derive(Debug)]
pub struct PinnedParent {
    pub fd: OwnedFd,
    pub canon_parent: PathBuf,
    pub canon_target: PathBuf,
    /// The target's final component, as bytes (the only name ever passed to
    /// an `*at` syscall — it cannot contain a separator).
    pub target_name: Vec<u8>,
}

/// Pinning failures. All are effect-phase failures: the decision was made
/// upstream (audited `Authorized` by the caller), the effect cannot run
/// (`ExecutionFailed`).
#[derive(Debug, thiserror::Error)]
pub enum PinError {
    #[error("target path has no parent directory")]
    NoParent,
    #[error("target path has no final component")]
    NoFinalComponent,
    #[error("target parent no longer resolvable: {0}")]
    ParentGone(String),
    /// The parent resolved to a path whose final component is a symlink at
    /// open time — it was swapped between resolution and open.
    #[error("target parent is a symlink at open time (swapped during pin): {0}")]
    ParentSymlink(String),
    /// The opened fd references a different directory (device + inode) than
    /// the one resolved before the open: the directory was swapped mid-pin.
    #[error("target parent was swapped between resolution and open")]
    ParentSwapped,
    #[error("failed to open target parent directory: {0}")]
    Open(String),
}

/// Resolve `target`'s parent exactly once and pin it to an open directory
/// fd. `target` is the client-supplied path; its parent must exist (the
/// guard checked that at decision time).
pub fn pin_parent(target: &Path) -> Result<PinnedParent, PinError> {
    let parent = target
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .ok_or(PinError::NoParent)?;
    let name = target
        .file_name()
        .ok_or(PinError::NoFinalComponent)?
        .as_bytes()
        .to_vec();

    // Resolve all symlinks in the parent exactly once.
    let canon_parent = std::fs::canonicalize(parent)
        .map_err(|e| PinError::ParentGone(e.to_string()))?;

    // Record the directory's identity *before* opening it; the post-open
    // `fstat` must match, or the directory was swapped under us.
    let pre = std::fs::symlink_metadata(&canon_parent)
        .map_err(|e| PinError::ParentGone(e.to_string()))?;
    if pre.file_type().is_symlink() {
        // canonicalize returns a path with no symlink components; reaching
        // here means the tree moved between the two calls.
        return Err(PinError::ParentSwapped);
    }

    // O_NOFOLLOW rejects a final-component symlink swap; O_DIRECTORY makes
    // the fd usable only as a directory.
    let fd = open_dir(&canon_parent).map_err(|e| match e.raw_os_error() {
        Some(libc::ELOOP) => PinError::ParentSymlink(e.to_string()),
        _ => PinError::Open(e.to_string()),
    })?;

    let post = fstat(&fd).map_err(|e| PinError::Open(e.to_string()))?;
    if (pre.dev(), pre.ino()) != (post.st_dev as u64, post.st_ino)
        || post.st_mode & libc::S_IFMT != libc::S_IFDIR
    {
        return Err(PinError::ParentSwapped);
    }

    let name_os = std::ffi::OsString::from_vec(name.clone());
    Ok(PinnedParent {
        fd,
        canon_parent: canon_parent.clone(),
        canon_target: canon_parent.join(&name_os),
        target_name: name,
    })
}

/// `openat(2)` relative to `dirfd`, naming a final component only.
pub fn openat(dirfd: &OwnedFd, name: &[u8], flags: libc::c_int, mode: libc::mode_t) -> io::Result<std::fs::File> {
    let c = to_cstring(name)?;
    let rc =
        unsafe { libc::openat(dirfd.as_raw_fd(), c.as_ptr(), flags, mode as libc::c_uint) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `rc` is a fresh fd owned by this process; `File` takes
    // ownership and closes it on drop.
    Ok(unsafe { std::fs::File::from_raw_fd(rc) })
}

/// `renameat(2)` within the same pinned directory (atomic replace).
pub fn renameat(dirfd: &OwnedFd, old: &[u8], new: &[u8]) -> io::Result<()> {
    let old_c = to_cstring(old)?;
    let new_c = to_cstring(new)?;
    let rc = unsafe {
        libc::renameat(dirfd.as_raw_fd(), old_c.as_ptr(), dirfd.as_raw_fd(), new_c.as_ptr())
    };
    if rc != 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// `unlinkat(2)` within the pinned directory.
pub fn unlinkat(dirfd: &OwnedFd, name: &[u8]) -> io::Result<()> {
    let c = to_cstring(name)?;
    let rc = unsafe { libc::unlinkat(dirfd.as_raw_fd(), c.as_ptr(), 0) };
    if rc != 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Apple `fclonefileat(2)` (macOS 10.12+): COW-clone the file open at
/// `srcfd` to `dst_name` inside the directory open at `dst_dirfd`
/// (which must not exist). The source is the fd, so the snapshot is taken
/// of exactly the file the effect opened — never of whatever a re-resolved
/// path string would refer to. No data is copied at call time. Fails with
/// `EXDEV` across volumes (checked at startup) and `ENOTSUP`/`ENOCSUP` on
/// filesystems without clones.
pub fn clone_to_dir_fd(
    srcfd: &impl AsRawFd,
    dst_dirfd: &impl AsRawFd,
    dst_name: &[u8],
) -> io::Result<()> {
    let dst_c = to_cstring(dst_name)?;
    let rc =
        unsafe { libc::fclonefileat(srcfd.as_raw_fd(), dst_dirfd.as_raw_fd(), dst_c.as_ptr(), 0) };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// True if the `stat` describes a regular file.
pub fn is_regular(st: &libc::stat) -> bool {
    st.st_mode & libc::S_IFMT == libc::S_IFREG
}

/// `fstat(2)`.
pub fn fstat(fd: &impl AsRawFd) -> io::Result<libc::stat> {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::fstat(fd.as_raw_fd(), &mut st) };
    if rc != 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(st)
    }
}

/// `fsync(2)` the pinned parent directory (durable creates/renames/unlinks).
pub fn fsync_dir_fd(dirfd: &impl AsRawFd) -> io::Result<()> {
    let rc = unsafe { libc::fsync(dirfd.as_raw_fd()) };
    if rc != 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Open a directory for `*at` operations (`O_RDONLY | O_DIRECTORY | O_NOFOLLOW`).
pub fn open_dir(path: &Path) -> io::Result<OwnedFd> {
    let c = to_cstring(path.as_os_str().as_bytes())?;
    let flags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW;
    let rc = unsafe { libc::open(c.as_ptr(), flags) };
    from_rc(rc)
}

fn from_rc(rc: libc::c_int) -> io::Result<OwnedFd> {
    if rc < 0 {
        Err(io::Error::last_os_error())
    } else {
        // SAFETY: `rc` is a fresh fd owned by this process; `OwnedFd` takes
        // ownership and closes it on drop.
        Ok(unsafe { OwnedFd::from_raw_fd(rc) })
    }
}

fn to_cstring(bytes: &[u8]) -> io::Result<CString> {
    // A NUL byte is impossible in a path component the kernel accepted.
    CString::new(bytes)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn pin_resolves_symlinked_parent_and_names_target() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = std::fs::canonicalize(tmp.path()).unwrap();
        let real = dir.join("real");
        std::fs::create_dir(&real).unwrap();
        let link = dir.join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();

        // A symlinked intermediate component: the pin must land on the real
        // directory, and the canonical target must be fully resolved.
        let target = link.join("f.txt");
        let pinned = pin_parent(&target).unwrap();
        assert_eq!(pinned.canon_parent, real, "parent must be canonical");
        assert_eq!(
            pinned.canon_target,
            real.join("f.txt"),
            "target must be canonical"
        );
        assert_eq!(pinned.target_name, b"f.txt".to_vec());
    }

    #[test]
    fn pin_fails_when_parent_is_missing() {
        let dir = tempfile::tempdir().unwrap();
        let err = pin_parent(&dir.path().join("nope/f.txt")).unwrap_err();
        assert!(matches!(err, PinError::ParentGone(_)), "{err:?}");
    }

    #[test]
    fn pin_rejects_bare_filename() {
        // A bare filename has no parent directory to pin: it is a
        // `NoParent` error (in practice the guard only admits absolute
        // paths under an allowed prefix, so this is defense in depth).
        let err = pin_parent(std::path::Path::new("f.txt")).unwrap_err();
        assert!(matches!(err, PinError::NoParent), "{err:?}");
        let err = pin_parent(std::path::Path::new("/")).unwrap_err();
        assert!(matches!(err, PinError::NoParent), "{err:?}");
    }

    #[test]
    fn swap_after_pin_cannot_steer_the_effect() {
        // The pin is the whole point: after `pin_parent` returns, replacing
        // the directory at the path must not change where the fd-relative
        // syscalls land.
        let dir = tempfile::tempdir().unwrap();
        let parent = dir.path().join("work");
        std::fs::create_dir(&parent).unwrap();
        let target = parent.join("f.txt");

        let pinned = pin_parent(&target).unwrap();

        // Swap the directory out from under the path: the path string now
        // names a *different* directory.
        let swapped = dir.path().join("work-swapped");
        std::fs::rename(&parent, &swapped).unwrap();
        std::fs::create_dir(&parent).unwrap();

        // Create through the pin: must land in the ORIGINAL directory (the
        // one the fd references), not the fresh one at the same path.
        let name = &pinned.target_name;
        let mut file = openat(
            &pinned.fd,
            name,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW,
            0o600,
        )
        .unwrap();
        file.write_all(b"pinned").unwrap();
        drop(file);

        assert!(
            swapped.join("f.txt").exists(),
            "the write must land in the pinned (original) directory"
        );
        assert!(
            !parent.join("f.txt").exists(),
            "the write must not land in the swapped-in directory"
        );
        assert_eq!(std::fs::read_to_string(swapped.join("f.txt")).unwrap(), "pinned");
    }

    #[test]
    fn openat_refuses_symlink_final_component() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("link.txt");
        let decoy = dir.path().join("decoy.txt");
        std::fs::write(&decoy, b"decoy").unwrap();
        std::os::unix::fs::symlink(&decoy, &target).unwrap();

        let pinned = pin_parent(&target).unwrap();
        let err = openat(
            &pinned.fd,
            &pinned.target_name,
            libc::O_RDONLY | libc::O_NOFOLLOW,
            0,
        )
        .unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::ELOOP));
        assert_eq!(std::fs::read(&decoy).unwrap(), b"decoy", "decoy untouched");
    }

    #[test]
    fn clone_to_dir_fd_clones_the_opened_file() {
        let dir = tempfile::tempdir().unwrap();
        let snaps = dir.path().join("snaps");
        std::fs::create_dir(&snaps).unwrap();
        let target = dir.path().join("f.txt");
        std::fs::write(&target, b"original").unwrap();
        let pinned = pin_parent(&target).unwrap();

        let src = openat(&pinned.fd, &pinned.target_name, libc::O_RDONLY | libc::O_NOFOLLOW, 0)
            .unwrap();
        let st = fstat(&src).unwrap();
        assert!(is_regular(&st));

        let snap_dir = open_dir(&snaps).unwrap();
        clone_to_dir_fd(&src, &snap_dir, b"snap.txt").unwrap();
        assert_eq!(std::fs::read(snaps.join("snap.txt")).unwrap(), b"original");

        // The clone is of the file the fd references: replacing the path's
        // referent afterwards changes nothing about the snapshot.
        std::fs::write(&target, b"changed").unwrap();
        assert_eq!(std::fs::read(snaps.join("snap.txt")).unwrap(), b"original");
    }

    #[test]
    fn renameat_replaces_within_pinned_dir() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("f.txt");
        std::fs::write(&target, b"old").unwrap();
        let pinned = pin_parent(&target).unwrap();

        let tmp_name = b".f.txt.ramen-tmp.test";
        let mut f = openat(
            &pinned.fd,
            tmp_name,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW,
            0o600,
        )
        .unwrap();
        f.write_all(b"new").unwrap();
        drop(f);

        renameat(&pinned.fd, tmp_name, &pinned.target_name).unwrap();
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "new");
        // The renamed-in file must be 0600 as created.
        let mode = std::fs::metadata(&target).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
}
