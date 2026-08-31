//! Filesystem access for the guard's path checks (`04-guard.md` §6).
//!
//! Injected so that the acceptance criteria can *assert* on filesystem
//! behavior — e.g. that a lexically-rejected `..` path never touches the
//! filesystem — without pointing real paths at observable locations.

use std::path::{Path, PathBuf};

/// The two filesystem queries the path check needs.
pub trait Fs: Send + Sync {
    /// Fully canonicalize `path` (resolving symlinks). `None` if any
    /// component does not exist.
    fn canonicalize(&self, path: &Path) -> Option<PathBuf>;

    /// True if `path` exists and is a symlink.
    fn is_symlink(&self, path: &Path) -> bool;
}

/// The real filesystem.
pub struct StdFs;

impl Fs for StdFs {
    fn canonicalize(&self, path: &Path) -> Option<PathBuf> {
        path.canonicalize().ok()
    }

    fn is_symlink(&self, path: &Path) -> bool {
        path.symlink_metadata()
            .map(|m| m.file_type().is_symlink())
            .unwrap_or(false)
    }
}
