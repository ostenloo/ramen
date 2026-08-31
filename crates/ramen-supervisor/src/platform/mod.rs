//! Platform-specific peer identity (`03-supervisor.md` §4).
//!
//! The peer of an `AF_UNIX` connection is identified through its
//! `LOCAL_PEERTOKEN` audit token — **never** by PID. PIDs are recycled and
//! attacker-controllable; a process that can spawn children can race a PID
//! check. The audit token is assigned by the kernel at connection time and
//! cannot be chosen by the peer.
//!
//! This module is the safe API. All `unsafe` lives in the single `darwin`
//! backend (crate-level `deny(unsafe_code)` + module-level allow,
//! `00-overview.md` Unsafe policy). The crate root refuses to compile on
//! non-macOS targets: the design is macOS-first and the identity mechanism
//! is platform-specific.

pub use security_framework::os::macos::code_signing::{Flags, SecCode, SecRequirement};

/// Identity of the peer process of a local connection, captured at accept
/// time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerIdentity {
    /// Diagnostics only — never used for authorization.
    pub pid: i32,
    /// Signing identifier when the peer is signed.
    pub signing_id: Option<String>,
    /// Code directory hash (lowercase hex) when the peer is signed.
    pub cdhash: Option<String>,
    /// True only when the peer satisfied the configured requirement.
    pub verified: bool,
}

/// Signing information of a binary on disk (used by the test harness to pin
/// its own cdhash in the test configuration).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigningInfo {
    pub signing_id: Option<String>,
    pub cdhash: Option<String>,
}

/// Peer identity failures. Every variant is a refusal: fail closed, no
/// fallback to any weaker check.
#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    /// The peer's audit token could not be resolved to a code object (e.g.
    /// the peer exited before we could look it up).
    #[error("could not resolve peer code: {reason}")]
    NoPeerCode { reason: String },
    /// A filesystem path could not be resolved to a code object.
    #[error("could not resolve code at path: {reason}")]
    NoCode { reason: String },
    /// Other (non-recoverable) failure.
    #[error("identity check failed: {0}")]
    Other(String),
}

/// Identify the peer of local socket `fd` and check it against
/// `requirement`.
///
/// `verified` is the result of the requirement check; it is returned rather
/// than forced, so the caller can still audit *what* the peer was when it
/// fails (`03-supervisor.md` §4: on failure, audit `IdentityRejected` with
/// whatever identity information was obtained, then close).
pub use darwin::identify;

/// The effective user id of this process (ownership checks for the config
/// file and socket directory).
pub use darwin::geteuid;

/// Signing information of the binary at `path`.
pub use darwin::signing_info_for_path;

/// Filesystem type name of the filesystem containing `path` (`statfs(2)`).
pub use darwin::fs_type;

/// Device id (`st_dev`) of the filesystem containing `path` (`stat(2)`).
pub use darwin::device_id;

/// APFS copy-on-write clone of `src` to `dst` (`clonefile(2)`); `dst` must
/// not exist (`05-operations.md` M6 step 4).
pub use darwin::clonefile;

mod darwin;
