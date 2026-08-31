//! Ramen control-plane supervisor (`spec/03-supervisor.md`).
//!
//! v0 milestones M3+M4+M5+M6: peer identity (macOS code-signing requirement
//! over `LOCAL_PEERTOKEN`), Biscuit handshake, Biscuit authorization
//! through `ramen-guard` with both decision paths audited, the `Whoami`
//! operation, the `FileWrite` operation (snapshot via `fclonefileat(2)`, atomic
//! rename, durable audit trail), fatal protocol violations, connection
//! caps, rate-limited rejection auditing, and graceful shutdown.
//!
//! Both operations are implemented: an authorized `Whoami` returns the
//! guard's live view of the token; an authorized `FileWrite` performs the
//! write effect (`05-operations.md` M6). Denied requests answer `Denied`
//! with the classified code and the audit sequence.
//!
//! Safety: `deny(unsafe_code)` at the crate root; the single `allow` lives in
//! [`platform::darwin`] (macOS syscalls + Security.framework FFI).

#![deny(unsafe_code)]

/// Process exit code when the audit log can no longer be written
/// (`00-overview.md` invariant 4). A supervisor that cannot audit cannot
/// enforce, so it exits instead of degrading. Startup failures and usage
/// errors both use exit code `1`.
pub const EXIT_AUDIT_UNAVAILABLE: i32 = 4;

#[cfg(not(target_os = "macos"))]
compile_error!(
    "ramen-supervisor requires macOS: peer identity uses AF_UNIX LOCAL_PEERTOKEN \
     + Security.framework (03-supervisor.md §4). The design is macOS-first; \
     other platforms are out of scope for v0."
);

pub mod config;
pub mod conn;
pub mod filewrite;
pub mod fsat;
pub mod rate_limit;
pub mod rootkey;
pub mod socket;
pub mod token;
pub mod volume;

#[cfg(target_os = "macos")]
pub mod platform;
