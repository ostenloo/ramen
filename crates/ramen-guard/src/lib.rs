//! `ramen-guard` — Biscuit token authorization for the Ramen control plane
//! (`04-guard.md`, milestone M4).
//!
//! The guard answers one question — *may this operation run for this token,
//! now* — and returns a `Decision`. It never performs I/O of its own beyond
//! the filesystem checks in `pathcheck` (through an injectable `Fs` trait)
//! and never touches the audit log: the supervisor records the decision
//! (`02-audit.md`). A denial is a normal outcome of a working system, so
//! `authorize` returns `Decision`, not `Result` (`01-protocol.md` §7).
//!
//! Invariants (`04-guard.md` §2/§9):
//!
//! - There is no path from an internal fault to `Allow`. Anything
//!   unexpected — a token that cannot be built into an authorizer, a
//!   malformed token reaching `authorize`, a query that fails — is a `Deny`.
//! - The authoritative decision is always the full authorizer run with the
//!   `deny if true` trailer; classification is a diagnostic that runs only
//!   after that run has already denied.
//! - A fresh `Authorizer` is built per request. Fact accumulation across
//!   requests is a privilege-escalation bug waiting to happen.
//! - Facts added by the guard come from trusted sources only: the operation
//!   name and reversibility (from the request the client *cannot* rename
//!   without changing what runs), the wall clock, and the canonicalized
//!   path. Client-supplied metadata (`Hello.client`, peer signing id) never
//!   enters the authorizer.

#![forbid(unsafe_code)]

mod fs;
mod guard;
mod pathcheck;
mod rootkey;

pub use fs::{Fs, StdFs};
pub use guard::{AuthzRequest, Decision, Guard};
pub use pathcheck::ControlPlanePaths;
pub use rootkey::{FileRootKey, GuardError, RootKey};
