//! `ramen-audit` — the tamper-evident, append-only, hash-chained audit log
//! for the Ramen supervisor (`02-audit.md`).
//!
//! Every decision the supervisor makes is recorded here *before* its effect:
//! `Authorized` → (effect) → `Executed`/`ExecutionFailed`, plus denials,
//! errors, session lifecycle, and protocol violations. A standalone verifier
//! (`ramen-audit-verify`) replays the hash chain and cross-checks the
//! authorization invariants.
//!
//! # What the log is and is not
//!
//! - It is the source of truth for *what the supervisor decided and did*,
//!   and for tamper detection. `tracing`/`log` is for operators and is not
//!   tamper-evident; the two are separate channels with no dependency
//!   between them.
//! - Records carry references (paths, byte counts, content hashes) — never
//!   content. The log must stay small enough to be read and verified whole.
//! - It is a flat, unrotated append-only file in v0.
//!
//! # Safety
//!
//! The whole crate is `unsafe_code`-free except [`ffullsync`], the single
//! module that issues the `F_FULLFSYNC` and `flock` syscalls. Implemented as
//! a crate-level `deny(unsafe_code)` with a single module-level `allow`
//! (a `forbid` cannot be locally relaxed — that is how "forbid except the
//! F_FULLFSYNC module" is realized).
//!
//! # Dependencies note
//!
//! The spec's core dependency list is `serde`, `serde_json`, `sha2`,
//! `thiserror`, `tokio` (sync only). Two more are required by the spec's own
//! requirements: `ulid` (the log id is a ULID, §3) and `libc` (the
//! `F_FULLFSYNC`/`flock` syscalls, §5). The `tokio` dependency is
//! `sync`-only (a `oneshot` per in-flight append); the group-commit writer
//! is a plain blocking `std::thread` — no runtime feature anywhere in the
//! library.

#![deny(unsafe_code)]

mod chain;
mod ffullsync;
mod log;
mod record;
mod time;
mod verify;

pub use chain::{genesis_hash, hex, is_valid_hex_hash, next_hash, GENESIS_DOMAIN};
pub use log::{AuditError, AuditLog};
pub use record::{
    ClientMeta, EventRecord, LogHeader, NewRecord, PeerInfo, Record, RecordKind,
};
pub use verify::{Finding, Severity, Split, VerifyReport, split_frames, verify_bytes};
