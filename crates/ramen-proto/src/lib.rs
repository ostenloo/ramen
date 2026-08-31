//! `ramen-proto` — wire types and codec for the Ramen control-plane protocol.
//!
//! M1 of the build order (`00-overview.md`): **pure types and codec, no I/O.**
//! No `tokio`, no `std::fs`, no sockets. The codec operates on byte slices and
//! buffers only.
//!
//! ## What this crate is
//!
//! - Framing: a 4-byte big-endian length prefix + UTF-8 JSON payload
//!   (`codec`), with a bounded incremental `Decoder`.
//! - Identifiers: `RequestId` / `SessionId` as ULID newtypes (`ids`).
//! - The message envelopes: `Hello`, `Welcome`, `Request`, `Response`, `Fault`,
//!   and the operation/denial/error payloads (`messages`).
//!
//! ## What this crate is not
//!
//! It does not open sockets, enforce peer identity, run the guard, or write the
//! audit log. Those are later milestones. This crate is the contract they all
//! share, so it must stay dependency-lean: only `serde`, `serde_json`,
//! `thiserror`, and `ulid` (`01-protocol.md`).

#![forbid(unsafe_code)]

pub mod codec;
pub mod ids;
pub mod messages;

pub use codec::{CodecError, Decoder, MAX_FRAME_BYTES, encode};
pub use ids::{RequestId, SessionId};
pub use messages::{
    CapabilitySummary, ClientInfo, Constraints, Denial, DenialCode, ErrorInfo, ErrorCode,
    FileWriteOp, FileWriteResult, Fault, Hello, Message, Operation, OpResult, ProtoError, Request,
    Response, RestoreHandle, RestoreKind, WhoamiOp, WhoamiResult, WriteMode, Reversibility,
};

/// The protocol version carried in every envelope as `v`.
///
/// The supervisor rejects any message whose `v` does not exactly equal this
/// (`01-protocol.md` §4). There is no range negotiation and no forward
/// compatibility in v0.
pub const PROTOCOL_VERSION: u16 = 1;
