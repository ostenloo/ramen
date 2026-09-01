//! Message envelopes and payloads (`01-protocol.md` §4–§8, `05-operations.md` §3).
//!
//! Every envelope carries `v` (the protocol version). Request-side structs use
//! `#[serde(deny_unknown_fields)]`: an unknown field is a protocol violation,
//! not a forward-compatibility extension (`01-protocol.md` §6).
//!
//! `Message` is the top-level dispatch type. Wire messages come in two
//! families:
//!
//! - tagged by `"type"`: `Hello`, `Welcome`, `Fault`
//! - keyed by `id` + `op` (`Request`) or `id` + `status` (`Response`)
//!
//! `Message::decode` validates UTF-8, rejects duplicate JSON keys
//! deterministically, then dispatches by shape.

use serde::{Deserialize, Serialize, Serializer};
use serde::de::Error as _;
use serde_json::Value;

use crate::codec::CodecError;
use crate::ids::{RequestId, SessionId};
use crate::PROTOCOL_VERSION;

// ---------------------------------------------------------------------------
// Reversibility (`01-protocol.md` §4)
// ---------------------------------------------------------------------------

/// Whether an operation can be undone, and how.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum Reversibility {
    Trivial,
    Compensable,
    Irreversible,
}

// ---------------------------------------------------------------------------
// Client metadata (`01-protocol.md` §5)
// ---------------------------------------------------------------------------

/// Advisory client metadata carried in `Hello`.
///
/// Each field is capped at 64 bytes by the *supervisor* (which records the
/// truncation in the `SessionOpened` audit record); this type only carries the
/// raw values.
#[derive(Clone, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientInfo {
    pub name: String,
    pub version: String,
}

impl ClientInfo {
    /// The per-field byte cap imposed by the protocol.
    pub const MAX_FIELD_BYTES: usize = 64;

    /// Truncate `name` and `version` to at most `MAX_FIELD_BYTES` bytes each,
    /// on a character boundary. Returns the capped copy and whether either
    /// field was truncated.
    pub fn capped(&self) -> (Self, bool) {
        let (name, t1) = truncate_utf8(&self.name, Self::MAX_FIELD_BYTES);
        let (version, t2) = truncate_utf8(&self.version, Self::MAX_FIELD_BYTES);
        (Self { name, version }, t1 || t2)
    }
}

fn truncate_utf8(s: &str, max_bytes: usize) -> (String, bool) {
    if s.len() <= max_bytes {
        return (s.to_string(), false);
    }
    // Step back to a UTF-8 character boundary (never split a character).
    let mut i = max_bytes;
    while !s.is_char_boundary(i) {
        i -= 1;
    }
    (s[..i].to_string(), true)
}

// ---------------------------------------------------------------------------
// Capabilities (`01-protocol.md` §4, `05-operations.md` §3.1)
// ---------------------------------------------------------------------------

/// One entry in `Welcome.capabilities` / `Whoami` results.
#[derive(Clone, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilitySummary {
    /// The operation type name, e.g. `"Whoami"`.
    pub op: String,
    pub reversibility: Reversibility,
    /// Operation-specific constraints extracted from the token
    /// (e.g. `path_prefix` for `FileWrite`). Absent for unconstrained
    /// capabilities.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub constraints: Option<Constraints>,
}

/// The v0 constraint shape. Only `path_prefix` exists today; the struct exists
/// so future constraints extend it additively.
#[derive(Clone, PartialEq, Eq, Hash, Debug, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Constraints {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub path_prefix: Vec<String>,
}

// ---------------------------------------------------------------------------
// Request side (`01-protocol.md` §4, §7; `05-operations.md` §3.2)
// ---------------------------------------------------------------------------

/// A client request: `v`, `id`, and the `op` envelope.
#[derive(Clone, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub v: u16,
    pub id: RequestId,
    pub op: Operation,
}

impl Request {
    /// A new request with a fresh id and the current protocol version.
    pub fn new(op: Operation) -> Self {
        Self { v: PROTOCOL_VERSION, id: RequestId::new(), op }
    }
}

/// The `Whoami` operation carries no fields. An *empty* struct (not a unit
/// struct) so that extra fields on the operation object produce a named
/// `unknown field` error rather than an opaque `invalid type: map` one.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WhoamiOp {}

/// Request payload: the operation and its arguments (`01-protocol.md` §4).
///
/// Internally tagged by `"type"`. Every variant is a newtype over a payload
/// struct with `deny_unknown_fields`; an internally-tagged *unit* variant
/// would silently accept extra fields, so even `Whoami` wraps a payload.
/// Adding a variant here changes the wire format: `Operation::reversibility()`
/// is an exhaustive match with no wildcard, so the compiler forces the
/// question to be answered for every new operation (`01-protocol.md` §4,
/// acceptance criterion).
#[derive(Clone, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
#[serde(tag = "type", deny_unknown_fields)]
pub enum Operation {
    /// No arguments.
    Whoami(WhoamiOp),
    FileWrite(FileWriteOp),
}

impl Operation {
    /// The static reversibility classification of this operation.
    ///
    /// Exhaustive, no wildcard: a new operation cannot be added without
    /// deciding its reversibility here.
    pub fn reversibility(&self) -> Reversibility {
        match self {
            Operation::Whoami(_) => Reversibility::Trivial,
            Operation::FileWrite(_) => Reversibility::Trivial,
        }
    }

    /// The wire name of this operation, as used in `CapabilitySummary::op`
    /// and in the `capability` predicate.
    pub fn type_name(&self) -> &'static str {
        match self {
            Operation::Whoami(_) => "Whoami",
            Operation::FileWrite(_) => "FileWrite",
        }
    }

    /// The reversibility of the operation with this wire name, if known.
    ///
    /// For best-effort capability summaries (`04-guard.md` §3,
    /// `Guard::describe_capabilities`): a token's `capability` fact carries a
    /// bare type name, not a payload, so a summary cannot be built through an
    /// `Operation` value. Must stay in sync with `reversibility()` (tested).
    pub fn reversibility_for_type_name(name: &str) -> Option<Reversibility> {
        match name {
            "Whoami" => Some(Reversibility::Trivial),
            "FileWrite" => Some(Reversibility::Trivial),
            _ => None,
        }
    }
}

/// `FileWrite` parameters (`05-operations.md` §3.2).
#[derive(Clone, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileWriteOp {
    /// Absolute, already-canonicalized path. The client sends the canonical
    /// form it intends to write; the supervisor re-canonicalizes and checks
    /// the prefix itself.
    pub path: String,
    /// Standard base64 (with padding) of the file content.
    pub content_b64: String,
    pub mode: WriteMode,
}

/// Write mode (`05-operations.md` §3.2, §3.6).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum WriteMode {
    /// File must not already exist (`O_CREAT | O_EXCL`).
    Create,
    /// Replace the file's content; snapshot the old content first.
    Overwrite,
}

// ---------------------------------------------------------------------------
// Response side (`01-protocol.md` §4, §7)
// ---------------------------------------------------------------------------

/// The response envelope, tagged by `"status"`.
///
/// Modelled with `v` and `id` inside each variant so the enum stays internally
/// tagged without `#[serde(flatten)]` (which serde does not support for
/// internally tagged enums).
#[derive(Clone, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
#[serde(tag = "status", deny_unknown_fields)]
pub enum Response {
    Ok {
        v: u16,
        id: RequestId,
        result: OpResult,
    },
    Denied {
        v: u16,
        id: RequestId,
        denial: Denial,
    },
    Error {
        v: u16,
        id: RequestId,
        error: ErrorInfo,
    },
}

impl Response {
    /// A successful response for `id`, stamped with the current version.
    pub fn ok(id: RequestId, result: OpResult) -> Self {
        Self::Ok { v: PROTOCOL_VERSION, id, result }
    }

    /// A capability denial for `id`.
    pub fn denied(id: RequestId, denial: Denial) -> Self {
        Self::Denied { v: PROTOCOL_VERSION, id, denial }
    }

    /// A non-fatal error response for `id`.
    pub fn error(id: RequestId, code: ErrorCode, message: impl Into<String>) -> Self {
        Self::Error { v: PROTOCOL_VERSION, id, error: ErrorInfo { code, message: message.into() } }
    }
}

/// The `result` payload of an `Ok` response. Untagged: the two operation
/// results have disjoint shapes (`identity`/`session` vs `path`/`bytes_written`).
#[derive(Clone, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum OpResult {
    Whoami(WhoamiResult),
    FileWrite(FileWriteResult),
}

/// Result of `Whoami` (`05-operations.md` §3.1).
#[derive(Clone, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WhoamiResult {
    pub identity: String,
    pub session: SessionId,
    pub capabilities: Vec<CapabilitySummary>,
    /// The token's declared expiry, or `null` when the token has no expiry
    /// fact.
    pub token_expires_at: Option<String>,
}

/// Result of `FileWrite` (`05-operations.md` §3.2).
#[derive(Clone, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileWriteResult {
    pub path: String,
    pub bytes_written: u64,
    /// Hex-encoded SHA-256 of the content as written.
    pub content_sha256: String,
    /// The snapshot handle for restoring the previous content (Overwrite only;
    /// `Create` writes a handle for the *new* file).
    pub restore: RestoreHandle,
}

/// The restore affordance returned by a mutating operation.
#[derive(Clone, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestoreHandle {
    /// `Snapshot` in v0.
    pub kind: RestoreKind,
    /// The snapshot filename (under the supervisor's snapshots directory).
    pub handle: String,
    pub reversibility: Reversibility,
}

/// Closed set of restore kinds. v0 has exactly one.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum RestoreKind {
    Snapshot,
}

/// A capability denial: `code`, human-readable `reason`, and the audit record
/// `seq` to quote when reporting.
#[derive(Clone, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Denial {
    pub code: DenialCode,
    pub reason: String,
    pub audit_seq: u64,
}

/// Closed set of denial codes (`01-protocol.md` §4).
///
/// Deliberately does **not** include a token-expiry or generic "invalid
/// token" code: the only valid expiry denial is the specific `TokenExpired`
/// that follows successful verification with an expired token.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum DenialCode {
    CapabilityNotGranted,
    ConstraintViolated,
    ReversibilityNotPermitted,
    ControlPlaneProtected,
    TokenExpired,
    TokenRejected,
}

impl DenialCode {
    /// The wire name (the serde PascalCase form), for audit `detail` and
    /// error messages.
    pub fn as_str(&self) -> &'static str {
        match self {
            DenialCode::CapabilityNotGranted => "CapabilityNotGranted",
            DenialCode::ConstraintViolated => "ConstraintViolated",
            DenialCode::ReversibilityNotPermitted => "ReversibilityNotPermitted",
            DenialCode::ControlPlaneProtected => "ControlPlaneProtected",
            DenialCode::TokenExpired => "TokenExpired",
            DenialCode::TokenRejected => "TokenRejected",
        }
    }
}

/// A non-fatal error: `code` (closed set) + one-line `message`.
#[derive(Clone, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ErrorInfo {
    pub code: ErrorCode,
    pub message: String,
}

/// Closed set of error codes (`01-protocol.md` §4).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum ErrorCode {
    VersionMismatch,
    MalformedRequest,
    NotImplemented,
    IdentityUnverifiable,
    AuditUnavailable,
    EvaluationIncomplete,
    ExecutionFailed,
    Internal,
}

// ---------------------------------------------------------------------------
// Connection-lifecycle messages (`01-protocol.md` §5)
// ---------------------------------------------------------------------------

/// Client → supervisor: first message on a connection (`01-protocol.md` §5).
#[derive(Clone, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Hello {
    pub v: u16,
    #[serde(rename = "type")]
    pub kind: HelloTag,
    /// The Biscuit token, base64url-encoded, no padding.
    pub token: String,
    pub client: ClientInfo,
}

impl Hello {
    /// A handshake carrying `token`, stamped with the current version.
    pub fn new(token: String, client: ClientInfo) -> Self {
        Self { v: PROTOCOL_VERSION, kind: HelloTag::Hello, token, client }
    }
}

/// `Welcome` — supervisor → client, the only successful `Hello` response.
#[derive(Clone, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Welcome {
    pub v: u16,
    #[serde(rename = "type")]
    pub kind: WelcomeTag,
    pub session: SessionId,
    /// The `identity` fact extracted from the token.
    pub identity: String,
    /// Capabilities extracted from the token (not a static list).
    pub capabilities: Vec<CapabilitySummary>,
}

/// Terminal connection-level failure (`01-protocol.md` §8).
///
/// No `id`: it may be produced before any request exists. Always followed
/// immediately by close. Distinct from the `Error` *status* of a response.
#[derive(Clone, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Fault {
    pub v: u16,
    #[serde(rename = "type")]
    pub kind: FaultTag,
    pub error: ErrorInfo,
}

impl Fault {
    /// A fault with the current version.
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self { v: PROTOCOL_VERSION, kind: FaultTag::Fault, error: ErrorInfo { code, message: message.into() } }
    }
}

/// `"type": "Hello"` — a single-variant enum so the field serializes to the
/// literal string (a zero-sized unit struct would serialize to `null`), and a
/// `Hello` frame cannot carry a foreign `type` value.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
pub enum HelloTag {
    Hello,
}

/// `"type": "Welcome"`.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
pub enum WelcomeTag {
    Welcome,
}

/// `"type": "Fault"`.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
pub enum FaultTag {
    Fault,
}

// ---------------------------------------------------------------------------
// Top-level message dispatch
// ---------------------------------------------------------------------------

/// Any message that can appear on the wire.
///
/// `Message` is the unit the codec and the transports deal in. Use
/// [`Message::encode`] / [`Message::decode`] rather than `serde_json`
/// directly: `decode` enforces the frame payload rules (UTF-8, no duplicate
/// keys) that raw `serde_json` would silently paper over.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub enum Message {
    Hello(Hello),
    Welcome(Welcome),
    Request(Request),
    Response(Response),
    Fault(Fault),
}

impl Message {
    /// The `v` field of this message.
    pub fn version(&self) -> u16 {
        match self {
            Message::Hello(m) => m.v,
            Message::Welcome(m) => m.v,
            Message::Request(m) => m.v,
            Message::Response(m) => match m {
                Response::Ok { v, .. }
                | Response::Denied { v, .. }
                | Response::Error { v, .. } => *v,
            },
            Message::Fault(m) => m.v,
        }
    }

    /// Reject this message unless its `v` exactly matches
    /// [`PROTOCOL_VERSION`] (`01-protocol.md` §4).
    pub fn ensure_version(&self) -> Result<(), ProtoError> {
        if self.version() != PROTOCOL_VERSION {
            Err(ProtoError::VersionMismatch {
                got: self.version(),
                expected: PROTOCOL_VERSION,
            })
        } else {
            Ok(())
        }
    }

    /// Frame `self` and append it to `out` (4-byte BE length prefix + JSON).
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<(), CodecError> {
        crate::codec::encode(self, out)
    }

    /// Decode a frame payload (the bytes after the length prefix) into a
    /// `Message`.
    ///
    /// Deterministic behavior, in order:
    /// 1. the payload must be valid UTF-8 → [`CodecError::Utf8`]
    /// 2. duplicate keys at any depth are rejected → [`ProtoError::DuplicateKey`]
    ///    (serde_json's default is silent last-wins; we do not inherit it)
    /// 3. the top-level value must be an object with a recognized shape, and
    ///    every field must be known to its envelope type
    pub fn decode(payload: &[u8]) -> Result<Self, ProtoError> {
        let s = std::str::from_utf8(payload).map_err(|e| ProtoError::Codec(CodecError::Utf8(e)))?;
        // Pass 1: structure + duplicate keys (streaming, cheap, no allocation).
        // serde_json's default on duplicate keys is silent last-wins; the
        // protocol rejects them instead (01-protocol.md §6).
        let mut d = serde_json::Deserializer::from_str(s);
        crate::codec::DuplicateKeyCheck::deserialize(&mut d)
            .map_err(|e| ProtoError::DuplicateKey(e.to_string()))?;
        // Pass 2: parse and dispatch.
        let v: Value = serde_json::from_str(s).map_err(|e| ProtoError::Codec(CodecError::Json(e)))?;
        Self::from_value(v).map_err(|e| ProtoError::Codec(CodecError::Json(e)))
    }

    fn from_value(v: Value) -> Result<Self, serde_json::Error> {
        let obj = v
            .as_object()
            .ok_or_else(|| serde_json::Error::custom("message must be a JSON object"))?;

        if let Some(t) = obj.get("type").and_then(Value::as_str) {
            return match t {
                "Hello" => Ok(Message::Hello(serde_json::from_value(v)?)),
                "Welcome" => Ok(Message::Welcome(serde_json::from_value(v)?)),
                "Fault" => Ok(Message::Fault(serde_json::from_value(v)?)),
                other => Err(serde_json::Error::custom(format!("unknown message type {other:?}"))),
            };
        }

        if obj.contains_key("id") && obj.contains_key("op") {
            return Ok(Message::Request(serde_json::from_value(v)?));
        }
        if obj.contains_key("id") && obj.contains_key("status") {
            return Ok(Message::Response(serde_json::from_value(v)?));
        }

        Err(serde_json::Error::custom(
            "unrecognized message shape: expected a Hello, Welcome, Request, Response, or Fault envelope",
        ))
    }
}

impl Serialize for Message {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Message::Hello(m) => m.serialize(serializer),
            Message::Welcome(m) => m.serialize(serializer),
            Message::Request(m) => m.serialize(serializer),
            Message::Response(m) => m.serialize(serializer),
            Message::Fault(m) => m.serialize(serializer),
        }
    }
}

/// Error type for message-level validation (framing errors are
/// [`CodecError`]).
#[derive(Debug, thiserror::Error)]
pub enum ProtoError {
    #[error("duplicate JSON key in message: {0}")]
    DuplicateKey(String),
    #[error("protocol version mismatch: got {got}, expected {expected}")]
    VersionMismatch {
        got: u16,
        expected: u16,
    },
    #[error("frame payload error: {0}")]
    Codec(#[source] CodecError),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reversibility_for_type_name_agrees_with_reversibility() {
        let ops = [
            Operation::Whoami(WhoamiOp {}),
            Operation::FileWrite(FileWriteOp {
                path: "/x".into(),
                content_b64: "".into(),
                mode: WriteMode::Create,
            }),
        ];
        for op in ops {
            assert_eq!(
                Operation::reversibility_for_type_name(op.type_name()),
                Some(op.reversibility()),
                "name lookup must agree with the variant match for {}",
                op.type_name()
            );
        }
        assert_eq!(Operation::reversibility_for_type_name("Bogus"), None);
        assert_eq!(Operation::reversibility_for_type_name("whoami"), None);
    }

    #[test]
    fn denial_code_as_str_matches_serde_name() {
        let codes = [
            DenialCode::CapabilityNotGranted,
            DenialCode::ConstraintViolated,
            DenialCode::ReversibilityNotPermitted,
            DenialCode::ControlPlaneProtected,
            DenialCode::TokenExpired,
        ];
        for code in codes {
            assert_eq!(
                serde_json::to_string(&code).unwrap(),
                format!("\"{}\"", code.as_str()),
                "as_str must be the wire name"
            );
        }
    }

    #[test]
    fn no_wildcard_in_reversibility_match() {
        // Compile-time guarantee: `Operation::reversibility()` and
        // `Operation::type_name()` are exhaustive matches with no `_` arm.
        // This test pins the v0 values so a change is a deliberate edit.
        assert_eq!(Operation::Whoami(WhoamiOp {}).reversibility(), Reversibility::Trivial);
        assert_eq!(
            Operation::FileWrite(FileWriteOp {
                path: "/x".into(),
                content_b64: "".into(),
                mode: WriteMode::Create,
            })
            .reversibility(),
            Reversibility::Trivial
        );
        assert_eq!(Operation::Whoami(WhoamiOp {}).type_name(), "Whoami");
        assert_eq!(
            Operation::FileWrite(FileWriteOp {
                path: "/x".into(),
                content_b64: "".into(),
                mode: WriteMode::Create,
            })
            .type_name(),
            "FileWrite"
        );
    }

    #[test]
    fn client_info_capped_respects_byte_limit() {
        let short = ClientInfo { name: "ramenctl".into(), version: "0.1.0".into() };
        let (c, t) = short.capped();
        assert!(!t);
        assert_eq!(c, short);

        let long_name = "n".repeat(100);
        let long = ClientInfo { name: long_name, version: "1.0".into() };
        let (c, t) = long.capped();
        assert!(t);
        assert_eq!(c.name.len(), ClientInfo::MAX_FIELD_BYTES);
        assert_eq!(c.version, "1.0");

        // Exactly at the limit: not truncated.
        let exact = ClientInfo {
            name: "a".repeat(64),
            version: "b".repeat(64),
        };
        let (c, t) = exact.capped();
        assert!(!t);
        assert_eq!(c, exact);
    }

    #[test]
    fn client_info_capped_never_splits_utf8() {
        // "é" is 2 bytes. 64 bytes = 32 chars; put one more char so the
        // naive 64-byte cut lands inside a character.
        let s = "é".repeat(33); // 66 bytes
        let info = ClientInfo { name: s.clone(), version: "1".into() };
        let (c, t) = info.capped();
        assert!(t);
        assert_eq!(c.name.len(), 64);
        // 32 whole é characters, no dangling continuation bytes.
        assert_eq!(c.name, "é".repeat(32));
    }
}
