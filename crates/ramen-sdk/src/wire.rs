//! Envelope types, defined independently from `01-protocol.md` (spec §3–§7).
//!
//! These types intentionally do **not** share code with `ramen-proto`.
//! Conformance between the two is proven by the golden-fixture round-trip
//! tests in `tests/golden.rs`.

pub mod codec;

use serde::{Deserialize, Serialize};

use codec::WireError;

/// Protocol version. `v = 1` for every envelope.
pub const PROTOCOL_VERSION: u16 = 1;

// ---------------------------------------------------------------------------
// Identifiers
// ---------------------------------------------------------------------------

/// Client-generated request ID (ULID, serialized as the canonical string
/// form). Newtyped: never a bare `String` (spec §1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RequestId(pub ulid::Ulid);

impl RequestId {
    /// Generate a fresh, unique request ID.
    pub fn new() -> Self {
        Self(ulid::Ulid::new())
    }
}

impl Default for RequestId {
    fn default() -> Self {
        Self::new()
    }
}

/// Server-generated session ID (ULID, canonical string form).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SessionId(pub ulid::Ulid);

// ---------------------------------------------------------------------------
// Hello (client → supervisor, first message)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientInfo {
    pub name: String,
    pub version: String,
}

impl ClientInfo {
    pub fn new(name: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            version: version.into(),
        }
    }
}

/// First message of every connection (spec §4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Hello {
    pub v: u16,
    #[serde(rename = "type")]
    pub kind: String,
    /// Serialized Biscuit, base64url, no padding.
    pub token: String,
    pub client: ClientInfo,
}

impl Hello {
    pub const TYPE: &'static str = "Hello";

    pub fn new(token: String, client: ClientInfo) -> Self {
        Self {
            v: PROTOCOL_VERSION,
            kind: Self::TYPE.to_string(),
            token,
            client,
        }
    }
}

// ---------------------------------------------------------------------------
// Welcome (supervisor → client, second message)
// ---------------------------------------------------------------------------

/// Reversibility classification (spec §1, §7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Reversibility {
    Trivial,
    Compensable,
    Irreversible,
}

/// Capability grant summary carried in `Welcome` and `Whoami` results
/// (spec §5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilitySummary {
    pub op: String,
    pub reversibility: Reversibility,
    /// `null` (absent) when the grant is unrestricted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub constraints: Option<Constraints>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Constraints {
    /// Paths outside these prefixes are `ConstraintViolated`.
    pub path_prefix: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Welcome {
    pub v: u16,
    #[serde(rename = "type")]
    pub kind: String,
    pub session: SessionId,
    /// Identity derived from the token claims (spec §5).
    pub identity: String,
    pub capabilities: Vec<CapabilitySummary>,
}

impl Welcome {
    pub const TYPE: &'static str = "Welcome";
}

// ---------------------------------------------------------------------------
// Request (client → supervisor)
// ---------------------------------------------------------------------------

/// Write mode (spec 05-operations.md).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WriteMode {
    Create,
    Overwrite,
}

/// A single operation (spec §3; the closed set for v0 is Whoami/FileWrite).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", deny_unknown_fields)]
pub enum Operation {
    Whoami(WhoamiOp),
    FileWrite(FileWriteOp),
}

/// The `Whoami` operation carries no fields. An *empty* struct (not a unit
/// variant): an internally-tagged unit variant silently accepts unknown
/// fields (serde drops them), which would violate the protocol's
/// unknown-fields rule (`01-protocol.md` §6). The wrapper is what makes
/// `deny_unknown_fields` apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WhoamiOp {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileWriteOp {
    pub path: String,
    /// base64 (standard alphabet, padded — as in the golden fixtures) of the
    /// file content.
    pub content_b64: String,
    pub mode: WriteMode,
}

/// `v` + request ID + operation (spec §3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub v: u16,
    pub id: RequestId,
    pub op: Operation,
}

impl Request {
    pub fn new(id: RequestId, op: Operation) -> Self {
        Self {
            v: PROTOCOL_VERSION,
            id,
            op,
        }
    }
}

// ---------------------------------------------------------------------------
// Response (supervisor → client)
// ---------------------------------------------------------------------------

/// Terminal status of an operation (spec §7). Three terminal statuses; v0
/// has no non-terminal status (`Pending` was cut — 00-overview.md D1), and
/// the SDK rejects an unrecognized status with an error rather than waiting.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status")]
pub enum Response {
    /// `result` is op-specific and passed through as JSON (the SDK does not
    /// model the result payload per the spec §2 `OpOutcome::Ok(Value)`),
    /// but it must be a *legal v0 result shape* — see `validate_ok_result`.
    Ok {
        v: u16,
        id: RequestId,
        result: serde_json::Value,
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

// ── Ok result-shape validation ────────────────────────────────────────────
//
// `OpOutcome::Ok(Value)` hands the result to clients opaquely, so the SDK
// does not *model* it. But the *parser* must reject results that are not
// legal v0 frames: an opaque `Value` would accept anything JSON-shaped, and
// `{}` is not a legal v0 result (the first sweep of the spec examples
// found the SDK accepting it while `ramen-proto` rejected it). The two
// shapes below are the v0 result payloads (`05-operations.md` §3),
// independently defined here. When a new operation ships with a new result
// shape, this must grow with it — and the corpus must pin the new shape.

// Validation-only types: the deserializer writes them, no code reads a field,
// so the fields are dead by construction.
#[allow(dead_code)]
#[derive(Deserialize)]
#[serde(untagged)]
enum OkResultShape {
    Whoami(WhoamiResultShape),
    FileWrite(FileWriteResultShape),
}

#[allow(dead_code)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WhoamiResultShape {
    identity: String,
    session: SessionId,
    capabilities: Vec<CapabilitySummary>,
    token_expires_at: Option<String>,
}

#[allow(dead_code)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FileWriteResultShape {
    path: String,
    bytes_written: u64,
    content_sha256: String,
    restore: RestoreHandleShape,
}

#[allow(dead_code)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RestoreHandleShape {
    kind: RestoreKindShape,
    handle: String,
    reversibility: Reversibility,
}

#[allow(dead_code)]
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
enum RestoreKindShape {
    Snapshot,
}

fn validate_ok_result(result: &serde_json::Value) -> Result<(), WireError> {
    serde_json::from_value::<OkResultShape>(result.clone())
        .map_err(|e| {
            WireError::Json(format!(
                "`result` is not a legal v0 shape (Whoami or FileWrite): {e}"
            ))
        })
        .map(|_| ())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Denial {
    pub code: DenialCode,
    pub reason: String,
    /// Audit log sequence number for the recorded denial (spec §7).
    pub audit_seq: u64,
}

/// Closed set (spec §7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum DenialCode {
    CapabilityNotGranted,
    ConstraintViolated,
    ReversibilityNotPermitted,
    ControlPlaneProtected,
    TokenExpired,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ErrorInfo {
    pub code: ErrorCode,
    pub message: String,
}

/// Closed set (spec §6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum ErrorCode {
    VersionMismatch,
    MalformedRequest,
    NotImplemented,
    IdentityUnverifiable,
    AuditUnavailable,
    ExecutionFailed,
    Internal,
}

// ---------------------------------------------------------------------------
// Fault (supervisor → client, best-effort, connection is then closed)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Fault {
    pub v: u16,
    #[serde(rename = "type")]
    pub kind: String,
    pub error: ErrorInfo,
}

impl Fault {
    pub const TYPE: &'static str = "Fault";
}

// ---------------------------------------------------------------------------
// Message (any envelope)
// ---------------------------------------------------------------------------

/// Any envelope on the wire.
///
/// The five variants are heterogeneous (Hello/Welcome/Fault are tagged with
/// a `"type"` field, Response is tagged with `"status"`, Request has no tag),
/// so dispatch is by structural inspection rather than a uniform serde tag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    Hello(Hello),
    Welcome(Welcome),
    Request(Request),
    Response(Response),
    Fault(Fault),
}

impl Serialize for Message {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Message::Hello(m) => m.serialize(serializer),
            Message::Welcome(m) => m.serialize(serializer),
            Message::Request(m) => m.serialize(serializer),
            Message::Response(m) => m.serialize(serializer),
            Message::Fault(m) => m.serialize(serializer),
        }
    }
}

impl Message {
    /// The `v` field of this envelope (`01-protocol.md` §4). Every envelope
    /// carries it; a conforming endpoint rejects any frame whose `v` does not
    /// exactly equal its own `PROTOCOL_VERSION`, validated *before* the body
    /// is parsed.
    pub fn version(&self) -> u16 {
        match self {
            Message::Hello(m) => m.v,
            Message::Welcome(m) => m.v,
            Message::Request(m) => m.v,
            Message::Response(r) => match r {
                Response::Ok { v, .. }
                | Response::Denied { v, .. }
                | Response::Error { v, .. } => *v,
            },
            Message::Fault(m) => m.v,
        }
    }

    /// Serialize to the JSON wire form.
    pub fn to_json(&self) -> Result<String, WireError> {
        serde_json::to_string(self).map_err(|e| WireError::Json(e.to_string()))
    }

    /// Parse a frame payload (UTF-8 → duplicate-key check → JSON →
    /// envelope).
    ///
    /// Duplicate keys are *rejected*, not last-wins: that is the behavior the
    /// protocol chose (01-protocol.md M1 acceptance: "handled
    /// deterministically; assert the chosen behavior explicitly"), and the
    /// SDK enforces the same semantics on messages it receives.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, WireError> {
        let s = std::str::from_utf8(bytes)
            .map_err(|e| WireError::Utf8(e.to_string()))?;
        DuplicateKeyCheck::deserialize(&mut serde_json::Deserializer::from_str(s))
            .map_err(|e: serde_json::Error| WireError::Json(e.to_string()))?;
        let value: serde_json::Value =
            serde_json::from_str(s).map_err(|e| WireError::Json(e.to_string()))?;
        Self::from_value(value)
    }

    /// Dispatch a parsed JSON value onto an envelope variant.
    pub fn from_value(value: serde_json::Value) -> Result<Self, WireError> {
        let json_err = |e: serde_json::Error| WireError::Json(e.to_string());

        if let Some(obj) = value.as_object() {
            if let Some(tag) = obj.get("type") {
                return match tag.as_str() {
                    Some(Hello::TYPE) => {
                        let h: Hello = serde_json::from_value(value).map_err(json_err)?;
                        if h.kind != Hello::TYPE {
                            return Err(WireError::Json(
                                "hello `type` tag mismatch".to_string(),
                            ));
                        }
                        Ok(Message::Hello(h))
                    }
                    Some(Welcome::TYPE) => {
                        let w: Welcome =
                            serde_json::from_value(value).map_err(json_err)?;
                        if w.kind != Welcome::TYPE {
                            return Err(WireError::Json(
                                "welcome `type` tag mismatch".to_string(),
                            ));
                        }
                        Ok(Message::Welcome(w))
                    }
                    Some(Fault::TYPE) => {
                        let f: Fault = serde_json::from_value(value).map_err(json_err)?;
                        if f.kind != Fault::TYPE {
                            return Err(WireError::Json(
                                "fault `type` tag mismatch".to_string(),
                            ));
                        }
                        Ok(Message::Fault(f))
                    }
                    Some(other) => Err(WireError::Json(format!(
                        "unknown envelope `type`: {other}"
                    ))),
                    None => Err(WireError::Json(
                        "`type` tag is not a string".to_string(),
                    )),
                };
            }
            if let Some(status) = obj.get("status") {
                // v0 has exactly three terminal statuses (spec §7). An
                // unrecognized one — e.g. a future `Pending`, which v0 never
                // emits — is a transport-level error, not a hang (spec
                // 06-ramenctl.md §2). Rejected explicitly, not by accident of
                // the internal tag.
                match status.as_str() {
                    Some("Ok" | "Denied" | "Error") => {}
                    Some(other) => {
                        return Err(WireError::Json(format!(
                            "unrecognized response status: {other} (v0 has exactly three terminal statuses)"
                        )));
                    }
                    None => {
                        return Err(WireError::Json(
                            "`status` tag is not a string".to_string(),
                        ));
                    }
                }
                let r: Response = serde_json::from_value(value).map_err(json_err)?;
                if let Response::Ok { result, .. } = &r {
                    validate_ok_result(result)?;
                }
                return Ok(Message::Response(r));
            }
        }
        let r: Request = serde_json::from_value(value).map_err(json_err)?;
        Ok(Message::Request(r))
    }
}

/// Streaming pass that rejects any object with duplicate keys (01-protocol.md
/// M1: the protocol's chosen, asserted behavior). Structure-only; no
/// allocation of the payload. Each object level gets its own key set, which
/// is exactly the duplicate scope (keys are unique *within an object*).
struct DuplicateKeyCheck;

impl<'de> serde::de::Deserialize<'de> for DuplicateKeyCheck {
    fn deserialize<D: serde::de::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Self, D::Error> {
        deserializer
            .deserialize_any(DupVisitor)
            .map(|_| DuplicateKeyCheck)
    }
}

struct DupVisitor;

impl<'de> serde::de::Visitor<'de> for DupVisitor {
    type Value = ();

    fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str("any JSON value")
    }

    fn visit_map<A: serde::de::MapAccess<'de>>(
        self,
        mut map: A,
    ) -> Result<(), A::Error> {
        let mut seen = std::collections::HashSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if seen.contains(&key) {
                return Err(serde::de::Error::custom(format!(
                    "duplicate key in object: {key:?}"
                )));
            }
            seen.insert(key);
            map.next_value::<serde::de::IgnoredAny>()?;
        }
        Ok(())
    }

    fn visit_seq<A: serde::de::SeqAccess<'de>>(
        self,
        mut seq: A,
    ) -> Result<(), A::Error> {
        while (seq.next_element::<serde::de::IgnoredAny>()?).is_some() {}
        Ok(())
    }

    fn visit_unit<E>(self) -> Result<(), E> { Ok(()) }
    fn visit_bool<E>(self, _: bool) -> Result<(), E> { Ok(()) }
    fn visit_i64<E>(self, _: i64) -> Result<(), E> { Ok(()) }
    fn visit_u64<E>(self, _: u64) -> Result<(), E> { Ok(()) }
    fn visit_f64<E>(self, _: f64) -> Result<(), E> { Ok(()) }
    fn visit_str<E>(self, _: &str) -> Result<(), E> { Ok(()) }
    fn visit_string<E>(self, _: String) -> Result<(), E> { Ok(()) }
    fn visit_bytes<E>(self, _: &[u8]) -> Result<(), E> { Ok(()) }
    fn visit_byte_buf<E>(self, _: Vec<u8>) -> Result<(), E> { Ok(()) }
    fn visit_none<E>(self) -> Result<(), E> { Ok(()) }
    fn visit_some<D: serde::de::Deserializer<'de>>(
        self,
        d: D,
    ) -> Result<(), D::Error> {
        serde::de::Deserializer::deserialize_any(d, self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_accessor_covers_every_envelope() {
        let hello = Message::Hello(Hello::new("tok".into(), ClientInfo::new("c", "1")));
        assert_eq!(hello.version(), PROTOCOL_VERSION);

        let welcome = Message::Welcome(Welcome {
            v: 7,
            kind: Welcome::TYPE.to_string(),
            session: SessionId(ulid::Ulid::new()),
            identity: "i".into(),
            capabilities: vec![],
        });
        assert_eq!(welcome.version(), 7);

        let req = Message::Request(Request::new(
            RequestId::new(),
            Operation::Whoami(WhoamiOp {}),
        ));
        assert_eq!(req.version(), PROTOCOL_VERSION);

        for r in [
            Response::Ok { v: 3, id: RequestId::new(), result: serde_json::json!({}) },
            Response::Denied {
                v: 3,
                id: RequestId::new(),
                denial: Denial { code: DenialCode::TokenExpired, reason: "r".into(), audit_seq: 1 },
            },
            Response::Error {
                v: 3,
                id: RequestId::new(),
                error: ErrorInfo { code: ErrorCode::Internal, message: "m".into() },
            },
        ] {
            assert_eq!(Message::Response(r).version(), 3);
        }

        let fault = Message::Fault(Fault {
            v: 9,
            kind: Fault::TYPE.to_string(),
            error: ErrorInfo { code: ErrorCode::Internal, message: "m".into() },
        });
        assert_eq!(fault.version(), 9);
    }

    #[test]
    fn hello_round_trips_through_value() {
        let m = Message::Hello(Hello::new(
            "tok".into(),
            ClientInfo::new("c", "1"),
        ));
        let v: serde_json::Value =
            serde_json::from_str(&m.to_json().unwrap()).unwrap();
        // Note: key *order* on the wire is pinned by the golden test's
        // byte-identity; `Value` here is order-insensitive (BTreeMap).
        let obj = v.as_object().unwrap();
        let keys: Vec<&str> = obj.keys().map(|s| s.as_str()).collect();
        let mut keys = keys;
        keys.sort();
        assert_eq!(keys, vec!["client", "token", "type", "v"]);
        assert_eq!(obj["type"], "Hello");
        assert_eq!(Message::from_value(v).unwrap(), m);
    }

    #[test]
    fn request_unknown_op_rejected() {
        let v = serde_json::json!({
            "v": 1,
            "id": "01ARZ3NDEKTSV4RRFFQ69G5FAV",
            "op": { "type": "Frobnicate" }
        });
        assert!(Message::from_value(v).is_err());
    }

    #[test]
    fn request_unknown_field_rejected() {
        let v = serde_json::json!({
            "v": 1,
            "id": "01ARZ3NDEKTSV4RRFFQ69G5FAV",
            "op": { "type": "Whoami" },
            "junk": 1
        });
        assert!(Message::from_value(v).is_err());
    }

    #[test]
    fn operation_filewrite_unknown_field_rejected() {
        let v = serde_json::json!({
            "v": 1,
            "id": "01ARZ3NDEKTSV4RRFFQ69G5FAV",
            "op": {
                "type": "FileWrite",
                "path": "/tmp/x",
                "content_b64": "aGk=",
                "mode": "Overwrite",
                "junk": true
            }
        });
        assert!(Message::from_value(v).is_err());
    }

    #[test]
    fn response_variants_dispatch_by_status() {
        let ok: serde_json::Value = serde_json::from_str(
            r#"{"status":"Ok","v":1,"id":"01ARZ3NDEKTSV4RRFFQ69G5FAV","result":{"identity":"agent:planner","session":"01ARZ3NDEKTSV4RRFFQ69G5FAV","capabilities":[],"token_expires_at":null}}"#
        )
        .unwrap();
        assert!(matches!(Message::from_value(ok).unwrap(), Message::Response(Response::Ok { .. })));

        let err: serde_json::Value = serde_json::from_str(
            r#"{"status":"Error","v":1,"id":"01ARZ3NDEKTSV4RRFFQ69G5FAV","error":{"code":"Internal","message":"x"}}"#
        )
        .unwrap();
        assert!(matches!(Message::from_value(err).unwrap(), Message::Response(Response::Error { .. })));
    }

    #[test]
    fn ok_result_must_be_a_legal_v0_shape() {
        let mk = |result: &str| {
            serde_json::from_str(&format!(
                r#"{{"status":"Ok","v":1,"id":"01ARZ3NDEKTSV4RRFFQ69G5FAV","result":{result}}}"#,
            ))
            .unwrap()
        };
        // `{}` is not a legal v0 result — the opaque-Value laxness this
        // validator closes. Unknown fields and wrong shapes are equally
        // illegal.
        assert!(Message::from_value(mk("{}")).is_err());
        assert!(Message::from_value(mk(r#"{"junk":1}"#)).is_err());
        assert!(Message::from_value(mk(r#"[1,2,3]"#)).is_err());
        // Both v0 shapes parse.
        assert!(Message::from_value(
            mk(r#"{"identity":"agent:planner","session":"01ARZ3NDEKTSV4RRFFQ69G5FAV","capabilities":[{"op":"Whoami","reversibility":"Trivial"}],"token_expires_at":null}"#)
        ).is_ok());
        assert!(Message::from_value(
            mk(r#"{"path":"/x/f.txt","bytes_written":3,"content_sha256":"a3f1e2c9","restore":{"kind":"Snapshot","handle":"h","reversibility":"Trivial"}}"#)
        ).is_ok());
    }

    #[test]
    fn response_unknown_status_rejected() {
        // v0 has exactly three terminal statuses; a future `Pending` (cut from
        // v0, 00-overview.md D1) must surface as an error, not a hang or a
        // silent drop.
        let pending: serde_json::Value = serde_json::from_str(
            r#"{"status":"Pending","v":1,"id":"01ARZ3NDEKTSV4RRFFQ69G5FAV","pending":{"reason":"AwaitingApproval","expires_at":"2026-08-30T18:22:00Z"}}"#
        ).unwrap();
        let e = Message::from_value(pending).unwrap_err();
        assert!(matches!(e, WireError::Json(_)));
        assert!(e.to_string().contains("unrecognized response status"), "got: {e}");
        assert!(e.to_string().contains("Pending"), "got: {e}");

        let bogus: serde_json::Value = serde_json::from_str(
            r#"{"status":"Maybe","v":1,"id":"01ARZ3NDEKTSV4RRFFQ69G5FAV"}"#
        ).unwrap();
        assert!(Message::from_value(bogus).is_err());
    }

    #[test]
    fn duplicate_keys_rejected() {
        // The protocol's chosen behavior (01 M1 acceptance): reject, with the
        // duplicate named — not serde_json's silent last-wins.
        let e = Message::from_bytes(b"{\"v\":1,\"v\":2}").unwrap_err();
        assert!(matches!(e, WireError::Json(_)));
        assert!(e.to_string().contains("\"v\""), "got: {e}");
        // Nested duplicates too.
        assert!(Message::from_bytes(
            b"{\"a\":{\"b\":1,\"b\":2}}"
        )
        .is_err());
        // No duplicates: fine (the JSON is otherwise not a known envelope).
        assert!(matches!(
            Message::from_bytes(b"{\"a\":1,\"b\":2}"),
            Err(WireError::Json(_))
        ));
    }

    #[test]
    fn response_unknown_field_in_payload_rejected() {
        let v = serde_json::json!({
            "status": "Denied",
            "v": 1,
            "id": "01ARZ3NDEKTSV4RRFFQ69G5FAV",
            "denial": { "code": "TokenExpired", "reason": "r", "audit_seq": 1, "junk": 1 }
        });
        assert!(Message::from_value(v).is_err());
    }
}
