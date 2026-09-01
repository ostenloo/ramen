//! Record schema (`02-audit.md` §4).
//!
//! Two record shapes on disk:
//! - [`LogHeader`] — record 0 of every log: `log_id`, `created_at`,
//!   `supervisor_version`, and the genesis `prev_hash`.
//! - [`EventRecord`] — every decision and lifecycle event.
//!
//! Both carry `kind` from the closed [`RecordKind`] set. [`Record`] is the
//! sum type parsed off the log; its (de)serialization dispatches on the
//! `kind` value, so an unknown `kind` is a parse failure (the verifier
//! reports it as a corrupted record) rather than a silent ignore.
//!
//! **`detail` carries references only** (paths, byte counts, content hashes).
//! Never put request content in `detail` — the log must remain tamper-evident
//! without doubling as a content store (`02-audit.md` §4).

use ramen_proto::{Reversibility, RequestId, SessionId};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;

/// The closed set of record kinds. Unknown kinds are parse errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RecordKind {
    LogHeader,
    SessionOpened,
    SessionClosed,
    IdentityRejected,
    Authorized,
    Denied,
    Indeterminate,
    Errored,
    Executed,
    ExecutionFailed,
    ProtocolViolation,
    TailTruncated,
}

impl std::fmt::Display for RecordKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            RecordKind::LogHeader => "LogHeader",
            RecordKind::SessionOpened => "SessionOpened",
            RecordKind::SessionClosed => "SessionClosed",
            RecordKind::IdentityRejected => "IdentityRejected",
            RecordKind::Authorized => "Authorized",
            RecordKind::Denied => "Denied",
            RecordKind::Indeterminate => "Indeterminate",
            RecordKind::Errored => "Errored",
            RecordKind::Executed => "Executed",
            RecordKind::ExecutionFailed => "ExecutionFailed",
            RecordKind::ProtocolViolation => "ProtocolViolation",
            RecordKind::TailTruncated => "TailTruncated",
        };
        f.write_str(name)
    }
}

/// Record 0 of every log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogHeader {
    pub seq: u64,
    pub kind: RecordKind,
    /// ULID identifying this log (26-char Crockford string).
    pub log_id: String,
    /// RFC 3339 UTC.
    pub created_at: String,
    /// Hex SHA-256 of `GENESIS_DOMAIN || log_id`.
    pub prev_hash: String,
    pub supervisor_version: String,
}

/// Peer identification captured at handshake (`03-supervisor.md` §3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerInfo {
    pub pid: u32,
    /// `LC_UUID` signing identity when the peer is signed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signing_id: Option<String>,
    /// Code directory hash (ad-hoc signed or unsigned binaries).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cdhash: Option<String>,
    /// True only after the supervisor's signature/cdhash check passed.
    pub verified: bool,
}

/// Advisory client metadata, recorded on `SessionOpened` only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientMeta {
    pub name: String,
    pub version: String,
    /// True when a field exceeded 64 bytes and was truncated.
    pub truncated: bool,
}

/// A session/lifecycle event (records 1..).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventRecord {
    pub seq: u64,
    /// RFC 3339 UTC, assigned by the log at append time.
    pub ts: String,
    /// Hex `record_hash[seq-1]`.
    pub prev_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session: Option<SessionId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peer: Option<PeerInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<RequestId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub op_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reversibility: Option<Reversibility>,
    pub kind: RecordKind,
    /// References only — never content (see module docs).
    #[serde(default)]
    pub detail: Value,
    /// Advisory client metadata; present on `SessionOpened` records only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client: Option<ClientMeta>,
}

/// A record as it appears in the log: a header or an event.
// Records are small (a few hundred bytes); boxing the larger variant would
// add a per-record allocation for no meaningful win.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq)]
pub enum Record {
    LogHeader(LogHeader),
    Event(EventRecord),
}

impl Record {
    pub fn seq(&self) -> u64 {
        match self {
            Record::LogHeader(h) => h.seq,
            Record::Event(e) => e.seq,
        }
    }

    pub fn prev_hash(&self) -> &str {
        match self {
            Record::LogHeader(h) => &h.prev_hash,
            Record::Event(e) => &e.prev_hash,
        }
    }

    pub fn kind(&self) -> RecordKind {
        match self {
            Record::LogHeader(h) => h.kind,
            Record::Event(e) => e.kind,
        }
    }

    /// The record's timestamp field (`created_at` for the header, `ts` for
    /// events) — used by the verifier's non-decreasing check.
    pub fn timestamp(&self) -> &str {
        match self {
            Record::LogHeader(h) => &h.created_at,
            Record::Event(e) => &e.ts,
        }
    }
}

impl Serialize for Record {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Record::LogHeader(h) => h.serialize(serializer),
            Record::Event(e) => e.serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for Record {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        // Parse through `Value` so we can dispatch on `kind` without
        // requiring a specific underlying format.
        let v = Value::deserialize(deserializer)?;
        let is_header = v
            .get("kind")
            .and_then(Value::as_str)
            .is_some_and(|k| k == "LogHeader");
        if is_header {
            serde_json::from_value(v).map(Record::LogHeader).map_err(serde::de::Error::custom)
        } else {
            // Any other known kind (or an unknown one, which then fails the
            // EventRecord parse) is an event record.
            serde_json::from_value(v).map(Record::Event).map_err(serde::de::Error::custom)
        }
    }
}

/// The semantic content of an event record, as supplied by the supervisor.
///
/// Chain fields (`seq`, `ts`, `prev_hash`) are deliberately absent: the log
/// assigns them at append time, so a caller *cannot* supply them
/// (`02-audit.md` §5).
#[derive(Debug, Clone)]
pub struct NewRecord {
    pub kind: RecordKind,
    pub session: Option<SessionId>,
    pub identity: Option<String>,
    pub peer: Option<PeerInfo>,
    pub request_id: Option<RequestId>,
    pub op_type: Option<String>,
    pub reversibility: Option<Reversibility>,
    pub detail: Value,
    pub client: Option<ClientMeta>,
}

impl NewRecord {
    pub fn new(kind: RecordKind) -> Self {
        Self {
            kind,
            session: None,
            identity: None,
            peer: None,
            request_id: None,
            op_type: None,
            reversibility: None,
            detail: Value::Object(Default::default()),
            client: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_event() -> EventRecord {
        EventRecord {
            seq: 1,
            ts: "2026-08-30T14:07:33.119Z".into(),
            prev_hash: "00".repeat(32),
            session: Some(SessionId::new()),
            identity: Some("agent:planner".into()),
            peer: Some(PeerInfo {
                pid: 48213,
                signing_id: Some("com.example.planner".into()),
                cdhash: Some("a3f1e2c9".into()),
                verified: true,
            }),
            request_id: Some(RequestId::new()),
            op_type: Some("Whoami".into()),
            reversibility: Some(Reversibility::Trivial),
            kind: RecordKind::Authorized,
            detail: serde_json::json!({}),
            client: None,
        }
    }

    #[test]
    fn event_record_serializes_with_kind_as_tag() {
        let json = serde_json::to_string(&Record::Event(sample_event())).unwrap();
        let v: Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["kind"], "Authorized");
        assert_eq!(v["op_type"], "Whoami");
    }

    #[test]
    fn header_round_trips_through_record() {
        let h = LogHeader {
            seq: 0,
            kind: RecordKind::LogHeader,
            log_id: "01ARZ3NDEKTSV4RRFFQ69G5FAV".into(),
            created_at: "2026-08-30T14:07:33.119Z".into(),
            prev_hash: "00".repeat(32),
            supervisor_version: "0.1.0".into(),
        };
        let json = serde_json::to_string(&Record::LogHeader(h.clone())).unwrap();
        let back: Record = serde_json::from_str(&json).unwrap();
        assert!(matches!(back, Record::LogHeader(_)));
        assert_eq!(back.seq(), 0);
        assert_eq!(back.kind(), RecordKind::LogHeader);
    }

    #[test]
    fn unknown_kind_fails_to_parse() {
        let json = r#"{"seq":1,"ts":"2026-08-30T14:07:33.119Z","prev_hash":"00","kind":"Bogus","detail":{}}"#;
        let res: Result<Record, _> = serde_json::from_str(json);
        assert!(res.is_err());
    }

    #[test]
    fn unknown_fields_are_rejected() {
        let mut e = sample_event();
        e.kind = RecordKind::Denied;
        let mut v = serde_json::to_value(Record::Event(e)).unwrap();
        v.as_object_mut().unwrap().insert("rogue".into(), Value::Null);
        let res: Result<Record, _> = serde_json::from_value(v);
        assert!(res.is_err());
    }

    #[test]
    fn detail_is_free_form_value() {
        let e = EventRecord {
            detail: serde_json::json!({"bytes_discarded": 17, "sha256": "ab"}),
            ..sample_event()
        };
        let v = serde_json::to_value(Record::Event(e)).unwrap();
        assert_eq!(v["detail"]["bytes_discarded"], 17);
    }
}
