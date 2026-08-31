//! Roundtrip tests (`01-protocol.md` M1 acceptance).
//!
//! "Property test: any Request encodes and decodes identically." No
//! `proptest` dependency (the crate's dep set is capped at serde /
//! serde_json / thiserror / ulid), so the property is exercised with a
//! deterministic LCG over a large sample of inputs.

use ramen_proto::{
    ClientInfo, Constraints, Denial, DenialCode, ErrorCode, FileWriteOp, FileWriteResult,
    Fault, Hello, Message, Operation, ProtoError, Request, RestoreHandle, RestoreKind,
    Response, WhoamiOp, WhoamiResult, WriteMode,
};

/// Deterministic LCG (SplitMix64) — good enough for input generation.
struct Rng(u64);

impl Rng {
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E3779B97F4A7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        z ^ (z >> 31)
    }

    fn range(&mut self, lo: u64, hi: u64) -> u64 {
        lo + self.next_u64() % (hi - lo)
    }
}

fn random_request(rng: &mut Rng) -> Request {
    let id = ramen_proto::RequestId::new();
    let op = if rng.range(0, 2) == 0 {
        Operation::Whoami(WhoamiOp {})
    } else {
        Operation::FileWrite(FileWriteOp {
            path: format!("/tmp/ramen-rt-{}", rng.range(0, 1_000_000)),
            content_b64: base64(rng),
            mode: if rng.range(0, 2) == 0 {
                WriteMode::Create
            } else {
                WriteMode::Overwrite
            },
        })
    };
    Request { v: 1, id, op }
}

fn base64(rng: &mut Rng) -> String {
    const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let n = rng.range(4, 64) as usize;
    let s: String = (0..n).map(|_| A[rng.range(0, 64) as usize] as char).collect();
    s + "=="
}

#[test]
fn any_request_round_trips_through_the_codec() {
    let mut rng = Rng(0x5EED);
    for i in 0..10_000 {
        let req = random_request(&mut rng);
        let mut frame = Vec::new();
        ramen_proto::encode(&req, &mut frame).unwrap();
        let decoded = Message::decode(&frame[4..]).unwrap();
        match decoded {
            Message::Request(r) => assert_eq!(r, req, "roundtrip failed at i={i}"),
            other => panic!("i={i}: expected Request back, got {other:?}"),
        }
    }
}

#[test]
fn request_round_trips_via_raw_serde_json_too() {
    // The serde shape itself (independent of the codec) must round-trip.
    let mut rng = Rng(42);
    for i in 0..1000 {
        let req = random_request(&mut rng);
        let s = req.to_string_json();
        let back: Request = serde_json::from_str(&s).unwrap();
        assert_eq!(req, back, "serde roundtrip failed at i={i}");
    }
}

trait ToStringJson {
    fn to_string_json(&self) -> String;
}

impl<T: serde::Serialize> ToStringJson for T {
    fn to_string_json(&self) -> String {
        serde_json::to_string(self).unwrap()
    }
}

#[test]
fn every_message_variant_round_trips() {
    let req_id = ramen_proto::RequestId::new();
    let sess = ramen_proto::SessionId::new();

    let hello = Hello::new(
        "token-abc123".into(),
        ClientInfo { name: "ramenctl".into(), version: "0.1.0".into() },
    );

    let welcome = Message::Welcome(ramen_proto::messages::Welcome {
        v: 1,
        kind: ramen_proto::messages::WelcomeTag::Welcome,
        session: sess,
        identity: "agent:planner".into(),
        capabilities: vec![
            ramen_proto::CapabilitySummary {
                op: "Whoami".into(),
                reversibility: ramen_proto::Reversibility::Trivial,
                constraints: None,
            },
            ramen_proto::CapabilitySummary {
                op: "FileWrite".into(),
                reversibility: ramen_proto::Reversibility::Trivial,
                constraints: Some(Constraints { path_prefix: vec!["/work".into()] }),
            },
        ],
    });

    let req = Request::new(Operation::FileWrite(FileWriteOp {
        path: "/work/out.txt".into(),
        content_b64: "aGVsbG8=".into(),
        mode: WriteMode::Create,
    }));

    let ok = Response::ok(
        req_id,
        ramen_proto::OpResult::Whoami(WhoamiResult {
            identity: "agent:planner".into(),
            session: sess,
            capabilities: vec![],
            token_expires_at: Some("2026-08-31T00:00:00Z".into()),
        }),
    );

    let denied = Response::denied(
        req_id,
        Denial {
            code: DenialCode::CapabilityNotGranted,
            reason: "token does not grant FileWrite".into(),
            audit_seq: 12,
        },
    );

    let err = Response::error(req_id, ErrorCode::AuditUnavailable, "audit log write failed");

    let fault = Fault::new(ErrorCode::MalformedRequest, "unknown field `x`");

    let filewrite_ok = Response::ok(
        req_id,
        ramen_proto::OpResult::FileWrite(FileWriteResult {
            path: "/work/out.txt".into(),
            bytes_written: 5,
            content_sha256: "a3f1".into(),
            restore: RestoreHandle {
                kind: RestoreKind::Snapshot,
                handle: "01ARZ.out.txt.123".into(),
                reversibility: ramen_proto::Reversibility::Trivial,
            },
        }),
    );

    for msg in [
        Message::Hello(hello),
        welcome,
        Message::Request(req),
        Message::Response(ok),
        Message::Response(denied),
        Message::Response(err),
        Message::Fault(fault),
        Message::Response(filewrite_ok),
    ] {
        let mut frame = Vec::new();
        msg.encode(&mut frame).unwrap();
        let payload = &frame[4..];
        let decoded = Message::decode(payload).unwrap();
        assert_eq!(msg, decoded, "roundtrip mismatch");
    }
}
#[test]
fn op_result_is_distinguishable() {
    let sess = ramen_proto::SessionId::new();
    let whoami = ramen_proto::OpResult::Whoami(WhoamiResult {
        identity: "a".into(),
        session: sess,
        capabilities: vec![],
        token_expires_at: None,
    });
    let fw = ramen_proto::OpResult::FileWrite(FileWriteResult {
        path: "/p".into(),
        bytes_written: 1,
        content_sha256: "x".into(),
        restore: RestoreHandle {
            kind: RestoreKind::Snapshot,
            handle: "h".into(),
            reversibility: ramen_proto::Reversibility::Trivial,
        },
    });
    assert_ne!(whoami, fw);
    // Each serializes to its own shape and back.
    for r in [whoami, fw] {
        let s = r.to_string_json();
        let back: ramen_proto::OpResult = serde_json::from_str(&s).unwrap();
        assert_eq!(r, back);
    }
}

#[test]
fn version_mismatch_is_detected() {
    let req = Request::new(Operation::Whoami(WhoamiOp {}));
    let s = req.to_string_json();
    // Forge a v=2 frame payload.
    let bad: String = s.replacen("\"v\":1", "\"v\":2", 1);
    let payload = bad.into_bytes();
    match Message::decode(&payload).unwrap() {
        Message::Request(r) => {
            let e = r_v_err(&r);
            match e {
                Err(ProtoError::VersionMismatch { got, expected }) => {
                    assert_eq!(got, 2);
                    assert_eq!(expected, 1);
                }
                other => panic!("expected VersionMismatch, got {other:?}"),
            }
        }
        other => panic!("expected Request, got {other:?}"),
    }
}

fn r_v_err(r: &Request) -> Result<(), ProtoError> {
    Message::Request(r.clone()).ensure_version()
}

#[test]
fn reversal_classifications_are_stable() {
    assert_eq!(
        Operation::Whoami(WhoamiOp {}).reversibility(),
        ramen_proto::Reversibility::Trivial
    );
    assert_eq!(
        Operation::FileWrite(FileWriteOp {
            path: "/x".into(),
            content_b64: "x".into(),
            mode: WriteMode::Create,
        })
        .reversibility(),
        ramen_proto::Reversibility::Trivial
    );
}
