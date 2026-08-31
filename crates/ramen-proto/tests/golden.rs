//! Golden file tests (`01-protocol.md` M1 acceptance): at least one
//! serialization example per envelope variant, committed as fixtures.
//!
//! Run with `UPDATE_GOLDEN=1` to regenerate the fixtures (do this only when
//! the wire format intentionally changes, and review the diff).

use ramen_proto::{
    CapabilitySummary, ClientInfo, Constraints, Denial, DenialCode, ErrorInfo, ErrorCode,
    FileWriteOp, FileWriteResult, Fault, Hello, Message, Operation, OpResult, Request,
    Response, RestoreHandle, RestoreKind, WhoamiOp, WhoamiResult, WriteMode,
};

const ID: &str = "01ARZ3NDEKTSV4RRFFQ69G5FAV";

fn fixed_id<T>() -> T
where
    T: for<'de> serde::Deserialize<'de>,
{
    serde_json::from_str(&format!("\"{ID}\"")) .unwrap()
}

fn hello() -> Message {
    Message::Hello(Hello::new(
        "dG9rZW4tbm90LXJlYWwtYmFzZTY0".into(),
        ClientInfo { name: "ramenctl".into(), version: "0.1.0".into() },
    ))
}

fn welcome() -> Message {
    Message::Welcome(ramen_proto::messages::Welcome {
        v: 1,
        kind: ramen_proto::messages::WelcomeTag::Welcome,
        session: fixed_id(),
        identity: "agent:planner".into(),
        capabilities: vec![
            CapabilitySummary {
                op: "Whoami".into(),
                reversibility: ramen_proto::Reversibility::Trivial,
                constraints: None,
            },
            CapabilitySummary {
                op: "FileWrite".into(),
                reversibility: ramen_proto::Reversibility::Trivial,
                constraints: Some(Constraints { path_prefix: vec!["/Users/austin/work".into()] }),
            },
        ],
    })
}

fn request_whoami() -> Message {
    let id = fixed_id::<ramen_proto::RequestId>();
    Message::Request(Request { v: 1, id, op: Operation::Whoami(WhoamiOp {}) })
}

fn request_filewrite() -> Message {
    let id = fixed_id::<ramen_proto::RequestId>();
    Message::Request(Request {
        v: 1,
        id,
        op: Operation::FileWrite(FileWriteOp {
            path: "/Users/austin/work/notes.md".into(),
            content_b64: "SGVsbG8sIHdvcmxkLgo=".into(),
            mode: WriteMode::Overwrite,
        }),
    })
}

fn response_ok_whoami() -> Message {
    let id = fixed_id::<ramen_proto::RequestId>();
    let session = fixed_id::<ramen_proto::SessionId>();
    Message::Response(Response::ok(
        id,
        OpResult::Whoami(WhoamiResult {
            identity: "agent:planner".into(),
            session,
            capabilities: vec![
                CapabilitySummary {
                    op: "Whoami".into(),
                    reversibility: ramen_proto::Reversibility::Trivial,
                    constraints: None,
                },
                CapabilitySummary {
                    op: "FileWrite".into(),
                    reversibility: ramen_proto::Reversibility::Trivial,
                    constraints: Some(Constraints {
                        path_prefix: vec!["/Users/austin/work".into()],
                    }),
                },
            ],
            token_expires_at: Some("2026-08-31T00:00:00Z".into()),
        }),
    ))
}

fn response_ok_filewrite() -> Message {
    let id = fixed_id::<ramen_proto::RequestId>();
    Message::Response(Response::ok(
        id,
        OpResult::FileWrite(FileWriteResult {
            path: "/Users/austin/work/notes.md".into(),
            bytes_written: 14,
            content_sha256: "a3f1e2c9".into(),
            restore: RestoreHandle {
                kind: RestoreKind::Snapshot,
                handle: "01ARZ3NDEKTSV4RRFFQ69G5FAV.notes.md".into(),
                reversibility: ramen_proto::Reversibility::Trivial,
            },
        }),
    ))
}

fn response_denied() -> Message {
    let id = fixed_id::<ramen_proto::RequestId>();
    Message::Response(Response::denied(
        id,
        Denial {
            code: DenialCode::CapabilityNotGranted,
            reason: "token does not grant FileWrite".into(),
            audit_seq: 41,
        },
    ))
}

fn response_error() -> Message {
    let id = fixed_id::<ramen_proto::RequestId>();
    Message::Response(Response::Error {
        v: 1,
        id,
        error: ErrorInfo {
            code: ErrorCode::AuditUnavailable,
            message: "audit log write failed".into(),
        },
    })
}

fn fault() -> Message {
    Message::Fault(Fault::new(ErrorCode::MalformedRequest, "unknown field `x`"))
}

fn cases() -> Vec<(&'static str, Message)> {
    vec![
        ("hello", hello()),
        ("welcome", welcome()),
        ("request-whoami", request_whoami()),
        ("request-filewrite", request_filewrite()),
        ("response-ok-whoami", response_ok_whoami()),
        ("response-ok-filewrite", response_ok_filewrite()),
        ("response-denied", response_denied()),
        ("response-error", response_error()),
        ("fault", fault()),
    ]
}

#[test]
fn golden_files_match_envelope_serialization() {
    let mut failures = 0;
    for (name, msg) in cases() {
        let mut frame = Vec::new();
        msg.encode(&mut frame).unwrap();
        let json = std::str::from_utf8(&frame[4..]).unwrap();

        let path = format!("tests/golden/{name}.json");
        if std::env::var_os("UPDATE_GOLDEN").is_some() {
            std::fs::create_dir_all("tests/golden").unwrap();
            std::fs::write(&path, format!("{json}\n")).unwrap();
            eprintln!("wrote {path}");
            continue;
        }

        let expected = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("missing golden file {path}: {e}"));
        if expected.trim_end() != json {
            failures += 1;
            eprintln!("GOLDEN MISMATCH: {name}\n  expected: {expected}\n  actual:   {json}");
        }

        // And the golden must decode back to the same message.
        let decoded = Message::decode(json.as_bytes()).unwrap();
        assert_eq!(decoded, msg, "golden {name} does not round-trip");
    }
    assert_eq!(failures, 0, "{failures} golden file(s) mismatched");
}
