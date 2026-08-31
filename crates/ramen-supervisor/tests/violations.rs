//! Fatal protocol violations (`01-protocol.md` §8): each closes the
//! connection, sends a best-effort `Fault`, and (post-handshake) is audited
//! as `ProtocolViolation`. One test per violation type.

mod common;

use ramen_audit::RecordKind;
use ramen_proto::{ErrorCode, Message};

/// Helper: a connected, handshaked client.
fn handshaken(sup: &common::Supervisor) -> common::Client {
    let mut client = common::Client::connect(&sup.socket);
    client.hello(&sup.token("agent:planner", &["Whoami"]));
    client
}

/// Assert the violation outcome: Fault of `code`, connection closed, and a
/// post-handshake `ProtocolViolation` audit record.
fn assert_violation(
    client: &mut common::Client,
    expected: ErrorCode,
    sup: &common::Supervisor,
) {
    let resp = client.recv().expect("Fault for fatal violation");
    match resp {
        Message::Fault(f) => assert_eq!(f.error.code, expected, "fault code"),
        other => panic!("expected Fault, got {other:?}"),
    }
    assert!(client.recv().is_none(), "connection must be closed");

    let records = sup.audit_records();
    assert!(
        records.iter().any(|r| {
            matches!(r, ramen_audit::Record::Event(e)
                if e.kind == RecordKind::ProtocolViolation && e.session.is_some())
        }),
        "post-handshake ProtocolViolation must be audited with a session"
    );
}

#[test]
fn oversize_frame_rejected() {
    let mut sup = common::Supervisor::start();
    let mut client = handshaken(&sup);
    // A prefix claiming 1 MiB + 1, followed by a few bytes: the supervisor
    // must reject on the prefix alone, before buffering any body.
    let prefix = (ramen_proto::MAX_FRAME_BYTES + 1).to_be_bytes();
    let mut frame = prefix.to_vec();
    frame.extend_from_slice(&[0, 0, 0, 0]);
    client.send_raw(&frame);
    assert_violation(&mut client, ErrorCode::MalformedRequest, &sup);
    drop(client);
    sup.terminate_and_wait();
}

#[test]
fn zero_length_frame_rejected() {
    let mut sup = common::Supervisor::start();
    let mut client = handshaken(&sup);
    client.send_raw(&0u32.to_be_bytes());
    assert_violation(&mut client, ErrorCode::MalformedRequest, &sup);
    drop(client);
    sup.terminate_and_wait();
}

#[test]
fn non_utf8_payload_rejected() {
    let mut sup = common::Supervisor::start();
    let mut client = handshaken(&sup);
    let payload = vec![0xFF, 0xFE, 0x00, 0x80, 0x81];
    let mut buf = Vec::new();
    buf.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    buf.extend_from_slice(&payload);
    client.send_raw(&buf);
    assert_violation(&mut client, ErrorCode::MalformedRequest, &sup);
    drop(client);
    sup.terminate_and_wait();
}

#[test]
fn invalid_json_payload_rejected() {
    let mut sup = common::Supervisor::start();
    let mut client = handshaken(&sup);
    let payload = b"this is not json";
    let mut buf = Vec::new();
    buf.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    buf.extend_from_slice(payload);
    client.send_raw(&buf);
    assert_violation(&mut client, ErrorCode::MalformedRequest, &sup);
    drop(client);
    sup.terminate_and_wait();
}

#[test]
fn unknown_field_in_request_rejected() {
    let mut sup = common::Supervisor::start();
    let mut client = handshaken(&sup);
    // A Whoami request with a stray field.
    let req = ramen_proto::Request::new(ramen_proto::Operation::Whoami(
        ramen_proto::WhoamiOp {},
    ));
    let value: serde_json::Value = serde_json::to_value(&req).unwrap();
    let mut bad = value;
    bad["bogus_field"] = serde_json::json!("surprise");
    let payload = serde_json::to_vec(&bad).unwrap();
    let mut buf = Vec::new();
    buf.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    buf.extend_from_slice(&payload);
    client.send_raw(&buf);
    assert_violation(&mut client, ErrorCode::MalformedRequest, &sup);
    drop(client);
    sup.terminate_and_wait();
}

#[test]
fn hello_after_handshake_rejected() {
    let mut sup = common::Supervisor::start();
    let mut client = handshaken(&sup);
    let hello = Message::Hello(ramen_proto::Hello::new(
        sup.token("agent:planner", &["Whoami"]),
        ramen_proto::ClientInfo {
            name: "t".into(),
            version: "0".into(),
        },
    ));
    client.send(&hello);
    assert_violation(&mut client, ErrorCode::MalformedRequest, &sup);
    drop(client);
    sup.terminate_and_wait();
}

#[test]
fn request_id_reuse_rejected() {
    let mut sup = common::Supervisor::start();
    let mut client = handshaken(&sup);
    // First request with a fixed id.
    let id = ramen_proto::RequestId::new();
    let req = ramen_proto::Request {
        v: ramen_proto::PROTOCOL_VERSION,
        id,
        op: ramen_proto::Operation::Whoami(ramen_proto::WhoamiOp {}),
    };
    client.send(&Message::Request(req));
    // Consume the response (M5: `Whoami` is implemented, so this is `Ok`).
    let first = client.recv().expect("first response");
    assert!(matches!(first, Message::Response(_)), "got {first:?}");

    // Reuse the same id: fatal.
    let req2 = ramen_proto::Request {
        v: ramen_proto::PROTOCOL_VERSION,
        id,
        op: ramen_proto::Operation::Whoami(ramen_proto::WhoamiOp {}),
    };
    client.send(&Message::Request(req2));
    assert_violation(&mut client, ErrorCode::MalformedRequest, &sup);
    drop(client);
    sup.terminate_and_wait();
}

#[test]
fn version_mismatch_on_request_rejected() {
    let mut sup = common::Supervisor::start();
    let mut client = handshaken(&sup);
    let req = ramen_proto::Request::new(ramen_proto::Operation::Whoami(
        ramen_proto::WhoamiOp {},
    ));
    let value: serde_json::Value = serde_json::to_value(&req).unwrap();
    let mut bad = value;
    bad["v"] = serde_json::json!(99);
    let payload = serde_json::to_vec(&bad).unwrap();
    let mut buf = Vec::new();
    buf.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    buf.extend_from_slice(&payload);
    client.send_raw(&buf);
    assert_violation(&mut client, ErrorCode::VersionMismatch, &sup);
    drop(client);
    sup.terminate_and_wait();
}

#[test]
fn response_as_client_message_rejected() {
    let mut sup = common::Supervisor::start();
    let mut client = handshaken(&sup);
    // A client sending a Response (a server-only message) is fatal.
    let resp = ramen_proto::Response::error(
        ramen_proto::RequestId::new(),
        ErrorCode::NotImplemented,
        "client playing server",
    );
    client.send(&Message::Response(resp));
    assert_violation(&mut client, ErrorCode::MalformedRequest, &sup);
    drop(client);
    sup.terminate_and_wait();
}
