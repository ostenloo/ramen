//! Handshake tests (`01-protocol.md` §5, `03-supervisor.md` §4–§5).

mod common;

use common::assert_chain_valid;
use ramen_audit::RecordKind;
use ramen_proto::{ErrorCode, Fault, Message};

/// A valid token yields a Welcome; the audit shows SessionOpened with
/// `verified: true`, a populated cdhash, and client metadata.
#[test]
fn valid_token_gets_welcome_and_is_audited() {
    let mut sup = common::Supervisor::start();
    let mut client = common::Client::connect(&sup.socket);
    let session = client.hello(&sup.token("agent:planner", &["Whoami"]));
    assert!(!session.to_string().is_empty());

    let records = sup.audit_records();
    let opened = records
        .iter()
        .find(|r| {
            matches!(r, ramen_audit::Record::Event(e) if e.kind == RecordKind::SessionOpened)
        })
        .expect("SessionOpened in audit");
    let ramen_audit::Record::Event(opened) = opened else {
        unreachable!()
    };
    assert_eq!(opened.session, Some(session));
    assert_eq!(opened.identity.as_deref(), Some("agent:planner"));
    let peer = opened.peer.as_ref().expect("peer recorded");
    assert!(peer.verified, "peer must be verified");
    assert!(
        peer.cdhash.as_ref().map(|h| h.len() == 40).unwrap_or(false),
        "cdhash must be a 40-hex-digit string, got {:?}",
        peer.cdhash
    );
    assert!(
        peer.signing_id.is_some(),
        "signing identifier must be recorded"
    );
    let client_meta = opened.client.as_ref().expect("client metadata recorded");
    assert_eq!(client_meta.name, "ramen-supervisor-test");
    assert!(!client_meta.truncated);

    assert_chain_valid(&sup.audit);
    drop(client);
    sup.terminate_and_wait();
}

/// The Welcome carries the identity from the token and a best-effort
/// capability summary (M4, `04-guard.md` §3).
#[test]
fn welcome_carries_identity_and_capability_summary() {
    let mut sup = common::Supervisor::start();
    let mut client = common::Client::connect(&sup.socket);
    let resp = client
        .hello_raw(&sup.token("agent:planner", &["Whoami"]))
        .expect("Welcome");
    let Message::Welcome(w) = resp else {
        panic!("expected Welcome, got {resp:?}")
    };
    assert_eq!(w.identity, "agent:planner");
    // M4: the Welcome carries a best-effort capability summary derived from
    // the token's authority-block facts (04-guard.md §3). Advisory only —
    // it never affects a decision.
    let whoami = w
        .capabilities
        .iter()
        .find(|c| c.op == "Whoami")
        .expect("Whoami capability advertised");
    assert_eq!(whoami.reversibility, ramen_proto::Reversibility::Trivial);
    assert!(whoami.constraints.is_none());
    drop(client);
    sup.terminate_and_wait();
}

/// A token signed by a different key is rejected: Fault, no SessionOpened,
/// and a pre-handshake ProtocolViolation (rate-limited per PID).
#[test]
fn wrong_key_token_rejected() {
    let mut sup = common::Supervisor::start();
    let mut client = common::Client::connect(&sup.socket);
    let resp = client.hello_raw(&sup.foreign_token()).expect("Fault");
    match resp {
        Message::Fault(f) => {
            assert!(
                matches!(f.error.code, ErrorCode::MalformedRequest),
                "expected MalformedRequest, got {:?}",
                f.error.code
            );
        }
        other => panic!("expected Fault, got {other:?}"),
    }
    // Connection is closed: the next read sees EOF.
    assert!(client.recv().is_none(), "connection must be closed");

    let records = sup.audit_records();
    assert!(
        !records.iter().any(|r| {
            matches!(r, ramen_audit::Record::Event(e) if e.kind == RecordKind::SessionOpened)
        }),
        "no SessionOpened for a rejected token"
    );
    assert!(
        records.iter().any(|r| {
            matches!(r, ramen_audit::Record::Event(e) if e.kind == RecordKind::ProtocolViolation)
        }),
        "pre-handshake ProtocolViolation must be audited"
    );
    drop(client);
    sup.terminate_and_wait();
}

/// A token that is not even parseable is rejected the same way (the
/// supervisor does not disclose which check failed).
#[test]
fn malformed_token_rejected() {
    let mut sup = common::Supervisor::start();
    let mut client = common::Client::connect(&sup.socket);
    let resp = client.hello_raw("AAAA").expect("Fault");
    assert!(matches!(resp, Message::Fault(_)), "expected Fault, got {resp:?}");
    drop(client);
    sup.terminate_and_wait();
}

/// A token with a valid signature but no identity fact is rejected.
#[test]
fn token_without_identity_rejected() {
    use biscuit_auth::{BiscuitBuilder, KeyPair};

    let mut sup = common::Supervisor::start();
    let mut client = common::Client::connect(&sup.socket);
    // Signed with the supervisor's root key, but no identity fact.
    let root = KeyPair::from_private_key_pem(&sup.parts.root_priv_pem).unwrap();
    let biscuit = BiscuitBuilder::new()
        .code("capability(\"Whoami\");\n")
        .unwrap()
        .build(&root)
        .unwrap();
    let token = biscuit.to_base64().unwrap();
    let resp = client.hello_raw(&token).expect("Fault");
    assert!(matches!(resp, Message::Fault(_)), "expected Fault, got {resp:?}");
    drop(client);
    sup.terminate_and_wait();
}

/// A version mismatch on the Hello is fatal with `VersionMismatch`.
#[test]
fn hello_version_mismatch_rejected() {
    let mut sup = common::Supervisor::start();
    let mut client = common::Client::connect(&sup.socket);
    let hello = ramen_proto::Hello::new(
        sup.token("agent:planner", &["Whoami"]),
        ramen_proto::ClientInfo {
            name: "test".into(),
            version: "0".into(),
        },
    );
    // Hand-craft the frame with v = 99.
    let value: serde_json::Value = serde_json::to_value(&hello).unwrap();
    let mut bad = value;
    bad["v"] = serde_json::json!(99);
    let payload = serde_json::to_vec(&bad).unwrap();
    let mut buf = Vec::new();
    buf.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    buf.extend_from_slice(&payload);
    client.send_raw(&buf);
    let resp = client.recv().expect("Fault");
    match resp {
        Message::Fault(f) => {
            assert!(matches!(f.error.code, ErrorCode::VersionMismatch), "{:?}", f.error.code);
        }
        other => panic!("expected Fault, got {other:?}"),
    }
    drop(client);
    sup.terminate_and_wait();
}

/// The first message must be a Hello. A Request first is fatal.
#[test]
fn request_as_first_message_rejected() {
    let mut sup = common::Supervisor::start();
    let mut client = common::Client::connect(&sup.socket);
    let req = Message::Request(ramen_proto::Request::new(
        ramen_proto::Operation::Whoami(ramen_proto::WhoamiOp {}),
    ));
    client.send(&req);
    let resp = client.recv().expect("Fault");
    assert!(matches!(resp, Message::Fault(_)), "expected Fault, got {resp:?}");
    drop(client);
    sup.terminate_and_wait();
}

/// Client name over 64 bytes is truncated, not fatal; the truncation is
/// recorded in SessionOpened.
#[test]
fn oversized_client_name_truncated_and_recorded() {
    let mut sup = common::Supervisor::start();
    let mut client = common::Client::connect(&sup.socket);
    let long = "x".repeat(100);
    let hello = ramen_proto::Hello::new(
        sup.token("agent:planner", &["Whoami"]),
        ramen_proto::ClientInfo {
            name: long,
            version: "0.0.0-test".into(),
        },
    );
    client.send(&Message::Hello(hello));
    let resp = client.recv().expect("Welcome");
    assert!(matches!(resp, Message::Welcome(_)), "got {resp:?}");

    let records = sup.audit_records();
    let opened = records
        .iter()
        .find(|r| {
            matches!(r, ramen_audit::Record::Event(e) if e.kind == RecordKind::SessionOpened)
        })
        .unwrap();
    let ramen_audit::Record::Event(opened) = opened else {
        unreachable!()
    };
    let client_meta = opened.client.as_ref().expect("client meta recorded");
    assert!(client_meta.truncated, "truncation must be recorded");
    assert!(client_meta.name.len() <= 64);
    drop(client);
    sup.terminate_and_wait();
}

/// A peer whose identifier does not satisfy the requirement is rejected
/// with IdentityRejected and no SessionOpened.
#[test]
fn identifier_mismatch_rejected_with_identity_rejected() {
    let f = common::Fixture::new();
    let body = f
        .parts
        .body("identifier \"com.example.not-the-test-binary\"");
    let mut sup = common::Supervisor::start_with_body(&f, &body);

    // The connection is closed immediately (the server never sends a
    // pre-handshake Fault for identity failures).
    let mut client = common::Client::connect(&sup.socket);
    // Nothing arrives before the close.
    assert!(
        client.recv().is_none(),
        "no message should precede the identity-rejection close"
    );

    let records = sup.audit_records();
    // The last IdentityRejected is ours: the harness's readiness probe
    // (connect-then-immediate-close) can itself produce an earlier,
    // peerless IdentityRejected (the peer is already gone by the time
    // getsockopt(LOCAL_PEERTOKEN) runs → ENOTCONN → fail-closed, no peer).
    let rejected = records
        .iter()
        .filter(|r| {
            matches!(r, ramen_audit::Record::Event(e) if e.kind == RecordKind::IdentityRejected)
        })
        .next_back()
        .expect("IdentityRejected in audit");
    let ramen_audit::Record::Event(rejected) = rejected else {
        unreachable!()
    };
    assert_eq!(rejected.session, None);
    assert!(
        rejected.peer.as_ref().map(|p| !p.verified).unwrap_or(false),
        "peer recorded as unverified"
    );
    assert!(
        !records.iter().any(|r| {
            matches!(r, ramen_audit::Record::Event(e) if e.kind == RecordKind::SessionOpened)
        }),
        "no SessionOpened for a rejected peer"
    );
    drop(client);
    sup.terminate_and_wait();
}

/// Fault messages are typed: the code field round-trips.
#[test]
fn fault_shape() {
    let f = Fault::new(ErrorCode::VersionMismatch, "nope");
    assert_eq!(f.error.code, ErrorCode::VersionMismatch);
}
