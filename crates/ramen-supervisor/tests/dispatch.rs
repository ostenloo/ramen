//! M5 dispatch (`03-supervisor.md` §6, `04-guard.md` §8–§10,
//! `05-operations.md` M5): the guard decides, both paths are audited, and
//! `Whoami` is the first implemented operation.
//!
//! M5 acceptance criteria covered here:
//! 1. authorized `Whoami` returns identity, session, capabilities, and
//!    `token_expires_at` — `whoami_returns_identity_session_and_capabilities`
//! 2. a token without the capability gets `Denied(CapabilityNotGranted)` and
//!    the audit shows a `Denied` record — `whoami_denied_without_capability`
//! 3. the capability list matches a direct `describe_capabilities` call —
//!    `whoami_capabilities_match_direct_guard_call`
//! 4. the audit shows `Authorized` → `Executed` for the request id —
//!    `whoami_audited_authorized_then_executed`
//! 5. the result stays inside the grant (no supervisor configuration
//!    leaks) — `whoami_result_stays_inside_the_grant`
//! 6. three concurrent `Whoami` requests are matched by request id —
//!    `three_concurrent_whoami_matched_by_id`
//!
//! `FileWrite` still has no effect: an allowed `FileWrite` answers
//! `Error/NotImplemented` (audited `Authorized` then `Errored`); the effect
//! arrives in M6.

mod common;

use ramen_audit::{EventRecord, Record, RecordKind};
use ramen_proto::messages::DenialCode;
use ramen_proto::{
    ErrorCode, Message, Operation, OpResult, Request, RequestId, Response, WhoamiOp,
    WhoamiResult,
};
use std::collections::BTreeSet;
use std::time::Duration;

use biscuit_auth::{KeyPair, PublicKey};
use common::Supervisor;
use ramen_guard::{ControlPlanePaths, Guard, RootKey, StdFs};

/// `Whoami` as an `Operation` value (the unit-struct variant).
const WHOAMI: Operation = Operation::Whoami(WhoamiOp {});

/// `FileWrite` with trivial content ("hello" in standard base64).
fn filewrite_hello() -> Operation {
    Operation::FileWrite(ramen_proto::FileWriteOp {
        path: "/tmp/never.txt".into(),
        content_b64: "aGVsbG8=".into(),
        mode: ramen_proto::WriteMode::Create,
    })
}

/// A supervisor with an established session: a connected, handshaken client
/// whose token grants both v0 operations. Returns the session id.
fn sup_with_session() -> (Supervisor, common::Client, ramen_proto::SessionId) {
    let sup = Supervisor::start();
    let token = sup.token("agent:planner", &["Whoami", "FileWrite"]);
    let mut client = common::Client::connect(&sup.socket);
    let session = client.hello(&token);
    (sup, client, session)
}

/// The event records in the audit log, in chain order.
fn events(sup: &Supervisor) -> Vec<EventRecord> {
    sup.audit_records()
        .into_iter()
        .filter_map(|r| match r {
            Record::Event(e) => Some(e),
            Record::LogHeader(_) => None,
        })
        .collect()
}

/// A `Guard` built directly from the supervisor's own root key and control
/// plane paths — the reference implementation `Whoami` must agree with
/// (acceptance criterion 3).
fn direct_guard(sup: &Supervisor) -> Guard {
    let kp = KeyPair::from_private_key_pem(&sup.parts.root_priv_pem).unwrap();
    struct StaticRoot(PublicKey);
    impl RootKey for StaticRoot {
        fn public_key(&self) -> PublicKey {
            self.0
        }
    }
    let config_path = sup.parts.dir_path.join("config.toml");
    let cp = ControlPlanePaths::new(
        &[
            sup.parts.socket.clone(),
            sup.parts.audit.clone(),
            sup.parts.root_key.clone(),
            config_path,
        ],
        &sup.parts.state,
    )
    .unwrap();
    Guard::new(Box::new(StaticRoot(kp.public())), cp, Box::new(StdFs))
}

#[test]
fn whoami_returns_identity_session_and_capabilities() {
    let mut sup = Supervisor::start();
    let token = sup.token("agent:planner", &["Whoami", "FileWrite"]);
    let mut client = common::Client::connect(&sup.socket);
    let session = client.hello(&token);

    let (_, resp) = client.request(WHOAMI);
    let Response::Ok { result, .. } = &resp else {
        panic!("expected Ok, got {resp:?}");
    };
    let OpResult::Whoami(WhoamiResult {
        identity,
        session: resp_session,
        capabilities,
        token_expires_at,
    }) = result
    else {
        panic!("expected Whoami result, got {result:?}");
    };

    // 1. The response carries the handshake identity, the session id, and
    // the capability list from the token.
    assert_eq!(*identity, "agent:planner");
    assert_eq!(*resp_session, session);
    let names: BTreeSet<&str> = capabilities.iter().map(|c| c.op.as_str()).collect();
    assert_eq!(names, BTreeSet::from(["Whoami", "FileWrite"]));

    // The harness token declares no `expires_at` fact, so the advisory
    // metadata is `null` (serialized `None`), not an error.
    assert!(token_expires_at.is_none());

    drop(client);
    sup.terminate_and_wait();
}

#[test]
fn whoami_denied_without_capability() {
    let mut sup = Supervisor::start();
    // The token grants FileWrite only — Whoami is not in it.
    let token = sup.token("agent:planner", &["FileWrite"]);
    let mut client = common::Client::connect(&sup.socket);
    client.hello(&token);

    let (id, resp) = client.request(WHOAMI);
    let Response::Denied { denial, .. } = &resp else {
        panic!("expected Denied, got {resp:?}");
    };
    assert_eq!(denial.code, DenialCode::CapabilityNotGranted);

    // 2. The audit shows a `Denied` record for the request id — and no
    // `Authorized` record.
    let events = events(&sup);
    let denied = events
        .iter()
        .filter(|r| r.request_id == Some(id) && r.kind == RecordKind::Denied)
        .count();
    let authorized = events
        .iter()
        .filter(|r| r.request_id == Some(id) && r.kind == RecordKind::Authorized)
        .count();
    assert_eq!(denied, 1, "exactly one Denied record for the request");
    assert_eq!(authorized, 0, "no Authorized record for a denied request");

    drop(client);
    sup.terminate_and_wait();
}

#[test]
fn whoami_capabilities_match_direct_guard_call() {
    let mut sup = Supervisor::start();
    let token = sup.token("agent:planner", &["Whoami", "FileWrite"]);
    let mut client = common::Client::connect(&sup.socket);
    client.hello(&token);

    let (_, resp) = client.request(WHOAMI);
    let Response::Ok { result, .. } = &resp else {
        panic!("expected Ok, got {resp:?}");
    };
    let OpResult::Whoami(w) = result else {
        panic!("expected Whoami result, got {result:?}");
    };

    // 3. The capability list is exactly what `describe_capabilities`
    // returns for the token — a live query, not a cached `Welcome` summary.
    // (Compared as a set: the datalog query result is unordered.)
    let guard = direct_guard(&sup);
    let as_set = |caps: &[ramen_proto::CapabilitySummary]| -> BTreeSet<String> {
        caps.iter()
            .map(|c| serde_json::to_string(c).unwrap())
            .collect()
    };
    assert_eq!(
        as_set(&w.capabilities),
        as_set(&guard.describe_capabilities(&token))
    );

    drop(client);
    sup.terminate_and_wait();
}

#[test]
fn whoami_audited_authorized_then_executed() {
    let mut sup = Supervisor::start();
    let token = sup.token("agent:planner", &["Whoami"]);
    let mut client = common::Client::connect(&sup.socket);
    client.hello(&token);

    let (id, resp) = client.request(WHOAMI);
    assert!(matches!(&resp, Response::Ok { .. }));

    // 4. The audit shows Authorized → Executed for the request id: the
    // Executed record follows the Authorized record for the same id, with
    // no sequence gap between them.
    let events = events(&sup);
    let authorized = events
        .iter()
        .find(|r| r.request_id == Some(id) && r.kind == RecordKind::Authorized)
        .expect("Authorized record for the request");
    let executed = events
        .iter()
        .find(|r| r.request_id == Some(id) && r.kind == RecordKind::Executed)
        .expect("Executed record for the request");
    assert_eq!(
        executed.seq,
        authorized.seq + 1,
        "Executed immediately follows Authorized for the request id"
    );
    // No other record for this request (no Errored, no Denied): exactly the
    // Authorized + Executed pair.
    assert_eq!(
        events
            .iter()
            .filter(|r| r.request_id == Some(id))
            .count(),
        2,
        "exactly Authorized + Executed for an allowed Whoami"
    );

    drop(client);
    sup.terminate_and_wait();
}

#[test]
fn whoami_result_stays_inside_the_grant() {
    let mut sup = Supervisor::start();
    let token = sup.token("agent:planner", &["Whoami"]);
    let mut client = common::Client::connect(&sup.socket);
    client.hello(&token);

    let (_, resp) = client.request(WHOAMI);
    let Response::Ok { result, .. } = &resp else {
        panic!("expected Ok, got {resp:?}");
    };
    let OpResult::Whoami(w) = result else {
        panic!("expected Whoami result, got {result:?}");
    };

    // 5. Automated portion: the serialized result must not leak anything
    // about the supervisor's configuration — no control-plane paths, no
    // state directory, no token bytes.
    let json = serde_json::to_string(result).unwrap();
    for path in [
        &sup.parts.socket,
        &sup.parts.audit,
        &sup.parts.root_key,
        &sup.parts.state,
        &sup.parts.dir_path,
    ] {
        assert!(
            !json.contains(path.to_string_lossy().as_ref()),
            "result leaks supervisor path {path:?}"
        );
    }
    assert!(!json.contains(&token), "result leaks the token");

    // The capability summary reports only the granted capability.
    let names: BTreeSet<&str> = w.capabilities.iter().map(|c| c.op.as_str()).collect();
    assert_eq!(names, BTreeSet::from(["Whoami"]));

    // (The manual "flip the token and re-run" half of criterion 5 is
    // exercised by `whoami_denied_without_capability`: with the capability
    // removed, the same request denies and the result is never delivered.)

    drop(client);
    sup.terminate_and_wait();
}

#[test]
fn whoami_reports_token_expires_at_when_declared() {
    let mut sup = Supervisor::start();
    // A token that declares an `expires_at` fact: the result surfaces it
    // as ISO-8601 UTC advisory metadata (the token itself is still valid
    // at request time).
    let token = sup.token_with_extra(
        "agent:planner",
        &["Whoami"],
        "expires_at(2099-01-01T00:00:00Z);",
    );
    let mut client = common::Client::connect(&sup.socket);
    client.hello(&token);

    let (_, resp) = client.request(WHOAMI);
    let Response::Ok { result, .. } = &resp else {
        panic!("expected Ok, got {resp:?}");
    };
    let OpResult::Whoami(w) = result else {
        panic!("expected Whoami result, got {result:?}");
    };
    assert_eq!(w.token_expires_at.as_deref(), Some("2099-01-01T00:00:00Z"));

    drop(client);
    sup.terminate_and_wait();
}

#[test]
fn three_concurrent_whoami_matched_by_id() {
    let (mut sup, mut client, session) = sup_with_session();

    // 6. Three `Whoami` requests in flight at once: each response must be
    // matched to its request by request id.
    let mut ids = vec![];
    for _ in 0..3 {
        let req = Request::new(WHOAMI);
        ids.push(req.id);
        client.send(&Message::Request(req));
        // Keep all three in flight before reading anything.
        std::thread::sleep(Duration::from_millis(25));
    }

    let mut seen: BTreeSet<RequestId> = BTreeSet::new();
    for _ in 0..3 {
        let resp = client.recv().expect("response");
        let Message::Response(r) = resp else {
            panic!("expected Response, got {resp:?}");
        };
        match &r {
            Response::Ok { id, result, .. } => {
                let OpResult::Whoami(w) = result else {
                    panic!("expected Whoami result, got {result:?}");
                };
                assert!(
                    ids.contains(id),
                    "response id {id} was not one of the three requests"
                );
                assert!(seen.insert(*id), "duplicate response for {id}");
                // Every response carries the session and identity,
                // regardless of arrival order.
                assert_eq!(w.session, session);
                assert_eq!(w.identity, "agent:planner");
            }
            other => panic!("expected Ok, got {other:?}"),
        }
    }
    assert_eq!(seen.len(), 3, "all three request ids answered exactly once");

    drop(client);
    sup.terminate_and_wait();
}

#[test]
fn denied_operation_returns_denied_with_audit_seq() {
    let mut sup = Supervisor::start();
    let token = sup.token("agent:planner", &["Whoami"]);
    let mut client = common::Client::connect(&sup.socket);
    client.hello(&token);

    let (id, resp) = client.request(filewrite_hello());
    let Response::Denied { id: resp_id, denial, .. } = &resp else {
        panic!("expected Denied, got {resp:?}");
    };
    assert_eq!(*resp_id, id);
    assert_eq!(denial.code, DenialCode::CapabilityNotGranted);
    assert!(!denial.reason.is_empty());

    // The client-visible `audit_seq` matches a real `Denied` audit record
    // with the same request id, so an auditor can join them.
    let events = events(&sup);
    let denied = events
        .iter()
        .find(|r| r.request_id == Some(id) && r.kind == RecordKind::Denied)
        .expect("Denied record in the audit");
    assert_eq!(denial.audit_seq, denied.seq);

    drop(client);
    sup.terminate_and_wait();
}

#[test]
fn denial_response_is_not_terminal_and_session_continues() {
    let mut sup = Supervisor::start();
    let token = sup.token("agent:planner", &["Whoami"]);
    let mut client = common::Client::connect(&sup.socket);
    client.hello(&token);

    // Denied FileWrite: the connection must not be closed.
    let (_, resp) = client.request(filewrite_hello());
    assert!(matches!(&resp, Response::Denied { .. }));

    // The same connection now works for a permitted operation.
    let (_, resp) = client.request(WHOAMI);
    assert!(
        matches!(&resp, Response::Ok { .. }),
        "session must continue after a denial"
    );

    drop(client);
    sup.terminate_and_wait();
}

#[test]
fn multiple_requests_same_session() {
    let (mut sup, mut client, _session) = sup_with_session();

    let (id1, resp1) = client.request(WHOAMI);
    let (id2, resp2) = client.request(WHOAMI);
    assert_ne!(id1, id2, "fresh request id per request");
    assert!(matches!(&resp1, Response::Ok { .. }));
    assert!(matches!(&resp2, Response::Ok { .. }));

    drop(client);
    sup.terminate_and_wait();
}

#[test]
fn burst_of_1000() {
    let (mut sup, mut client, _session) = sup_with_session();

    for _ in 0..1000 {
        let (_, resp) = client.request(WHOAMI);
        assert!(
            matches!(&resp, Response::Ok { .. }),
            "request failed: {resp:?}"
        );
    }

    drop(client);
    sup.terminate_and_wait();
}

#[test]
fn in_flight_cap_is_non_fatal() {
    // 32 in-flight cap: 40 requests in flight at once must exceed it. The
    // point of the test is that an over-cap request is answered
    // `Error/Internal` and the connection survives.
    let (mut sup, mut client, _session) = sup_with_session();

    // Fire all 40 without reading, so the in-flight set grows past the
    // cap. The supervisor processes them concurrently; every request gets
    // exactly one answer: either a normal `Ok` or the non-fatal `Internal`
    // rejection (never a closed connection).
    for _ in 0..40 {
        client.send_request_only(WHOAMI);
    }

    let mut rejected = 0usize;
    let mut ok = 0usize;
    for _ in 0..40 {
        let resp = client.recv().expect("response for every request");
        let Message::Response(r) = resp else {
            panic!("expected Response, got {resp:?}");
        };
        match &r {
            Response::Ok { .. } => ok += 1,
            Response::Error {
                error: e,
                ..
            } if e.code == ErrorCode::Internal => rejected += 1,
            other => panic!("unexpected response: {other:?}"),
        }
    }
    assert_eq!(ok + rejected, 40, "all 40 requests answered (ok={ok}, rejected={rejected})");

    // The connection is still usable.
    let (_, resp) = client.request(WHOAMI);
    assert!(
        matches!(&resp, Response::Ok { .. }),
        "connection must survive an over-cap rejection"
    );

    drop(client);
    sup.terminate_and_wait();
}

// ---------------------------------------------------------------------------
// Invariant 4, fail-exit form: a dead audit writer is a process fatal, not a
// per-request refusal. `RAMEN_TEST_AUDIT_FAIL_AFTER=2` makes the second
// append (the Whoami `Authorized`) fail; the supervisor must exit with
// `EXIT_AUDIT_UNAVAILABLE` instead of answering `Error/AuditUnavailable`,
// and the chain must remain valid up to the last durable record.
// ---------------------------------------------------------------------------

#[test]
fn audit_failure_is_process_fatal_not_per_request_refusal() {
    let fx = common::Fixture::new();
    let requirement = format!("identifier \"{}\"", common::test_binary_identifier());
    let body = fx.parts.body(&requirement);
    let mut sup = common::Supervisor::start_with_body_env(
        &fx,
        &body,
        &[("RAMEN_TEST_AUDIT_FAIL_AFTER", "2")],
    );

    let token = sup.token("agent:audit", &["Whoami"]);
    let mut client = common::Client::connect(&sup.socket);
    // Append 1 (SessionOpened) succeeds: the handshake completes.
    client.hello(&token);

    // Append 2 (Whoami `Authorized`) is simulated to fail.
    client.send(&Message::Request(Request::new(WHOAMI)));

    // The process exits on its own with the fatal audit code...
    let status = sup.wait_exit();
    assert_eq!(
        status.code(),
        Some(ramen_supervisor::EXIT_AUDIT_UNAVAILABLE),
        "invariant 4: a dead audit writer must exit the process, not degrade"
    );
    // ...and the client sees a closed connection, not a response.
    assert!(client.recv().is_none(), "no response may be sent once the audit writer is dead");

    // The chain is still valid: the SessionOpened record is durable and the
    // un-audited request left no dangling Authorized.
    common::assert_chain_valid(&sup.audit);
    let records = sup.audit_records();
    assert!(
        records.iter().any(|r| matches!(r, Record::Event(e)
            if e.kind == RecordKind::SessionOpened
                && e.identity.as_deref() == Some("agent:audit"))),
        "the SessionOpened record (append 1) must be durable"
    );
    assert!(
        !records.iter().any(|r| matches!(r, Record::Event(e)
            if e.kind == RecordKind::Authorized)),
        "no Authorized record may exist for the un-auditable request"
    );
}
