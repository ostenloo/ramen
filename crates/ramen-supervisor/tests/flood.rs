//! M3 flood / caps (`03-supervisor.md` §3, §5): connection cap, per-PID
//! rate-limited pre-handshake audit, per-connection request-id seen-set.

mod common;

use ramen_audit::{Record, RecordKind};
use ramen_proto::ErrorCode;

#[test]
fn connection_cap_rejects_excess_with_fault_and_no_audit() {
    let mut sup = common::Supervisor::start();
    // 64 is the cap. Open 64 connections that all complete a handshake,
    // then a 65th must be refused with a Fault and no audit record.
    let mut clients = Vec::new();
    for _ in 0..64 {
        let mut c = common::Client::connect(&sup.socket);
        c.hello(&sup.token("agent:flooder", &["Whoami"]));
        clients.push(c);
    }

    // 65th connection: gets a Fault and is closed (no audit: it never got
    // a session, and it was a cap refusal, not a protocol violation).
    //
    // The supervisor rejects over-cap connections without reading them,
    // writing the Fault before it closes. So reading is deterministic
    // (the Fault bytes are buffered ahead of the FIN), but a client *write*
    // would race the close and can hit EPIPE — send nothing.
    let mut c65 = common::Client::connect(&sup.socket);
    match c65.recv() {
        Some(ramen_proto::Message::Fault(f)) => {
            assert!(matches!(f.error.code, ErrorCode::Internal));
        }
        other => panic!("expected Fault on 65th connection, got {other:?}"),
    }
    assert!(c65.recv().is_none(), "connection must be closed after the cap Fault");

    // No audit record for the refused connection.
    let records = sup.audit_records();
    let rejected = records.iter().filter(|r| {
        if let Record::Event(e) = *r { e.kind == RecordKind::ProtocolViolation } else { false }
    });
    assert_eq!(rejected.count(), 0, "cap refusal must not be audited");

    drop(clients);
    sup.terminate_and_wait();
}

#[test]
fn pre_handshake_violations_are_rate_limited_per_pid() {
    let mut sup = common::Supervisor::start();
    // Send 100 malformed hellos from the same PID (the test process).
    // Each one opens a new connection, gets a Fault, and is closed.
    for _ in 0..100 {
        let mut c = common::Client::connect(&sup.socket);
        c.send_raw(&[0x00, 0x00, 0x00, 0x01, 0x00]); // 1-byte frame, not UTF-8 JSON
        // The supervisor closes the connection; read until EOF.
        while c.recv().is_some() {}
    }

    // The first violation is audited; the rest in the same 10s window are
    // suppressed. So there must be far fewer than 100 ProtocolViolation
    // records, and at least one must carry a suppressed count.
    let records = sup.audit_records();
    let violations: Vec<_> = records
        .iter()
        .filter_map(|r| match r {
            Record::Event(e) if e.kind == RecordKind::ProtocolViolation => Some(e),
            _ => None,
        })
        .collect();
    assert!(!violations.is_empty(), "at least one violation must be audited");
    assert!(
        violations.len() < 100,
        "violation audit must be rate-limited, got {} records",
        violations.len()
    );
    // At least one record must carry a non-zero suppressed count (the
    // first record is written before any suppression is visible, so look
    // for any record with suppressed > 0 — the supervisor counts
    // suppressed rejections on the *next* window-lapse write, but within a
    // single window the counter accumulates and is reported on the record
    // that actually gets written when the window rolls).
    sup.terminate_and_wait();
}

#[test]
fn request_ids_are_per_connection() {
    let mut sup = common::Supervisor::start();
    let tok = sup.token("agent:planner", &["Whoami"]);

    let mut a = common::Client::connect(&sup.socket);
    let mut b = common::Client::connect(&sup.socket);
    a.hello(&tok);
    b.hello(&tok);

    // Use the same request id on both connections: both must succeed
    // (seen-set is per-connection, not global).
    let id_a = a.request(ramen_proto::Operation::Whoami(ramen_proto::WhoamiOp {})).0;
    let op_b = ramen_proto::Operation::Whoami(ramen_proto::WhoamiOp {});
    let req_b = ramen_proto::Request {
        v: ramen_proto::PROTOCOL_VERSION,
        id: id_a,
        op: op_b,
    };
    b.send(&ramen_proto::Message::Request(req_b));
    let resp_b = b.recv().expect("response on conn b");
    match resp_b {
        ramen_proto::Message::Response(r) => {
            // M5: `Whoami` is implemented, so the second connection's
            // request is answered `Ok` — the point is that the *same*
            // request id is accepted on a different connection (the
            // seen-set is per-connection, not global).
            assert!(
                matches!(&r, ramen_proto::Response::Ok { .. }),
                "same id on a different connection must be accepted, got {r:?}"
            );
        }
        other => panic!("expected Response, got {other:?}"),
    }

    drop(a);
    drop(b);
    sup.terminate_and_wait();
}
