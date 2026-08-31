//! M3 shutdown (`03-supervisor.md` §5): SIGTERM → drain → exit 0; SIGKILL
//! mid-session leaves a verifiable, resumable log.

mod common;

use ramen_audit::{Record, RecordKind};

#[test]
fn sigterm_closes_session_drains_audit_and_exits_zero() {
    let mut sup = common::Supervisor::start();
    let mut client = common::Client::connect(&sup.socket);
    client.hello(&sup.token("agent:planner", &["Whoami"]));
    // One request in flight so the shutdown has something to drain.
    client.request(ramen_proto::Operation::Whoami(ramen_proto::WhoamiOp {}));

    let status = sup.terminate_and_wait();
    assert!(status.success());

    let records = sup.audit_records();
    // SessionClosed must be present with the right identity.
    let closed = records
        .iter()
        .find(|r| if let Record::Event(e) = *r { e.kind == RecordKind::SessionClosed } else { false });
    assert!(closed.is_some(), "SessionClosed missing: {records:?}");

    // The chain must verify with zero critical findings.
    common::assert_chain_valid(&sup.audit);

    // No socket left behind.
    assert!(!sup.socket.exists());
    drop(client);
}

#[test]
fn sigkill_mid_session_leaves_verifiable_log() {
    let mut sup = common::Supervisor::start();
    let mut client = common::Client::connect(&sup.socket);
    let _session = client.hello(&sup.token("agent:planner", &["Whoami"]));
    // A few requests so the log has content.
    for _ in 0..5 {
        client.request(ramen_proto::Operation::Whoami(ramen_proto::WhoamiOp {}));
    }

    // Kill -9: no clean shutdown, no SessionClosed.
    sup.kill_and_wait();

    // The log may end with a torn frame (writer was mid-commit). The
    // verifier must report it as a warning-level tail, not a critical
    // chain break.
    let report = common::verify_file(&sup.audit);
    assert!(
        report.ok(),
        "torn tail must not be a critical finding: {report:?}"
    );

    // A restart must recover: the supervisor truncates the torn tail and
    // continues the chain.
    let mut sup2 = sup.restart();
    let mut client2 = common::Client::connect(&sup2.socket);
    client2.hello(&sup2.token("agent:planner", &["Whoami"]));
    client2.request(ramen_proto::Operation::Whoami(ramen_proto::WhoamiOp {}));
    drop(client2);
    sup2.terminate_and_wait();

    // After the clean shutdown, the chain must be fully valid.
    common::assert_chain_valid(&sup2.audit);
    drop(client);
}
