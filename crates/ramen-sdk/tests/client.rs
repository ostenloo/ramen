//! M7 acceptance tests for the `ramen-sdk` client (06-ramenctl.md §5):
//!
//! - 16 concurrent calls on one `Client`, all responses matched.
//! - Supervisor killed mid-call → `SdkError`, does not hang (test timeout).

mod common;

use std::sync::Arc;
use std::time::Duration;

use biscuit_auth::UnverifiedBiscuit;
use ramen_sdk::{Client, Operation, OpOutcome, SdkError};

async fn connect(sup: &common::Supervisor, token_b64: &str) -> Client {
    let token = UnverifiedBiscuit::from_base64(token_b64)
        .unwrap_or_else(|e| panic!("test token should parse: {e}"));
    Client::connect(&sup.socket, &token)
        .await
        .unwrap_or_else(|e| {
            panic!(
                "handshake failed: {e}\nsupervisor logs:\n{}",
                sup.logs_drain()
            )
        })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn handshake_exposes_session_and_identity() {
    let sup = tokio::task::spawn_blocking(|| common::Supervisor::start(vec![], vec![]))
        .await
        .unwrap();
    let token = sup.whoami_token("agent:planner");
    let client = connect(&sup, &token).await;

    assert_eq!(client.identity(), "agent:planner");
    assert!(client.session().0 != ulid::Ulid::nil(), "session id must be set");

    let out = client.call(Operation::Whoami(ramen_sdk::WhoamiOp {})).await.unwrap();
    match out {
        OpOutcome::Ok(result) => {
            assert_eq!(result["identity"], "agent:planner");
            assert!(
                result.get("capabilities").is_some(),
                "whoami result carries capabilities: {result}"
            );
        }
        other => panic!("expected Ok(whoami), got {other:?}"),
    }
}

/// M7: "SDK issues 16 concurrent calls on one Client and matches all
/// responses." FileWrites to 16 distinct paths: a response matched to the
/// wrong caller would show up as a `path` mismatch.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sixteen_concurrent_calls_all_match() {
    let data = tempfile::tempdir().unwrap();
    let prefix = data.path().join("work");
    std::fs::create_dir_all(&prefix).unwrap();
    // Canonicalize: the guard checks the *canonical* target path against the
    // token's prefix facts (macOS /var → /private/var).
    let prefix = prefix.canonicalize().unwrap();

    let sup = tokio::task::spawn_blocking({
        let prefix = prefix.clone();
        move || common::Supervisor::start(vec![prefix], vec![])
    })
    .await
    .unwrap();
    let token = sup.filewrite_token("agent:writer", prefix.to_str().unwrap());
    let client = Arc::new(connect(&sup, &token).await);

    let mut handles = Vec::new();
    let mut expected = Vec::new();
    for i in 0..16u32 {
        let client = client.clone();
        let path = prefix.join(format!("file-{i}.txt"));
        let path_s = path.to_str().unwrap().to_string();
        let content = format!("payload-{i}\n");
        expected.push((path_s.clone(), content.clone()));
        handles.push(tokio::spawn(async move {
            let op = common::filewrite_op(&path_s, &content, ramen_sdk::WriteMode::Create);
            (path_s, client.call(op).await)
        }));
    }

    let mut ok_count = 0;
    for (handle, (path_s, want_content)) in handles.into_iter().zip(expected.iter()) {
        let (got_path, res) = handle.await.unwrap();
        match res {
            Ok(OpOutcome::Ok(result)) => {
                ok_count += 1;
                assert_eq!(
                    got_path, *path_s,
                    "handle bookkeeping mismatch"
                );
                assert_eq!(
                    result["path"].as_str(),
                    Some(path_s.as_str()),
                    "response matched to wrong request (path mismatch)"
                );
                assert!(
                    result["bytes_written"].as_u64().unwrap() > 0,
                    "bytes_written: {result}"
                );
                // The file really exists on disk with the requested content.
                assert_eq!(
                    std::fs::read_to_string(path_s).unwrap(),
                    want_content.as_str()
                );
            }
            Ok(other) => panic!("expected Ok result for {path_s}, got {other:?}"),
            Err(e) => panic!("call failed for {path_s}: {e}"),
        }
    }
    assert_eq!(ok_count, 16, "all 16 concurrent calls must succeed");
}

/// M7: "Supervisor killed mid-call → SDK returns SdkError, does not hang.
/// Assert with a test timeout."
///
/// Determinism: the supervisor is started with the
/// `RAMEN_TEST_PAUSE_AFTER_AUTHORIZED` test hook, which pauses the
/// `FileWrite` effect for 60 s after the `Authorized` record is durable and
/// before the response is sent. The call is therefore *guaranteed* in flight
/// when the supervisor is SIGKILLed — no response can be in transit.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn supervisor_killed_mid_call_errors_without_hanging() {
    let data = tempfile::tempdir().unwrap();
    let prefix = data.path().join("work");
    std::fs::create_dir_all(&prefix).unwrap();
    let prefix = prefix.canonicalize().unwrap();

    let mut sup = tokio::task::spawn_blocking({
        let prefix = prefix.clone();
        move || {
            common::Supervisor::start(
                vec![prefix],
                vec![("RAMEN_TEST_PAUSE_AFTER_AUTHORIZED", "1")],
            )
        }
    })
    .await
    .unwrap();
    let token = sup.filewrite_token("agent:writer", prefix.to_str().unwrap());
    let client = Arc::new(connect(&sup, &token).await);

    let path = prefix.join("killed.txt");
    let path_s = path.to_str().unwrap().to_string();
    let op = common::filewrite_op(&path_s, "never written\n", ramen_sdk::WriteMode::Create);
    let c2 = client.clone();
    let call = tokio::spawn(async move { c2.call(op).await });

    // Let the request reach the pause point (Authorized durable, 60 s
    // pause armed). The pause is 60 s, so any response is impossible now.
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(
        sup.audit_contains_authorized(),
        "request must be in flight (Authorized durable) before the kill;\n{}",
        sup.logs_drain()
    );

    sup.kill_and_wait();

    // The outstanding call must resolve with SdkError — and must not hang.
    let res = tokio::time::timeout(Duration::from_secs(10), call)
        .await
        .expect("SDK hung after supervisor kill");
    match res {
        Ok(Err(SdkError::ConnectionClosed)) => {}
        Ok(Err(e)) => panic!("expected ConnectionClosed, got: {e}"),
        Ok(Ok(o)) => panic!("call completed despite kill: {o:?}"),
        Err(_) => unreachable!("timeout is the panic above"),
    }
}
