//! Adversarial corpus (shared, cross-implementation):
//!
//! Every fixture in `tests/adversarial/` is a raw frame payload with an
//! expected outcome — `accept` or `reject` — recorded in `cases.json`.
//! The corpus is a *parity* contract: every implementation of the protocol
//! must reach the **same** classification for every case. A frame that one
//! implementation accepts and another rejects (or vice versa) is a
//! conformance failure in at least one of them.
//!
//! The corpus is deliberately not part of the canonical golden fixtures
//! (`spec/01-protocol.md` §9 lists exactly nine; those are round-trip
//! fixtures). These are edge cases: malformed, hostile, and boundary frames
//! that a live peer might send.
//!
//! The SDK-side twin of this test is `crates/ramen-sdk/tests/adversarial.rs`;
//! it runs the same bytes through the SDK's independently-written parser.

use std::path::Path;

#[derive(serde::Deserialize)]
struct Manifest {
    cases: Vec<Case>,
}

#[derive(serde::Deserialize)]
struct Case {
    file: String,
    expect: Expect,
}

#[derive(serde::Deserialize, PartialEq, Eq, Debug, Clone, Copy)]
#[serde(rename_all = "lowercase")]
enum Expect {
    Accept,
    Reject,
}

fn load_cases() -> Vec<(String, Vec<u8>, Expect)> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/adversarial");
    let manifest: Manifest = serde_json::from_str(
        &std::fs::read_to_string(dir.join("cases.json"))
            .expect("adversarial manifest missing"),
    )
    .expect("adversarial manifest is not JSON");

    // Hygiene: every manifest entry exists, and every fixture file is
    // listed (no orphan cases drifting out of the contract).
    let mut listed: std::collections::BTreeSet<String> =
        manifest.cases.iter().map(|c| c.file.clone()).collect();
    for entry in std::fs::read_dir(&dir).expect("adversarial directory missing") {
        let name = entry.unwrap().file_name().to_string_lossy().to_string();
        if name == "cases.json" {
            continue;
        }
        assert!(
            listed.remove(&name),
            "fixture {name} is not listed in cases.json"
        );
    }
    assert!(listed.is_empty(), "cases.json lists missing fixture(s): {listed:?}");

    let mut cases = manifest
        .cases
        .into_iter()
        .map(|c| {
            let bytes = std::fs::read(dir.join(&c.file))
                .unwrap_or_else(|e| panic!("cannot read fixture {}: {e}", c.file));
            (c.file, bytes, c.expect)
        })
        .collect::<Vec<_>>();
    cases.sort_by(|a, b| a.0.cmp(&b.0));
    assert!(!cases.is_empty(), "no adversarial cases found");
    cases
}

#[test]
fn corpus_classification() {
    for (name, bytes, expect) in load_cases() {
        let parsed = ramen_proto::Message::decode(&bytes);
        match expect {
            Expect::Accept => assert!(
                parsed.is_ok(),
                "{name}: expected accept, but ramen-proto rejected: {:?}",
                parsed.err()
            ),
            Expect::Reject => assert!(
                parsed.is_err(),
                "{name}: expected reject, but ramen-proto accepted: {:?}",
                parsed.ok()
            ),
        }
    }
}
