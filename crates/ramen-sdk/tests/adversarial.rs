//! Adversarial corpus (shared, cross-implementation) — SDK side:
//!
//! Runs the same raw frame payloads as `crates/ramen-proto/tests/adversarial.rs`
//! through the SDK's independently-written parser and asserts the same
//! accept/reject classification. If the two tests disagree on any case, one
//! of the two implementations has diverged from the other (or from the
//! protocol's documented behavior).
//!
//! The fixtures live in `crates/ramen-proto/tests/adversarial/` (the corpus
//! is shared data, not code: the SDK reads them as plain files, no
//! `ramen-proto` code is linked).

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
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../ramen-proto/tests/adversarial");
    let manifest: Manifest = serde_json::from_str(
        &std::fs::read_to_string(dir.join("cases.json"))
            .expect("adversarial manifest missing"),
    )
    .expect("adversarial manifest is not JSON");

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
fn corpus_classification_matches_proto() {
    for (name, bytes, expect) in load_cases() {
        let parsed = ramen_sdk::Message::from_bytes(&bytes);
        match expect {
            Expect::Accept => assert!(
                parsed.is_ok(),
                "{name}: expected accept, but ramen-sdk rejected: {:?}",
                parsed.err()
            ),
            Expect::Reject => assert!(
                parsed.is_err(),
                "{name}: expected reject, but ramen-sdk accepted: {:?}",
                parsed.ok()
            ),
        }
    }
}
