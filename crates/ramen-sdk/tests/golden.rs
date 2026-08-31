//! Golden-fixture round-trip (spec 06-ramenctl.md, M7 acceptance):
//!
//! Every fixture committed in M1 (`crates/ramen-proto/tests/golden/*.json`)
//! must parse into the SDK's *independently-defined* envelope types and
//! re-serialize byte-identically. The fixtures are consumed as plain JSON
//! files — no `ramen-proto` code is linked or read.
//!
//! A failure here is a *spec defect* (the wire format as documented is not
//! what the SDK implements, or the two disagree), not an SDK bug: the SDK
//! was written from `01-protocol.md` alone.

use ramen_sdk::Message;

const GOLDEN_DIR: &str = "../ramen-proto/tests/golden";

struct Case {
    name: String,
    fixture: String,
}

fn load_cases() -> Vec<Case> {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(GOLDEN_DIR);
    let mut cases: Vec<Case> = std::fs::read_dir(&dir)
        .expect("golden fixture directory missing")
        .map(|e| e.unwrap())
        .filter(|e| e.path().extension().is_some_and(|x| x == "json"))
        .map(|e| {
            let name = e.file_name().to_string_lossy().to_string();
            let mut fixture =
                std::fs::read_to_string(e.path()).unwrap_or_else(|err| {
                    panic!("cannot read fixture {}: {err}", name)
                });
            // The fixture files carry a trailing newline (a file-storage
            // artifact — a wire frame is the JSON payload itself, with no
            // trailing bytes). Strip it so the comparison is against the
            // frame contents.
            if fixture.ends_with('\n') {
                fixture.pop();
            }
            Case { name, fixture }
        })
        .collect();
    cases.sort_by(|a, b| a.name.cmp(&b.name));
    assert!(!cases.is_empty(), "no golden fixtures found");
    cases
}

#[test]
fn golden_fixtures_round_trip() {
    let cases = load_cases();
    for case in &cases {
        let value: serde_json::Value = serde_json::from_str(&case.fixture)
            .unwrap_or_else(|e| panic!("fixture {} is not JSON: {e}", case.name));

        let msg = Message::from_value(value.clone()).unwrap_or_else(|e| {
            panic!(
                "fixture {} does not parse into the SDK's types: {e}\nfixture: {}",
                case.name, case.fixture
            )
        });

        let reserialized = msg.to_json().unwrap();
        assert_eq!(
            reserialized, case.fixture,
            "fixture {} does not re-serialize byte-identically\n  sdk: {}\n  fix: {}",
            case.name, reserialized, case.fixture
        );

        // Round-trip again through the value form to catch asymmetric
        // (de)serialization.
        let msg2 = Message::from_value(
            serde_json::from_str(&reserialized).unwrap(),
        )
        .unwrap();
        assert_eq!(msg2, msg, "fixture {} round-trip is not stable", case.name);
    }
}
