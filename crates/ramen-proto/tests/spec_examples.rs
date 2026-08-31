//! Spec-example round-trip, `ramen-proto` side (cross-implementation):
//!
//! Extracts every ` ```json ` example from `spec/01-protocol.md` and parses
//! it with this crate's decoder. The SDK carries an identical test
//! (`crates/ramen-sdk/tests/spec_examples.rs`) against its independent
//! parser; if the two disagree on any example, one of the two
//! implementations has diverged from the other — or from the protocol.
//!
//! Why this exists as a test rather than a one-time sweep: the normative
//! text of the spec has been reviewed, the illustrative examples never
//! were. Two sweeps have each found an example that contradicted a
//! normative rule (a snippet a client or test writer would copy, that a
//! conforming parser rejects). Extracting the examples programmatically and
//! round-tripping them closes that class permanently: the next spec edit
//! that reopens it fails CI instead of shipping silently.
//!
//! Examples are illustrations, so a small number of *obviously truncated*
//! values are normalized to valid ones before parsing (see
//! `normalize`). Structural conformance — fields, tags, codes — is never
//! normalized; that is exactly what this test checks.

use std::path::{Path, PathBuf};

fn spec_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../spec/01-protocol.md")
}

fn load_blocks() -> Vec<String> {
    let text = std::fs::read_to_string(spec_path())
        .unwrap_or_else(|e| panic!("cannot read spec/01-protocol.md: {e}"));
    let mut blocks = Vec::new();
    for chunk in text.split("```") {
        // The spec's fences are "```json" openers; the chunk following the
        // opener starts with "json\n<content>".
        if let Some(body) = chunk.strip_prefix("json") {
            blocks.push(body.trim().to_string());
        }
    }
    assert!(
        blocks.len() >= 7,
        "expected at least 7 json examples in 01-protocol.md, found {} — \
         did the spec's fences change and make this test vacuous?",
        blocks.len()
    );
    blocks
}

/// Split a spec example block into its top-level JSON objects. One block may
/// hold several (the §7 response-status trio is one object per line).
fn split_top_level_objects(block: &str) -> Vec<String> {
    let bytes = block.as_bytes();
    let mut out = Vec::new();
    let mut depth = 0usize;
    let mut start: Option<usize> = None;
    let mut in_string = false;
    let mut escape = false;
    let mut i = 0;
    while i < bytes.len() {
        // Structural JSON characters are ASCII; bytes >= 0x80 can only occur
        // inside string literals (this spec's examples are well-formed).
        let c = bytes[i] as char;
        if in_string {
            if escape {
                escape = false;
            } else if c == '\\' {
                escape = true;
            } else if c == '"' {
                in_string = false;
            }
        } else if c == '"' {
            in_string = true;
        } else if c == '{' {
            if depth == 0 {
                start = Some(i);
            }
            depth += 1;
        } else if c == '}' {
            depth -= 1;
            if depth == 0 {
                if let Some(s) = start {
                    out.push(block[s..=i].trim().to_string());
                    start = None;
                }
            }
        }
        i += 1;
    }
    assert!(depth == 0, "unbalanced braces in spec example block: {block}");
    out
}

/// Replace the examples' obviously-truncated values with valid ones. Nothing
/// structural is touched: a missing `v` or `id` is a defect, not a
/// placeholder, and must fail.
fn normalize(object: &str) -> String {
    let mut s = object.to_string();
    // Truncated ULIDs.
    s = s.replace("\"01J8ZQ...\"", "\"01J8ZQ3K9X2M0W4Y5A6B7C8D9E\"");
    s = s.replace("\"01J8Z...\"", "\"01J8ZQ3K9X2M0W4Y5A6B7C8D9E\"");
    // The Hello token's inline description.
    s = s.replace(
        "\"<base64url, no padding — serialized Biscuit>\"",
        "\"c2VyaWFsaXplZEJpc2N1aXQ=\"",
    );
    // The §7 trio's elided bodies. `result` is op-specific (05-operations);
    // an empty body is not a legal v0 frame for either implementation
    // (ramen-proto models it as the untagged `OpResult`), so normalize to a
    // concrete `Whoami` result — the status tag is what the trio illustrates.
    s = s.replace(
        "\"result\": { ... }",
        "\"result\": { \"identity\": \"agent:planner\", \"session\": \"01J8ZQ3K9X2M0W4Y5A6B7C8D9E\", \"capabilities\": [], \"token_expires_at\": null }",
    );
    s = s.replace(
        "\"denial\": { ... }",
        "\"denial\": { \"code\": \"CapabilityNotGranted\", \"reason\": \"r\", \"audit_seq\": 1 }",
    );
    s = s.replace(
        "\"error\": { ... }",
        "\"error\": { \"code\": \"Internal\", \"message\": \"m\" }",
    );
    s
}

#[test]
fn every_spec_example_is_a_legal_wire_frame() {
    let mut total = 0usize;
    for (i, block) in load_blocks().into_iter().enumerate() {
        let objects = split_top_level_objects(&block);
        assert!(
            !objects.is_empty(),
            "spec example block {i} contains no top-level JSON object: {block}"
        );
        for (j, object) in objects.iter().enumerate() {
            let parsed = ramen_proto::Message::decode(normalize(object).as_bytes());
            assert!(
                parsed.is_ok(),
                "spec example {i}.{j} is not a legal wire frame per \
                 ramen-proto — the spec's illustrative snippet contradicts \
                 the normative text it illustrates:\n{object}\nerror: {:?}",
                parsed.err()
            );
            total += 1;
        }
    }
    assert!(total >= 7, "parsed only {total} spec examples — test is vacuous");
}
