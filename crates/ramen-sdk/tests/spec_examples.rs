//! Spec-example round-trip, `ramen-sdk` side (cross-implementation):
//!
//! Extracts every ` ```json ` example from `spec/01-protocol.md` and parses
//! it with this crate's independent decoder. The proto crate carries an identical test
//! (`crates/ramen-proto/tests/spec_examples.rs`) against its
//! independent parser; if the two disagree on any example, one of the two
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
//! The contract is the whole point: **every ` ```json ` block in the spec
//! is a legal wire frame, as written.** No normalization of any kind —
//! every normalization rule is a place where the test stops checking the
//! spec as written and starts checking a dialect the spec doesn't contain.
//! That is why the spec's examples are written out in full (no truncated
//! ULIDs, no `{ ... }` elisions): a reader copies what the spec contains.

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
            let parsed = ramen_sdk::Message::from_bytes(object.as_bytes());
            assert!(
                parsed.is_ok(),
                "spec example {i}.{j} is not a legal wire frame per \
                 ramen-sdk — the spec's illustrative snippet contradicts \
                 the normative text it illustrates:\n{object}\nerror: {:?}",
                parsed.err()
            );
            total += 1;
        }
    }
    assert!(total >= 7, "parsed only {total} spec examples — test is vacuous");
}
