//! `01-protocol.md` §7 says `AuditUnavailable` is unreachable from a v0
//! supervisor: an audit failure is a process fatal (exit
//! `EXIT_AUDIT_UNAVAILABLE`), never an `Error` response. The closed set
//! includes the code, and the corpus pins that both *parsers* accept it as
//! a known variant — but nothing pinned that no *code path emits* it. That
//! is the gap this test closes, at the grep level: the string may appear in
//! the supervisor's source only on comment lines (the doc that states the
//! invariant, the test that asserts it) — never in code. A future change
//! that answers `Error/AuditUnavailable` fails this test.
//!
//! Line-based by design (the reviewer-approved "grep-level test"): it would
//! not see the string inside a multi-line block comment whose continuation
//! line lacks a `//` marker; no such comment exists in this crate, and the
//! failure mode of a false positive is a test that demands a human look,
//! not a silently passing one.

use std::path::{Path, PathBuf};

fn src_files() -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![Path::new(env!("CARGO_MANIFEST_DIR")).join("src")];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == "rs") {
                out.push(path);
            }
        }
    }
    out
}

#[test]
fn audit_unavailable_is_never_emitted_by_the_supervisor() {
    let files = src_files();
    assert!(!files.is_empty(), "no source files found — test is vacuous");
    for file in &files {
        let content = std::fs::read_to_string(file)
            .unwrap_or_else(|e| panic!("cannot read {}: {e}", file.display()));
        for (n, line) in content.lines().enumerate() {
            if line.contains("AuditUnavailable") {
                let t = line.trim_start();
                assert!(
                    t.starts_with("//") || t.starts_with("*") || t.starts_with("/*"),
                    "{}:{}: AuditUnavailable in code, not a comment — a code \
                     path now emits or handles Error/AuditUnavailable, \
                     contradicting 01-protocol.md §7 (v0: audit failure is \
                     a process fatal, never an Error response)",
                    file.display(),
                    n + 1
                );
            }
        }
    }
}
