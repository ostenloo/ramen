//! Log verification (`02-audit.md` §8) — the single source of truth shared by
//! the standalone `ramen-audit-verify` binary and [`crate::AuditLog::open`].
//!
//! Checks, in order:
//! 1. Record 0 is a well-formed `LogHeader`.
//! 2. The header's `prev_hash` equals `SHA-256(GENESIS_DOMAIN || log_id)`.
//! 3. `seq` increments by exactly 1 with no gaps.
//! 4. Every record's stated `prev_hash` equals the recomputed hash of the
//!    *previous frame's exact bytes* (prefix included).
//! 5. Timestamps are non-decreasing (warning only — NTP steps are not
//!    tampering).
//! 6. Every `Authorized` record has `peer.verified == true` (critical).
//! 7. Every `Authorized` is followed by `Executed`/`ExecutionFailed` with the
//!    same `request_id`. Unmatched at EOF is a warning (crash window); an
//!    effect without a prior `Authorized`, or a duplicate `Authorized`, is
//!    critical.
//! 8. A trailing partial frame is reported (warning) with the last valid seq.
//!
//! Chain integrity is always verified end-to-end, regardless of any
//! `--from`/`--to` report range: a local range is only meaningful over a
//! verified chain.

use std::collections::HashMap;

use ramen_proto::MAX_FRAME_BYTES;

use crate::chain::{genesis_hash, hex, next_hash};
use crate::record::{LogHeader, Record, RecordKind};
use crate::time::is_valid_rfc3339;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Warning,
    Critical,
}

#[derive(Debug, Clone)]
pub struct Finding {
    pub severity: Severity,
    /// The seq the finding is attributed to (e.g. a `ChainMismatch` detected
    /// at record `n` is attributed to seq `n-1`, the corrupted frame).
    pub seq: Option<u64>,
    /// Stable machine-readable code.
    pub code: &'static str,
    pub message: String,
}

#[derive(Debug)]
pub struct VerifyReport {
    pub findings: Vec<Finding>,
    /// Number of complete frames.
    pub record_count: usize,
    pub last_valid_seq: Option<u64>,
    /// Byte offset just past the last complete frame.
    pub last_valid_end: usize,
    /// Trailing bytes that do not form a complete frame.
    pub tail_bytes: usize,
    /// True when the file has zero bytes.
    pub empty: bool,
    /// `record_hash` of the last complete frame (the chain continuation
    /// point for `AuditLog::open`).
    pub last_hash: Option<[u8; 32]>,
}

impl VerifyReport {
    pub fn criticals(&self) -> impl Iterator<Item = &Finding> {
        self.findings.iter().filter(|f| f.severity == Severity::Critical)
    }

    pub fn warnings(&self) -> impl Iterator<Item = &Finding> {
        self.findings.iter().filter(|f| f.severity == Severity::Warning)
    }

    /// True when there are no critical findings.
    pub fn ok(&self) -> bool {
        self.criticals().next().is_none()
    }

    /// Verifier exit code for a readable file: 0 clean, 1 warnings, 2 failed.
    /// (3 — unreadable — is the caller's job.)
    pub fn status_code(&self) -> u32 {
        if !self.ok() {
            2
        } else if self.findings.is_empty() {
            0
        } else {
            1
        }
    }
}

pub struct Split {
    /// (start, end) offsets of each complete frame.
    pub frames: Vec<(usize, usize)>,
    /// Bytes after the last complete frame that do not form a frame.
    pub tail: usize,
}

/// Split a byte stream into complete frames.
///
/// Deliberately a manual walk (rather than `ramen-proto::Decoder`) so a
/// malformed prefix *in the middle* of the file yields a precise finding at
/// the right seq instead of poisoning the whole decode.
pub fn split_frames(bytes: &[u8]) -> Split {
    let mut frames = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes.len() - i < 4 {
            break; // torn prefix
        }
        let len = u32::from_be_bytes([bytes[i], bytes[i + 1], bytes[i + 2], bytes[i + 3]]) as usize;
        if len == 0 || len > MAX_FRAME_BYTES as usize {
            break; // torn/bogus prefix
        }
        if bytes.len() - i - 4 < len {
            break; // torn body
        }
        frames.push((i, i + 4 + len));
        i += 4 + len;
    }
    Split { frames, tail: bytes.len() - i }
}

/// The chain anchor: `SHA-256(GENESIS_DOMAIN || log_id)` read from record 0.
/// If record 0 does not parse as a header the log is already failing
/// (`BadHeader`/`CorruptRecord`); anchor at all-zero so downstream links can
/// still be checked against each other.
fn chain_anchor(bytes: &[u8], split: &Split) -> [u8; 32] {
    if let Some((start, end)) = split.frames.first() {
        let payload = &bytes[*start + 4..*end];
        if let Ok(header) = serde_json::from_slice::<LogHeader>(payload) {
            return genesis_hash(&header.log_id);
        }
    }
    [0u8; 32]
}

pub fn verify_bytes(bytes: &[u8]) -> VerifyReport {
    let mut findings: Vec<Finding> = Vec::new();

    if bytes.is_empty() {
        findings.push(Finding {
            severity: Severity::Warning,
            seq: None,
            code: "EmptyLog",
            message: "log file is empty (no records)".into(),
        });
        return VerifyReport {
            findings,
            record_count: 0,
            last_valid_seq: None,
            last_valid_end: 0,
            tail_bytes: 0,
            empty: true,
            last_hash: None,
        };
    }

    let split = split_frames(bytes);
    let n = split.frames.len();
    let mut prev = chain_anchor(bytes, &split); // record_hash of the previous frame
    let mut prev_ts: Option<String> = None;
    // request_id -> seq of its open `Authorized` (single-use ids make this
    // unambiguous across sessions).
    let mut open_authorized: HashMap<String, u64> = HashMap::new();

    for (pos, (start, end)) in split.frames.iter().enumerate() {
        let frame = &bytes[*start..*end];
        let payload = &frame[4..];
        let expected_seq = pos as u64;

        let h_here = next_hash(&prev, frame);

        let record: Record = match serde_json::from_slice(payload) {
            Ok(rec) => rec,
            Err(e) => {
                findings.push(Finding {
                    severity: Severity::Critical,
                    seq: Some(expected_seq),
                    code: "CorruptRecord",
                    message: format!("frame at seq {expected_seq} is not a valid record: {e}"),
                });
                prev = h_here;
                continue;
            }
        };

        // Check 1 / 2 — header at record 0.
        if expected_seq == 0 {
            match &record {
                Record::LogHeader(h) => {
                    if h.kind != RecordKind::LogHeader || h.seq != 0 {
                        findings.push(Finding {
                            severity: Severity::Critical,
                            seq: Some(0),
                            code: "BadHeader",
                            message: format!(
                                "record 0 is not a well-formed LogHeader (kind {:?}, seq {})",
                                h.kind, h.seq
                            ),
                        });
                    } else {
                        if h.prev_hash != hex(&genesis_hash(&h.log_id)) {
                            findings.push(Finding {
                                severity: Severity::Critical,
                                seq: Some(0),
                                code: "GenesisMismatch",
                                message: "header prev_hash does not match SHA-256(GENESIS_DOMAIN || log_id)".into(),
                            });
                        }
                        if !is_valid_rfc3339(&h.created_at) {
                            findings.push(Finding {
                                severity: Severity::Critical,
                                seq: Some(0),
                                code: "MalformedTimestamp",
                                message: format!("header created_at is not RFC 3339 UTC: {:?}", h.created_at),
                            });
                        }
                    }
                }
                Record::Event(_) => {
                    findings.push(Finding {
                        severity: Severity::Critical,
                        seq: Some(0),
                        code: "BadHeader",
                        message: "record 0 is not a LogHeader".into(),
                    });
                }
            }
        } else {
            // Check 3 — seq continuity.
            if record.seq() != expected_seq {
                findings.push(Finding {
                    severity: Severity::Critical,
                    seq: Some(expected_seq),
                    code: "SeqBroken",
                    message: format!("record at position {expected_seq} has seq {}", record.seq()),
                });
            }
            if record.kind() == RecordKind::LogHeader {
                findings.push(Finding {
                    severity: Severity::Critical,
                    seq: Some(expected_seq),
                    code: "BadHeader",
                    message: format!("LogHeader found at seq {expected_seq} (headers are only record 0)"),
                });
            }
            // Check 4 — chain link. A mismatch is *caused* by the previous
            // frame, so the finding is attributed to seq n-1.
            if record.prev_hash() != hex(&prev) {
                findings.push(Finding {
                    severity: Severity::Critical,
                    seq: Some(expected_seq - 1),
                    code: "ChainMismatch",
                    message: format!(
                        "frame at seq {} does not match the chain hash stated by record {expected_seq}",
                        expected_seq - 1
                    ),
                });
            }
        }

        // Check 5 — timestamps (warning only).
        let ts = record.timestamp();
        if !is_valid_rfc3339(ts) {
            findings.push(Finding {
                severity: Severity::Critical,
                seq: Some(expected_seq),
                code: "MalformedTimestamp",
                message: format!("record {} timestamp is not RFC 3339 UTC: {ts:?}", expected_seq),
            });
        } else if let Some(p) = &prev_ts {
            if ts < p.as_str() {
                findings.push(Finding {
                    severity: Severity::Warning,
                    seq: Some(expected_seq),
                    code: "ClockStep",
                    message: format!("timestamp {ts} is earlier than previous {p}"),
                });
            }
        }
        prev_ts = Some(ts.to_string());

        // Checks 6 / 7 — authorization pairing.
        match record.kind() {
            RecordKind::Authorized => {
                if let Record::Event(e) = &record {
                    if e.peer.as_ref().map(|p| p.verified) != Some(true) {
                        findings.push(Finding {
                            severity: Severity::Critical,
                            seq: Some(expected_seq),
                            code: "UnverifiedAuthorization",
                            message: "Authorized record lacks a verified peer".into(),
                        });
                    }
                    if let Some(rid) = &e.request_id {
                        let key = rid.to_string();
                        if let Some(first) = open_authorized.get(&key) {
                            findings.push(Finding {
                                severity: Severity::Critical,
                                seq: Some(expected_seq),
                                code: "DuplicateAuthorization",
                                message: format!(
                                    "request {key} is authorized again at seq {expected_seq} (first at seq {first}; ids are single-use)"
                                ),
                            });
                        } else {
                            open_authorized.insert(key, expected_seq);
                        }
                    }
                }
            }
            RecordKind::Executed | RecordKind::ExecutionFailed => {
                if let Record::Event(e) = &record {
                    if let Some(rid) = &e.request_id {
                        let key = rid.to_string();
                        if open_authorized.remove(&key).is_none() {
                            findings.push(Finding {
                                severity: Severity::Critical,
                                seq: Some(expected_seq),
                                code: "EffectWithoutAuthorization",
                                message: format!(
                                    "{} at seq {expected_seq} for request {key} has no prior Authorized",
                                    record.kind()
                                ),
                            });
                        }
                    }
                }
            }
            RecordKind::TailTruncated => {
                findings.push(Finding {
                    severity: Severity::Warning,
                    seq: Some(expected_seq),
                    code: "TailTruncatedRecord",
                    message: "tail-truncation recovery was recorded at this seq".into(),
                });
            }
            _ => {}
        }

        prev = h_here;
    }

    // Check 7 (EOF): open authorizations are the documented crash window.
    for (rid, seq) in &open_authorized {
        findings.push(Finding {
            severity: Severity::Warning,
            seq: Some(*seq),
            code: "CrashWindow",
            message: format!(
                "Authorized at seq {seq} for request {rid} has no terminal record (crash window)"
            ),
        });
    }

    // Check 8 — trailing partial frame.
    if split.tail > 0 {
        findings.push(Finding {
            severity: Severity::Warning,
            seq: if n > 0 { Some((n - 1) as u64) } else { None },
            code: "TrailingPartialFrame",
            message: format!(
                "{} trailing bytes do not form a complete frame (last valid seq: {})",
                split.tail,
                if n > 0 {
                    (n - 1).to_string()
                } else {
                    "-".into()
                }
            ),
        });
    }

    let (last_valid_end, last_valid_seq) = match split.frames.last() {
        Some((_, end)) => (*end, Some((n - 1) as u64)),
        None => (0, None),
    };

    VerifyReport {
        findings,
        record_count: n,
        last_valid_seq,
        last_valid_end,
        tail_bytes: split.tail,
        empty: false,
        last_hash: Some(prev),
    }
}
