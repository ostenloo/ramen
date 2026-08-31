//! `ramen-audit-verify` — standalone verifier for Ramen audit logs
//! (`02-audit.md` §8).
//!
//! ```text
//! ramen-audit-verify <path> [--json] [--from SEQ] [--to SEQ]
//! ```
//!
//! Exit codes: `0` clean, `1` warnings only, `2` verification failed,
//! `3` file unreadable.
//!
//! `--from`/`--to` restrict *which records' findings are reported* (record-
//! level checks 5–8). Chain integrity (checks 1–4) is always verified
//! end-to-end — a local range is only meaningful over a verified chain.

use std::process::exit;

use ramen_audit::{verify_bytes, VerifyReport};

struct Opts {
    path: String,
    json: bool,
    from: Option<u64>,
    to: Option<u64>,
}

fn usage() -> ! {
    eprintln!("usage: ramen-audit-verify <path> [--json] [--from SEQ] [--to SEQ]");
    exit(2)
}

fn parse_args() -> Opts {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut opts = Opts {
        path: String::new(),
        json: false,
        from: None,
        to: None,
    };
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--json" => opts.json = true,
            "--from" => {
                i += 1;
                opts.from = args.get(i).and_then(|s| s.parse().ok());
                if opts.from.is_none() {
                    eprintln!("--from requires a SEQ");
                    usage();
                }
            }
            "--to" => {
                i += 1;
                opts.to = args.get(i).and_then(|s| s.parse().ok());
                if opts.to.is_none() {
                    eprintln!("--to requires a SEQ");
                    usage();
                }
            }
            s if s.starts_with("--") => {
                eprintln!("unknown flag: {s}");
                usage();
            }
            s => {
                if !opts.path.is_empty() {
                    eprintln!("unexpected argument: {s}");
                    usage();
                }
                opts.path = s.to_string();
            }
        }
        i += 1;
    }
    if opts.path.is_empty() {
        usage();
    }
    opts
}

fn main() {
    let opts = parse_args();

    let bytes = match std::fs::read(&opts.path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("cannot read {}: {e}", opts.path);
            exit(3);
        }
    };

    let report = verify_bytes(&bytes);

    if opts.json {
        let findings: Vec<serde_json::Value> = report
            .findings
            .iter()
            .filter(|f| in_range_single(f.seq, opts.from, opts.to))
            .map(|f| {
                serde_json::json!({
                    "severity": if f.severity == ramen_audit::Severity::Critical {
                        "critical"
                    } else {
                        "warning"
                    },
                    "seq": f.seq,
                    "code": f.code,
                    "message": f.message,
                })
            })
            .collect();
        let status = match report.status_code() {
            0 => "ok",
            1 => "warnings",
            _ => "failed",
        };
        let out = serde_json::json!({
            "path": opts.path,
            "records": report.record_count,
            "last_seq": report.last_valid_seq,
            "tail_bytes": report.tail_bytes,
            "findings": findings,
            "status": status,
        });
        println!("{}", serde_json::to_string_pretty(&out).unwrap());
    } else {
        in_range(&report, opts.from, opts.to, |f| {
            let sev = if f.severity == ramen_audit::Severity::Critical {
                "CRITICAL"
            } else {
                "WARNING "
            };
            let seq = f
                .seq
                .map(|s| format!("[seq {s}]"))
                .unwrap_or_else(|| "[n/a]".into());
            println!("{sev} {seq} {} : {}", f.code, f.message);
        });
        println!(
            "records: {} (last seq {:?})  tail bytes: {}",
            report.record_count, report.last_valid_seq, report.tail_bytes
        );
        match report.status_code() {
            0 => println!("status: OK"),
            1 => println!("status: WARNINGS"),
            _ => println!("status: FAILED"),
        }
    }

    exit(report.status_code() as i32);
}

/// True when `seq` falls inside the (inclusive) report range; a `None` seq
/// (log-level finding) is always reported.
fn in_range_single(seq: Option<u64>, from: Option<u64>, to: Option<u64>) -> bool {
    match seq {
        None => true,
        Some(s) => {
            if let Some(lo) = from {
                if s < lo {
                    return false;
                }
            }
            if let Some(hi) = to {
                if s > hi {
                    return false;
                }
            }
            true
        }
    }
}

fn in_range(report: &VerifyReport, from: Option<u64>, to: Option<u64>, mut f: impl FnMut(&ramen_audit::Finding)) {
    for finding in &report.findings {
        if in_range_single(finding.seq, from, to) {
            f(finding);
        }
    }
}
