//! `ramenctl` — the Ramen control-plane CLI (`06-ramenctl.md` §3).
//!
//! First consumer of `ramen-sdk`. The CLI exists to keep the SDK free of
//! CLI-shaped assumptions: the SDK is the measuring instrument, `ramenctl`
//! is its cheapest user.
//!
//! Exit codes (spec §3):
//!
//! | 0 | operation succeeded |
//! | 1 | operation denied |
//! | 2 | transport, handshake, or protocol error |
//! | 3 | usage error |
//!
//! Denials get their own exit code (1, not 2): a script that retries on
//! failure must not retry a denial, because the answer will not change.

mod conform;

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use base64::Engine;
use biscuit_auth::UnverifiedBiscuit;
use clap::{Parser, Subcommand};
use ramen_sdk::{Client, Operation, OpOutcome, WriteMode};
use serde_json::json;

#[derive(Parser)]
#[command(
    name = "ramenctl",
    about = "Ramen control-plane CLI (M7)",
    disable_help_subcommand = true
)]
struct Args {
    /// Path to the supervisor's Unix socket.
    #[arg(long)]
    socket: PathBuf,

    /// Path to a file containing the base64url-encoded biscuit token.
    #[arg(long)]
    token: PathBuf,

    /// Machine-readable output: JSON on stdout, no ANSI escapes.
    #[arg(long, global = true)]
    json: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Connect, complete the handshake, and disconnect.
    Ping,
    /// Issue Whoami and print identity, session, and capabilities.
    Whoami,
    /// Issue FileWrite. Content from `--content` or stdin.
    Write {
        /// Target path.
        path: PathBuf,
        /// File content (otherwise read from stdin).
        #[arg(long)]
        content: Option<String>,
        /// Create mode (the file must not exist). Default: Overwrite.
        #[arg(long)]
        create: bool,
    },
    /// Run the protocol conformance harness (`06-ramenctl.md` §4).
    Conform {
        /// A directory under both the supervisor's allowed prefixes and the
        /// token's `allowed_prefix` fact. Used by the `out_of_order` check's
        /// FileWrite variance. Without it, `out_of_order` uses Whoami only.
        #[arg(long)]
        prefix: Option<PathBuf>,
    },
}

fn main() -> ExitCode {
    let args = match Args::try_parse() {
        Ok(a) => a,
        Err(e) => {
            // Usage errors are exit 3; clap's own default (2) is reserved
            // for transport/handshake/protocol errors in this CLI.
            let _ = e.print();
            return ExitCode::from(3);
        }
    };

    let token = match load_token(&args.token) {
        Ok(t) => t,
        Err(detail) => {
            return usage_failure(&args, &format!("token: {detail}"));
        }
    };

    let code = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(dispatch(&args, &token));
    code
}

/// A usage failure (bad token file, bad stdin): exit 3.
fn usage_failure(args: &Args, detail: &str) -> ExitCode {
    if args.json {
        eprintln!("{}", json!({ "error": "usage", "detail": detail }));
    } else {
        eprintln!("ramenctl: {detail}");
    }
    ExitCode::from(3)
}

/// A transport/handshake/protocol failure: exit 2.
fn protocol_failure(args: &Args, detail: &str) -> ExitCode {
    if args.json {
        eprintln!("{}", json!({ "error": "protocol", "detail": detail }));
    } else {
        eprintln!("ramenctl: {detail}");
    }
    ExitCode::from(2)
}

fn load_token(path: &Path) -> Result<UnverifiedBiscuit, String> {
    let raw =
        std::fs::read_to_string(path).map_err(|e| format!("cannot read {path:?}: {e}"))?;
    UnverifiedBiscuit::from_base64(raw.trim())
        .map_err(|e| format!("not a biscuit token: {e}"))
}

async fn dispatch(args: &Args, token: &UnverifiedBiscuit) -> ExitCode {
    match &args.command {
        Command::Ping => {
            match Client::connect(&args.socket, token).await {
                Ok(client) => {
                    let session = client.session();
                    drop(client); // clean disconnect
                    if args.json {
                        println!(
                            "{}",
                            json!({ "ok": true, "session": session.0.to_string() })
                        );
                    } else {
                        println!("ok (session {:?})", session);
                    }
                    ExitCode::SUCCESS
                }
                Err(e) => protocol_failure(args, &e.to_string()),
            }
        }
        Command::Whoami => run_call(args, token, Operation::Whoami, |outcome| {
            match outcome {
                OpOutcome::Ok(result) => {
                    if args.json {
                        println!("{}", result);
                    } else {
                        let s = |v: &serde_json::Value| v.as_str().unwrap_or_default().to_string();
                        println!("identity:    {}", s(&result["identity"]));
                        println!("session:     {}", s(&result["session"]));
                        println!("capabilities:");
                        let caps = result["capabilities"].as_array();
                        for cap in caps.map(|v| v.iter()).unwrap_or_default() {
                            let mut line = format!(
                                "  {} ({})",
                                s(&cap["op"]),
                                s(&cap["reversibility"])
                            );
                            if let Some(prefixes) = cap["constraints"]["path_prefix"]
                                .as_array()
                            {
                                line.push_str(" [path_prefix: ");
                                line.push_str(&prefixes
                                    .iter()
                                    .map(|p| p.as_str().unwrap_or_default())
                                    .collect::<Vec<_>>()
                                    .join(", "));
                                line.push(']');
                            }
                            println!("{line}");
                        }
                    }
                    ExitCode::SUCCESS
                }
                other => denial_or_error(args, other),
            }
        })
        .await,
        Command::Write {
            path,
            content,
            create,
        } => {
            let content = match content.clone() {
                Some(c) => c,
                None => {
                    let mut s = String::new();
                    match std::io::stdin().read_to_string(&mut s) {
                        Ok(_) => s,
                        Err(e) => return usage_failure(args, &format!("stdin: {e}")),
                    }
                }
            };
            let op = Operation::FileWrite(ramen_sdk::FileWriteOp {
                path: path.display().to_string(),
                content_b64: base64::engine::general_purpose::STANDARD.encode(content),
                mode: if *create {
                    WriteMode::Create
                } else {
                    WriteMode::Overwrite
                },
            });
            let code = run_call(args, token, op, |outcome| {
                match outcome {
                    OpOutcome::Ok(result) => {
                        if args.json {
                            println!("{}", result);
                        } else {
                            let s = |v: &serde_json::Value| v.as_str().unwrap_or_default().to_string();
                            println!(
                                "wrote {} ({} bytes)",
                                s(&result["path"]),
                                result["bytes_written"]
                            );
                            if let Some(handle) = result["restore"]["handle"].as_str() {
                                println!(
                                    "restore: {} ({}; {})",
                                    handle,
                                    s(&result["restore"]["kind"]),
                                    s(&result["restore"]["reversibility"])
                                );
                            }
                        }
                        ExitCode::SUCCESS
                    }
                    other => denial_or_error(args, other),
                }
            })
            .await;
            code
        }
        Command::Conform { prefix } => conform::run(&args.socket, &args.token, prefix, args.json),
    }
}

/// Shared: connect, issue one operation, render the outcome.
async fn run_call(
    args: &Args,
    token: &UnverifiedBiscuit,
    op: Operation,
    render: impl FnOnce(OpOutcome) -> ExitCode,
) -> ExitCode {
    let client = match Client::connect(&args.socket, token).await {
        Ok(c) => c,
        Err(e) => return protocol_failure(args, &e.to_string()),
    };
    match client.call(op).await {
        Ok(outcome) => render(outcome),
        Err(e) => protocol_failure(args, &e.to_string()),
    }
}

/// A `Denied` outcome: exit 1, code/reason/audit_seq printed prominently.
/// An `Error` outcome: exit 2 (the machinery failed, but the round-trip
/// succeeded).
fn denial_or_error(args: &Args, outcome: OpOutcome) -> ExitCode {
    match outcome {
        OpOutcome::Denied {
            code,
            reason,
            audit_seq,
        } => {
            if args.json {
                println!(
                    "{}",
                    json!({
                        "status": "denied",
                        "code": format!("{code:?}"),
                        "reason": reason,
                        "audit_seq": audit_seq,
                    })
                );
            } else {
                println!("denied: {code:?}");
                println!("reason: {reason}");
                // The audit_seq is the handle an operator uses to find the
                // decision in the log without trusting the CLI's account of it.
                println!("audit_seq: {audit_seq}");
            }
            ExitCode::from(1)
        }
        OpOutcome::Error { code, message } => {
            if args.json {
                println!(
                    "{}",
                    json!({
                        "status": "error",
                        "code": format!("{code:?}"),
                        "message": message,
                    })
                );
            } else {
                println!("error: {code:?} — {message}");
            }
            protocol_failure(args, &format!("{code:?}: {message}"))
        }
        OpOutcome::Ok(_) => unreachable!("render handles Ok"),
    }
}
