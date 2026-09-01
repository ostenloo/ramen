//! ramen-mint — out-of-band token minter for Ramen.
//!
//! The root private key lives here and nowhere else: the supervisor only ever
//! sees the public key (`04-guard.md` §3 — a process that can both verify and
//! mint is one bug away from minting for itself).
//!
//! Subcommands:
//!   keygen     generate the P-256 root keypair
//!   issue      mint a root authority block token
//!   attenuate  append a check-clause-only block (delegation)
//!   inspect    print block contents, optionally verify the signature

#![forbid(unsafe_code)]

use std::error::Error;
use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use biscuit_auth::builder::BlockBuilder;
use biscuit_auth::{Algorithm, KeyPair, PublicKey, UnverifiedBiscuit};
use clap::{Parser, Subcommand};
use time::OffsetDateTime;

const DEFAULT_DIR: &str = "~/.ramen";
const PRIVATE_KEY_NAME: &str = "root.key";
const PUBLIC_KEY_NAME: &str = "root.key.pub";

#[derive(Parser)]
#[command(
    name = "ramen-mint",
    about = "Out-of-band Biscuit token minter for Ramen (P-256 root key)"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Generate the P-256 root keypair (root.key 0400, root.key.pub 0644)
    Keygen {
        /// Key directory (default: ~/.ramen)
        #[arg(long)]
        dir: Option<String>,
        /// Overwrite an existing key — invalidates every token minted with it
        #[arg(long)]
        force: bool,
    },

    /// Mint a root authority block token
    Issue {
        /// Root private key file (default: <dir>/root.key)
        #[arg(long)]
        root: Option<String>,
        /// Key directory (default: ~/.ramen); used to derive --root
        #[arg(long)]
        dir: Option<String>,
        /// Identity granted by this token, e.g. "agent:planner"
        #[arg(long)]
        identity: String,
        /// Capability to grant (repeatable). v0 operations: Whoami, FileWrite.
        /// Default: both.
        #[arg(long = "capability")]
        capabilities: Vec<String>,
        /// Path prefix grant as OP=PATH (repeatable). Required if FileWrite is
        /// granted: FileWrite cannot be exercised without an allowed_prefix.
        #[arg(long = "prefix")]
        prefixes: Vec<String>,
        /// Reversibility level allowed (repeatable), e.g. Trivial, Compensable
        #[arg(long = "reversibility")]
        reversibilities: Vec<String>,
        /// Expiry as RFC 3339. Writes the expires_at fact AND the time check
        /// clause; the check is authoritative, the fact is advisory
        /// (04-guard.md §1).
        #[arg(long)]
        expires: Option<String>,
    },

    /// Append a check-clause-only block to a token (delegation/attenuation)
    ///
    /// The block may contain `check if` clauses only — facts and rules are
    /// rejected, because blocks must not be able to grant (04-guard.md §1).
    Attenuate {
        /// Base64 token to attenuate
        token: String,
        /// Datalog check clauses, e.g. 'check if path($p), $p.starts_with("/tmp/scratch");'
        code: String,
        /// Signing key for the new block (PEM). Default: a throwaway keypair
        /// generated for this invocation — the public key is embedded in the
        /// token, so the key can be discarded afterwards.
        #[arg(long)]
        key: Option<String>,
    },

    /// Print a token's blocks (facts, rules, checks) and key ids
    ///
    /// With --root-pub, also verify the signature against that root public key.
    Inspect {
        /// Base64 token
        token: String,
        /// Root public key file (PEM) to verify the authority block against
        #[arg(long = "root-pub")]
        root_pub: Option<String>,
    },
}

fn main() {
    let cli = Cli::parse();
    if let Err(e) = run(cli) {
        eprintln!("ramen-mint: {e}");
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> Result<(), Box<dyn Error>> {
    match cli.cmd {
        Cmd::Keygen { dir, force } => keygen(&dir.unwrap_or_else(|| DEFAULT_DIR.to_string()), force),
        Cmd::Issue { root, dir, identity, capabilities, prefixes, reversibilities, expires } => {
            let dir = dir.unwrap_or_else(|| DEFAULT_DIR.to_string());
            let root = root
                .as_deref()
                .map(expand)
                .unwrap_or_else(|| expand(&dir).join(PRIVATE_KEY_NAME));
            issue(&root, &identity, &capabilities, &prefixes, &reversibilities, expires.as_deref())
        }
        Cmd::Attenuate { token, code, key } => attenuate(&token, &code, key.as_deref()),
        Cmd::Inspect { token, root_pub } => inspect(&token, root_pub.as_deref()),
    }
}

fn expand(p: &str) -> PathBuf {
    if let Some(rest) = p.strip_prefix("~/") {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/".to_string());
        PathBuf::from(home).join(rest)
    } else {
        PathBuf::from(p)
    }
}

fn keygen(dir: &str, force: bool) -> Result<(), Box<dyn Error>> {
    let dir = expand(dir);
    fs::create_dir_all(&dir)?;

    let priv_path = dir.join(PRIVATE_KEY_NAME);
    let pub_path = dir.join(PUBLIC_KEY_NAME);

    if !force && (priv_path.exists() || pub_path.exists()) {
        return Err(format!(
            "key already exists at {} — refusing to overwrite (it would invalidate all existing tokens); use --force to replace",
            priv_path.display()
        )
        .into());
    }

    let kp = KeyPair::new_with_algorithm(Algorithm::Secp256r1);
    let pem = kp.to_private_key_pem()?;
    let pub_pem = kp.public().to_pem()?;

    let mut f = fs::File::create(&priv_path)?;
    f.write_all(pem.as_bytes())?;
    fs::set_permissions(&priv_path, fs::Permissions::from_mode(0o400))?;
    fs::write(&pub_path, pub_pem.as_bytes())?;
    fs::set_permissions(&pub_path, fs::Permissions::from_mode(0o644))?;

    println!("private key:  {} (mode 0400)", priv_path.display());
    println!("public key:   {} (mode 0644)", pub_path.display());
    println!("fingerprint:  {}", kp.public().to_bytes_hex());
    println!();
    println!("the supervisor's root_key_path must point at the PUBLIC key file.");
    println!("the private key must never appear in supervisor configuration.");
    Ok(())
}

fn issue(
    root_path: &Path,
    identity: &str,
    capabilities: &[String],
    prefixes: &[String],
    reversibilities: &[String],
    expires: Option<&str>,
) -> Result<(), Box<dyn Error>> {
    let root_pem = fs::read_to_string(root_path)
        .map_err(|e| format!("cannot read root key {}: {e}", root_path.display()))?;
    let root = KeyPair::from_private_key_pem_with_algorithm(
        &root_pem,
        Algorithm::Secp256r1,
    )
    .map_err(|e| format!("{} is not a valid P-256 private key: {e}", root_path.display()))?;

    let caps: Vec<String> = if capabilities.is_empty() {
        vec!["Whoami".into(), "FileWrite".into()]
    } else {
        capabilities.to_vec()
    };

    let mut src = String::new();
    src.push_str(&format!("identity({:?});\n", identity));
    for c in &caps {
        src.push_str(&format!("capability({:?});\n", c));
    }
    for p in prefixes {
        let (op, path) = p
            .split_once('=')
            .ok_or_else(|| format!("--prefix must be OP=PATH, got {p:?}"))?;
        src.push_str(&format!("allowed_prefix({:?}, {:?});\n", op, path));
    }
    for r in reversibilities {
        src.push_str(&format!("reversibility_allowed({:?});\n", r));
    }

    let expiry_literal = match expires {
        Some(e) => {
            let dt = OffsetDateTime::parse(e, &time::format_description::well_known::Rfc3339)
                .map_err(|err| format!("--expires is not valid RFC 3339 ({e:?}): {err}"))?;
            let lit = dt
                .format(&time::format_description::well_known::Rfc3339)
                .map_err(|e| e.to_string())?;
            // The check is authoritative; the fact is advisory metadata only
            // (Whoami reports it, nothing else reads it).
            src.push_str(&format!("expires_at({lit});\n"));
            // `date` is the guard's clock fact (`04-guard.md` §4); a check on
            // any other predicate is unresolvable and denies every request.
            src.push_str(&format!("check if date($t), $t < {lit};\n"));
            Some(lit)
        }
        None => None,
    };

    if caps.iter().any(|c| c == "FileWrite")
        && !prefixes
            .iter()
            .any(|p| p.split_once('=').map(|(op, _)| op) == Some("FileWrite"))
    {
        return Err(
            "FileWrite is granted but no --prefix FileWrite=<path> was given: \
             the token could never pass the path check. Add a prefix or drop the capability."
                .into(),
        );
    }

    let builder = biscuit_auth::BiscuitBuilder::new()
        .code(&src)
        .map_err(|e| format!("token datalog failed to parse: {e:?}"))?;
    let token = builder
        .build(&root)
        .map_err(|e| format!("failed to build token: {e:?}"))?;
    let b64 = token.to_base64()?;

    println!("{b64}");
    eprintln!("minted for identity {identity:?}, capabilities {caps:?}");
    if let Some(lit) = expiry_literal {
        eprintln!("expires {lit} (check clause is authoritative)");
    }
    eprintln!("token printed to stdout");
    Ok(())
}

fn attenuate(token_b64: &str, code: &str, key_path: Option<&str>) -> Result<(), Box<dyn Error>> {
    // Blocks may only add check clauses; facts and rules cannot grant, so
    // reject any statement that is not a `check if` clause (04-guard.md §1).
    for stmt in code.split(';') {
        let stmt = stmt.trim();
        if stmt.is_empty() {
            continue;
        }
        if !stmt.starts_with("check if") {
            return Err(format!(
                "attenuation blocks may only contain `check if` clauses, found: {stmt:?}"
            )
            .into());
        }
    }

    let token = UnverifiedBiscuit::from_base64(token_b64)
        .map_err(|e| format!("token failed to parse: {e:?}"))?;

    let keypair = match key_path {
        Some(p) => {
            let path = expand(p);
            let pem = fs::read_to_string(&path)
                .map_err(|e| format!("cannot read key {}: {e}", path.display()))?;
            KeyPair::from_private_key_pem_with_algorithm(&pem, Algorithm::Secp256r1)
                .map_err(|e| format!("{} is not a valid P-256 private key: {e}", path.display()))?
        }
        None => KeyPair::new_with_algorithm(Algorithm::Secp256r1),
    };

    let block = BlockBuilder::new()
        .code(code)
        .map_err(|e| format!("block datalog failed to parse: {e:?}"))?;
    let new = token
        .append_with_keypair(&keypair, block)
        .map_err(|e| format!("failed to append block: {e:?}"))?;

    println!("{}", new.to_base64()?);
    eprintln!("attenuated: {} block(s) total", new.block_count());
    Ok(())
}

fn inspect(token_b64: &str, root_pub_path: Option<&str>) -> Result<(), Box<dyn Error>> {
    let token = UnverifiedBiscuit::from_base64(token_b64)
        .map_err(|e| format!("token failed to parse: {e:?}"))?;

    let count = token.block_count();
    println!("blocks: {count}");
    for i in 0..count {
        println!();
        println!("--- block {i}");
        print!("{}", token.print_block_source(i)?);
    }

    for (i, key) in token.external_public_keys().iter().enumerate() {
        if let Some(k) = key {
            println!();
            println!("block {i} external public key (hex): {}", k.to_bytes_hex());
        }
    }

    if let Some(p) = root_pub_path {
        let path = expand(p);
        let pem = fs::read_to_string(&path)
            .map_err(|e| format!("cannot read public key {}: {e}", path.display()))?;
        let pub_key = PublicKey::from_pem(&pem)
            .map_err(|e| format!("{} is not a valid public key: {e}", path.display()))?;
        match token.verify(pub_key) {
            Ok(_) => {
                println!();
                println!("signature: OK against {}", path.display());
            }
            Err(e) => {
                println!();
                println!("signature: FAILED against {} ({e:?})", path.display());
                std::process::exit(1);
            }
        }
    } else {
        println!();
        println!("(pass --root-pub <key.pub> to verify the signature)");
    }
    Ok(())
}
