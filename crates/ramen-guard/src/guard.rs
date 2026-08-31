//! The guard: Biscuit authorization for every request (`04-guard.md` §1-6, §9-10).
//!
//! ## Decision procedure (deterministic order)
//!
//! 1. **Root defense** (`04-guard.md` §9): re-verify the token's signature
//!    against the guard's configured root key. The guard takes the token as
//!    its base64url wire form and verifies it independently — a
//!    misconfigured deployment (supervisor and guard with different roots)
//!    fails here; the guard's root wins.
//! 2. **Path safety** (FileWrite only): `04-guard.md` §6/§7 via
//!    [`check_file_write_path`]: absolute → no lexical `..` (before any
//!    filesystem access) → parent exists → control-plane protection (before
//!    the prefix and symlink checks) → no final-component symlink. The
//!    canonical target becomes the `path` fact — the canonical form is what
//!    is executed on (§6).
//! 3. **Authorization**: a fresh `Authorizer` per request (step 1 of §9)
//!    built from the token plus the guard's facts (`operation`,
//!    `reversibility`, `path`, `date`) and the §5 policy:
//!
//!    ```datalog
//!    allow if operation($op), capability($op),
//!             reversibility($r), reversibility_allowed($r);
//!    deny if true;
//!    ```
//!
//!    `Ok(0)` (the allow policy) → `Allow`; anything else → `Deny`. The
//!    token cannot add policies (its blocks only carry check clauses), so
//!    only index 0 can ever be the allow decision.
//! 4. **Prefix** (FileWrite, only after the authorizer allows): the
//!    canonical target is within at least one
//!    `allowed_prefix("FileWrite", ...)` — component-wise, never a raw
//!    `str::starts_with`.
//! 5. **Denial classification** (deterministic order, first match wins):
//!    missing capability, missing reversibility, expiry (far-past re-run),
//!    catch-all. The probes never produce an Allow; they name the denial.

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use biscuit_auth::builder::{date as date_term, fact as datalog_fact, AuthorizerBuilder};
use biscuit_auth::{error, Authorizer, Biscuit, UnverifiedBiscuit};
use ramen_proto::messages::{
    CapabilitySummary, Constraints, DenialCode, Operation, Reversibility,
};

use crate::fs::Fs;
use crate::pathcheck::{check_file_write_path, path_within, ControlPlanePaths, PathCheck};
use crate::rootkey::RootKey;

/// A single authorization request: the client's token (base64url, no
/// padding), the operation, and the decision time. `now` is injected —
/// `04-guard.md` §5 (`date($now)` is a guard fact, never minted into the
/// token) — and must be the supervisor's clock at dispatch time.
#[derive(Clone, Copy)]
pub struct AuthzRequest<'a> {
    pub token: &'a str,
    pub op: &'a Operation,
    pub now: SystemTime,
}

/// The outcome of a guard decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// The operation may proceed (M4: the supervisor still responds
    /// `Error/NotImplemented`; the audit trail says `Authorized` first).
    Allow,
    /// The operation is denied with a classified code and a human-readable
    /// reason for the client.
    Deny {
        code: DenialCode,
        reason: String,
    },
}

/// The guard. Stateless across requests: the only per-request state is the
/// `Authorizer` built inside `authorize`.
pub struct Guard {
    root: Box<dyn RootKey>,
    control_plane: ControlPlanePaths,
    fs: Box<dyn Fs>,
}

impl Guard {
    pub fn new(
        root: Box<dyn RootKey>,
        control_plane: ControlPlanePaths,
        fs: Box<dyn Fs>,
    ) -> Self {
        Self {
            root,
            control_plane,
            fs,
        }
    }

    /// Re-verify the token against this guard's root (`04-guard.md` §9).
    fn verify_against_root(&self, token_b64: &str) -> Result<Biscuit, ()> {
        UnverifiedBiscuit::from_base64(token_b64)
            .map_err(|_| ())
            .and_then(|u| u.verify(|_kid| Ok(self.root.public_key())).map_err(|_| ()))
    }

    /// The full decision procedure (see the module docs for the order).
    pub fn authorize(&self, req: AuthzRequest) -> Decision {
        // 1. Root defense: fail closed.
        let biscuit = match self.verify_against_root(req.token) {
            Ok(b) => b,
            Err(()) => {
                return Decision::Deny {
                    code: DenialCode::ConstraintViolated,
                    reason: "token not issued by the root key".into(),
                }
            }
        };

        // 2. Path safety (FileWrite only). A safety violation denies with
        //    its own code (e.g. ControlPlaneProtected), decided before the
        //    authorizer. The canonical target becomes the path fact.
        let canon_path: Option<PathBuf> = if let Operation::FileWrite(op) = req.op {
            match check_file_write_path(&op.path, &*self.fs, &self.control_plane) {
                PathCheck::Ok(t) => Some(t),
                PathCheck::Deny { code, reason } => return Decision::Deny { code, reason },
            }
        } else {
            None
        };

        // 3. Authorization: fresh authorizer, guard facts, §5 policy.
        let mut az = match self.build_authorizer(&biscuit, req, canon_path.as_deref()) {
            Ok(az) => az,
            Err(e) => {
                // A token the guard cannot evaluate is malformed — fail
                // closed with the catch-all.
                return Decision::Deny {
                    code: DenialCode::ConstraintViolated,
                    reason: format!("token could not be evaluated: {e}"),
                };
            }
        };
        let allowed = matches!(az.authorize(), Ok(0));

        // 4. Prefix (FileWrite, only after the authorizer allowed): within
        //    at least one allowed_prefix("FileWrite", ...), component-wise.
        if allowed {
            if let Some(canon) = &canon_path {
                let prefixes = self.allowed_prefixes(&biscuit, "FileWrite");
                if !prefixes
                    .iter()
                    .any(|p| path_within(Path::new(p), canon))
                {
                    return Decision::Deny {
                        code: DenialCode::ConstraintViolated,
                        reason: "target path is outside every allowed prefix".into(),
                    };
                }
            }
        }

        if allowed {
            Decision::Allow
        } else {
            // 5. Denial classification (deterministic order, first match).
            let (code, reason) = self.classify(&biscuit, req.op);
            Decision::Deny { code, reason }
        }
    }

    /// Best-effort capability summary for `Welcome` (`04-guard.md` §3): a
    /// query against the token's own facts. It must never affect a
    /// decision — any failure yields an empty list.
    pub fn describe_capabilities(&self, token_b64: &str) -> Vec<CapabilitySummary> {
        let Ok(biscuit) = self.verify_against_root(token_b64) else {
            return Vec::new();
        };
        let Ok(mut q) = biscuit.authorizer() else {
            return Vec::new();
        };
        let Ok(caps) = q.query::<_, (String,), error::Token>("res($op) <- capability($op)")
        else {
            return Vec::new();
        };
        let mut out: Vec<CapabilitySummary> = caps.into_iter().filter_map(|(name,)| {
                let reversibility = Operation::reversibility_for_type_name(&name)?;
                let constraints = if name == "FileWrite" {
                    let Ok(prefixes) = q.query::<_, (String,), error::Token>(
                        "res($p) <- allowed_prefix(\"FileWrite\", $p)",
                    ) else {
                        return None;
                    };
                    let mut v: Vec<String> = prefixes.into_iter().map(|(p,)| p).collect();
                    v.sort();
                    if v.is_empty() {
                        None
                    } else {
                        Some(Constraints { path_prefix: v })
                    }
                } else {
                    None
                };
                Some(CapabilitySummary {
                    op: name,
                    reversibility,
                    constraints,
                })
            })
        .collect();
        // Datalog result order is not stable across runs; the capability
        // summary is part of the `Welcome`/`Whoami` wire surface, so it
        // must serialize deterministically (sort by op name).
        out.sort_by(|a, b| a.op.cmp(&b.op));
        out
    }

    /// The `expires_at` fact the token declares, as an ISO-8601 UTC string
    /// (`2026-08-31T00:00:00Z`) — advisory metadata for `Whoami`
    /// (`05-operations.md` M5). The token's own time check is authoritative;
    /// this only reports what the token says, and it says so in the
    /// authority block. `None` when the token does not verify against this
    /// root, has no `expires_at` fact, or the fact is not a date.
    pub fn token_expires_at(&self, token_b64: &str) -> Option<String> {
        let Ok(biscuit) = self.verify_against_root(token_b64) else {
            return None;
        };
        let Ok(mut q) = biscuit.authorizer() else {
            return None;
        };
        let Ok(res) = q.query::<_, (SystemTime,), error::Token>("res($d) <- expires_at($d)")
        else {
            return None;
        };
        res.into_iter()
            .next()
            .map(|(t,)| format_iso8601_utc(t))
    }

    // ── Authorizer construction ────────────────────────────────────────────

    /// The guard's facts and the §5 policy, as one datalog source. The
    /// `operation`/`reversibility`/`path` facts are string-interpolated with
    /// [`Self::datalog_string`] escaping (the operation type name and
    /// reversibility name are guard-controlled constants; the escape is still
    /// applied — it is uniform and free). The `date` fact is added separately
    /// as a proper Date term: biscuit's parser accepts only ISO-8601 date
    /// literals in code, never numeric epoch literals.
    fn facts_and_policy(
        &self,
        op: &Operation,
        canon_path: Option<&Path>,
    ) -> String {
        let mut s = String::new();
        s.push_str(&format!(
            "operation({});\n",
            Self::datalog_string(op.type_name())
        ));
        s.push_str(&format!(
            "reversibility({});\n",
            Self::datalog_string(Self::reversibility_name(op.reversibility()))
        ));
        if let Some(p) = canon_path {
            s.push_str(&format!(
                "path({});\n",
                Self::datalog_string(&p.to_string_lossy())
            ));
        }
        s.push_str(POLICY);
        s
    }

    /// A fresh authorizer per request (`04-guard.md` §9 step 1: "build a
    /// fresh Authorizer").
    fn build_authorizer(
        &self,
        biscuit: &Biscuit,
        req: AuthzRequest,
        canon_path: Option<&Path>,
    ) -> Result<Authorizer, String> {
        let code = self.facts_and_policy(req.op, canon_path);
        AuthorizerBuilder::new()
            .code(&code)
            .map_err(|e| e.to_string())?
            .fact(datalog_fact("date", &[date_term(&req.now)]))
            .map_err(|e| e.to_string())?
            .build(biscuit)
            .map_err(|e| e.to_string())
    }

    /// A probe authorizer (classification): same facts and policy, but
    /// without the `path` fact — probes are about the token, not the target
    /// path — and with an injected clock (the far-past expiry probe).
    fn probe_authorizer(
        &self,
        biscuit: &Biscuit,
        op: &Operation,
        now: SystemTime,
    ) -> Option<Authorizer> {
        let code = self.facts_and_policy(op, None);
        AuthorizerBuilder::new()
            .code(&code)
            .ok()
            .and_then(|b| b.fact(datalog_fact("date", &[date_term(&now)])).ok())
            .and_then(|b| b.build(biscuit).ok())
    }

    // ── Denial classification ──────────────────────────────────────────────

    /// Denial classification probes (`04-guard.md` §7 step 5).
    fn classify(&self, biscuit: &Biscuit, op: &Operation) -> (DenialCode, String) {
        let op_name = op.type_name().to_string();

        // Probe 1: no capability for this operation.
        if let Some(mut az) = self.probe_authorizer(biscuit, op, SystemTime::now()) {
            if let Ok(caps) = az.query::<_, (String,), error::Token>("res($op) <- capability($op)") {
                if !caps.into_iter().any(|(c,)| c == op_name) {
                    return (
                        DenialCode::CapabilityNotGranted,
                        format!("token grants no capability for `{op_name}`"),
                    );
                }
            }
        }

        // Probe 2: capability present, but the operation's reversibility is
        // not among the token's reversibility_allowed facts.
        if let Some(mut az) = self.probe_authorizer(biscuit, op, SystemTime::now()) {
            if let Ok(revs) = az.query::<_, (String,), error::Token>("res($r) <- reversibility_allowed($r)") {
                let name = Self::reversibility_name(op.reversibility());
                if !revs.into_iter().any(|(r,)| r == name) {
                    return (
                        DenialCode::ReversibilityNotPermitted,
                        format!(
                            "operation `{op_name}` requires reversibility `{name}`, not granted by the token"
                        ),
                    );
                }
            }
        }

        // Probe 3: expiry. Re-run the same authorizer with a far-past
        // `now` (well before any plausible mint time): the policy is
        // now-independent, so if the far-past run allows, the only thing
        // that changed between the runs is the date — the token is expired.
        let now = SystemTime::now();
        let far_past = if now > UNIX_EPOCH + std::time::Duration::from_secs(31 * 24 * 3600) {
            UNIX_EPOCH + std::time::Duration::from_secs(31 * 24 * 3600)
        } else {
            UNIX_EPOCH
        };
        if let Some(mut az) = self.probe_authorizer(biscuit, op, far_past) {
            if matches!(az.authorize(), Ok(0)) {
                return (
                    DenialCode::TokenExpired,
                    "token is expired".into(),
                );
            }
        }

        // Probe 4: catch-all (check-clause violation, or anything else).
        (
            DenialCode::ConstraintViolated,
            "token constraint not satisfied".into(),
        )
    }

    fn allowed_prefixes(&self, biscuit: &Biscuit, op_name: &str) -> Vec<String> {
        let Ok(mut q) = biscuit.authorizer() else {
            return Vec::new();
        };
        let rule = format!("res($p) <- allowed_prefix(\"{op_name}\", $p)");
        match q.query::<_, (String,), error::Token>(rule.as_str()) {
            Ok(p) => p.into_iter().map(|(x,)| x).collect(),
            Err(_) => Vec::new(),
        }
    }

    /// Escape a string for interpolation into datalog source, including the
    /// surrounding quotes. The biscuit parser supports `\\` and `\"` (raw
    /// newlines/tabs are legal inside string literals), so those two are all
    /// that need escaping. Public because token mints (e.g. the
    /// supervisor's tests) need to embed paths in `allowed_prefix` facts.
    pub fn datalog_string(s: &str) -> String {
        format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
    }

    fn reversibility_name(r: Reversibility) -> &'static str {
        match r {
            Reversibility::Trivial => "Trivial",
            Reversibility::Compensable => "Compensable",
            Reversibility::Irreversible => "Irreversible",
        }
    }
}

/// Format an instant as ISO-8601 UTC with second precision
/// (`2026-08-31T00:00:00Z`) — the wire form of `token_expires_at`
/// (`05-operations.md` M5). Hand-rolled (Howard Hinnant's civil-from-days
/// algorithm) because the guard's dependency set is `biscuit-auth`,
/// `ramen-proto`, and `thiserror` only — no date library.
fn format_iso8601_utc(instant: SystemTime) -> String {
    let secs = instant
        .duration_since(UNIX_EPOCH)
        .expect("instants before the Unix epoch are not representable")
        .as_secs();
    let days = (secs / 86_400) as i64;
    let secs_of_day = (secs % 86_400) as u32;
    let h = secs_of_day / 3600;
    let m = (secs_of_day % 3600) / 60;
    let s = secs_of_day % 60;

    let z = days + 719_468; // shift so the epoch is a Monday
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096] day of era
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let mo = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let y = if mo <= 2 { y + 1 } else { y };

    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{m:02}:{s:02}Z")
}

/// The §5 policy: allow only what the token's facts grant; otherwise deny.
/// The explicit `deny if true` makes the fall-through visible in policy
/// lists and guarantees an explicit denial (the guard also treats any
/// non-`Ok(0)` outcome as a denial).
const POLICY: &str = r#"
allow if operation($op), capability($op), reversibility($r), reversibility_allowed($r);
deny if true;
"#;

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::{Duration, UNIX_EPOCH};

    use biscuit_auth::builder::{Algorithm, BlockBuilder, BiscuitBuilder};
    use biscuit_auth::{KeyPair, PublicKey, UnverifiedBiscuit};
    use ramen_proto::messages::{FileWriteOp, WhoamiOp, WriteMode};

    use super::*;
    use crate::fs::StdFs;


    /// A fixed "now" (2025-06-15) — deterministic.
    fn now() -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(1_750_000_000)
    }

    /// The full v0 token: both capabilities, one prefix, two
    /// reversibilities.
    const FULL_CODE: &str = r#"
        identity("agent:planner");
        capability("Whoami");
        capability("FileWrite");
        allowed_prefix("FileWrite", "/work");
        reversibility_allowed("Trivial");
        reversibility_allowed("Compensable");
    "#;

    #[derive(Clone)]
    struct TestRoot {
        pubk: PublicKey,
        pem: String,
    }

    impl TestRoot {
        fn new() -> Self {
            let kp = KeyPair::new_with_algorithm(Algorithm::Secp256r1);
            TestRoot {
                pubk: kp.public(),
                pem: kp.to_private_key_pem().unwrap().to_string(),
            }
        }
        /// Reconstruct the keypair from the private key PEM (KeyPair is not
        /// Clone in biscuit-auth 6.0.0).
        fn keypair(&self) -> KeyPair {
            KeyPair::from_private_key_pem(&self.pem).unwrap()
        }
    }

    impl RootKey for TestRoot {
        fn public_key(&self) -> PublicKey {
            self.pubk
        }
    }

    /// In-memory filesystem for path-check tests. `calls` counts every
    /// filesystem access so tests can assert the lexical `..` rejection
    /// happens *before* any fs access.
    enum Entry {
        Dir,
        File,
        Link(String),
    }

    struct FakeFs {
        entries: std::collections::HashMap<String, Entry>,
        calls: AtomicUsize,
    }

    impl FakeFs {
        fn new() -> Self {
            Self {
                entries: std::collections::HashMap::new(),
                calls: AtomicUsize::new(0),
            }
        }
        fn dir(&mut self, p: &str) {
            self.entries.insert(p.trim_start_matches('/').into(), Entry::Dir);
        }
        fn file(&mut self, p: &str) {
            self.entries.insert(p.trim_start_matches('/').into(), Entry::File);
        }
        fn link(&mut self, p: &str, target: &str) {
            self.entries.insert(p.trim_start_matches('/').into(), Entry::Link(target.into()));
        }
        fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }

        /// Symlink-resolving canonicalization over the fake tree.
        fn resolve(&self, path: &Path) -> Option<PathBuf> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let mut comps: Vec<String> = path
                .components()
                .skip(1)
                .map(|c| c.as_os_str().to_string_lossy().into_owned())
                .collect();
            let mut cur = String::new();
            let mut i = 0;
            while i < comps.len() {
                let next = if cur.is_empty() {
                    comps[i].clone()
                } else {
                    format!("{}/{}", cur, comps[i])
                };
                match self.entries.get(next.as_str()) {
                    None => return None,
                    Some(Entry::Link(target)) => {
                        // Replace the remainder with target + rest.
                        let target_comps: Vec<String> = target
                            .trim_start_matches('/')
                            .split('/')
                            .filter(|s| !s.is_empty())
                            .map(|s| s.to_string())
                            .collect();
                        let rest: Vec<String> = comps[i + 1..].to_vec();
                        let mut new_comps = target_comps;
                        new_comps.extend(rest);
                        cur = String::new();
                        comps = new_comps;
                        i = 0;
                        continue;
                    }
                    Some(Entry::Dir) | Some(Entry::File) => {
                        cur = next;
                        i += 1;
                    }
                }
            }
            if cur.is_empty() {
                // The root itself.
                Some(PathBuf::from("/"))
            } else {
                Some(PathBuf::from(format!("/{}", cur)))
            }
        }
    }

    /// Arc<FakeFs> behind the Fs trait (the Arc makes it Sync).
    struct ArcFs(Arc<FakeFs>);
    impl Fs for ArcFs {
        fn canonicalize(&self, path: &Path) -> Option<PathBuf> {
            self.0.resolve(path)
        }
        fn is_symlink(&self, path: &Path) -> bool {
            self.0.calls.fetch_add(1, Ordering::SeqCst);
            let key = path
                .components()
                .skip(1)
                .map(|c| c.as_os_str().to_string_lossy().into_owned())
                .collect::<Vec<_>>()
                .join("/");
            matches!(self.0.entries.get(key.as_str()), Some(Entry::Link(_)))
        }
    }

    fn control_plane() -> ControlPlanePaths {
        ControlPlanePaths {
            files: BTreeSet::from([
                PathBuf::from("/run/ramen.sock"),
                PathBuf::from("/var/ramen/audit.log"),
            ]),
            file_parents: BTreeSet::from([
                PathBuf::from("/run"),
                PathBuf::from("/var/ramen"),
            ]),
            state_dir: PathBuf::from("/var/ramen/state"),
        }
    }

    fn test_guard(fs: Arc<FakeFs>) -> (Guard, TestRoot) {
        let root = TestRoot::new();
        let guard =
            Guard::new(Box::new(root.clone()), control_plane(), Box::new(ArcFs(fs)));
        (guard, root)
    }

    fn mint(root: &TestRoot, code: &str) -> String {
        let token = BiscuitBuilder::new()
            .code(code)
            .unwrap()
            .build(&root.keypair())
            .unwrap();
        token.to_base64().unwrap()
    }


    fn file_write(path: &str) -> Operation {
        Operation::FileWrite(FileWriteOp {
            path: path.into(),
            content_b64: "aGVsbG8=".into(),
            mode: WriteMode::Overwrite,
        })
    }

    fn whoami() -> Operation {
        Operation::Whoami(WhoamiOp {})
    }

    fn req<'a>(token: &'a str, op: &'a Operation) -> AuthzRequest<'a> {
        AuthzRequest {
            token,
            op,
            now: now(),
        }
    }

    // ── Root defense (§9) ──────────────────────────────────────────────────

    #[test]
    fn token_from_different_root_is_denied() {
        let fs = FakeFs::new();
        let (guard, root) = test_guard(Arc::new(fs));
        let other = KeyPair::new_with_algorithm(Algorithm::Secp256r1);
        let other_root = TestRoot {
            pubk: other.public(),
            pem: other.to_private_key_pem().unwrap().to_string(),
        };
        let token = mint(&other_root, FULL_CODE);
        // The same token is accepted by a guard holding the other root...
        let guard2 = Guard::new(
            Box::new(other_root),
            ControlPlanePaths {
                files: BTreeSet::new(),
                file_parents: BTreeSet::new(),
                state_dir: PathBuf::from("/var/ramen/state"),
            },
            Box::new(StdFs),
        );
        assert_eq!(guard2.authorize(req(&token, &whoami())), Decision::Allow);
        // ...but denied by this guard: the guard's root wins.
        let d = guard.authorize(req(&token, &whoami()));
        assert_eq!(
            d,
            Decision::Deny {
                code: DenialCode::ConstraintViolated,
                reason: "token not issued by the root key".into(),
            }
        );
        let _ = root;
    }

    // ── Capability / reversibility ─────────────────────────────────────────

    #[test]
    fn whoami_with_capability_is_allowed() {
        let fs = FakeFs::new();
        let (guard, root) = test_guard(Arc::new(fs));
        let token = mint(&root, FULL_CODE);
        assert_eq!(guard.authorize(req(&token, &whoami())), Decision::Allow);
    }

    #[test]
    fn filewrite_with_capability_is_allowed() {
        let mut fs = FakeFs::new();
        fs.dir("/work");
        fs.file("/work/a.txt");
        let (guard, root) = test_guard(Arc::new(fs));
        let token = mint(&root, FULL_CODE);
        assert_eq!(
            guard.authorize(req(&token, &file_write("/work/a.txt"))),
            Decision::Allow
        );
    }

    #[test]
    fn token_without_filewrite_capability_denies_with_capability_not_granted() {
        let mut fs = FakeFs::new();
        fs.dir("/work");
        fs.file("/work/a.txt");
        let (guard, root) = test_guard(Arc::new(fs));
        let token = mint(
            &root,
            r#"
            identity("agent:x");
            capability("Whoami");
            allowed_prefix("FileWrite", "/work");
            reversibility_allowed("Trivial");
        "#,
        );
        assert_eq!(
            guard.authorize(req(&token, &file_write("/work/a.txt"))),
            Decision::Deny {
                code: DenialCode::CapabilityNotGranted,
                reason: "token grants no capability for `FileWrite`".into(),
            }
        );
    }

    #[test]
    fn token_without_whoami_capability_denies_with_capability_not_granted() {
        let fs = FakeFs::new();
        let (guard, root) = test_guard(Arc::new(fs));
        let token = mint(
            &root,
            r#"
            identity("agent:x");
            capability("FileWrite");
            allowed_prefix("FileWrite", "/work");
            reversibility_allowed("Trivial");
        "#,
        );
        assert_eq!(
            guard.authorize(req(&token, &whoami())),
            Decision::Deny {
                code: DenialCode::CapabilityNotGranted,
                reason: "token grants no capability for `Whoami`".into(),
            }
        );
    }

    #[test]
    fn reversibility_not_permitted_when_missing() {
        // FileWrite is Trivial; a token granting only Compensable denies it.
        let mut fs = FakeFs::new();
        fs.dir("/work");
        fs.file("/work/a.txt");
        let (guard, root) = test_guard(Arc::new(fs));
        let token = mint(
            &root,
            r#"
            identity("agent:x");
            capability("FileWrite");
            allowed_prefix("FileWrite", "/work");
            reversibility_allowed("Compensable");
        "#,
        );
        assert_eq!(
            guard.authorize(req(&token, &file_write("/work/a.txt"))),
            Decision::Deny {
                code: DenialCode::ReversibilityNotPermitted,
                reason: "operation `FileWrite` requires reversibility `Trivial`, not granted by the token"
                    .into(),
            }
        );
    }

    #[test]
    fn expired_token_denies_with_token_expired() {
        let fs = FakeFs::new();
        let (guard, root) = test_guard(Arc::new(fs));
        // Expiry 2025-06-01 (before our fixed "now" of 2025-06-15). The
        // token grants everything else, so only the date clause can be the
        // reason for the denial — that is what makes the far-past probe
        // classify it as expiry.
        let code = r#"
            identity("agent:x");
            capability("Whoami");
            reversibility_allowed("Trivial");
            check if date($d), $d < 2025-06-01T00:00:00Z;
        "#;
        let token = mint(&root, code);
        assert_eq!(
            guard.authorize(req(&token, &whoami())),
            Decision::Deny {
                code: DenialCode::TokenExpired,
                reason: "token is expired".into(),
            }
        );
    }

    #[test]
    fn unexpired_check_clause_allows() {
        let fs = FakeFs::new();
        let (guard, root) = test_guard(Arc::new(fs));
        // Expiry 2030-01-01 (after our fixed "now").
        let code = r#"
            identity("agent:x");
            capability("Whoami");
            reversibility_allowed("Trivial");
            check if date($d), $d < 2030-01-01T00:00:00Z;
        "#;
        let token = mint(&root, code);
        assert_eq!(guard.authorize(req(&token, &whoami())), Decision::Allow);
    }

    #[test]
    fn failing_non_date_check_clause_is_constraint_violated() {
        let fs = FakeFs::new();
        let (guard, root) = test_guard(Arc::new(fs));
        // A check clause that fails for a reason unrelated to the clock.
        let code = r#"
            identity("agent:x");
            capability("Whoami");
            reversibility_allowed("Trivial");
            check if scope("no-such-scope");
        "#;
        let token = mint(&root, code);
        assert_eq!(
            guard.authorize(req(&token, &whoami())),
            Decision::Deny {
                code: DenialCode::ConstraintViolated,
                reason: "token constraint not satisfied".into(),
            }
        );
    }

    #[test]
    fn expiry_boundary_minus_1_at_plus_1() {
        // The token is valid until T=1_750_000_000 (our fixed "now").
        let fs = FakeFs::new();
        let (guard, root) = test_guard(Arc::new(fs));
        let code = r#"
            identity("agent:x");
            capability("Whoami");
            reversibility_allowed("Trivial");
            check if date($d), $d < 2025-06-15T15:06:40Z;
        "#;
        let token = mint(&root, code);
        let t = |s: u64| UNIX_EPOCH + Duration::from_secs(s);
        // At T-1 it is allowed.
        let op = whoami();
        assert_eq!(
            guard.authorize(AuthzRequest {
                token: &token,
                op: &op,
                now: t(1_750_000_000 - 1),
            }),
            Decision::Allow
        );
        // At T+1 the check clause fails; the far-past probe re-allows it, so
        // the denial classifies as TokenExpired.
        assert_eq!(
            guard.authorize(AuthzRequest {
                token: &token,
                op: &op,
                now: t(1_750_000_000 + 1),
            }),
            Decision::Deny {
                code: DenialCode::TokenExpired,
                reason: "token is expired".into(),
            }
        );
    }

    // ── Prefix semantics (§7 step 4, component-wise) ───────────────────────

    #[test]
    fn prefix_component_wise_not_raw_starts_with() {
        let mut fs = FakeFs::new();
        fs.dir("/work");
        fs.dir("/workx");
        fs.file("/workx/a.txt");
        let (guard, root) = test_guard(Arc::new(fs));
        let token = mint(&root, FULL_CODE); // prefix "/work"
        assert_eq!(
            guard.authorize(req(&token, &file_write("/workx/a.txt"))),
            Decision::Deny {
                code: DenialCode::ConstraintViolated,
                reason: "target path is outside every allowed prefix".into(),
            }
        );
    }

    #[test]
    fn prefix_exact_and_subpath_allowed() {
        let mut fs = FakeFs::new();
        fs.dir("/work");
        fs.dir("/work/deep");
        fs.file("/work/deep/a.txt");
        let (guard, root) = test_guard(Arc::new(fs));
        let token = mint(&root, FULL_CODE); // prefix "/work"
        assert_eq!(
            guard.authorize(req(&token, &file_write("/work/deep/a.txt"))),
            Decision::Allow
        );
    }

    #[test]
    fn no_prefix_fact_denies_filewrite() {
        let mut fs = FakeFs::new();
        fs.dir("/work");
        fs.file("/work/a.txt");
        let (guard, root) = test_guard(Arc::new(fs));
        let token = mint(
            &root,
            r#"
            identity("agent:x");
            capability("FileWrite");
            reversibility_allowed("Trivial");
        "#,
        );
        assert_eq!(
            guard.authorize(req(&token, &file_write("/work/a.txt"))),
            Decision::Deny {
                code: DenialCode::ConstraintViolated,
                reason: "target path is outside every allowed prefix".into(),
            }
        );
    }

    // ── Path checks (§6, §7) ────────────────────────────────────────────────

    #[test]
    fn relative_path_denied() {
        let fs = FakeFs::new();
        let (guard, root) = test_guard(Arc::new(fs));
        let token = mint(&root, FULL_CODE);
        assert_eq!(
            guard.authorize(req(&token, &file_write("relative.txt"))),
            Decision::Deny {
                code: DenialCode::ConstraintViolated,
                reason: "path must be absolute".into(),
            }
        );
    }

    #[test]
    fn dotdot_denied_lexically_before_any_fs_access() {
        let mut fs = FakeFs::new();
        fs.dir("/work");
        let fs = std::sync::Arc::new(fs);
        let (guard, root) = test_guard(fs.clone());
        let token = mint(&root, FULL_CODE);
        assert_eq!(
            guard.authorize(req(&token, &file_write("/work/../etc/passwd"))),
            Decision::Deny {
                code: DenialCode::ConstraintViolated,
                reason: "path must not contain a '..' component".into(),
            }
        );
        // The rejection is lexical: no filesystem access happened.
        assert_eq!(fs.calls(), 0);
    }

    #[test]
    fn parent_missing_denied() {
        let fs = FakeFs::new();
        // /work does not exist.
        let (guard, root) = test_guard(Arc::new(fs));
        let token = mint(&root, FULL_CODE);
        assert_eq!(
            guard.authorize(req(&token, &file_write("/work/a.txt"))),
            Decision::Deny {
                code: DenialCode::ConstraintViolated,
                reason: "path does not exist".into(),
            }
        );
    }

    #[test]
    fn symlink_as_final_component_denied() {
        let mut fs = FakeFs::new();
        fs.dir("/work");
        fs.file("/work/real.txt");
        fs.link("/work/link.txt", "/work/real.txt");
        let (guard, root) = test_guard(Arc::new(fs));
        let token = mint(&root, FULL_CODE);
        assert_eq!(
            guard.authorize(req(&token, &file_write("/work/link.txt"))),
            Decision::Deny {
                code: DenialCode::ConstraintViolated,
                reason: "final path component is a symlink".into(),
            }
        );
    }

    #[test]
    fn control_plane_files_parents_and_state_are_protected() {
        let mut fs = FakeFs::new();
        fs.dir("/run");
        fs.file("/run/ramen.sock");
        fs.dir("/var");
        fs.dir("/var/ramen");
        fs.dir("/var/ramen/state");
        fs.file("/var/ramen/state/x");
        let (guard, root) = test_guard(Arc::new(fs));
        let token = mint(
            &root,
            r#"
            identity("agent:x");
            capability("FileWrite");
            allowed_prefix("FileWrite", "/run");
            allowed_prefix("FileWrite", "/var/ramen");
            allowed_prefix("FileWrite", "/var/ramen/state");
            reversibility_allowed("Trivial");
        "#,
        );
        // Even with prefixes covering the control plane, it is protected:
        // the exact file path, the exact containing directory, and the
        // state_dir subtree.
        assert_eq!(
            guard.authorize(req(&token, &file_write("/run/ramen.sock"))),
            Decision::Deny {
                code: DenialCode::ControlPlaneProtected,
                reason: "target is control-plane state".into(),
            }
        );
        assert_eq!(
            guard.authorize(req(&token, &file_write("/run"))),
            Decision::Deny {
                code: DenialCode::ControlPlaneProtected,
                reason: "target is control-plane state".into(),
            }
        );
        assert_eq!(
            guard.authorize(req(&token, &file_write("/var/ramen/state/x"))),
            Decision::Deny {
                code: DenialCode::ControlPlaneProtected,
                reason: "target is control-plane state".into(),
            }
        );
    }

    #[test]
    fn symlinked_parent_resolving_outside_prefix_denied() {
        // A symlinked parent directory resolving outside every prefix is
        // denied by the component-wise prefix check on the canonical target.
        let mut fs = FakeFs::new();
        fs.dir("/work");
        fs.dir("/elsewhere");
        fs.file("/elsewhere/a.txt");
        fs.link("/work/esc", "/elsewhere");
        let (guard, root) = test_guard(Arc::new(fs));
        let token = mint(&root, FULL_CODE); // prefix "/work"
        assert_eq!(
            guard.authorize(req(&token, &file_write("/work/esc/a.txt"))),
            Decision::Deny {
                code: DenialCode::ConstraintViolated,
                reason: "target path is outside every allowed prefix".into(),
            }
        );
    }

    #[test]
    fn symlink_to_control_plane_state_is_protected() {
        let mut fs = FakeFs::new();
        fs.dir("/work");
        fs.dir("/var");
        fs.dir("/var/ramen");
        fs.dir("/var/ramen/state");
        fs.file("/var/ramen/state/audit.log");
        fs.link("/work/evil", "/var/ramen/state");
        let (guard, root) = test_guard(Arc::new(fs));
        let token = mint(&root, FULL_CODE);
        assert_eq!(
            guard.authorize(req(&token, &file_write("/work/evil/audit.log"))),
            Decision::Deny {
                code: DenialCode::ControlPlaneProtected,
                reason: "target is control-plane state".into(),
            }
        );
    }

    // ── Structural guarantees (§9, §10) ─────────────────────────────────────

    #[test]
    fn sequential_requests_use_distinct_authorizers() {
        // The guarantee is structural (a fresh Authorizer per call), but a
        // regression that reused a stale authorizer would show up as state
        // leaking between requests — repeated decisions must stay
        // consistent, interleaved with denials.
        let mut fs = FakeFs::new();
        fs.dir("/work");
        fs.file("/work/a.txt");
        let (guard, root) = test_guard(Arc::new(fs));
        let token = mint(&root, FULL_CODE);
        let other = mint(
            &root,
            r#"
            identity("agent:x");
            capability("Whoami");
            reversibility_allowed("Trivial");
        "#,
        );
        for _ in 0..5 {
            assert_eq!(
                guard.authorize(req(&token, &file_write("/work/a.txt"))),
                Decision::Allow
            );
            // A denied op interleaved in between does not change the outcome.
            assert!(matches!(
                guard.authorize(req(&other, &file_write("/work/a.txt"))),
                Decision::Deny { .. }
            ));
        }
    }

    #[test]
    fn attenuation_removal_is_real() {
        // Attenuation can only *add* facts; a capability the base token
        // lacks cannot appear later. Model the "narrowed" token directly and
        // verify the guard classifies the missing capability — the
        // append-with-different-key path is covered by
        // `attenuation_appended_block_is_accepted_when_root_ok`.
        let mut fs = FakeFs::new();
        fs.dir("/work");
        fs.file("/work/a.txt");
        let (guard, root) = test_guard(Arc::new(fs));
        let no_filewrite = mint(
            &root,
            r#"
            identity("agent:planner");
            capability("Whoami");
            reversibility_allowed("Trivial");
        "#,
        );
        assert_eq!(
            guard.authorize(req(&no_filewrite, &whoami())),
            Decision::Allow
        );
        assert_eq!(
            guard.authorize(req(&no_filewrite, &file_write("/work/a.txt"))),
            Decision::Deny {
                code: DenialCode::CapabilityNotGranted,
                reason: "token grants no capability for `FileWrite`".into(),
            }
        );
    }

    #[test]
    fn attenuation_check_clause_is_enforced_by_guard() {
        // The attenuator appends a check clause narrowing the token to
        // FileWrite only. The token still verifies against the root, and the
        // guard enforces the appended check: Whoami is denied, FileWrite is
        // allowed.
        let mut fs = FakeFs::new();
        fs.dir("/work");
        fs.file("/work/a.txt");
        let (guard, root) = test_guard(std::sync::Arc::new(fs));
        let base = mint(
            &root,
            r#"
            identity("agent:planner");
            capability("Whoami");
            capability("FileWrite");
            allowed_prefix("FileWrite", "/work");
            reversibility_allowed("Trivial");
        "#,
        );
        let unv = UnverifiedBiscuit::from_base64(base.as_bytes()).unwrap();
        let kp = KeyPair::new_with_algorithm(Algorithm::Secp256r1);
        let block = BlockBuilder::new()
            .code(r#"check if operation($op), $op == "FileWrite";"#)
            .unwrap();
        let attenuated = unv
            .append_with_keypair(&kp, block)
            .unwrap()
            .verify(|_k| Ok(root.pubk))
            .unwrap()
            .to_base64()
            .unwrap();
        // The narrowing check is enforced by the guard.
        assert!(matches!(
            guard.authorize(req(&attenuated, &whoami())),
            Decision::Deny {
                code: DenialCode::ConstraintViolated,
                ..
            }
        ));
        assert_eq!(
            guard.authorize(req(&attenuated, &file_write("/work/a.txt"))),
            Decision::Allow
        );
    }

    #[test]
    fn appended_block_cannot_grant_new_capability() {
        // The trust boundary: the guard's policy trusts only the authority
        // (root) block for granting facts. An attenuator adding a capability
        // fact in its own block cannot expand permissions — the operation is
        // denied with CapabilityNotGranted.
        let mut fs = FakeFs::new();
        fs.dir("/work");
        fs.file("/work/a.txt");
        let (guard, root) = test_guard(std::sync::Arc::new(fs));
        let base = mint(
            &root,
            r#"
            identity("agent:planner");
            capability("Whoami");
            reversibility_allowed("Trivial");
        "#,
        );
        let unv = UnverifiedBiscuit::from_base64(base.as_bytes()).unwrap();
        let kp = KeyPair::new_with_algorithm(Algorithm::Secp256r1);
        let block = BlockBuilder::new()
            .code(
                r#"
                capability("FileWrite");
                allowed_prefix("FileWrite", "/work");
                reversibility_allowed("Trivial");
            "#,
            )
            .unwrap();
        let token = unv
            .append_with_keypair(&kp, block)
            .unwrap()
            .verify(|_k| Ok(root.pubk))
            .unwrap()
            .to_base64()
            .unwrap();
        assert_eq!(
            guard.authorize(req(&token, &file_write("/work/a.txt"))),
            Decision::Deny {
                code: DenialCode::CapabilityNotGranted,
                reason: "token grants no capability for `FileWrite`".into(),
            }
        );
        // ...while the root-granted capability still works.
        assert_eq!(guard.authorize(req(&token, &whoami())), Decision::Allow);
    }

    #[test]
    fn corrupted_token_is_denied_not_panicked() {
        // Fuzz-style: truncation and byte flips on the base64 must yield a
        // denial (root defense or malformed), never a panic.
        let mut fs = FakeFs::new();
        fs.dir("/work");
        fs.file("/work/a.txt");
        let (guard, root) = test_guard(Arc::new(fs));
        let token = mint(&root, FULL_CODE);
        let op = file_write("/work/a.txt");

        // Truncation at every prefix length.
        for n in 1..token.len() {
            let _ = guard.authorize(req(&token[..n], &op));
        }
        // Single-byte flips.
        let bytes: Vec<u8> = token.bytes().collect();
        for i in 0..bytes.len() {
            let mut b = bytes.clone();
            b[i] ^= 0x01;
            let s = String::from_utf8_lossy(&b).into_owned();
            let _ = guard.authorize(req(&s, &op));
        }
    }

    #[test]
    fn path_with_quotes_and_backslashes_round_trips() {
        // A path containing quotes and backslashes must be escaped for
        // datalog interpolation and still reach the authorizer intact.
        let mut fs = FakeFs::new();
        fs.dir("/work");
        fs.file("/work/a\"b\\c.md");
        let (guard, root) = test_guard(Arc::new(fs));
        let token = mint(&root, FULL_CODE);
        // Without datalog escaping this would be a parse failure; with it,
        // the canonical path reaches the authorizer intact.
        assert_eq!(
            guard.authorize(req(&token, &file_write("/work/a\"b\\c.md"))),
            Decision::Allow
        );
    }

    #[test]
    fn describe_capabilities_lists_token_facts() {
        let fs = FakeFs::new();
        let (guard, root) = test_guard(Arc::new(fs));
        let token = mint(&root, FULL_CODE);
        let caps = guard.describe_capabilities(&token);
        let names: BTreeSet<String> = caps.iter().map(|c| c.op.clone()).collect();
        assert_eq!(
            names,
            BTreeSet::from(["Whoami".to_string(), "FileWrite".to_string()])
        );
        let fw = caps.iter().find(|c| c.op == "FileWrite").unwrap();
        assert_eq!(
            fw.constraints,
            Some(Constraints {
                path_prefix: vec!["/work".into()]
            })
        );
        let w = caps.iter().find(|c| c.op == "Whoami").unwrap();
        assert_eq!(w.constraints, None);
        // Reversibility comes from the operation type, not the token.
        assert_eq!(fw.reversibility, Reversibility::Trivial);
    }

    #[test]
    fn describe_capabilities_of_garbage_is_empty_not_error() {
        let fs = FakeFs::new();
        let (guard, _) = test_guard(Arc::new(fs));
        assert!(guard.describe_capabilities("!!!not-base64!!!").is_empty());
    }

    // ── `token_expires_at` (M5, `05-operations.md`) ────────────────────

    #[test]
    fn token_expires_at_reports_the_declared_fact() {
        let fs = FakeFs::new();
        let (guard, root) = test_guard(Arc::new(fs));
        let code = "\n        identity(\"agent:planner\");
        capability(\"Whoami\");
        expires_at(2026-08-31T00:00:00Z);
    ";
        let token = mint(&root, code);
        assert_eq!(
            guard.token_expires_at(&token),
            Some("2026-08-31T00:00:00Z".to_string())
        );
    }

    #[test]
    fn token_expires_at_absent_fact_is_none() {
        let fs = FakeFs::new();
        let (guard, root) = test_guard(Arc::new(fs));
        let token = mint(&root, FULL_CODE); // no `expires_at` fact
        assert_eq!(guard.token_expires_at(&token), None);
    }

    #[test]
    fn token_expires_at_of_foreign_token_is_none() {
        let fs = FakeFs::new();
        let (guard, _) = test_guard(Arc::new(fs));
        let other = KeyPair::new_with_algorithm(Algorithm::Secp256r1);
        let other_root = TestRoot {
            pubk: other.public(),
            pem: other.to_private_key_pem().unwrap().to_string(),
        };
        let code = "\n        identity(\"agent:evil\");
        expires_at(2026-08-31T00:00:00Z);
    ";
        let token = mint(&other_root, code);
        assert_eq!(guard.token_expires_at(&token), None);
    }

    #[test]
    fn iso8601_formatting_matches_known_values() {
        fn at(secs: u64) -> String {
            format_iso8601_utc(UNIX_EPOCH + Duration::from_secs(secs))
        }
        assert_eq!(at(0), "1970-01-01T00:00:00Z");
        assert_eq!(at(86_399), "1970-01-01T23:59:59Z");
        // The fixed "now" of this test module: 2025-06-15T15:06:40Z.
        assert_eq!(at(1_750_000_000), "2025-06-15T15:06:40Z");
        assert_eq!(at(1_788_134_400), "2026-08-31T00:00:00Z");
        // A leap-day boundary: 2024-02-29T12:30:45Z.
        assert_eq!(at(1_709_209_845), "2024-02-29T12:30:45Z");
    }

    // ── RootKey: the P-256 curve assertion (§3) ─────────────────────────────

    #[test]
    fn file_root_key_rejects_ed25519() {
        let dir = tempfile::tempdir().unwrap();
        let ed = KeyPair::new_with_algorithm(Algorithm::Ed25519);
        let path = dir.path().join("root.pub");
        std::fs::write(&path, ed.public().to_pem().unwrap()).unwrap();
        let err = crate::rootkey::FileRootKey::load(&path).unwrap_err();
        match &err {
            crate::rootkey::GuardError::NotP256 { .. } => {}
            other => panic!("expected NotP256, got {other:?}"),
        }
    }

    #[test]
    fn file_root_key_loads_p256() {
        let dir = tempfile::tempdir().unwrap();
        let kp = KeyPair::new_with_algorithm(Algorithm::Secp256r1);
        let path = dir.path().join("root.pub");
        std::fs::write(&path, kp.public().to_pem().unwrap()).unwrap();
        let loaded = crate::rootkey::FileRootKey::load(&path).unwrap();
        assert_eq!(loaded.public_key(), kp.public());
    }
}
