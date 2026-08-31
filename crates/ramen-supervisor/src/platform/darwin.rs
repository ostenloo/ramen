//! macOS platform implementation: peer identity via `LOCAL_PEERTOKEN` and
//! Security.framework code signing.
//!
//! This is the **only** module in the crate allowed to use `unsafe`.
//! Everything it does maps 1:1 to a documented system call or Security
//! framework C function:
//!
//! - `getsockopt(fd, SOL_LOCAL, LOCAL_PEERTOKEN, ...)` — the kernel audit
//!   token of the connected peer (sys/un.h). Assigned by the kernel at
//!   connection time; a peer cannot choose or forge it.
//! - `getsockopt(fd, SOL_LOCAL, LOCAL_PEERPID, ...)` — peer PID (sys/un.h),
//!   diagnostics only.
//! - `SecCodeCopyGuestWithAttributes(kSecGuestAttributeAudit, token)` —
//!   resolve the audit token to the peer's `SecCode` guest (SecCode.h).
//! - `SecCodeCheckValidity(code, flags, requirement)` — evaluate the
//!   configured requirement against the peer's code (SecCode.h).
//! - `SecCodeCopySigningInformation(code, flags, &dict)` — extract the
//!   signing identifier and cdhash for the audit trail (SecCode.h).
//!
//! **Note on cdhash pinning** (empirically verified on macOS 26): the
//! requirement-language `cdhash` term only accepts 20-byte (SHA-1) hashes
//! and does **not** match binaries signed with SHA-256, which is what all
//! modern ad-hoc signatures use. CI therefore pins the peer with an
//! `identifier "..."` requirement; the cdhash (truncated SHA-256, from
//! `kSecCodeInfoUnique`) is still extracted and recorded in the audit
//! trail as a content-unique reference.

// Sole `unsafe` module of the crate (crate root is `deny(unsafe_code)`).
// Every `unsafe` block wraps a single system call or Security framework
// C function; see the module docs for the 1:1 mapping.
#![allow(unsafe_code)]

use std::ffi::c_void;

use core_foundation::base::{CFType, TCFType};
use core_foundation::data::CFData;
use core_foundation::dictionary::CFDictionary;
use core_foundation::string::CFString;
use security_framework::os::macos::code_signing::{
    Flags, GuestAttributes, SecCode, SecRequirement,
};

use super::{IdentityError, PeerIdentity, SigningInfo};

// --- sys/un.h constants ---------------------------------------------------

/// `SOL_LOCAL` (0): protocol level for local (Unix-domain) socket options.
const SOL_LOCAL: i32 = 0;
/// `LOCAL_PEERPID` (2): peer process ID.
const LOCAL_PEERPID: i32 = 0x002;
/// `LOCAL_PEERTOKEN` (6): the peer's kernel **audit token** (32 bytes on
/// macOS), per sys/un.h.
const LOCAL_PEERTOKEN: i32 = 0x006;

/// Size of an `audit_token_t` on macOS (8 × int32).
const AUDIT_TOKEN_LEN: u32 = 32;

// --- SecCode.h -------------------------------------------------------------

/// `kSecCSDefaultFlags` (0): the generic set of signing-info entries, which
/// always includes the identifier (if signed) and the unique cdhash.
///
/// Passing an invalid flag combination (e.g. 0xFFFFFFFF) makes
/// `SecCodeCopySigningInformation` fail with -67070.
const K_SEC_CS_DEFAULT_FLAGS: u32 = 0;

/// `kSecCodeInfoIdentifier`: the signing identifier (CFString).
const KEY_IDENTIFIER: &str = "identifier";
/// `kSecCodeInfoUnique`: the code's unique cdhash (CFData; 20 bytes for
/// SHA-256-signed code: the first 20 bytes of the SHA-256 code-directory
/// hash).
const KEY_UNIQUE: &str = "unique";

extern "C" {
    /// Security framework: `SecCodeCopySigningInformation` (not wrapped by
    /// the `security-framework` crate as of 2.11).
    ///
    /// `flags` must be `kSecCSDefaultFlags` (0) or a subset of the
    /// `kSecCS*Information` flags (1 << 0 .. 1 << 4).
    fn SecCodeCopySigningInformation(
        code: *const c_void,
        flags: u32,
        information: *mut *mut c_void,
    ) -> i32;
}

/// Extract a CFString value from a CFDictionary by key name.
fn dict_string(dict: &CFDictionary, key: &str) -> Option<String> {
    let k = CFString::new(key);
    let item = dict.find(k.as_CFTypeRef())?;
    let t = unsafe { CFType::wrap_under_get_rule(*item) };
    let s = t.downcast::<CFString>()?;
    Some(std::borrow::Cow::<str>::from(&s).into_owned())
}

/// Extract a CFData value from a CFDictionary by key name.
fn dict_data(dict: &CFDictionary, key: &str) -> Option<Vec<u8>> {
    let k = CFString::new(key);
    let item = dict.find(k.as_CFTypeRef())?;
    let t = unsafe { CFType::wrap_under_get_rule(*item) };
    let d = t.downcast::<CFData>()?;
    Some(d.bytes().to_vec())
}

/// The effective user id of this process (used by config/socket checks to
/// verify file ownership). Lives here so the `libc` FFI stays inside the
/// crate's single `unsafe` module.
pub fn geteuid() -> u32 {
    unsafe { libc::geteuid() }
}

/// The filesystem type name of the filesystem containing `path`
/// (`statfs(2)` → `f_fstypename`; e.g. `"apfs"`, `"apfs"`, `"udf"`).
pub fn fs_type(path: &std::path::Path) -> std::io::Result<String> {
    let cpath = to_cstring(path)?;
    let mut buf: libc::statfs = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::statfs(cpath.as_ptr(), &mut buf) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let name = unsafe { std::ffi::CStr::from_ptr(buf.f_fstypename.as_ptr()) };
    name.to_str()
        .map(|s| s.to_string())
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}

/// The device id (`st_dev`) of the filesystem containing `path`
/// (`stat(2)`). Used to verify that two paths share a volume
/// (`clonefile(2)` does not cross volumes).
pub fn device_id(path: &std::path::Path) -> std::io::Result<u64> {
    let cpath = to_cstring(path)?;
    let mut buf: libc::stat = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::stat(cpath.as_ptr(), &mut buf) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(buf.st_dev as u64)
}

/// `clonefile(2)` — an APFS copy-on-write clone of `src` to `dst`.
///
/// `dst` must not exist. Used for the pre-write snapshot
/// (`05-operations.md` M6 step 4); CoW makes it effectively free
/// regardless of file size.
pub fn clonefile(src: &std::path::Path, dst: &std::path::Path) -> std::io::Result<()> {
    let src_c = to_cstring(src)?;
    let dst_c = to_cstring(dst)?;
    let rc = unsafe { libc::clonefile(src_c.as_ptr(), dst_c.as_ptr(), 0) };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

fn to_cstring(p: &std::path::Path) -> std::io::Result<std::ffi::CString> {
    use std::os::unix::ffi::OsStrExt;
    std::ffi::CString::new(p.as_os_str().as_bytes())
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))
}

/// Query the kernel for the peer's audit token, resolve it to a `SecCode`
/// guest, and evaluate the requirement against the peer's code.
///
/// Fail-closed: if the kernel does not provide a token, or the peer has no
/// code signature, this returns `Err`. There is no PID fallback — PIDs are
/// recycled and attacker-controllable; the audit token is not.
pub fn identify(fd: i32, requirement: &SecRequirement) -> Result<PeerIdentity, IdentityError> {
    // --- get the peer's audit token via LOCAL_PEERTOKEN ---
    let mut token = [0u8; AUDIT_TOKEN_LEN as usize];
    let mut len = AUDIT_TOKEN_LEN;
    let rc = unsafe {
        libc::getsockopt(
            fd,
            SOL_LOCAL,
            LOCAL_PEERTOKEN,
            &mut token as *mut _ as *mut c_void,
            &mut len as *mut u32,
        )
    };
    if rc != 0 || len != AUDIT_TOKEN_LEN {
        return Err(IdentityError::NoPeerCode {
            reason: if rc == 0 {
                format!("unexpected audit token length {len}")
            } else {
                format!(
                    "getsockopt(LOCAL_PEERTOKEN) fd={fd} rc={rc} len={len}: {}",
                    std::io::Error::last_os_error()
                )
            },
        });
    }

    // --- get the peer PID via LOCAL_PEERPID (record-building only) ---
    // The pid is never used for an identity decision (the decision is the
    // requirement check against the LOCAL_PEERTOKEN-derived code guest);
    // it populates the audit record and the rate-limit key. If the kernel
    // does not provide it, degrade to 0 rather than reject.
    let mut pid: i32 = 0;
    let mut pid_len = std::mem::size_of::<i32>() as u32;
    let _rc = unsafe {
        libc::getsockopt(
            fd,
            SOL_LOCAL,
            LOCAL_PEERPID,
            &mut pid as *mut _ as *mut c_void,
            &mut pid_len as *mut u32,
        )
    };
    let pid = if _rc == 0 { pid } else { 0 };

    // --- resolve the audit token to the peer's code guest ---
    let cfdata = CFData::from_buffer(&token);
    let mut attrs = GuestAttributes::new();
    attrs.set_audit_token(cfdata.as_CFTypeRef() as _);
    let code = SecCode::copy_guest_with_attribues(None, &attrs, Flags::NONE).map_err(|e| {
        IdentityError::NoPeerCode {
            reason: format!("could not resolve audit token to code: {e}"),
        }
    })?;

    // --- evaluate the requirement against the peer's code ---
    let verified = code.check_validity(Flags::NONE, requirement).is_ok();

    // --- extract signing identifier and cdhash for the audit trail ---
    let (signing_id, cdhash) = signing_info_from_code(code.as_CFTypeRef());

    Ok(PeerIdentity {
        pid,
        signing_id,
        cdhash,
        verified,
    })
}

/// Extract `identifier` and `unique` (cdhash) from a code object. Returns
/// `(None, None)` for unsigned code.
fn signing_info_from_code(code: core_foundation::base::CFTypeRef) -> (Option<String>, Option<String>) {
    let mut dict_ptr: *mut c_void = std::ptr::null_mut();
    let status = unsafe {
        SecCodeCopySigningInformation(code, K_SEC_CS_DEFAULT_FLAGS, &mut dict_ptr)
    };
    if status != 0 || dict_ptr.is_null() {
        return (None, None);
    }
    let dict: CFDictionary = unsafe { CFDictionary::wrap_under_create_rule(dict_ptr as _) };
    let signing_id = dict_string(&dict, KEY_IDENTIFIER);
    let cdhash = dict_data(&dict, KEY_UNIQUE).map(|b| hex(&b));
    (signing_id, cdhash)
}

/// Query the signing identifier and cdhash for a path on disk, via
/// `SecStaticCode`. Used by tests and tooling; the connection path uses
/// `identify` on the live guest.
pub fn signing_info_for_path(path: &std::path::Path) -> Result<SigningInfo, IdentityError> {
    use core_foundation::url::CFURL;
    use security_framework::os::macos::code_signing::SecStaticCode;

    let url = CFURL::from_path(path, false)
        .ok_or_else(|| IdentityError::NoCode { reason: "not a valid path".into() })?;
    let static_code = SecStaticCode::from_path(&url, Flags::NONE)
        .map_err(|e| IdentityError::NoCode { reason: e.to_string() })?;

    let mut dict_ptr: *mut c_void = std::ptr::null_mut();
    let status = unsafe {
        SecCodeCopySigningInformation(
            static_code.as_CFTypeRef(),
            K_SEC_CS_DEFAULT_FLAGS,
            &mut dict_ptr,
        )
    };
    if status != 0 || dict_ptr.is_null() {
        return Err(IdentityError::NoCode {
            reason: if status == 0 {
                "unsigned code".into()
            } else {
                format!("OSStatus {status}")
            },
        });
    }

    let dict: CFDictionary = unsafe { CFDictionary::wrap_under_create_rule(dict_ptr as _) };
    let signing_id = dict_string(&dict, KEY_IDENTIFIER)
        .ok_or_else(|| IdentityError::NoCode { reason: "unsigned code".into() })?;
    let cdhash = dict_data(&dict, KEY_UNIQUE).map(|b| hex(&b));

    Ok(SigningInfo { signing_id: Some(signing_id), cdhash })
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsRawFd;
    use std::os::unix::net::{UnixListener, UnixStream};

    /// A connected peer (this process) must be identifiable: the kernel
    /// provides an audit token, the test binary is ad-hoc signed (verified
    /// against `codesign -dv`), so the identifier requirement must succeed
    /// and a wrong identifier must fail closed.
    #[test]
    fn self_identification_matches_codesign() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("test.sock");
        let listener = UnixListener::bind(&sock).unwrap();

        // The peer must stay alive for the duration of the test (the kernel
        // audit token is valid only while the peer process is connected).
        let _peer = UnixStream::connect(&sock).unwrap();
        let server = listener.accept().unwrap().0;

        let fd = server.as_raw_fd();

        // Independent ground truth: `codesign -dv` on the test binary.
        let exe = std::env::current_exe().unwrap();
        let out = std::process::Command::new("codesign")
            .args(["-dv", "--verbose=4"])
            .arg(&exe)
            .output()
            .unwrap();
        let codesign_output = String::from_utf8_lossy(&out.stderr).to_string();
        let expected_id = codesign_output
            .lines()
            .find_map(|l| l.strip_prefix("Identifier="))
            .expect("codesign did not report an identifier");

        let info = signing_info_for_path(&exe).unwrap();
        assert_eq!(info.signing_id.as_deref(), Some(expected_id), "framework identifier differs from codesign");
        assert_eq!(info.cdhash.as_ref().map(|h| h.len()), Some(40), "cdhash must be 20 bytes");

        // Full connection path: requirement = identifier pin (the form that
        // works for SHA-256 ad-hoc signatures; `cdhash` requirements do not
        // match SHA-256-signed code on macOS 26 — see module docs).
        let req: SecRequirement = format!("identifier \"{expected_id}\"").parse().unwrap();
        let id = identify(fd, &req).unwrap();
        assert!(
            id.verified,
            "own ad-hoc signed binary must satisfy its identifier requirement"
        );
        assert_eq!(id.signing_id.as_deref(), Some(expected_id));

        // A wrong identifier must fail closed.
        let bad: SecRequirement = "identifier \"definitely-not-the-right-id\"".parse().unwrap();
        let id2 = identify(fd, &bad).unwrap();
        assert!(!id2.verified, "wrong identifier must fail");
    }

    /// `signing_info_for_path` on the test binary (which the linker
    /// ad-hoc signs) must return a non-empty identifier and a 40-hex-digit
    /// cdhash.
    #[test]
    fn signing_info_for_self_binary() {
        let exe = std::env::current_exe().unwrap();
        let info = signing_info_for_path(&exe).unwrap();
        let id = info.signing_id.expect("ad-hoc signed binary must have an identifier");
        assert!(!id.is_empty());
        let cdhash = info.cdhash.expect("ad-hoc signed binary must have a cdhash");
        assert_eq!(cdhash.len(), 40);
        assert!(cdhash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    /// `03-supervisor.md` §7 (CI grep): `LOCAL_PEERPID` must not appear in
    /// any conditional expression — it is used only in the record-building
    /// path (populating the audit pid / rate-limit key). Identity decisions
    /// use `LOCAL_PEERTOKEN` exclusively.
    ///
    /// The search token is built from two string literals so that this
    /// test's own source lines (which contain the check) are not flagged.
    #[test]
    fn local_peercid_never_appears_in_a_decision() {
        let token = concat!("LOCAL_PEER", "PID");
        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut files = Vec::new();
        collect_rs_files(&src, &mut files);
        assert!(!files.is_empty(), "no source files found under {src:?}");
        for file in &files {
            let text = std::fs::read_to_string(file).unwrap();
            for (i, line) in text.lines().enumerate() {
                let is_conditional = line.contains("if ")
                    || line.contains("match ")
                    || line.contains("while ");
                if line.contains(token) && is_conditional {
                    panic!(
                        "{}:{}: LOCAL_PEERPID appears in a conditional expression: {}",
                        file.display(),
                        i + 1,
                        line.trim()
                    );
                }
            }
        }
    }

    fn collect_rs_files(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                collect_rs_files(&path, out);
            } else if path.extension().is_some_and(|e| e == "rs") {
                out.push(path);
            }
        }
    }
}
