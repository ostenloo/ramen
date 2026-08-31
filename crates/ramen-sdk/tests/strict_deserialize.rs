//! Mechanical closed-set strictness check (cross-implementation):
//!
//! A corpus case pins one input; this test pins the *class*. Every type the
//! wire parser deserializes must reject unknown fields, except where there
//! are no fields to reject or the strictness lives one level down:
//!
//! - a fieldless enum needs nothing — an unknown *variant* is already an
//!   error under enum semantics (`DenialCode`, `ErrorCode`, ...);
//! - an untagged enum's variant structs carry the attribute
//!   (`OkResultShape` → `WhoamiResultShape` / `FileWriteResultShape`);
//! - a transparent newtype's inner type decides (`RequestId`).
//!
//! This is the permanent answer to "is `Denial` the last one?": a new wire
//! type added without `deny_unknown_fields` fails this test in the crate it
//! was added to, and a removed attribute fails it too. The sibling test in
//! `crates/ramen-proto` pins the same property on the independent
//! implementation, so the two attribute sets stay checked against each other
//! the way the spec-examples test checks the examples against the parsers.

use std::path::Path;

#[derive(Debug)]
struct DeserType {
    file: String,
    name: String,
    kind: Kind,
    has_deny: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Struct,
    Enum,
    UntaggedEnum,
    Transparent,
}

/// True when an enum body (attributes and doc comments stripped, outer
/// braces removed) contains a variant with fields — a struct variant `{` or
/// a tuple variant `(`.
fn enum_has_payload_variants(src: &str) -> bool {
    let mut body = String::new();
    for line in src.lines() {
        let t = line.trim_start();
        if t.starts_with("//") || t.starts_with("#[") {
            continue;
        }
        body.push_str(line);
        body.push('\n');
    }
    body.contains('{') || body.contains('(')
}

fn collect(file: &str, src: &str) -> Vec<DeserType> {
    let mut out = Vec::new();
    let bytes = src.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        // Byte-level prefix check: `i` may sit mid-character in a doc
        // comment, and `#[derive(` is ASCII, so a match implies a boundary.
        if !bytes[i..].starts_with(b"#[derive(") {
            i += 1;
            continue;
        }
        let open = i + "#[derive(".len();
        let close = match src[open..].find(')') {
            Some(c) => open + c,
            None => break,
        };
        let derives = &src[open..close];
        if !derives
            .split(',')
            .any(|d| d.trim() == "Deserialize")
        {
            i = close + 1;
            continue;
        }
        // Gather the #[...] attribute lines between the derive and the
        // declaration. `j` starts just after the derive's `)`; consume the
        // derive attribute's own closing `]` first.
        let mut j = close + 1;
        if bytes.get(j) == Some(&b']') {
            j += 1;
        }
        let mut attrs = String::new();
        loop {
            while j < src.len() && src.as_bytes()[j].is_ascii_whitespace() {
                j += 1;
            }
            if bytes[j..].starts_with(b"#[") {
                let end = j + src[j..].find(']').expect("unterminated attribute");
                attrs.push_str(&src[j..end]);
                j = end + 1;
            } else {
                break;
            }
        }
        let rest = src[j..].trim_start();
        let (is_enum, decl) = if let Some(r) = rest
            .strip_prefix("pub struct")
            .or_else(|| rest.strip_prefix("struct"))
        {
            (false, r.trim_start())
        } else if let Some(r) = rest
            .strip_prefix("pub enum")
            .or_else(|| rest.strip_prefix("enum"))
        {
            (true, r.trim_start())
        } else {
            i = j.max(i + 1);
            continue;
        };
        // Name: identifier up to `{`, `(`, `<`, or whitespace.
        let name_end = decl
            .char_indices()
            .find(|(_, c)| c.is_whitespace() || *c == '{' || *c == '(' || *c == '<')
            .map(|(p, _)| p)
            .unwrap_or(decl.len());
        let name = decl[..name_end].trim().to_string();
        if name.is_empty() {
            i = j.max(i + 1);
            continue;
        }
        let has_deny = attrs.contains("deny_unknown_fields");
        let kind = if attrs.contains("transparent") {
            Kind::Transparent
        } else if attrs.contains("untagged") {
            Kind::UntaggedEnum
        } else if is_enum {
            // Body: from the declaration's `{` to its matching close.
            let brace = j + src[j..].find('{').expect("enum without body");
            let mut depth = 0usize;
            let mut k = brace;
            while k < src.len() {
                match src.as_bytes()[k] {
                    b'{' => depth += 1,
                    b'}' => {
                        depth -= 1;
                        if depth == 0 {
                            break;
                        }
                    }
                    _ => {}
                }
                k += 1;
            }
            let body = &src[brace + 1..k];
            if enum_has_payload_variants(body) {
                Kind::Enum
            } else {
                // Fieldless: no fields to reject; unknown variants are
                // already errors.
                Kind::Transparent
            }
        } else {
            Kind::Struct
        };
        out.push(DeserType {
            file: file.to_string(),
            name,
            kind,
            has_deny,
        });
        i = j.max(i + 1);
    }
    out
}

#[test]
fn every_deserialized_wire_type_rejects_unknown_fields() {
    let src_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut types = Vec::new();
    for entry in std::fs::read_dir(&src_dir)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", src_dir.display()))
    {
        let path = entry.unwrap().path();
        if path.extension().is_some_and(|e| e == "rs") {
            let src = std::fs::read_to_string(&path).unwrap();
            types.extend(collect(
                &path.file_name().unwrap().to_string_lossy(),
                &src,
            ));
        }
    }
    assert!(
        types.len() >= 15,
        "found only {} deserialized types — the scan is not seeing the \
         wire types, and this test is vacuous",
        types.len()
    );
    for t in &types {
        // Transparent newtypes and fieldless/untagged enums are exempt by
        // construction (see the module doc); everything else must carry the
        // attribute.
        let exempt = matches!(t.kind, Kind::Transparent | Kind::UntaggedEnum);
        assert!(
            t.has_deny || exempt,
            "{}/{}: `{}` derives Deserialize without \
             `#[serde(deny_unknown_fields)]` — unknown fields would be \
             silently accepted (or, for a tagged enum with payload \
             variants, the two implementations diverge on strictness). \
             Add the attribute, or if the type genuinely has no fields to \
             reject, it should classify as exempt in this test.",
            t.file, t.name, t.name
        );
    }
}
