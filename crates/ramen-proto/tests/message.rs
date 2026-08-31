//! Message-level validation (`01-protocol.md` M1 acceptance).
//!
//! - Unknown fields are rejected, and the error names the field.
//! - Duplicate JSON keys are rejected deterministically (serde_json's
//!   silent last-wins is explicitly *not* inherited).
//! - Dispatch by shape works and foreign `type` values are rejected.

use ramen_proto::{Message, ProtoError, Request, WhoamiOp};

fn payload(s: &str) -> Vec<u8> {
    let mut out = Vec::new();
    let len = s.len() as u32;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(s.as_bytes());
    out
}

fn decode(s: &str) -> Result<Message, ProtoError> {
    let f = payload(s);
    Message::decode(&f[4..])
}

#[test]
fn unknown_field_on_request_is_rejected_and_named() {
    let s = r#"{"v":1,"id":"01ARZ3NDEKTSV4RRFFQ69G5FAV","op":{"type":"Whoami"},"bogus":1}"#;
    let err = decode(s).unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("bogus"), "error must name the unknown field: {msg}");
}

#[test]
fn unknown_field_inside_op_is_rejected_and_named() {
    let s = r#"{"v":1,"id":"01ARZ3NDEKTSV4RRFFQ69G5FAV","op":{"type":"Whoami","extra":true}}"#;
    let err = decode(s).unwrap_err();
    assert!(err.to_string().contains("extra"));
}

#[test]
fn unknown_field_on_hello_is_rejected() {
    let s = r#"{"v":1,"type":"Hello","token":"x","client":{"name":"a","version":"1","junk":2}}"#;
    let err = decode(s).unwrap_err();
    assert!(err.to_string().contains("junk"));
}

#[test]
fn unknown_field_on_response_is_rejected() {
    let s = r#"{"v":1,"id":"01ARZ3NDEKTSV4RRFFQ69G5FAV","status":"Error","error":{"code":"Internal","message":"m"},"zzz":0}"#;
    assert!(decode(s).is_err());
}

#[test]
fn duplicate_top_level_keys_rejected_deterministically() {
    let s = r#"{"v":1,"v":1,"id":"01ARZ3NDEKTSV4RRFFQ69G5FAV","op":{"type":"Whoami"}}"#;
    let err = decode(s).unwrap_err();
    match &err {
        ProtoError::DuplicateKey(d) => assert!(d.contains("\"v\""), "should name the key: {d}"),
        other => panic!("expected DuplicateKey, got {other:?}"),
    }
    // Same input, same result, every time (determinism).
    for _ in 0..10 {
        let e2 = decode(s).unwrap_err();
        assert_eq!(err.to_string(), e2.to_string());
    }
}

#[test]
fn duplicate_nested_keys_rejected() {
    let s = r#"{"v":1,"id":"01ARZ3NDEKTSV4RRFFQ69G5FAV","op":{"type":"FileWrite","path":"/a","path":"/b","content_b64":"aGk=","mode":"Create"}}"#;
    let err = decode(s).unwrap_err();
    match &err {
        ProtoError::DuplicateKey(d) => assert!(d.contains("\"path\"")),
        other => panic!("expected DuplicateKey, got {other:?}"),
    }
}

#[test]
fn duplicate_keys_inside_array_elements_rejected() {
    // An array of objects with duplicates in one element.
    let s = r#"{"v":1,"type":"Welcome","session":"01ARZ3NDEKTSV4RRFFQ69G5FAV","identity":"i","capabilities":[{"op":"A","op":"B","reversibility":"Trivial"}]}"#;
    let err = decode(s).unwrap_err();
    assert!(matches!(err, ProtoError::DuplicateKey(_)));
}

#[test]
fn duplicate_keys_do_not_hide_valid_shape() {
    // If the duplicate-key check were skipped, this would parse as a
    // last-wins Request. It must not.
    let s = r#"{"v":1,"id":"01ARZ3NDEKTSV4RRFFQ69G5FAV","op":{"type":"Whoami"},"op":{"type":"FileWrite"}}"#;
    assert!(matches!(decode(s), Err(ProtoError::DuplicateKey(_))));
}

#[test]
fn unrecognized_top_level_shape_rejected() {
    assert!(decode(r#"{"v":1,"foo":1}"#).is_err());
    assert!(decode(r#"{}"#).is_err());
    assert!(decode(r#"[1,2]"#).is_err());
    assert!(decode(r#""hi""#).is_err());
}

#[test]
fn unknown_type_value_rejected() {
    let s = r#"{"v":1,"type":"Bogus","x":1}"#;
    let err = decode(s).unwrap_err();
    assert!(err.to_string().contains("Bogus"));
}

#[test]
fn hello_type_must_be_exactly_hello() {
    // A Hello-shaped frame claiming to be a Welcome is a foreign type.
    let s = r#"{"v":1,"type":"Welcome","token":"x","client":{"name":"a","version":"1"}}"#;
    assert!(decode(s).is_err());
}

#[test]
fn request_and_response_shapes_dispatch() {
    let req = Request::new(ramen_proto::Operation::Whoami(WhoamiOp {}));
    let s = serde_json::to_string(&req).unwrap();
    match decode(&s).unwrap() {
        Message::Request(r) => assert_eq!(r, req),
        other => panic!("expected Request, got {other:?}"),
    }

    let resp = ramen_proto::Response::error(
        req.id,
        ramen_proto::ErrorCode::NotImplemented,
        "M3",
    );
    let s = serde_json::to_string(&resp).unwrap();
    match decode(&s).unwrap() {
        Message::Response(r) => assert_eq!(r, resp),
        other => panic!("expected Response, got {other:?}"),
    }
}

#[test]
fn token_expires_at_serializes_as_null_when_absent() {
    let r = ramen_proto::WhoamiResult {
        identity: "a".into(),
        session: fixed_session(),
        capabilities: vec![],
        token_expires_at: None,
    };
    let v: serde_json::Value = serde_json::to_value(&r).unwrap();
    // Present as `null`, not omitted.
    assert!(v.get("token_expires_at").is_some());
    assert_eq!(v["token_expires_at"], serde_json::Value::Null);
}

fn fixed_session() -> ramen_proto::SessionId {
    serde_json::from_str("\"01ARZ3NDEKTSV4RRFFQ69G5FAV\"").unwrap()
}

#[test]
fn wire_json_field_names_match_spec() {
    // Pin the exact field names from 01-protocol.md §4 / §5.
    let req = Request::new(ramen_proto::Operation::Whoami(WhoamiOp {}));
    let v: serde_json::Value = serde_json::to_value(&req).unwrap();
    assert!(v.get("v").is_some());
    assert!(v.get("id").is_some());
    assert!(v.get("op").is_some());
    assert_eq!(v["op"]["type"], "Whoami");

    let fw = ramen_proto::Operation::FileWrite(ramen_proto::FileWriteOp {
        path: "/p".into(),
        content_b64: "aGk=".into(),
        mode: ramen_proto::WriteMode::Overwrite,
    });
    let v: serde_json::Value = serde_json::to_value(&fw).unwrap();
    assert_eq!(v["type"], "FileWrite");
    assert_eq!(v["mode"], "Overwrite");

    let hello = ramen_proto::Hello::new(
        "tok".into(),
        ramen_proto::ClientInfo { name: "n".into(), version: "1".into() },
    );
    let v: serde_json::Value = serde_json::to_value(&hello).unwrap();
    assert_eq!(v["type"], "Hello");
    assert!(v.get("token").is_some());
    assert!(v.get("client").is_some());

    let fault = ramen_proto::Fault::new(ramen_proto::ErrorCode::Internal, "m");
    let v: serde_json::Value = serde_json::to_value(&fault).unwrap();
    assert_eq!(v["type"], "Fault");
    assert_eq!(v["error"]["code"], "Internal");

    let resp = ramen_proto::Response::denied(
        ramen_proto::RequestId::new(),
        ramen_proto::Denial {
            code: ramen_proto::DenialCode::TokenExpired,
            reason: "expired".into(),
            audit_seq: 7,
        },
    );
    let v: serde_json::Value = serde_json::to_value(&resp).unwrap();
    assert_eq!(v["status"], "Denied");
    assert_eq!(v["denial"]["code"], "TokenExpired");
    assert_eq!(v["denial"]["audit_seq"], 7);
}
