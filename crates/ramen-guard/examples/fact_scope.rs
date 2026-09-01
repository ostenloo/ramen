use biscuit_auth::builder::{Algorithm, BlockBuilder, BiscuitBuilder, AuthorizerBuilder};
use biscuit_auth::{KeyPair, UnverifiedBiscuit};

fn main() {
    let root = KeyPair::new_with_algorithm(Algorithm::Secp256r1);

    // Test A: authorize() enforces a failing check in an appended block?
    let base = BiscuitBuilder::new()
        .code(r#"identity("a"); capability("Whoami");"#)
        .unwrap().build(&root).unwrap().to_base64().unwrap();
    let unv = UnverifiedBiscuit::from_base64(base.as_bytes()).unwrap();
    let kp = KeyPair::new_with_algorithm(Algorithm::Secp256r1);
    let bad = BlockBuilder::new().code(r#"check if false;"#).unwrap();
    let tok = unv.append_with_keypair(&kp, bad).unwrap();
    match tok.verify(|_k| Ok(root.public())) {
        Ok(v) => {
            let mut az = AuthorizerBuilder::new()
                .code("allow if capability($op);\ndeny if true;")
                .unwrap().build(&v).unwrap();
            println!("A) appended 'check if false' -> authorize(): {:?}", az.authorize());
        }
        Err(e) => println!("A) verify() rejected: {e}"),
    }

    // Test B: append reusing a predicate name already in the root -> overlap error?
    let unv2 = UnverifiedBiscuit::from_base64(base.as_bytes()).unwrap();
    let kp2 = KeyPair::new_with_algorithm(Algorithm::Secp256r1);
    let reuse = BlockBuilder::new().code(r#"capability("FileWrite");"#).unwrap();
    match unv2.append_with_keypair(&kp2, reuse) {
        Ok(_) => println!("B) reuse of 'capability' name: append SUCCEEDED"),
        Err(e) => println!("B) reuse of 'capability' name: append FAILED ({e})"),
    }

    // Test C: append a brand-new predicate name -> does its fact become visible to policy?
    let unv3 = UnverifiedBiscuit::from_base64(base.as_bytes()).unwrap();
    let kp3 = KeyPair::new_with_algorithm(Algorithm::Secp256r1);
    let newp = BlockBuilder::new().code(r#"grant_op("FileWrite");"#).unwrap();
    let tok3 = unv3.append_with_keypair(&kp3, newp).unwrap();
    let v3 = tok3.verify(|_k| Ok(root.public())).unwrap();
    let mut q = v3.authorizer().unwrap();
    let res: Vec<(String,)> = q.query("res($x) <- grant_op($x)").unwrap();
    println!("C) new predicate 'grant_op' fact visible to policy: {res:?}");
}
