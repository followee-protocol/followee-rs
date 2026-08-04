//! Guard for the mechanical direct-verification-call restriction
//! (IMPLEMENTATION.md sections 6.2 and 11.7): CI enforcement relies on the
//! committed Clippy configuration, so this test fails if that configuration
//! or its lint level is weakened or removed.

#[test]
fn sec_6_2_disallowed_method_configuration_is_intact() {
    let clippy_toml = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/clippy.toml"))
        .expect("clippy.toml present at the repository root");
    for required in [
        "ed25519_dalek::VerifyingKey::verify_strict",
        "ed25519_dalek::Verifier::verify",
        "ed25519_dalek::hazmat::raw_verify",
    ] {
        assert!(
            clippy_toml.contains(required),
            "clippy.toml must keep the disallowed-method entry for {required}"
        );
    }

    let cargo_toml = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"))
        .expect("Cargo.toml present");
    assert!(
        cargo_toml.contains("disallowed_methods = \"deny\""),
        "Cargo.toml must deny clippy::disallowed_methods"
    );
    assert!(
        cargo_toml.contains("arithmetic_side_effects = \"deny\""),
        "Cargo.toml must deny clippy::arithmetic_side_effects"
    );
}

#[test]
fn sec_6_2_no_scoped_allowance_exists_outside_the_strict_wrapper() {
    // The strict wrapper is built from curve arithmetic and needs no
    // allowance; therefore no file in src/ may carry one.
    let src = concat!(env!("CARGO_MANIFEST_DIR"), "/src");
    for entry in walk(src.as_ref()) {
        let content = std::fs::read_to_string(&entry).expect("source file readable");
        assert!(
            !content.contains("allow(clippy::disallowed_methods)"),
            "{} must not carry a disallowed_methods allowance",
            entry.display()
        );
    }
}

fn walk(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut files = Vec::new();
    for entry in std::fs::read_dir(dir).expect("directory readable") {
        let path = entry.expect("entry readable").path();
        if path.is_dir() {
            files.extend(walk(&path));
        } else if path.extension().is_some_and(|e| e == "rs") {
            files.push(path);
        }
    }
    files
}
