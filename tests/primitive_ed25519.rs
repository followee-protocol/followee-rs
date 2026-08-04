//! Primitive strict-Ed25519 conformance against externally published
//! cross-implementation edge-case vectors (ed25519-speccheck; provenance in
//! fixtures/external/PROVENANCE.json).
//!
//! Every vector executes through the production entry point
//! `crypto::verify_followee_ed25519` — the exact function record verification
//! delegates to (IMPLEMENTATION.md section 11.1). The expected rejection for
//! each case is independently established here by computing which section 3.3
//! rule the vector violates using curve primitives, rather than by trusting
//! either the upstream table or the verifier under test.
#![allow(clippy::arithmetic_side_effects)]

use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::IsIdentity;
use followee::crypto::verify_followee_ed25519;

struct PointProperties {
    canonical: bool,
    torsion_free: bool,
    identity: bool,
}

fn point_properties(bytes: &[u8; 32]) -> PointProperties {
    match CompressedEdwardsY(*bytes).decompress() {
        None => PointProperties {
            canonical: false,
            torsion_free: false,
            identity: false,
        },
        Some(point) => PointProperties {
            canonical: point.compress().to_bytes() == *bytes,
            torsion_free: point.is_torsion_free(),
            identity: point.is_identity(),
        },
    }
}

#[test]
fn speccheck_vectors_all_violate_a_section_3_3_rule_and_are_rejected() {
    let cases: Vec<serde_json::Value> = serde_json::from_str(
        &std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/fixtures/external/ed25519_speccheck_cases.json"
        ))
        .expect("external vector file present"),
    )
    .expect("vector JSON parses");
    assert_eq!(cases.len(), 12, "the published set has 12 cases");

    for (index, case) in cases.iter().enumerate() {
        let field = |name: &str| -> Vec<u8> {
            hex::decode(case[name].as_str().expect("field present")).expect("valid hex")
        };
        let message = field("message");
        let public_key: [u8; 32] = field("pub_key").try_into().expect("32-byte key");
        let signature: [u8; 64] = field("signature").try_into().expect("64-byte signature");

        // Independently establish the violated rules from curve properties.
        let a = point_properties(&public_key);
        let r = point_properties(&signature[..32].try_into().expect("32 bytes"));
        let s_bytes: [u8; 32] = signature[32..].try_into().expect("32 bytes");
        let s_canonical = Option::<Scalar>::from(Scalar::from_canonical_bytes(s_bytes)).is_some();

        let mut violated: Vec<&str> = Vec::new();
        if !a.canonical || !r.canonical {
            violated.push("rule 3 (canonical encodings)");
        }
        if !s_canonical {
            violated.push("rule 4 (S < L)");
        }
        if a.identity || (a.canonical && !a.torsion_free) {
            violated.push("rule 5 (A non-identity, prime-order subgroup)");
        }
        if r.canonical && !r.torsion_free {
            violated.push("rule 6 (R prime-order subgroup)");
        }

        assert!(
            !violated.is_empty(),
            "case {index}: expected at least one structural section 3.3 violation; \
             a vector with none would need an equation-level expectation instead"
        );
        assert!(
            !verify_followee_ed25519(&public_key, &message, &signature),
            "case {index} must be rejected (violates {violated:?})"
        );
    }
}

#[test]
fn positive_control_passes_through_the_same_entry_point() {
    // RFC 8032 test vector 2 (one-byte message), exercised through the exact
    // production function the negative vectors use.
    let seed: [u8; 32] =
        hex::decode("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")
            .expect("hex")
            .try_into()
            .expect("32 bytes");
    let public = followee::crypto::ed25519_public_key(&seed);
    assert_eq!(
        hex::encode(public),
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"
    );
    let signature = followee::crypto::ed25519_sign(&seed, &[0x72]);
    assert_eq!(
        hex::encode(signature),
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da\
         085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
    );
    assert!(verify_followee_ed25519(&public, &[0x72], &signature));
}
