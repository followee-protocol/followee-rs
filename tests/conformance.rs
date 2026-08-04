//! Appendix B positive conformance: every published byte sequence must
//! reproduce exactly from structured input, and every published envelope must
//! verify through the public production path.
#![allow(clippy::arithmetic_side_effects)]

mod common;

use common::*;
use followee::crypto;
use followee::did::FolloweeDid;
use followee::error::VerifyError;
use followee::ordering::{AuthorityState, select_current};
use followee::record::{encode_public_key, revocation_commitment, sign_record};
use followee::verify::verify_record;

#[test]
fn sec_b2_public_keys_derive_from_published_seeds() {
    assert_eq!(
        crypto::ed25519_public_key(&root_seed()),
        fx32("root_public_key")
    );
    assert_eq!(
        crypto::ed25519_public_key(&revocation_seed()),
        fx32("revocation_public_key")
    );
    assert_eq!(
        crypto::ed25519_public_key(&attacker_root_seed()),
        fx32("attacker_root_public_key")
    );
    assert_eq!(
        crypto::ed25519_public_key(&attacker_revocation_seed()),
        fx32("attacker_revocation_public_key")
    );
}

#[test]
fn sec_b3_commitment_descriptor_and_did_reproduce() {
    assert_eq!(
        encode_public_key(&fx32("revocation_public_key")),
        fx_bytes("revocation_public_key_cbor")
    );
    assert_eq!(
        revocation_commitment(&fx32("revocation_public_key")),
        fx32("revocation_commitment")
    );
    let descriptor = alice_descriptor();
    assert_eq!(descriptor.encode(), fx_bytes("authority_descriptor_cbor"));
    let did = descriptor.did();
    assert_eq!(did.as_str(), fx_str("followee_did"));
    assert_eq!(did.digest(), &fx32("descriptor_digest"));
    // Multihash framing: 0x12 0x20 then the digest.
    let mut multihash = vec![0x12, 0x20];
    multihash.extend_from_slice(did.digest());
    assert_eq!(multihash, fx_bytes("multihash_bytes"));
}

#[test]
fn sec_b4_root_record_reproduces_byte_for_byte() {
    let body = b4_body();
    let body_bytes = body.encode().expect("B.4 body encodes");
    assert_eq!(body_bytes, fx_bytes("root_record_body"), "record body CBOR");
    assert_eq!(
        followee::sig_structure(&body_bytes),
        fx_bytes("root_sig_structure"),
        "Sig_structure bytes"
    );
    assert_eq!(
        fx_bytes("root_sig_structure").len(),
        327,
        "Sig_structure length"
    );
    assert_eq!(
        crypto::sha256(&body_bytes),
        fx32("root_body_digest"),
        "body digest"
    );
    let envelope = sign_record(&body, &root_seed()).expect("B.4 signs");
    assert_eq!(
        envelope,
        fx_bytes("root_record_envelope"),
        "complete envelope"
    );
    // Signature bytes are the trailing 64 bytes of the envelope.
    assert_eq!(
        &envelope[envelope.len() - 64..],
        fx_bytes("root_signature").as_slice()
    );
}

#[test]
fn sec_b4_root_record_verifies_through_production_path() {
    let verified = verify_record(&alice_did(), &fx_bytes("root_record_envelope"))
        .expect("published B.4 envelope verifies");
    assert_eq!(verified.body(), &b4_body(), "verified body round-trips");
    assert_eq!(verified.body_digest(), &fx32("root_body_digest"));
    assert_eq!(
        verified.envelope_bytes(),
        fx_bytes("root_record_envelope").as_slice(),
        "exact received envelope bytes are retained"
    );
    assert_eq!(
        verified.payload_bytes(),
        fx_bytes("root_record_body").as_slice(),
        "exact received payload bytes are retained"
    );
}

#[test]
fn sec_b5_root_revoked_record_reproduces_and_verifies() {
    let body = b5_body();
    let body_bytes = body.encode().expect("B.5 body encodes");
    assert_eq!(
        body_bytes,
        fx_bytes("root_revoked_body"),
        "record body CBOR"
    );
    assert_eq!(
        crypto::sha256(&body_bytes),
        fx32("root_revoked_body_digest")
    );
    let envelope = sign_record(&body, &revocation_seed()).expect("B.5 signs");
    assert_eq!(
        envelope,
        fx_bytes("root_revoked_envelope"),
        "complete envelope"
    );
    assert_eq!(
        &envelope[envelope.len() - 64..],
        fx_bytes("root_revoked_signature").as_slice()
    );
    let verified = verify_record(&alice_did(), &envelope).expect("published B.5 envelope verifies");
    assert_eq!(verified.body(), &body);
}

#[test]
fn sec_b6_equal_time_ordering_selects_lower_digest() {
    let make = |name: &str| {
        let mut body = b4_body();
        body.contact.display_name = Some(name.to_owned());
        let envelope = sign_record(&body, &root_seed()).expect("variant signs");
        verify_record(&alice_did(), &envelope).expect("variant verifies")
    };
    let a = make("Alice A");
    let b = make("Alice B");
    assert_eq!(a.body_digest(), &fx32("alice_a_body_digest"));
    assert_eq!(b.body_digest(), &fx32("alice_b_body_digest"));

    // Same authority, same timestamp: the lower digest wins in either order.
    let now = B4_TIMESTAMP_MS;
    for candidates in [vec![a.clone(), b.clone()], vec![b.clone(), a.clone()]] {
        let selection = select_current(&alice_did(), &candidates, now, AuthorityState::Unknown);
        assert_eq!(
            selection.winner.expect("winner exists").body_digest(),
            &fx32("alice_a_body_digest"),
            "lower digest wins regardless of arrival order"
        );
    }
}

#[test]
fn sec_b8_descriptor_substitution_fails_binding_despite_valid_signature() {
    let envelope = fx_bytes("b8_envelope");

    // The attacker's signature over the substituted body is cryptographically
    // valid: prove it at the primitive boundary first.
    let payload_start = 7 + 3; // d2 84 43 a1 01 32 a0 + 59 xx xx
    let payload = &envelope[payload_start..envelope.len() - 66];
    assert_eq!(crypto::sha256(payload), fx32("b8_body_digest"));
    assert!(crypto::verify_followee_ed25519(
        &fx32("attacker_root_public_key"),
        &followee::sig_structure(payload),
        &fx_bytes("b8_signature")
            .try_into()
            .expect("64-byte signature"),
    ));

    // The complete verifier must nevertheless reject at descriptor binding.
    assert_eq!(
        verify_record(&alice_did(), &envelope),
        Err(VerifyError::IdentityBindingMismatch),
        "valid signature must not bypass identity binding"
    );

    // The attacker's own DID is exactly what the substituted descriptor
    // derives, for contrast.
    let attacker_descriptor = followee::record::AuthorityDescriptor {
        root_key: fx32("attacker_root_public_key"),
        revocation_commitment: fx32("attacker_revocation_commitment"),
    };
    assert_eq!(
        attacker_descriptor.encode(),
        fx_bytes("attacker_descriptor_cbor")
    );
    assert_eq!(attacker_descriptor.did().as_str(), fx_str("attacker_did"));
}

#[test]
fn sec_b7_item14_s_plus_l_signature_is_rejected_by_production_path() {
    // Independently recompute S + L over the B.4 signature (little-endian),
    // as required by IMPLEMENTATION.md section 11.1 item 14.
    let envelope = fx_bytes("root_record_envelope");
    let sig = &envelope[envelope.len() - 64..];
    let ell: [u8; 32] = {
        // L = 2^252 + 27742317777372353535851937790883648493, little-endian.
        let mut l = [0u8; 32];
        let low: u128 = 27742317777372353535851937790883648493;
        l[..16].copy_from_slice(&low.to_le_bytes());
        l[31] = 0x10;
        l
    };
    let mut mutated_s = [0u8; 32];
    let mut carry: u16 = 0;
    for i in 0..32 {
        let sum = u16::from(sig[32 + i]) + u16::from(ell[i]) + carry;
        mutated_s[i] = (sum & 0xff) as u8;
        carry = sum >> 8;
    }
    assert_eq!(carry, 0, "S + L fits 32 bytes");

    let mut mutated = envelope.clone();
    let sig_offset = envelope.len() - 32;
    mutated[sig_offset..].copy_from_slice(&mutated_s);

    // The recomputed bytes must equal the IMPLEMENTATION.md constant.
    let expected_hex = "4db146d7bc6ca7690bac44b0c6ef38bcdd685ff157fdcca15da6b64662a26f94\
                        aa69aeecb156fa78fa072ff9a4e54a9e67103f9346dbef51c053cac381a50214"
        .replace(' ', "");
    assert_eq!(
        hex::encode(&mutated[envelope.len() - 64..]),
        expected_hex,
        "independently recomputed S + L signature matches the published bytes"
    );

    // Everything else is byte-identical to the positive case; rejection goes
    // through the non-injectable production wrapper.
    assert_eq!(
        verify_record(&alice_did(), &mutated),
        Err(VerifyError::InvalidSignature)
    );
}

#[test]
fn sec_20_4_structured_input_determinism_across_runs() {
    // Byte-identical output from identical structured input, repeatedly.
    let first = b4_body().encode().expect("encodes");
    for _ in 0..10 {
        assert_eq!(b4_body().encode().expect("encodes"), first);
    }
}

#[test]
fn published_seeds_are_refused_nowhere_yet_but_derive_distinct_dids() {
    // Guard against fixture cross-contamination: Alice and the attacker
    // derive different DIDs from different descriptors.
    assert_ne!(fx_str("followee_did"), fx_str("attacker_did"));
    assert_ne!(
        FolloweeDid::parse(&fx_str("followee_did")).expect("parses"),
        FolloweeDid::parse(&fx_str("attacker_did")).expect("parses")
    );
}
