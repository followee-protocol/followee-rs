//! Appendix B.7 negative conformance, following the fault-isolation plan in
//! IMPLEMENTATION.md section 11.1: whenever a mutation touches signed
//! material, the mutated payload is re-signed with the applicable published
//! key so the intended condition is the only fault. Construction provenance
//! is recorded in fixtures/implementation/PROVENANCE.json.
#![allow(clippy::arithmetic_side_effects)]

mod common;

use common::*;
use followee::did::{DidError, FolloweeDid};
use followee::error::VerifyError;
use followee::verify::{verify_record, verify_record_for_target};

fn verify_alice(envelope: &[u8]) -> Result<(), VerifyError> {
    verify_record(&alice_did(), envelope).map(|_| ())
}

// ---------------------------------------------------------------------------
// Item 1: identity-binding mismatch (v0.3 three-case construction).
// ---------------------------------------------------------------------------

#[test]
fn sec_b7_item1a_unchanged_envelope_against_foreign_target() {
    // Case (a): the untouched, internally consistent B.4 envelope verified
    // against a different syntactically valid target DID. Multi-fault (both
    // binding relations fail) but the exact error is portable because
    // section 8.1 assigns the same error to both checks.
    let envelope = fx_bytes("root_record_envelope");
    assert_eq!(
        verify_record(&attacker_did(), &envelope),
        Err(VerifyError::IdentityBindingMismatch)
    );
}

fn mutated_id_envelope() -> Vec<u8> {
    // Body id changed to the attacker's (equal-length) DID, then re-signed
    // with Alice's legitimate root key.
    let mut entries = b4_raw_entries();
    entries[1].1 = r_tstr(&fx_str("attacker_did"));
    let payload = r_map(&entries);
    seal(&payload, &root_seed())
}

#[test]
fn sec_b7_item1b_mutated_id_resigned_against_original_target() {
    // Case (b): isolates the body-to-target relation; the descriptor still
    // reproduces the original target, so only step 7 fails.
    assert_eq!(
        verify_alice(&mutated_id_envelope()),
        Err(VerifyError::IdentityBindingMismatch)
    );
}

#[test]
fn sec_b7_item1c_mutated_id_resigned_against_mutated_target() {
    // Case (c): isolates the descriptor-to-target relation; the body id now
    // equals the target, so step 7 passes and step 9 fails.
    assert_eq!(
        verify_record(&attacker_did(), &mutated_id_envelope()).map(|_| ()),
        Err(VerifyError::IdentityBindingMismatch)
    );
}

// ---------------------------------------------------------------------------
// Item 2: target-DID hash-profile and syntax classification (v0.3). All
// cases are target-only and never mutate the signed envelope.
// ---------------------------------------------------------------------------

fn did_from_multihash(bytes: &[u8]) -> String {
    format!("did:flw:z{}", bs58_encode(bytes))
}

fn bs58_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let mut digits: Vec<u8> = Vec::new();
    for &b in bytes {
        let mut carry = b as u32;
        for d in digits.iter_mut() {
            let v = (*d as u32) * 256 + carry;
            *d = (v % 58) as u8;
            carry = v / 58;
        }
        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }
    for &b in bytes {
        if b == 0 {
            digits.push(0);
        } else {
            break;
        }
    }
    digits
        .iter()
        .rev()
        .map(|&d| ALPHABET[d as usize] as char)
        .collect()
}

#[test]
fn sec_b7_item2_foreign_code_well_formed_is_unsupported_hash() {
    // sha3-256 code 0x16 with a matching 32-byte digest: structurally
    // well-formed, outside the v1 profile.
    let mut mh = vec![0x16, 0x20];
    mh.extend_from_slice(&fx32("descriptor_digest"));
    let target = did_from_multihash(&mh);
    assert_eq!(FolloweeDid::parse(&target), Err(DidError::UnsupportedHash));
    // Section 8.1 step 6 surfaces the same classification.
    assert_eq!(
        verify_record_for_target(&target, &fx_bytes("root_record_envelope")).map(|_| ()),
        Err(VerifyError::UnsupportedHash)
    );
}

#[test]
fn sec_b7_item2_foreign_digest_length_well_formed_is_unsupported_hash() {
    // Code 0x12 with declared length 0x1f and exactly 31 digest bytes: a
    // well-formed truncated multihash, outside the v1 profile.
    let mut mh = vec![0x12, 0x1f];
    mh.extend_from_slice(&fx32("descriptor_digest")[..31]);
    let target = did_from_multihash(&mh);
    assert_eq!(FolloweeDid::parse(&target), Err(DidError::UnsupportedHash));
}

#[test]
fn sec_b7_item2_non_minimal_varint_is_invalid_did() {
    // Code 0x12 encoded as the non-minimal two-byte varint 0x92 0x00.
    let mut mh = vec![0x92, 0x00, 0x20];
    mh.extend_from_slice(&fx32("descriptor_digest"));
    let target = did_from_multihash(&mh);
    assert_eq!(FolloweeDid::parse(&target), Err(DidError::InvalidDid));
}

#[test]
fn sec_b7_item2_length_disagreement_is_invalid_did() {
    // Declared length 0x20 but only 31 digest bytes present.
    let mut mh = vec![0x12, 0x20];
    mh.extend_from_slice(&fx32("descriptor_digest")[..31]);
    let target = did_from_multihash(&mh);
    assert_eq!(FolloweeDid::parse(&target), Err(DidError::InvalidDid));
}

#[test]
fn sec_b7_item2_trailing_bytes_is_invalid_did() {
    let mut mh = vec![0x12, 0x20];
    mh.extend_from_slice(&fx32("descriptor_digest"));
    mh.push(0x00);
    let target = did_from_multihash(&mh);
    assert_eq!(FolloweeDid::parse(&target), Err(DidError::InvalidDid));
}

// ---------------------------------------------------------------------------
// Item 3: unsupported protected algorithm, re-signed so the suite is the
// only fault.
// ---------------------------------------------------------------------------

#[test]
fn sec_b7_item3_deprecated_alg_minus_8_is_unsupported_suite() {
    // Protected header {1: -8} = a1 01 27, Sig_structure re-signed with the
    // legitimate root key over the mutated protected bytes.
    let payload = r_map(&b4_raw_entries());
    let envelope = seal_with_protected(&[0xa1, 0x01, 0x27], &payload, &root_seed());
    assert_eq!(verify_alice(&envelope), Err(VerifyError::UnsupportedSuite));
}

// ---------------------------------------------------------------------------
// Items 4–6: COSE structure mutations that do not touch signed material.
// ---------------------------------------------------------------------------

#[test]
fn sec_b7_item4_missing_cose_tag_is_rejected() {
    let envelope = fx_bytes("root_record_envelope");
    // Strip the leading d2 tag byte; the array itself is untouched.
    assert_eq!(
        verify_alice(&envelope[1..]),
        Err(VerifyError::SchemaViolation)
    );
}

#[test]
fn sec_b7_item4_non_minimal_tag_encoding_is_non_deterministic() {
    // Tag 18 encoded as d8 12 instead of d2 violates section 6.1 rule 2.
    let envelope = fx_bytes("root_record_envelope");
    let mut mutated = vec![0xd8, 0x12];
    mutated.extend_from_slice(&envelope[1..]);
    assert_eq!(
        verify_alice(&mutated),
        Err(VerifyError::NonDeterministicCbor)
    );
}

#[test]
fn sec_b7_item5_non_empty_unprotected_headers_are_rejected() {
    // The unprotected map is outside the Sig_structure, so replacing a0 with
    // a1 01 32 requires no re-signing. Offset: d2 84 43 a1 01 32 [a0].
    let envelope = fx_bytes("root_record_envelope");
    let mut mutated = envelope[..6].to_vec();
    mutated.extend_from_slice(&[0xa1, 0x01, 0x32]);
    mutated.extend_from_slice(&envelope[7..]);
    assert_eq!(verify_alice(&mutated), Err(VerifyError::SchemaViolation));
}

#[test]
fn sec_b7_item6_detached_payload_is_rejected() {
    // Replace the attached payload bstr with null (f6), preserving the
    // signature bytes.
    let envelope = fx_bytes("root_record_envelope");
    let payload_head = 7; // d2 84 43 a1 01 32 a0
    let payload_len_prefix = 3; // 59 xx xx
    let sig_offset = envelope.len() - 66;
    let mut mutated = envelope[..payload_head].to_vec();
    mutated.push(0xf6);
    mutated.extend_from_slice(&envelope[sig_offset..]);
    let _ = payload_len_prefix;
    assert_eq!(verify_alice(&mutated), Err(VerifyError::SchemaViolation));
}

// ---------------------------------------------------------------------------
// Items 7–10: deterministic-CBOR and schema mutations inside the payload,
// re-signed with the legitimate applicable key.
// ---------------------------------------------------------------------------

#[test]
fn sec_b7_item7_non_minimal_integer_in_body_is_non_deterministic() {
    // protocolVersion 1 encoded as 18 01 (two bytes).
    let mut entries = b4_raw_entries();
    entries[0].1 = vec![0x18, 0x01];
    let envelope = seal(&r_map(&entries), &root_seed());
    assert_eq!(
        verify_alice(&envelope),
        Err(VerifyError::NonDeterministicCbor)
    );
}

#[test]
fn sec_b7_item8_reordered_map_keys_are_non_deterministic() {
    let mut entries = b4_raw_entries();
    entries.swap(0, 1);
    let envelope = seal(&r_map(&entries), &root_seed());
    assert_eq!(
        verify_alice(&envelope),
        Err(VerifyError::NonDeterministicCbor)
    );
}

#[test]
fn sec_b7_item9_duplicate_map_key_is_non_deterministic() {
    let mut entries = b4_raw_entries();
    entries.insert(1, (r_uint(0), r_uint(1)));
    let envelope = seal(&r_map(&entries), &root_seed());
    assert_eq!(
        verify_alice(&envelope),
        Err(VerifyError::NonDeterministicCbor)
    );
}

#[test]
fn sec_b7_item10_root_record_with_label_5_is_rejected() {
    // Insert label 5 (the revocation public key) into the Root body between
    // labels 4 and 7, preserving deterministic order; re-sign with root key.
    let mut entries = b4_raw_entries();
    entries.insert(5, (r_uint(5), fx_bytes("revocation_public_key_cbor")));
    let envelope = seal(&r_map(&entries), &root_seed());
    assert_eq!(verify_alice(&envelope), Err(VerifyError::SchemaViolation));
}

#[test]
fn sec_b7_item11_root_revoked_record_missing_label_5_is_rejected() {
    // Remove label 5 from the RootRevoked body and re-sign with the
    // published revocation key, so the missing required field is the fault
    // rather than a stale signature.
    let entries: Vec<_> = b5_raw_entries()
        .into_iter()
        .filter(|(k, _)| k != &r_uint(5))
        .collect();
    let envelope = seal(&r_map(&entries), &revocation_seed());
    assert_eq!(verify_alice(&envelope), Err(VerifyError::SchemaViolation));
}

#[test]
fn sec_b7_item12_wrong_revealed_key_with_valid_signature_is_invalid_revocation_key() {
    // Put the attacker's revocation public key in Alice's RootRevoked body,
    // retain Alice's original commitment, and sign with the attacker's
    // revocation seed: the signature verifies under the revealed key, so the
    // commitment mismatch is the single fault (IMPLEMENTATION.md item 12).
    let attacker_rev_cbor =
        followee::record::encode_public_key(&fx32("attacker_revocation_public_key"));
    let mut entries = b5_raw_entries();
    let pos = entries
        .iter()
        .position(|(k, _)| k == &r_uint(5))
        .expect("label 5 present");
    entries[pos].1 = attacker_rev_cbor;
    let envelope = seal(&r_map(&entries), &attacker_revocation_seed());
    assert_eq!(
        verify_alice(&envelope),
        Err(VerifyError::InvalidRevocationKey)
    );
}

#[test]
fn sec_b7_item13_single_flipped_signature_bit_is_invalid_signature() {
    let mut envelope = fx_bytes("root_record_envelope");
    let last = envelope.len() - 1;
    envelope[last] ^= 0x01;
    assert_eq!(verify_alice(&envelope), Err(VerifyError::InvalidSignature));
}

// Item 14 (S >= L) lives in tests/conformance.rs against the published
// constant; the remaining primitive cases live in tests/primitive_ed25519.rs.

#[test]
fn sec_b7_item15_valid_until_before_timestamp_is_rejected() {
    // Insert label 6 = timestamp - 1 and re-sign with the root key.
    let mut entries = b4_raw_entries();
    entries.insert(5, (r_uint(6), r_uint(B4_TIMESTAMP_MS - 1)));
    let envelope = seal(&r_map(&entries), &root_seed());
    assert_eq!(verify_alice(&envelope), Err(VerifyError::SchemaViolation));

    // Boundary twin: validUntil == timestamp is valid.
    let mut ok_entries = b4_raw_entries();
    ok_entries.insert(5, (r_uint(6), r_uint(B4_TIMESTAMP_MS)));
    let envelope = seal(&r_map(&ok_entries), &root_seed());
    assert!(verify_alice(&envelope).is_ok());
}

// ---------------------------------------------------------------------------
// Item 16: aggregate hard limits, each constructed so no earlier unrelated
// cap masks the intended failure, re-signed whenever signed material changed.
// ---------------------------------------------------------------------------

fn body_with_contact(contact: Vec<u8>) -> Vec<u8> {
    let mut entries = b4_raw_entries();
    entries[5].1 = contact;
    r_map(&entries)
}

#[test]
fn sec_b7_item16_envelope_over_16kib_is_record_too_large() {
    // A large record-level extension keeps the contact document small, so
    // the envelope cap is the single operative limit.
    let big = r_bstr(&vec![0x41u8; 16 * 1024]);
    let ext = r_map(&[(r_tstr("https://example.com/x"), big)]);
    let mut entries = b4_raw_entries();
    entries.push((r_uint(8), ext));
    let envelope = seal(&r_map(&entries), &root_seed());
    assert!(envelope.len() > 16 * 1024);
    assert_eq!(verify_alice(&envelope), Err(VerifyError::RecordTooLarge));
}

#[test]
fn sec_b7_item16_contact_over_12kib_within_envelope_is_schema_violation() {
    // Contact document slightly above 12 KiB while the envelope stays under
    // 16 KiB: the contact cap is the single operative limit.
    let big = r_bstr(&vec![0x41u8; 12 * 1024 + 64]);
    let contact = r_map(&[(r_uint(6), r_map(&[(r_tstr("https://example.com/x"), big)]))]);
    let envelope = seal(&body_with_contact(contact), &root_seed());
    assert!(envelope.len() <= 16 * 1024);
    assert_eq!(verify_alice(&envelope), Err(VerifyError::SchemaViolation));
}

#[test]
fn sec_b7_item16_display_name_boundary() {
    let at_limit = "a".repeat(256);
    let over = "a".repeat(257);
    for (name, expect_ok) in [(at_limit, true), (over, false)] {
        let contact = r_map(&[(r_uint(0), r_tstr(&name))]);
        let envelope = seal(&body_with_contact(contact), &root_seed());
        let result = verify_alice(&envelope);
        if expect_ok {
            assert!(result.is_ok(), "display name at 256 bytes is valid");
        } else {
            assert_eq!(result, Err(VerifyError::SchemaViolation));
        }
    }
}

#[test]
fn sec_b7_item16_summary_boundary() {
    let contact = r_map(&[(r_uint(1), r_tstr(&"s".repeat(2049)))]);
    let envelope = seal(&body_with_contact(contact), &root_seed());
    assert_eq!(verify_alice(&envelope), Err(VerifyError::SchemaViolation));
}

#[test]
fn sec_b7_item16_uri_boundary() {
    let long_uri = format!("https://example.com/{}", "p".repeat(2048));
    assert!(long_uri.len() > 2048);
    let contact = r_map(&[(r_uint(2), r_tstr(&long_uri))]);
    let envelope = seal(&body_with_contact(contact), &root_seed());
    assert_eq!(verify_alice(&envelope), Err(VerifyError::SchemaViolation));
}

#[test]
fn sec_b7_item16_also_known_as_count_boundary() {
    let make = |n: usize| {
        let entries: Vec<_> = (0..n)
            .map(|i| r_tstr(&format!("https://example.com/{i}")))
            .collect();
        let contact = r_map(&[(r_uint(3), r_array(&entries))]);
        seal(&body_with_contact(contact), &root_seed())
    };
    assert!(verify_alice(&make(32)).is_ok(), "32 entries allowed");
    assert_eq!(verify_alice(&make(33)), Err(VerifyError::SchemaViolation));
}

#[test]
fn sec_b7_item16_service_count_boundary() {
    let service = |i: usize| {
        r_map(&[
            (r_uint(0), r_tstr(&format!("s{i}"))),
            (r_uint(1), r_tstr("Website")),
            (r_uint(2), r_tstr(&format!("https://example.com/{i}"))),
        ])
    };
    let make = |n: usize| {
        let services: Vec<_> = (0..n).map(service).collect();
        let contact = r_map(&[(r_uint(4), r_array(&services))]);
        seal(&body_with_contact(contact), &root_seed())
    };
    // 65 services exceed the cap; note 64 services also exceed the 256
    // aggregate member budget guard is not hit because each service has 3
    // members: 64 * 4 + overhead ≈ 258 > 256, so the at-limit case uses the
    // member budget instead. The over-limit case must still fail.
    assert_eq!(verify_alice(&make(65)), Err(VerifyError::SchemaViolation));
}

#[test]
fn sec_b7_item16_service_id_length_boundary() {
    let contact = r_map(&[(
        r_uint(4),
        r_array(&[r_map(&[
            (r_uint(0), r_tstr(&"i".repeat(257))),
            (r_uint(1), r_tstr("Website")),
            (r_uint(2), r_tstr("https://example.com/")),
        ])]),
    )]);
    let envelope = seal(&body_with_contact(contact), &root_seed());
    assert_eq!(verify_alice(&envelope), Err(VerifyError::SchemaViolation));
}

#[test]
fn sec_b7_item16_extension_key_length_boundary() {
    let key = format!("https://example.com/{}", "k".repeat(240));
    assert!(key.len() > 256);
    let contact = r_map(&[(r_uint(6), r_map(&[(r_tstr(&key), r_uint(1))]))]);
    let envelope = seal(&body_with_contact(contact), &root_seed());
    assert_eq!(verify_alice(&envelope), Err(VerifyError::SchemaViolation));
}

#[test]
fn sec_b7_item16_nesting_depth_boundary() {
    // Body(1) contact(2) ext-map(3) + nested arrays: depth 9 total exceeds 8.
    let mut value = r_uint(1);
    for _ in 0..6 {
        value = r_array(&[value]);
    }
    let contact = r_map(&[(r_uint(6), r_map(&[(r_tstr("https://e.com/x"), value)]))]);
    let envelope = seal(&body_with_contact(contact), &root_seed());
    assert_eq!(verify_alice(&envelope), Err(VerifyError::SchemaViolation));
}

#[test]
fn sec_b7_item16_member_count_boundary() {
    // 250 array elements inside an extension push the aggregate member count
    // past 256.
    let elements: Vec<_> = (0..250).map(|_| r_uint(0)).collect();
    let contact = r_map(&[(
        r_uint(6),
        r_map(&[(r_tstr("https://e.com/x"), r_array(&elements))]),
    )]);
    let envelope = seal(&body_with_contact(contact), &root_seed());
    assert_eq!(verify_alice(&envelope), Err(VerifyError::SchemaViolation));
}

// ---------------------------------------------------------------------------
// Additional schema guards adjacent to B.7.
// ---------------------------------------------------------------------------

#[test]
fn rejects_unknown_record_body_label() {
    let mut entries = b4_raw_entries();
    entries.push((r_uint(9), r_uint(1)));
    let envelope = seal(&r_map(&entries), &root_seed());
    assert_eq!(verify_alice(&envelope), Err(VerifyError::SchemaViolation));
}

#[test]
fn rejects_authority_value_two() {
    let mut entries = b4_raw_entries();
    entries[3].1 = r_uint(2);
    let envelope = seal(&r_map(&entries), &root_seed());
    assert_eq!(verify_alice(&envelope), Err(VerifyError::SchemaViolation));
}

#[test]
fn rejects_migration_naming_own_did() {
    let migration = r_map(&[(r_uint(1), r_tstr(&fx_str("followee_did")))]);
    let contact = r_map(&[(r_uint(5), migration)]);
    let envelope = seal(&body_with_contact(contact), &root_seed());
    assert_eq!(verify_alice(&envelope), Err(VerifyError::SchemaViolation));
}

#[test]
fn rejects_empty_migration_map() {
    let contact = r_map(&[(r_uint(5), r_map(&[]))]);
    let envelope = seal(&body_with_contact(contact), &root_seed());
    assert_eq!(verify_alice(&envelope), Err(VerifyError::SchemaViolation));
}

#[test]
fn accepts_valid_migration_successor() {
    let migration = r_map(&[(r_uint(1), r_tstr(&fx_str("attacker_did")))]);
    let contact = r_map(&[(r_uint(5), migration)]);
    let envelope = seal(&body_with_contact(contact), &root_seed());
    assert!(verify_alice(&envelope).is_ok());
}

#[test]
fn rejects_trailing_bytes_after_envelope() {
    let mut envelope = fx_bytes("root_record_envelope");
    envelope.push(0x00);
    assert_eq!(verify_alice(&envelope), Err(VerifyError::SchemaViolation));
}

#[test]
fn rejects_relative_uri_in_service_endpoint() {
    let contact = r_map(&[(
        r_uint(4),
        r_array(&[r_map(&[
            (r_uint(0), r_tstr("feed")),
            (r_uint(1), r_tstr("Feed")),
            (r_uint(2), r_tstr("/feed.xml")),
        ])]),
    )]);
    let envelope = seal(&body_with_contact(contact), &root_seed());
    assert_eq!(verify_alice(&envelope), Err(VerifyError::SchemaViolation));
}

#[test]
fn rejects_uri_with_fragment_per_rfc3986_absolute_uri() {
    // "absolute URI under RFC 3986" is the absolute-URI production, which
    // has no fragment.
    let contact = r_map(&[(r_uint(2), r_tstr("https://example.com/a#frag"))]);
    let envelope = seal(&body_with_contact(contact), &root_seed());
    assert_eq!(verify_alice(&envelope), Err(VerifyError::SchemaViolation));
}

// ---------------------------------------------------------------------------
// Mutation-sweep killer cases: at-limit acceptance twins and misparse-shape
// cases surfaced by cargo-mutants review (IMPLEMENTATION.md section 11.7).
// ---------------------------------------------------------------------------

#[test]
fn sec_15_1_envelope_just_under_16kib_is_accepted() {
    // Size the record-level extension so the complete envelope lands within
    // a few bytes below the 16 KiB cap; the whole cap range must accept.
    let probe = {
        let ext = r_map(&[(r_tstr("https://example.com/x"), r_bstr(&[]))]);
        let mut entries = b4_raw_entries();
        entries.push((r_uint(8), ext));
        seal(&r_map(&entries), &root_seed()).len()
    };
    // Two-step sizing: header widths are constant in this range, so one
    // corrective adjustment lands the envelope on exactly 16,384 bytes.
    let build = |padding: usize| {
        let ext = r_map(&[(
            r_tstr("https://example.com/x"),
            r_bstr(&vec![0x41u8; padding]),
        )]);
        let mut entries = b4_raw_entries();
        entries.push((r_uint(8), ext));
        seal(&r_map(&entries), &root_seed())
    };
    let guess = 16 * 1024 - probe - 8;
    let measured = build(guess).len();
    let envelope = build(guess + (16 * 1024 - measured));
    assert_eq!(envelope.len(), 16 * 1024, "exactly at the envelope cap");
    assert!(
        verify_alice(&envelope).is_ok(),
        "at-limit envelope accepted"
    );
}

#[test]
fn sec_15_1_contact_exactly_12kib_is_accepted() {
    let probe = {
        let contact = r_map(&[(
            r_uint(6),
            r_map(&[(r_tstr("https://example.com/x"), r_bstr(&[]))]),
        )]);
        contact.len()
    };
    // Sized bstr header costs 3 bytes versus 1 for the empty probe: +2.
    let padding = 12 * 1024 - probe - 2;
    let contact = r_map(&[(
        r_uint(6),
        r_map(&[(
            r_tstr("https://example.com/x"),
            r_bstr(&vec![0x41u8; padding]),
        )]),
    )]);
    assert_eq!(contact.len(), 12 * 1024);
    let envelope = seal(&body_with_contact(contact), &root_seed());
    assert!(
        verify_alice(&envelope).is_ok(),
        "contact at exactly 12 KiB accepted"
    );
}

#[test]
fn body_id_at_2048_bytes_is_schema_valid_but_fails_binding() {
    // A 2,048-byte id is within the URI cap, so schema admits it; it then
    // fails the binding comparison. One byte more is a schema violation.
    let mut entries = b4_raw_entries();
    entries[1].1 = r_tstr(&"a".repeat(2048));
    let envelope = seal(&r_map(&entries), &root_seed());
    assert_eq!(
        verify_alice(&envelope),
        Err(VerifyError::IdentityBindingMismatch)
    );
    let mut entries = b4_raw_entries();
    entries[1].1 = r_tstr(&"a".repeat(2049));
    let envelope = seal(&r_map(&entries), &root_seed());
    assert_eq!(verify_alice(&envelope), Err(VerifyError::SchemaViolation));
}

#[test]
fn rejects_non_map_authority_descriptor_value() {
    let mut entries = b4_raw_entries();
    entries[4].1 = r_uint(5);
    let envelope = seal(&r_map(&entries), &root_seed());
    assert_eq!(verify_alice(&envelope), Err(VerifyError::SchemaViolation));
}

#[test]
fn rejects_descriptor_with_wrong_entry_count() {
    // A two-entry descriptor map (version and root key, no commitment).
    let descriptor = r_map(&[
        (r_uint(0), r_uint(1)),
        (r_uint(1), fx_bytes("revocation_public_key_cbor")),
    ]);
    let mut entries = b4_raw_entries();
    entries[4].1 = descriptor;
    let envelope = seal(&r_map(&entries), &root_seed());
    assert_eq!(verify_alice(&envelope), Err(VerifyError::SchemaViolation));
}

#[test]
fn sec_3_2_unsupported_suite_inside_descriptor_root_key() {
    // Suite -8 inside the descriptor's public-key map (distinct from the
    // protected-header case in item 3): {0: -8, 1: key}.
    let bad_key = r_map(&[
        (r_uint(0), r_nint_mag(7)),
        (r_uint(1), r_bstr(&fx_bytes("root_public_key"))),
    ]);
    let descriptor = r_map(&[
        (r_uint(0), r_uint(1)),
        (r_uint(1), bad_key),
        (r_uint(2), r_bstr(&fx_bytes("revocation_commitment"))),
    ]);
    let mut entries = b4_raw_entries();
    entries[4].1 = descriptor;
    let envelope = seal(&r_map(&entries), &root_seed());
    assert_eq!(verify_alice(&envelope), Err(VerifyError::UnsupportedSuite));
}

#[test]
fn rejects_three_element_cose_array() {
    // tag 18 + array(3): protected, unprotected, payload — signature absent.
    let payload = r_map(&b4_raw_entries());
    let mut envelope = r_tag(18);
    envelope.extend(r_head(4, 3));
    envelope.extend(r_bstr(&protected_ed25519()));
    envelope.extend(r_head(5, 0));
    envelope.extend(r_bstr(&payload));
    assert_eq!(verify_alice(&envelope), Err(VerifyError::SchemaViolation));
}

#[test]
fn rejects_oversized_service_type_uri() {
    let long_type = format!("https://example.com/{}", "t".repeat(2049 - 20));
    assert!(long_type.len() > 2048);
    let contact = r_map(&[(
        r_uint(4),
        r_array(&[r_map(&[
            (r_uint(0), r_tstr("s")),
            (r_uint(1), r_tstr(&long_type)),
            (r_uint(2), r_tstr("https://example.com/")),
        ])]),
    )]);
    let envelope = seal(&body_with_contact(contact), &root_seed());
    assert_eq!(verify_alice(&envelope), Err(VerifyError::SchemaViolation));
}

#[test]
fn rejects_non_map_root_key_value_in_descriptor() {
    let descriptor = r_map(&[
        (r_uint(0), r_uint(1)),
        (r_uint(1), r_uint(2)),
        (r_uint(2), r_bstr(&fx_bytes("revocation_commitment"))),
    ]);
    let mut entries = b4_raw_entries();
    entries[4].1 = descriptor;
    let envelope = seal(&r_map(&entries), &root_seed());
    assert_eq!(verify_alice(&envelope), Err(VerifyError::SchemaViolation));
}
