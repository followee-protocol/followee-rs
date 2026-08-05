//! External integration tests for the public `followee::validate_cbor`
//! conformance API: structural deterministic-CBOR validation under explicit
//! limits, with the section 15.3 error classifications. Calling through the
//! crate path from an external test proves the API is genuinely public.
#![allow(clippy::arithmetic_side_effects)]

mod common;

use common::*;
use followee::error::VerifyError;
use followee::limits::{MAX_BODY_DEPTH, MAX_BODY_MEMBERS};
use followee::validate_cbor;

fn full(bytes: &[u8]) -> Result<(), VerifyError> {
    validate_cbor(bytes, MAX_BODY_DEPTH, MAX_BODY_MEMBERS)
}

#[test]
fn accepts_valid_scalar_and_aggregate_values() {
    for bytes in [
        &[0x00][..],                                 // 0
        &[0x17],                                     // 23
        &[0x18, 0x18],                               // 24
        &[0x32],                                     // -19
        &[0xf4],                                     // false
        &[0xf5],                                     // true
        &[0xf6],                                     // null
        &[0x60],                                     // ""
        &[0x41, 0xff],                               // 1-byte bstr
        &[0x80],                                     // []
        &[0xa0],                                     // {}
        &[0xa2, 0x00, 0x01, 0x01, 0x82, 0x00, 0x01], // {0:1, 1:[0,1]}
    ] {
        assert_eq!(full(bytes), Ok(()), "{bytes:02x?}");
    }
    // The Appendix B.4 record body is one valid deterministic item.
    assert_eq!(full(&fx_bytes("root_record_body")), Ok(()));
}

#[test]
fn rejects_malformed_and_truncated_cbor_as_invalid() {
    for bytes in [
        &[][..],
        &[0x41],       // bstr length 1, no body
        &[0x19, 0x01], // truncated 2-byte head
        &[0x1c],       // reserved additional info
        &[0xff],       // stray break
        &[0x61, 0xff], // invalid UTF-8 in tstr
        &[0x00, 0x00], // trailing bytes
    ] {
        assert_eq!(full(bytes), Err(VerifyError::InvalidCbor), "{bytes:02x?}");
    }
}

#[test]
fn rejects_non_minimal_and_indefinite_encodings_as_non_deterministic() {
    for bytes in [
        &[0x18, 0x17][..],         // 23 in two bytes
        &[0x19, 0x00, 0x18],       // 24 in three bytes
        &[0x5f, 0x41, 0x00, 0xff], // indefinite bstr
        &[0x9f, 0x00, 0xff],       // indefinite array
        &[0xbf, 0x00, 0x00, 0xff], // indefinite map
        &[0xc0, 0x00],             // tag
        &[0xf7],                   // undefined
        &[0xf9, 0x00, 0x00],       // float16
    ] {
        assert_eq!(
            full(bytes),
            Err(VerifyError::NonDeterministicCbor),
            "{bytes:02x?}"
        );
    }
}

#[test]
fn rejects_duplicate_and_misordered_map_keys_as_non_deterministic() {
    // {1:0, 0:0} misordered; {0:0, 0:1} duplicate.
    assert_eq!(
        full(&[0xa2, 0x01, 0x00, 0x00, 0x00]),
        Err(VerifyError::NonDeterministicCbor)
    );
    assert_eq!(
        full(&[0xa2, 0x00, 0x00, 0x00, 0x01]),
        Err(VerifyError::NonDeterministicCbor)
    );
}

#[test]
fn exact_depth_boundary_and_one_over() {
    // Seven wrappers plus the innermost empty array nest to exactly depth 8.
    let mut at_limit = vec![0x81u8; 7];
    at_limit.push(0x80);
    assert_eq!(
        validate_cbor(&at_limit, MAX_BODY_DEPTH, MAX_BODY_MEMBERS),
        Ok(())
    );
    let mut over = vec![0x81u8; 8];
    over.push(0x80);
    assert_eq!(
        validate_cbor(&over, MAX_BODY_DEPTH, MAX_BODY_MEMBERS),
        Err(VerifyError::SchemaViolation)
    );
}

#[test]
fn exact_member_boundary_and_one_over() {
    let array_of = |n: usize| {
        let mut v = vec![0x99u8];
        v.extend((n as u16).to_be_bytes());
        v.extend(std::iter::repeat_n(0x00u8, n));
        v
    };
    assert_eq!(full(&array_of(256)), Ok(()));
    assert_eq!(full(&array_of(257)), Err(VerifyError::SchemaViolation));
}

#[test]
fn zero_limits_admit_scalars_only() {
    // Depth 0: any container descent exceeds the budget; scalars pass.
    assert_eq!(validate_cbor(&[0x00], 0, 0), Ok(()));
    assert_eq!(validate_cbor(&[0xf6], 0, 0), Ok(()));
    assert_eq!(
        validate_cbor(&[0x80], 0, MAX_BODY_MEMBERS),
        Err(VerifyError::SchemaViolation),
        "empty array still descends past depth 0"
    );
    // Members 0: any element or entry exceeds the budget; empty containers
    // hold zero members.
    assert_eq!(validate_cbor(&[0x80], 1, 0), Ok(()));
    assert_eq!(
        validate_cbor(&[0x81, 0x00], 1, 0),
        Err(VerifyError::SchemaViolation)
    );
}

#[test]
fn limits_above_followee_maxima_are_rejected_before_parsing() {
    // Bounded by contract: oversized limit requests never reach the parser,
    // so no unbounded-recursion surface exists regardless of caller input.
    assert_eq!(
        validate_cbor(&[0x00], MAX_BODY_DEPTH + 1, MAX_BODY_MEMBERS),
        Err(VerifyError::SchemaViolation)
    );
    assert_eq!(
        validate_cbor(&[0x00], MAX_BODY_DEPTH, MAX_BODY_MEMBERS + 1),
        Err(VerifyError::SchemaViolation)
    );
    assert_eq!(
        validate_cbor(&[0x00], u32::MAX, u32::MAX),
        Err(VerifyError::SchemaViolation)
    );
    // The maxima themselves are accepted.
    assert_eq!(
        validate_cbor(&[0x00], MAX_BODY_DEPTH, MAX_BODY_MEMBERS),
        Ok(())
    );
}

#[test]
fn classification_parity_with_the_record_verification_path() {
    // Representative payload-level defects must classify identically through
    // the public wrapper and through complete record verification, which
    // runs the same structural gate over the received payload.
    use followee::verify::verify_record;

    // Non-minimal integer inside the body: both say NonDeterministicCbor.
    let mut entries = b4_raw_entries();
    entries[0].1 = vec![0x18, 0x01];
    let payload = r_map(&entries);
    assert_eq!(full(&payload), Err(VerifyError::NonDeterministicCbor));
    let envelope = seal(&payload, &root_seed());
    assert_eq!(
        verify_record(&alice_did(), &envelope).map(|_| ()),
        Err(VerifyError::NonDeterministicCbor)
    );

    // Misordered body labels: both say NonDeterministicCbor.
    let mut entries = b4_raw_entries();
    entries.swap(0, 1);
    let payload = r_map(&entries);
    assert_eq!(full(&payload), Err(VerifyError::NonDeterministicCbor));
    let envelope = seal(&payload, &root_seed());
    assert_eq!(
        verify_record(&alice_did(), &envelope).map(|_| ()),
        Err(VerifyError::NonDeterministicCbor)
    );

    // The valid B.4 body passes the wrapper, and its envelope verifies.
    let body = fx_bytes("root_record_body");
    assert_eq!(full(&body), Ok(()));
    assert!(verify_record(&alice_did(), &fx_bytes("root_record_envelope")).is_ok());
}
