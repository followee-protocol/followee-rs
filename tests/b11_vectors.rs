//! Appendix B.11 relay-wrapper vectors: byte-level reproduction only.
//!
//! IMPLEMENTATION.md section 11.1 makes B.11 request and response bytes and
//! digests a Milestone 1 obligation, while their HTTP, client, and
//! synchronization behaviours are Milestone 3 and 4 acceptance gates. This
//! file therefore contains no relay implementation: every wrapper is built
//! from its structured description with the test-side CBOR emitters and
//! compared against the published bytes, lengths, and SHA-256 digests. The
//! embedded Full byte strings are the exact B.4, B.8, and B.9 envelopes and
//! remain opaque at the wrapper layer (specification section 6.1.1).
#![allow(clippy::arithmetic_side_effects)]

mod common;

use common::*;
use followee::crypto::sha256;

fn b11(case: &str) -> serde_json::Value {
    fixtures()["b11"][case].clone()
}

fn directory_generation() -> Vec<u8> {
    hex::decode(
        fixtures()["b11"]["directory_generation"]
            .as_str()
            .expect("generation"),
    )
    .expect("hex")
}

fn field_bytes(case: &serde_json::Value, field: &str) -> Vec<u8> {
    hex::decode(case[field].as_str().expect("hex field")).expect("valid hex")
}

/// Asserts `built` against the published bytes (when given), stated length,
/// and stated SHA-256 digest of `case`'s `side` (`request` or `response`).
fn assert_wrapper(case: &serde_json::Value, side: &str, built: &[u8]) {
    if let Some(hex_str) = case[format!("{side}_bytes")].as_str() {
        assert_eq!(
            built,
            hex::decode(hex_str).expect("valid hex").as_slice(),
            "{side}: exact published bytes"
        );
    }
    assert_eq!(
        built.len() as u64,
        case[format!("{side}_length")].as_u64().expect("length"),
        "{side}: stated length"
    );
    assert_eq!(
        hex::encode(sha256(built)),
        case[format!("{side}_sha256")].as_str().expect("digest"),
        "{side}: stated SHA-256"
    );
}

fn resolve_request(dids: &[&str]) -> Vec<u8> {
    r_map(&[
        (r_uint(0), r_uint(1)),
        (
            r_uint(1),
            r_array(&dids.iter().map(|d| r_tstr(d)).collect::<Vec<_>>()),
        ),
    ])
}

fn full_result(envelope: &[u8]) -> Vec<u8> {
    r_map(&[(r_uint(0), r_uint(0)), (r_uint(1), r_bstr(envelope))])
}

fn error_result(code: u64) -> Vec<u8> {
    r_map(&[(r_uint(0), r_uint(3)), (r_uint(2), r_uint(code))])
}

fn resolve_response(results: &[Vec<u8>]) -> Vec<u8> {
    r_map(&[
        (r_uint(0), r_uint(1)),
        (r_uint(1), r_bstr(&directory_generation())),
        (r_uint(2), r_array(results)),
    ])
}

fn change_entry(did: &str, result: Vec<u8>, last_updated: u64) -> Vec<u8> {
    r_array(&[r_tstr(did), result, r_uint(last_updated)])
}

fn changes_success_response(entries: &[Vec<u8>], next_cursor: &[u8]) -> Vec<u8> {
    r_map(&[
        (r_uint(0), r_uint(1)),
        (r_uint(1), r_uint(0)),
        (r_uint(2), r_array(entries)),
        (r_uint(3), r_bstr(next_cursor)),
        (r_uint(4), vec![0xf4]), // false
        (r_uint(5), r_bstr(&directory_generation())),
    ])
}

#[test]
fn sec_b11_1_invalid_outer_request_reproduces() {
    // Adjacent duplicate top-level label 1 entries: {0:1, 1:[Alice], 1:[Bob]}.
    // r_map emits entries in the given order without deduplication.
    let built = r_map(&[
        (r_uint(0), r_uint(1)),
        (r_uint(1), r_array(&[r_tstr(&fx_str("followee_did"))])),
        (r_uint(1), r_array(&[r_tstr(&fx_str("bob_did"))])),
    ]);
    assert_wrapper(&b11("b11_1"), "request", &built);

    // The duplicate label is a basic-validity fault: the wrapper classifies
    // as invalidCbor at the CBOR layer (the HTTP 400 behaviour is Milestone
    // 3 scope).
    assert_eq!(
        followee::validate_cbor(
            &built,
            followee::limits::MAX_BODY_DEPTH,
            followee::limits::MAX_BODY_MEMBERS
        ),
        Err(followee::error::VerifyError::InvalidCbor)
    );
}

#[test]
fn sec_b11_2_invalid_outer_response_reproduces() {
    // {0: 1, 1: h'generation', 2: [{0: 2}]} with protocol version 1
    // non-minimally encoded as 18 01.
    let built = r_map(&[
        (r_uint(0), vec![0x18, 0x01]),
        (r_uint(1), r_bstr(&directory_generation())),
        (r_uint(2), r_array(&[r_map(&[(r_uint(0), r_uint(2))])])),
    ]);
    assert_wrapper(&b11("b11_2"), "response", &built);

    // The non-minimal encoding is a deterministic-profile fault:
    // nonDeterministicCbor, exactly as the vector states.
    assert_eq!(
        followee::validate_cbor(
            &built,
            followee::limits::MAX_BODY_DEPTH,
            followee::limits::MAX_BODY_MEMBERS
        ),
        Err(followee::error::VerifyError::NonDeterministicCbor)
    );
}

#[test]
fn sec_b11_3_resolve_candidate_isolation_bytes_reproduce() {
    let case = b11("b11_3");
    let request = resolve_request(&[&fx_str("followee_did"), &fx_str("bob_did")]);
    assert_wrapper(&case, "request", &request);

    let response = resolve_response(&[
        full_result(&fx_bytes("b8_envelope")),
        full_result(&fx_bytes("bob_envelope")),
    ]);
    assert_wrapper(&case, "response", &response);

    // The wrapper itself is deterministic and basically valid even though
    // the embedded B.8 candidate later fails candidate verification:
    // byte-string opacity keeps candidate faults out of wrapper validity.
    assert_eq!(
        followee::validate_cbor(&response, 8, 256),
        Ok(()),
        "wrapper accepts; candidate verification is a separate boundary"
    );
    assert_eq!(
        followee::verify::verify_record(&alice_did(), &fx_bytes("b8_envelope")),
        Err(followee::error::VerifyError::IdentityBindingMismatch),
        "the embedded candidate still fails under section 8.1"
    );
}

#[test]
fn sec_b11_4_duplicate_dids_and_cardinality_bytes_reproduce() {
    let case = b11("b11_4");
    let alice = fx_str("followee_did");
    let request = resolve_request(&[&alice, &alice, &fx_str("bob_did")]);
    assert_wrapper(&case, "request", &request);

    let response = resolve_response(&[
        full_result(&fx_bytes("root_record_envelope")),
        full_result(&fx_bytes("root_record_envelope")),
        full_result(&fx_bytes("bob_envelope")),
    ]);
    assert_wrapper(&case, "response", &response);
}

#[test]
fn sec_b11_5_changes_isolation_and_cursor_progress_bytes_reproduce() {
    let case = b11("b11_5");
    // {0: 1, 1: h'v08-0000', 2: 2, 3: 1048576}
    let request = r_map(&[
        (r_uint(0), r_uint(1)),
        (r_uint(1), r_bstr(&field_bytes(&case, "request_cursor"))),
        (r_uint(2), r_uint(2)),
        (r_uint(3), r_uint(1_048_576)),
    ]);
    assert_eq!(
        field_bytes(&case, "request_cursor"),
        b"v08-0000",
        "opaque cursor bytes"
    );
    assert_wrapper(&case, "request", &request);

    let next_cursor = field_bytes(&case, "next_cursor");
    assert_eq!(next_cursor, b"v08-0002");
    let response = changes_success_response(
        &[
            change_entry(
                &fx_str("followee_did"),
                full_result(&fx_bytes("b8_envelope")),
                1001,
            ),
            change_entry(
                &fx_str("bob_did"),
                full_result(&fx_bytes("bob_envelope")),
                1002,
            ),
        ],
        &next_cursor,
    );
    assert_wrapper(&case, "response", &response);
}

#[test]
fn sec_b11_6_malformed_did_inside_valid_batch_bytes_reproduce() {
    let case = b11("b11_6");
    let request = resolve_request(&[
        &fx_str("followee_did"),
        "did:flw:not-a-multibase",
        &fx_str("bob_did"),
    ]);
    assert_wrapper(&case, "request", &request);

    // The malformed middle DID is valid UTF-8 text, so the request wrapper
    // is CBOR-clean; its classification is protocol-level (Milestone 3).
    assert_eq!(followee::validate_cbor(&request, 8, 256), Ok(()));
    assert_eq!(
        followee::did::FolloweeDid::parse("did:flw:not-a-multibase"),
        Err(followee::did::DidError::InvalidDid),
        "per-DID classification is exactly invalidDid"
    );

    // Response: [Full(B.4), Error(invalidDid), Full(B.9)] — error code 0.
    let response = resolve_response(&[
        full_result(&fx_bytes("root_record_envelope")),
        error_result(0),
        full_result(&fx_bytes("bob_envelope")),
    ]);
    assert_wrapper(&case, "response", &response);
}

#[test]
fn sec_b11_7_changes_item_limit_overflow_bytes_reproduce() {
    let case = b11("b11_7");
    let rejected_cursor = field_bytes(&case, "rejected_next_cursor");
    assert_eq!(rejected_cursor, b"v08-0003");
    // Three entries against itemLimit = 2; the third is a Ref to relay
    // index 0 for the attacker's own DID.
    let ref_result = r_map(&[(r_uint(0), r_uint(1)), (r_uint(1), r_uint(0))]);
    let response = changes_success_response(
        &[
            change_entry(
                &fx_str("followee_did"),
                full_result(&fx_bytes("b8_envelope")),
                1001,
            ),
            change_entry(
                &fx_str("bob_did"),
                full_result(&fx_bytes("bob_envelope")),
                1002,
            ),
            change_entry(&fx_str("attacker_did"), ref_result, 1003),
        ],
        &rejected_cursor,
    );
    assert_wrapper(&case, "response", &response);

    // The over-limit response is CBOR-clean as a wrapper: its rejection is
    // the section 12.6 item-limit rule, not a CBOR-layer fault (Milestone 4
    // behaviour scope).
    assert_eq!(followee::validate_cbor(&response, 8, 256), Ok(()));
}
