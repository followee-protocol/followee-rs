//! Inverse handle verification (specification section 10.4; IMPLEMENTATION.md
//! section 13 Milestone 5): a signed `alsoKnownAs` value is only a claim
//! until the exact handle inversely resolves to the same locally verified
//! DID, and no handle event — disappearance, failure, reassignment — can
//! change the followed DID, cached verified identity, or sticky state.
#![allow(clippy::arithmetic_side_effects)]

mod common;

use common::*;
use followee::clock::ManualClock;
use followee::ordering::AuthorityState;
use followee::relay::client::{BudgetMeter, NetworkPolicy, OperationBudget, TransportError};
use followee::resolver::ClientState;
use followee::verify::verify_record_for_target;
use followee::webfinger::{Handle, InverseOutcome, WebFingerClient, record_handle_claim};

const ENDPOINT: &str = "http://127.0.0.1:9310/";

fn meter() -> BudgetMeter {
    BudgetMeter::new(OperationBudget {
        deadline_ms: None,
        max_response_bytes: 1024 * 1024,
        max_requests: 16,
    })
}

fn verify_via(
    transport: &MockTransport,
    handle: &str,
    record_bytes: &[u8],
    did: &str,
) -> followee::webfinger::HandleVerification {
    let clock = ManualClock::new(RELAY_NOW_MS);
    let client = WebFingerClient::new(transport, NetworkPolicy::Development, &clock);
    let handle = Handle::parse(handle).expect("handle parses");
    let record = verify_record_for_target(did, record_bytes).expect("record verifies");
    client.verify_handle(&handle, &record, Some(ENDPOINT), &mut meter())
}

fn claiming_record() -> Vec<u8> {
    alice_record_with_contact(
        RELAY_NOW_MS,
        None,
        contact_claiming(&["acct:alice@example.com"]),
    )
}

#[test]
fn sec_10_4_signed_claim_without_successful_inverse_lookup_stays_unverified() {
    // The record's signed claim is present, but the inverse lookup fails
    // (transport failure): the claim alone never verifies the handle.
    let transport = MockTransport::new();
    transport.fail(
        &webfinger_url(ENDPOINT, "acct:alice@example.com"),
        TransportError::Io("unreachable".to_owned()),
    );
    let verification = verify_via(
        &transport,
        "alice@example.com",
        &claiming_record(),
        alice_did().as_str(),
    );
    assert_eq!(
        verification.claim.as_deref(),
        Some("acct:alice@example.com"),
        "the signed claim is reported as a claim"
    );
    assert!(matches!(verification.inverse, InverseOutcome::Failed(_)));
    assert!(!verification.verified, "a claim alone is never verified");
}

#[test]
fn sec_10_4_both_directions_binding_the_same_did_verifies() {
    let transport = MockTransport::new();
    transport.on(
        &webfinger_url(ENDPOINT, "acct:alice@example.com"),
        jrd_ok(&jrd_body("acct:alice@example.com", alice_did().as_str())),
    );
    let verification = verify_via(
        &transport,
        "alice@example.com",
        &claiming_record(),
        alice_did().as_str(),
    );
    assert!(matches!(
        verification.inverse,
        InverseOutcome::Matched { .. }
    ));
    assert!(verification.verified);
}

#[test]
fn sec_10_4_inverse_lookup_to_another_did_is_not_verified() {
    // The authority reassigned (or always mapped) the handle to Bob: the
    // exact resource resolves, but to a different DID.
    let transport = MockTransport::new();
    transport.on(
        &webfinger_url(ENDPOINT, "acct:alice@example.com"),
        jrd_ok(&jrd_body("acct:alice@example.com", bob_did().as_str())),
    );
    let verification = verify_via(
        &transport,
        "alice@example.com",
        &claiming_record(),
        alice_did().as_str(),
    );
    match &verification.inverse {
        InverseOutcome::Mismatched { discovery } => {
            assert_eq!(discovery.did, bob_did());
        }
        other => panic!("expected Mismatched, got {other:?}"),
    }
    assert!(!verification.verified);
}

#[test]
fn sec_10_4_mapping_without_a_signed_claim_is_not_verified() {
    // The domain maps the handle to Alice's DID, but Alice's record does
    // not claim the handle: one direction alone is insufficient.
    let transport = MockTransport::new();
    transport.on(
        &webfinger_url(ENDPOINT, "acct:alice@example.com"),
        jrd_ok(&jrd_body("acct:alice@example.com", alice_did().as_str())),
    );
    let record = alice_record_with_contact(RELAY_NOW_MS, None, contact_claiming(&[]));
    let verification = verify_via(
        &transport,
        "alice@example.com",
        &record,
        alice_did().as_str(),
    );
    assert!(verification.claim.is_none());
    assert!(matches!(
        verification.inverse,
        InverseOutcome::Matched { .. }
    ));
    assert!(!verification.verified);
}

#[test]
fn sec_10_1_claim_matching_is_local_case_sensitive_and_domain_canonical() {
    let record = verify_record_for_target(
        alice_did().as_str(),
        &alice_record_with_contact(
            RELAY_NOW_MS,
            None,
            contact_claiming(&["acct:Alice@EXAMPLE.com", "https://alice.example/"]),
        ),
    )
    .expect("verifies");
    // The domain canonicalizes, so EXAMPLE.com matches example.com …
    let upper = Handle::parse("Alice@example.com").expect("parses");
    assert_eq!(
        record_handle_claim(&record, &upper).as_deref(),
        Some("acct:Alice@EXAMPLE.com")
    );
    // … but the local part is case-sensitive: alice ≠ Alice.
    let lower = Handle::parse("alice@example.com").expect("parses");
    assert_eq!(record_handle_claim(&record, &lower), None);
}

#[test]
fn sec_10_4_handle_disappearance_changes_no_local_state() {
    // Client state holds Alice's verified record and sticky state; the
    // handle authority then answers 404 (handle disappeared). Nothing
    // about the durable DID, cached identity, or sticky state changes.
    let mut state = ClientState::new();
    state
        .restore_cached(alice_did().as_str(), &claiming_record())
        .expect("cache restores");
    state.assume_root_revoked(bob_did().as_str());
    let before = state.clone();

    let transport = MockTransport::new();
    transport.on(
        &webfinger_url(ENDPOINT, "acct:alice@example.com"),
        status_only(404),
    );
    let verification = verify_via(
        &transport,
        "alice@example.com",
        &claiming_record(),
        alice_did().as_str(),
    );
    assert!(!verification.verified);
    assert!(matches!(verification.inverse, InverseOutcome::Failed(_)));
    assert_eq!(state, before, "no state was read or written");
    assert_eq!(
        state.get(bob_did().as_str()).expect("entry").sticky,
        AuthorityState::RootRevoked,
        "sticky state is untouched"
    );
}

#[test]
fn sec_10_4_handle_reassignment_changes_no_local_state() {
    let mut state = ClientState::new();
    state
        .restore_cached(alice_did().as_str(), &claiming_record())
        .expect("cache restores");
    let before = state.clone();

    let transport = MockTransport::new();
    transport.on(
        &webfinger_url(ENDPOINT, "acct:alice@example.com"),
        jrd_ok(&jrd_body("acct:alice@example.com", bob_did().as_str())),
    );
    let verification = verify_via(
        &transport,
        "alice@example.com",
        &claiming_record(),
        alice_did().as_str(),
    );
    assert!(!verification.verified);
    assert_eq!(state, before);
    let cached = state
        .get(alice_did().as_str())
        .and_then(|s| s.cached.as_ref())
        .expect("cached record retained");
    assert_eq!(
        verify_record_for_target(alice_did().as_str(), &cached.envelope)
            .expect("still verifies")
            .body()
            .id,
        alice_did(),
        "the followed DID is unchanged by the reassigned handle"
    );
}
