//! Optional current-record bootstrap (specification section 10.3;
//! IMPLEMENTATION.md section 13 Milestone 5): every supplied candidate is
//! opaque bytes until complete local verification, selection runs through
//! the production core with the explicit mapped DID and retained sticky
//! state, and invalid, mismatched, premature, stale, losing, and
//! post-revocation candidates never alter existing verified state.
#![allow(clippy::arithmetic_side_effects)]

mod common;

use common::*;
use followee::clock::ManualClock;
use followee::error::VerifyError;
use followee::ordering::AuthorityState;
use followee::record::Authority;
use followee::relay::client::{
    BudgetMeter, ClientError, NetworkPolicy, OperationBudget, TransportResponse,
};
use followee::resolver::ClientState;
use followee::verify::verify_record_for_target;
use followee::webfinger::{
    BootstrapOutcome, CandidateStatus, Handle, WebFingerClient, WebFingerError,
};

const ENDPOINT: &str = "http://127.0.0.1:9320/";

fn meter() -> BudgetMeter {
    BudgetMeter::new(OperationBudget {
        deadline_ms: None,
        max_response_bytes: 1024 * 1024,
        max_requests: 16,
    })
}

/// Discovers alice with the given record URLs and runs bootstrap under
/// `sticky` at RELAY_NOW_MS.
fn bootstrap_with(
    transport: &MockTransport,
    record_urls: &[&str],
    sticky: AuthorityState,
) -> BootstrapOutcome {
    let links: Vec<String> = record_urls
        .iter()
        .map(|url| {
            format!(
                r#"{{"rel":"https://w3id.org/followee/rel/record","type":"application/cose","href":"{url}"}}"#
            )
        })
        .collect();
    let body = format!(
        r#"{{"subject":"acct:alice@example.com","links":[{{"rel":"https://w3id.org/followee/rel/did","href":"{}"}},{}]}}"#,
        alice_did().as_str(),
        links.join(",")
    );
    transport.on(
        &webfinger_url(ENDPOINT, "acct:alice@example.com"),
        jrd_ok(&body),
    );
    let clock = ManualClock::new(RELAY_NOW_MS);
    let client = WebFingerClient::new(transport, NetworkPolicy::Development, &clock);
    let handle = Handle::parse("alice@example.com").expect("parses");
    let mut meter = meter();
    let discovery = client
        .lookup(&handle, Some(ENDPOINT), &mut meter)
        .expect("discovery succeeds");
    client.bootstrap(&discovery, RELAY_NOW_MS, sticky, &mut meter)
}

fn record_url(name: &str) -> String {
    format!("{ENDPOINT}record/{name}")
}

#[test]
fn sec_10_3_valid_candidate_is_verified_and_selected() {
    let transport = MockTransport::new();
    let record = alice_record_with_contact(RELAY_NOW_MS, None, contact_claiming(&[]));
    transport.on(&record_url("alice"), cose_ok(record.clone()));
    let outcome = bootstrap_with(&transport, &[&record_url("alice")], AuthorityState::Unknown);
    let winner = outcome.winner.expect("winner selected");
    assert_eq!(winner.record.envelope_bytes(), &record[..]);
    assert!(!winner.stale);
    assert_eq!(outcome.authority_state, AuthorityState::Root);
    assert!(matches!(
        outcome.candidates[0].status,
        CandidateStatus::Verified { stale: false, .. }
    ));
}

#[test]
fn sec_10_3_invalid_candidate_is_rejected_with_the_production_classification() {
    let transport = MockTransport::new();
    let mut corrupt = alice_record_with_contact(RELAY_NOW_MS, None, contact_claiming(&[]));
    let last = corrupt.len() - 1;
    corrupt[last] ^= 0x01;
    transport.on(&record_url("alice"), cose_ok(corrupt));
    let outcome = bootstrap_with(&transport, &[&record_url("alice")], AuthorityState::Unknown);
    assert!(outcome.winner.is_none());
    assert_eq!(outcome.authority_state, AuthorityState::Unknown);
    assert!(matches!(
        outcome.candidates[0].status,
        CandidateStatus::Rejected(VerifyError::InvalidSignature)
    ));
}

#[test]
fn sec_10_3_wrong_did_candidate_fails_identity_binding() {
    // Bob's perfectly valid record served for alice's mapped DID: opaque
    // bytes verified against the mapped DID, so binding fails.
    let transport = MockTransport::new();
    transport.on(
        &record_url("alice"),
        cose_ok(bob_record_with_contact(
            RELAY_NOW_MS,
            None,
            contact_claiming(&[]),
        )),
    );
    let outcome = bootstrap_with(&transport, &[&record_url("alice")], AuthorityState::Unknown);
    assert!(outcome.winner.is_none());
    assert!(matches!(
        outcome.candidates[0].status,
        CandidateStatus::Rejected(VerifyError::IdentityBindingMismatch)
    ));
}

#[test]
fn sec_10_3_premature_candidate_is_excluded_from_selection() {
    let transport = MockTransport::new();
    // One admissible older record and one premature newer record: the
    // premature one is excluded, the older admissible one wins.
    let premature = alice_record_with_contact(RELAY_NOW_MS + 300_001, None, contact_claiming(&[]));
    let admissible = alice_record_with_contact(RELAY_NOW_MS - 10, None, contact_claiming(&[]));
    transport.on(&record_url("future"), cose_ok(premature));
    transport.on(&record_url("now"), cose_ok(admissible.clone()));
    let outcome = bootstrap_with(
        &transport,
        &[&record_url("future"), &record_url("now")],
        AuthorityState::Unknown,
    );
    assert!(matches!(
        outcome.candidates[0].status,
        CandidateStatus::Premature
    ));
    let winner = outcome.winner.expect("admissible candidate wins");
    assert_eq!(winner.record.envelope_bytes(), &admissible[..]);
}

#[test]
fn sec_5_5_stale_candidate_is_admissible_but_reported_stale() {
    let transport = MockTransport::new();
    let stale = alice_record_with_contact(
        RELAY_NOW_MS - 1_000,
        Some(RELAY_NOW_MS - 1),
        contact_claiming(&[]),
    );
    transport.on(&record_url("alice"), cose_ok(stale));
    let outcome = bootstrap_with(&transport, &[&record_url("alice")], AuthorityState::Unknown);
    let winner = outcome.winner.expect("stale is admissible");
    assert!(winner.stale, "staleness is exposed, not hidden");
    assert!(matches!(
        outcome.candidates[0].status,
        CandidateStatus::Verified { stale: true, .. }
    ));
}

#[test]
fn sec_8_3_losing_candidate_does_not_displace_the_winner() {
    let transport = MockTransport::new();
    let newer = alice_record_with_contact(RELAY_NOW_MS, None, contact_claiming(&[]));
    let older = alice_record_with_contact(RELAY_NOW_MS - 5_000, None, contact_claiming(&[]));
    transport.on(&record_url("older"), cose_ok(older));
    transport.on(&record_url("newer"), cose_ok(newer.clone()));
    // Order in the JRD does not matter: selection is deterministic.
    let outcome = bootstrap_with(
        &transport,
        &[&record_url("older"), &record_url("newer")],
        AuthorityState::Unknown,
    );
    let winner = outcome.winner.expect("winner");
    assert_eq!(winner.record.envelope_bytes(), &newer[..]);
    assert_eq!(winner.source, record_url("newer"));
}

#[test]
fn sec_14_1_losing_bootstrap_record_cannot_roll_back_cached_state() {
    // Existing verified state is newer than the bootstrap candidate: the
    // production cache rule refuses the rollback.
    let newer = alice_record_with_contact(RELAY_NOW_MS, None, contact_claiming(&[]));
    let older = alice_record_with_contact(RELAY_NOW_MS - 5_000, None, contact_claiming(&[]));
    let mut state = ClientState::new();
    state
        .restore_cached(alice_did().as_str(), &newer)
        .expect("cache restores");
    let older_record =
        verify_record_for_target(alice_did().as_str(), &older).expect("older verifies");
    let replaced =
        state.record_selection(alice_did().as_str(), AuthorityState::Root, &older_record);
    assert!(!replaced, "an earlier record never replaces a later one");
    let cached = state
        .get(alice_did().as_str())
        .and_then(|s| s.cached.as_ref())
        .expect("cached");
    assert_eq!(cached.envelope, newer, "cached identity is unchanged");
}

#[test]
fn sec_8_2_root_candidate_cannot_win_under_sticky_revocation() {
    let transport = MockTransport::new();
    let root = alice_record_with_contact(RELAY_NOW_MS, None, contact_claiming(&[]));
    transport.on(&record_url("alice"), cose_ok(root));
    let outcome = bootstrap_with(
        &transport,
        &[&record_url("alice")],
        AuthorityState::RootRevoked,
    );
    assert!(outcome.winner.is_none(), "no Root record after revocation");
    assert_eq!(
        outcome.authority_state,
        AuthorityState::RootRevoked,
        "sticky state is retained, never downgraded"
    );
    assert!(
        matches!(
            outcome.candidates[0].status,
            CandidateStatus::Verified { .. }
        ),
        "the candidate itself verified; exclusion is the sticky rule"
    );
}

#[test]
fn sec_8_2_root_revoked_bootstrap_candidate_takes_absolute_precedence() {
    let transport = MockTransport::new();
    let root = alice_record_with_contact(RELAY_NOW_MS, None, contact_claiming(&[]));
    let revoked = alice_revoked_record(RELAY_NOW_MS - 60_000);
    transport.on(&record_url("root"), cose_ok(root));
    transport.on(&record_url("revoked"), cose_ok(revoked.clone()));
    let outcome = bootstrap_with(
        &transport,
        &[&record_url("root"), &record_url("revoked")],
        AuthorityState::Unknown,
    );
    let winner = outcome.winner.expect("winner");
    assert_eq!(winner.record.envelope_bytes(), &revoked[..]);
    assert_eq!(winner.record.authority(), Authority::RootRevoked);
    assert_eq!(outcome.authority_state, AuthorityState::RootRevoked);
}

#[test]
fn sec_10_3_fetch_faults_are_reported_per_candidate_without_invention() {
    let transport = MockTransport::new();
    // Wrong media type.
    transport.on(
        &record_url("wrongtype"),
        TransportResponse {
            status: 200,
            content_type: Some("application/octet-stream".to_owned()),
            location: None,
            body: alice_record_with_contact(RELAY_NOW_MS, None, contact_claiming(&[])),
        },
    );
    // 404 from the record endpoint.
    transport.on(&record_url("gone"), status_only(404));
    let good = alice_record_with_contact(RELAY_NOW_MS - 1, None, contact_claiming(&[]));
    transport.on(&record_url("good"), cose_ok(good.clone()));
    let outcome = bootstrap_with(
        &transport,
        &[
            &record_url("wrongtype"),
            &record_url("gone"),
            &record_url("good"),
        ],
        AuthorityState::Unknown,
    );
    assert!(matches!(
        &outcome.candidates[0].status,
        CandidateStatus::FetchFailed(WebFingerError::Client(ClientError::MediaType))
    ));
    assert!(matches!(
        &outcome.candidates[1].status,
        CandidateStatus::FetchFailed(WebFingerError::Client(ClientError::HttpStatus {
            status: 404
        }))
    ));
    let winner = outcome.winner.expect("remaining candidate wins");
    assert_eq!(winner.record.envelope_bytes(), &good[..]);
}

#[test]
fn sec_15_1_oversized_record_bodies_classify_exactly() {
    // One byte past the 16 KiB cap reaches the verifier and gets the
    // protocol classification; grossly larger stops at the fetch bound.
    let transport = MockTransport::new();
    transport.on(&record_url("barely"), cose_ok(vec![0u8; 16 * 1024 + 1]));
    transport.on(&record_url("huge"), cose_ok(vec![0u8; 64 * 1024]));
    let outcome = bootstrap_with(
        &transport,
        &[&record_url("barely"), &record_url("huge")],
        AuthorityState::Unknown,
    );
    assert!(matches!(
        outcome.candidates[0].status,
        CandidateStatus::Rejected(VerifyError::RecordTooLarge)
    ));
    assert!(matches!(
        &outcome.candidates[1].status,
        CandidateStatus::FetchFailed(WebFingerError::Client(ClientError::ResponseTooLarge))
    ));
}

#[test]
fn sec_10_3_record_links_without_type_or_href_are_not_bootstrap_hints() {
    let transport = MockTransport::new();
    let body = format!(
        r#"{{"subject":"acct:alice@example.com","links":[{{"rel":"https://w3id.org/followee/rel/did","href":"{}"}},{{"rel":"https://w3id.org/followee/rel/record","href":"{}"}},{{"rel":"https://w3id.org/followee/rel/record","type":"application/cbor","href":"{}"}}]}}"#,
        alice_did().as_str(),
        record_url("untyped"),
        record_url("wrongtyped"),
    );
    transport.on(
        &webfinger_url(ENDPOINT, "acct:alice@example.com"),
        jrd_ok(&body),
    );
    let clock = ManualClock::new(RELAY_NOW_MS);
    let client = WebFingerClient::new(&transport, NetworkPolicy::Development, &clock);
    let handle = Handle::parse("alice@example.com").expect("parses");
    let discovery = client
        .lookup(&handle, Some(ENDPOINT), &mut meter())
        .expect("discovery succeeds");
    assert!(
        discovery.record_links.is_empty(),
        "only rel+type+href triples are section 10.3 hints"
    );
}
