//! Multi-relay resolver tests (specification sections 9.2, 14.1, 15.5,
//! 20.3; Appendix B.11.2 continuation): deterministic traversal through the
//! production client and resolver, shared budgets, reference following,
//! cycle detection, sticky authority state, cross-DID isolation, lazy path
//! compression, and winner permutation independence.
#![allow(clippy::arithmetic_side_effects)]

mod common;

use common::*;
use followee::clock::ManualClock;
use followee::error::VerifyError;
use followee::ordering::AuthorityState;
use followee::relay::client::{NetworkPolicy, RelayClient, TransportError};
use followee::resolver::{
    ClientState, DiagEvent, Resolution, ResolveOutcome, ResolverBudgets, ResolverConfig,
    normalize_base_uri, resolve_did,
};

const R1: &str = "http://127.0.0.1:9101/";
const R2: &str = "http://127.0.0.1:9102/";
const R3: &str = "http://127.0.0.1:9103/";

fn config(relays: &[&str]) -> ResolverConfig {
    ResolverConfig {
        relays: relays.iter().map(|r| (*r).to_owned()).collect(),
        budgets: ResolverBudgets::default(),
    }
}

fn resolve_url(base: &str) -> String {
    format!("{base}v1/resolve")
}

fn directory_url(base: &str) -> String {
    format!("{base}v1/directory")
}

fn run(
    transport: &MockTransport,
    relays: &[&str],
    did: &str,
    state: &mut ClientState,
) -> Resolution {
    run_with(transport, &config(relays), did, state)
}

fn run_with(
    transport: &MockTransport,
    config: &ResolverConfig,
    did: &str,
    state: &mut ClientState,
) -> Resolution {
    let clock = ManualClock::new(RELAY_NOW_MS);
    let client = RelayClient::new(transport, NetworkPolicy::Development, &clock);
    resolve_did(did, config, &client, &clock, state).expect("valid target DID")
}

fn found(resolution: &Resolution) -> &followee::resolver::ResolvedRecord {
    match &resolution.outcome {
        ResolveOutcome::Found(record) => record,
        other => panic!("expected Found, got {other:?}"),
    }
}

fn outcome_name(resolution: &Resolution) -> &'static str {
    match resolution.outcome {
        ResolveOutcome::Found(_) => "found",
        ResolveOutcome::NotFound => "notFound",
        ResolveOutcome::TemporarilyUnavailable => "temporarilyUnavailable",
    }
}

// ---------------------------------------------------------------------------
// Continuation rules.
// ---------------------------------------------------------------------------

#[test]
fn sec_b11_2_rejected_outer_response_does_not_terminate_or_become_absent() {
    let transport = MockTransport::new();
    transport.on(
        &resolve_url(R1),
        cbor_ok(fx_bytes_at("b11", "b11_2/response_bytes")),
    );
    transport.on(
        &resolve_url(R2),
        cbor_ok(resolve_response_with(
            &b11_generation(),
            &[rr_full(&fx_bytes("root_record_envelope"))],
        )),
    );
    let mut state = ClientState::new();
    let resolution = run(&transport, &[R1, R2], alice_did().as_str(), &mut state);

    // The rejected response was neither Absent nor terminal: the second
    // selected relay was still queried and produced the winner.
    let record = found(&resolution);
    assert_eq!(
        record.record.envelope_bytes(),
        fx_bytes("root_record_envelope").as_slice()
    );
    assert!(resolution.diagnostics.iter().any(|d| d.base_uri == R1
        && d.event == DiagEvent::RejectedOuterResponse(VerifyError::NonDeterministicCbor)));
    assert_eq!(
        resolution.relays_consulted, 2,
        "both budgeted consults counted"
    );
}

#[test]
fn sec_14_1_continues_past_absent_and_error_results_to_a_further_relay() {
    // R1 Absent, R2 Error(premature), R3 valid Full: resolution continues
    // and the candidate is classified only by the client's own clock.
    let transport = MockTransport::new();
    transport.on(
        &resolve_url(R1),
        cbor_ok(resolve_response_with(&b11_generation(), &[rr_absent()])),
    );
    transport.on(
        &resolve_url(R2),
        cbor_ok(resolve_response_with(&b11_generation(), &[rr_error(10)])),
    );
    transport.on(
        &resolve_url(R3),
        cbor_ok(resolve_response_with(
            &b11_generation(),
            &[rr_full(&fx_bytes("root_record_envelope"))],
        )),
    );
    let mut state = ClientState::new();
    let resolution = run(&transport, &[R1, R2, R3], alice_did().as_str(), &mut state);
    let record = found(&resolution);
    assert_eq!(
        record.record.envelope_bytes(),
        fx_bytes("root_record_envelope").as_slice(),
        "another relay's premature diagnosis never suppresses a candidate"
    );
    assert!(!record.stale);
    assert_eq!(resolution.relays_consulted, 3);
    assert!(
        resolution
            .diagnostics
            .iter()
            .any(|d| d.base_uri == R2 && d.event == DiagEvent::RelayError(10))
    );
}

#[test]
fn sec_14_1_rejected_candidate_is_positional_and_other_relays_still_win() {
    // R1 serves the B.8 forgery; R2 serves the genuine record.
    let transport = MockTransport::new();
    transport.on(
        &resolve_url(R1),
        cbor_ok(resolve_response_with(
            &b11_generation(),
            &[rr_full(&fx_bytes("b8_envelope"))],
        )),
    );
    transport.on(
        &resolve_url(R2),
        cbor_ok(resolve_response_with(
            &b11_generation(),
            &[rr_full(&fx_bytes("root_record_envelope"))],
        )),
    );
    let mut state = ClientState::new();
    let resolution = run(&transport, &[R1, R2], alice_did().as_str(), &mut state);
    assert!(resolution.diagnostics.iter().any(|d| d.base_uri == R1
        && d.event == DiagEvent::RejectedCandidate(VerifyError::IdentityBindingMismatch)));
    assert_eq!(
        found(&resolution).record.envelope_bytes(),
        fx_bytes("root_record_envelope").as_slice()
    );
}

#[test]
fn sec_15_5_not_found_versus_temporarily_unavailable() {
    // Every selected relay consulted cleanly with Absent: notFound.
    let transport = MockTransport::new();
    for base in [R1, R2] {
        transport.on(
            &resolve_url(base),
            cbor_ok(resolve_response_with(&b11_generation(), &[rr_absent()])),
        );
    }
    let mut state = ClientState::new();
    let resolution = run(&transport, &[R1, R2], alice_did().as_str(), &mut state);
    assert_eq!(outcome_name(&resolution), "notFound");

    // One selected relay unavailable: temporarilyUnavailable, not notFound.
    let transport = MockTransport::new();
    transport.on(
        &resolve_url(R1),
        cbor_ok(resolve_response_with(&b11_generation(), &[rr_absent()])),
    );
    transport.fail(&resolve_url(R2), TransportError::TimedOut);
    let mut state = ClientState::new();
    let resolution = run(&transport, &[R1, R2], alice_did().as_str(), &mut state);
    assert_eq!(outcome_name(&resolution), "temporarilyUnavailable");
}

#[test]
fn sec_14_1_absent_and_error_results_change_no_cached_or_sticky_state() {
    let mut state = ClientState::new();
    state
        .restore_cached(alice_did().as_str(), &fx_bytes("root_record_envelope"))
        .expect("cached record restores");
    let cached_before = state.get(alice_did().as_str()).unwrap().cached.clone();

    let transport = MockTransport::new();
    transport.on(
        &resolve_url(R1),
        cbor_ok(resolve_response_with(&b11_generation(), &[rr_absent()])),
    );
    transport.on(
        &resolve_url(R2),
        cbor_ok(resolve_response_with(&b11_generation(), &[rr_error(11)])),
    );
    let resolution = run(&transport, &[R1, R2], alice_did().as_str(), &mut state);
    assert_eq!(outcome_name(&resolution), "notFound");
    let entry = state.get(alice_did().as_str()).unwrap();
    assert_eq!(entry.cached, cached_before, "cached identity unchanged");
    assert_eq!(
        entry.sticky,
        AuthorityState::Unknown,
        "a relay's rootRevoked *error code* is not a verified transition"
    );
}

// ---------------------------------------------------------------------------
// Reference traversal, compression, cycles, budgets.
// ---------------------------------------------------------------------------

/// R1 answers Ref(0) whose directory names R2; R2 serves the Full record.
fn ref_chain_transport() -> MockTransport {
    let transport = MockTransport::new();
    transport.on(
        &resolve_url(R1),
        cbor_ok(resolve_response_with(&b11_generation(), &[rr_ref(0)])),
    );
    transport.on(
        &directory_url(R1),
        cbor_ok(directory_response_with(
            &b11_generation(),
            &[(0, [0x22; 16], R2)],
        )),
    );
    transport.on(
        &resolve_url(R2),
        cbor_ok(resolve_response_with(
            &b11_generation(),
            &[rr_full(&fx_bytes("root_record_envelope"))],
        )),
    );
    transport
}

#[test]
fn sec_11_5_reference_traversal_verifies_locally_and_compresses_lazily() {
    let transport = ref_chain_transport();
    let mut state = ClientState::new();
    let resolution = run(&transport, &[R1], alice_did().as_str(), &mut state);
    let record = found(&resolution);
    assert_eq!(
        record.record.envelope_bytes(),
        fx_bytes("root_record_envelope").as_slice(),
        "the final Full candidate is verified locally"
    );
    assert_eq!(record.source, R2);
    // Lazy path compression stored only routing state, after the verified
    // traversal; identity evidence is the verified record alone.
    assert_eq!(resolution.compressed_route.as_deref(), Some(R2));
    assert_eq!(
        state.get(alice_did().as_str()).unwrap().route.as_deref(),
        Some(R2)
    );

    // The next operation asks the compressed route first.
    let transport = MockTransport::new();
    transport.on(
        &resolve_url(R2),
        cbor_ok(resolve_response_with(
            &b11_generation(),
            &[rr_full(&fx_bytes("root_record_envelope"))],
        )),
    );
    let resolution = run(&transport, &[R1], alice_did().as_str(), &mut state);
    found(&resolution);
    assert_eq!(
        transport.requests()[0].url,
        resolve_url(R2),
        "routing hint consulted first; R1 never needed"
    );
}

#[test]
fn sec_12_3_mismatched_directory_generation_makes_the_reference_unusable() {
    let transport = MockTransport::new();
    transport.on(
        &resolve_url(R1),
        cbor_ok(resolve_response_with(&b11_generation(), &[rr_ref(0)])),
    );
    transport.on(
        &directory_url(R1),
        cbor_ok(directory_response_with(&[0x5A; 16], &[(0, [0x22; 16], R2)])),
    );
    let mut state = ClientState::new();
    let resolution = run(&transport, &[R1], alice_did().as_str(), &mut state);
    assert_eq!(outcome_name(&resolution), "temporarilyUnavailable");
    assert!(
        resolution
            .diagnostics
            .iter()
            .any(|d| d.event == DiagEvent::UnusableRef)
    );
    assert!(
        !transport.requests().iter().any(|r| r.url.starts_with(R2)),
        "the stale index was never interpreted under the newer generation"
    );
}

#[test]
fn sec_14_1_reference_cycles_are_rejected_and_terminate() {
    // R1 -> Ref -> R2 -> Ref -> R1 (by URI) plus a repeated relay-id.
    let transport = MockTransport::new();
    transport.on(
        &resolve_url(R1),
        cbor_ok(resolve_response_with(&b11_generation(), &[rr_ref(0)])),
    );
    transport.on(
        &directory_url(R1),
        cbor_ok(directory_response_with(
            &b11_generation(),
            &[(0, [0x22; 16], R2)],
        )),
    );
    transport.on(
        &resolve_url(R2),
        cbor_ok(resolve_response_with(&b11_generation(), &[rr_ref(7)])),
    );
    transport.on(
        &directory_url(R2),
        cbor_ok(directory_response_with(
            &b11_generation(),
            &[(7, [0x11; 16], R1)],
        )),
    );
    let mut state = ClientState::new();
    let resolution = run(&transport, &[R1], alice_did().as_str(), &mut state);
    assert!(
        resolution
            .diagnostics
            .iter()
            .any(|d| d.event == DiagEvent::CycleRefused)
    );
    assert_eq!(
        resolution.relays_consulted, 2,
        "terminates within the budget"
    );
    assert_eq!(outcome_name(&resolution), "notFound");
}

#[test]
fn sec_14_1_reference_depth_and_visited_budgets_terminate_traversal() {
    // Depth: R1 -> R2 -> R3 with max_ref_depth = 1 stops before R3.
    let transport = MockTransport::new();
    transport.on(
        &resolve_url(R1),
        cbor_ok(resolve_response_with(&b11_generation(), &[rr_ref(0)])),
    );
    transport.on(
        &directory_url(R1),
        cbor_ok(directory_response_with(
            &b11_generation(),
            &[(0, [0x22; 16], R2)],
        )),
    );
    transport.on(
        &resolve_url(R2),
        cbor_ok(resolve_response_with(&b11_generation(), &[rr_ref(0)])),
    );
    let mut config_small = config(&[R1]);
    config_small.budgets.max_ref_depth = 1;
    let mut state = ClientState::new();
    let resolution = run_with(&transport, &config_small, alice_did().as_str(), &mut state);
    assert!(
        resolution
            .diagnostics
            .iter()
            .any(|d| matches!(d.event, DiagEvent::BudgetStopped("reference-depth budget")))
    );
    assert_eq!(outcome_name(&resolution), "temporarilyUnavailable");

    // Visited relays: two configured relays under max_relays_visited = 1.
    let transport = MockTransport::new();
    transport.on(
        &resolve_url(R1),
        cbor_ok(resolve_response_with(&b11_generation(), &[rr_absent()])),
    );
    let mut config_one = config(&[R1, R2]);
    config_one.budgets.max_relays_visited = 1;
    let mut state = ClientState::new();
    let resolution = run_with(&transport, &config_one, alice_did().as_str(), &mut state);
    assert!(
        resolution
            .diagnostics
            .iter()
            .any(|d| matches!(d.event, DiagEvent::BudgetStopped("visited-relay budget")))
    );
    assert_eq!(outcome_name(&resolution), "temporarilyUnavailable");
    assert!(
        !transport.requests().iter().any(|r| r.url.starts_with(R2)),
        "the stopped relay was never contacted"
    );
}

#[test]
fn sec_14_1_exhausted_deadline_terminates_without_a_protocol_result() {
    let transport = MockTransport::new();
    let mut config_expired = config(&[R1]);
    config_expired.budgets.deadline_duration_ms = 0;
    let mut state = ClientState::new();
    let resolution = run_with(
        &transport,
        &config_expired,
        alice_did().as_str(),
        &mut state,
    );
    assert_eq!(outcome_name(&resolution), "temporarilyUnavailable");
    assert!(
        transport.requests().is_empty(),
        "no request under an expired deadline"
    );
}

// ---------------------------------------------------------------------------
// Sticky authority state and cross-DID isolation.
// ---------------------------------------------------------------------------

#[test]
fn sec_8_2_sticky_root_revoked_survives_resolution_and_excludes_root() {
    // Learn the revocation from R1.
    let transport = MockTransport::new();
    transport.on(
        &resolve_url(R1),
        cbor_ok(resolve_response_with(
            &b11_generation(),
            &[rr_full(&fx_bytes("root_revoked_envelope"))],
        )),
    );
    let mut state = ClientState::new();
    let resolution = run(&transport, &[R1], alice_did().as_str(), &mut state);
    assert_eq!(resolution.authority_state, AuthorityState::RootRevoked);
    assert_eq!(
        found(&resolution).record.envelope_bytes(),
        fx_bytes("root_revoked_envelope").as_slice()
    );

    // A later operation offered only the Root record selects nothing and
    // retains the sticky state.
    let transport = MockTransport::new();
    transport.on(
        &resolve_url(R1),
        cbor_ok(resolve_response_with(
            &b11_generation(),
            &[rr_full(&fx_bytes("root_record_envelope"))],
        )),
    );
    let resolution = run(&transport, &[R1], alice_did().as_str(), &mut state);
    assert_eq!(outcome_name(&resolution), "notFound");
    assert_eq!(resolution.authority_state, AuthorityState::RootRevoked);
    assert_eq!(
        state.get(alice_did().as_str()).unwrap().sticky,
        AuthorityState::RootRevoked,
        "sticky state survives the operation"
    );
}

#[test]
fn sec_b9_cross_did_state_is_independent() {
    let mut state = ClientState::new();
    state.assume_root_revoked(alice_did().as_str());

    // Resolving Bob touches only Bob's entry.
    let transport = MockTransport::new();
    transport.on(
        &resolve_url(R1),
        cbor_ok(resolve_response_with(
            &b11_generation(),
            &[rr_full(&fx_bytes("bob_envelope"))],
        )),
    );
    let resolution = run(&transport, &[R1], bob_did().as_str(), &mut state);
    found(&resolution);
    assert_eq!(resolution.authority_state, AuthorityState::Root);
    assert_eq!(
        state.get(alice_did().as_str()).unwrap().sticky,
        AuthorityState::RootRevoked,
        "Alice's sticky state is untouched by Bob's resolution"
    );
    assert!(state.get(alice_did().as_str()).unwrap().cached.is_none());
    assert!(state.get(bob_did().as_str()).unwrap().cached.is_some());
}

// ---------------------------------------------------------------------------
// Winner determinism across schedules.
// ---------------------------------------------------------------------------

#[test]
fn sec_8_3_winner_is_identical_for_every_relay_schedule_permutation() {
    // Three distinct candidates for one fresh identity: an older record, a
    // newer record, and an equal-time digest rival for the newer timestamp.
    let (did, older, seed) = synthetic_record_at(42, B4_TIMESTAMP_MS, "Older");
    let newer_a = {
        use followee::record::{Authority, RecordBody, sign_record};
        let descriptor = {
            let parsed = followee::verify::verify_record_for_target(&did, &older).unwrap();
            parsed.body().descriptor.clone()
        };
        let make = |name: &str| {
            let contact = followee::contact::ContactDocument {
                display_name: Some(name.to_owned()),
                ..Default::default()
            };
            let body = RecordBody {
                id: followee::did::FolloweeDid::parse(&did).unwrap(),
                timestamp_ms: B4_TIMESTAMP_MS + 500,
                authority: Authority::Root,
                descriptor: descriptor.clone(),
                revocation_key: None,
                valid_until_ms: None,
                contact,
                extensions: Default::default(),
            };
            sign_record(&body, &seed).expect("signs")
        };
        [make("Rival X"), make("Rival Y")]
    };
    let [rival_x, rival_y] = newer_a;
    let expected_winner = {
        // The production selection entry point decides the expected winner;
        // the permutation assertion is that traversal order cannot change it.
        let records: Vec<_> = [&older, &rival_x, &rival_y]
            .iter()
            .map(|e| followee::verify::verify_record_for_target(&did, e).unwrap())
            .collect();
        let target = followee::did::FolloweeDid::parse(&did).unwrap();
        let selection = followee::ordering::select_current(
            &target,
            &records,
            RELAY_NOW_MS,
            AuthorityState::Unknown,
        );
        *selection.winner.expect("one winner").body_digest()
    };

    let candidates = [&older, &rival_x, &rival_y];
    let orders: [[usize; 3]; 6] = [
        [0, 1, 2],
        [0, 2, 1],
        [1, 0, 2],
        [1, 2, 0],
        [2, 0, 1],
        [2, 1, 0],
    ];
    for order in orders {
        let transport = MockTransport::new();
        for (slot, candidate_index) in order.iter().enumerate() {
            let base = [R1, R2, R3][slot];
            transport.on(
                &resolve_url(base),
                cbor_ok(resolve_response_with(
                    &b11_generation(),
                    &[rr_full(candidates[*candidate_index])],
                )),
            );
        }
        let mut state = ClientState::new();
        let resolution = run(&transport, &[R1, R2, R3], &did, &mut state);
        assert_eq!(
            found(&resolution).record.body_digest(),
            &expected_winner,
            "schedule {order:?} changed the winner"
        );
    }
}

// ---------------------------------------------------------------------------
// Normalization.
// ---------------------------------------------------------------------------

#[test]
fn sec_14_1_base_uri_normalization_for_accounting() {
    assert_eq!(
        normalize_base_uri("HTTPS://Relay.Example:443/followee/"),
        "https://relay.example/followee/"
    );
    assert_eq!(
        normalize_base_uri("http://127.0.0.1:8080/a/../b/"),
        "http://127.0.0.1:8080/b/"
    );
    assert_eq!(
        normalize_base_uri("https://relay.example/%7Euser/"),
        "https://relay.example/~user/"
    );
    // The same relay under two spellings is one visited URI.
    let transport = MockTransport::new();
    transport.on(
        &resolve_url(R1),
        cbor_ok(resolve_response_with(&b11_generation(), &[rr_absent()])),
    );
    let mut state = ClientState::new();
    let resolution = run(
        &transport,
        &[R1, "HTTP://127.0.0.1:9101/"],
        alice_did().as_str(),
        &mut state,
    );
    assert_eq!(
        resolution.relays_consulted, 1,
        "deduplicated by normalization"
    );
    assert_eq!(outcome_name(&resolution), "notFound");
}

// ---------------------------------------------------------------------------
// Rejected outer response leaves cached identity intact (state assertion
// for the B.11.2 gate).
// ---------------------------------------------------------------------------

#[test]
fn sec_b11_2_rejected_outer_response_mutates_no_state() {
    let mut state = ClientState::new();
    state
        .restore_cached(alice_did().as_str(), &fx_bytes("root_record_envelope"))
        .expect("cache restores");
    state.assume_root_revoked(bob_did().as_str());
    let before_alice = state.get(alice_did().as_str()).cloned();
    let before_bob = state.get(bob_did().as_str()).cloned();

    let transport = MockTransport::new();
    transport.on(
        &resolve_url(R1),
        cbor_ok(fx_bytes_at("b11", "b11_2/response_bytes")),
    );
    let resolution = run(&transport, &[R1], alice_did().as_str(), &mut state);
    assert_eq!(outcome_name(&resolution), "temporarilyUnavailable");
    assert_eq!(state.get(alice_did().as_str()).cloned(), before_alice);
    assert_eq!(state.get(bob_did().as_str()).cloned(), before_bob);
}

#[test]
fn sec_14_1_default_port_removal_in_normalization() {
    assert_eq!(
        normalize_base_uri("http://relay.example:80/f/"),
        "http://relay.example/f/"
    );
    assert_eq!(
        normalize_base_uri("https://relay.example:443/"),
        "https://relay.example/"
    );
    assert_eq!(
        normalize_base_uri("http://relay.example:8080/"),
        "http://relay.example:8080/",
        "non-default ports are kept"
    );
}

#[test]
fn sec_14_1_reference_depth_exactly_at_the_budget_is_permitted() {
    // A one-hop reference chain with max_ref_depth = 1: depth 1 is within
    // the budget, so the traversal completes and verifies the Full.
    let transport = ref_chain_transport();
    let mut config_one = config(&[R1]);
    config_one.budgets.max_ref_depth = 1;
    let mut state = ClientState::new();
    let resolution = run_with(&transport, &config_one, alice_did().as_str(), &mut state);
    assert_eq!(
        found(&resolution).record.envelope_bytes(),
        fx_bytes("root_record_envelope").as_slice(),
        "depth exactly at the budget traverses"
    );
}

#[test]
fn sec_14_1_cached_record_is_not_replaced_by_an_earlier_winner() {
    // Cache the newer record, then resolve against a relay serving only the
    // older one: the older record wins this operation (sole candidate) but
    // must not displace the cached later record (section 14.1 SHOULD NOT).
    let (did, older, seed) = synthetic_record_at(77, B4_TIMESTAMP_MS, "Old");
    let newer = {
        use followee::record::{Authority, RecordBody, sign_record};
        let descriptor = followee::verify::verify_record_for_target(&did, &older)
            .unwrap()
            .body()
            .descriptor
            .clone();
        let body = RecordBody {
            id: followee::did::FolloweeDid::parse(&did).unwrap(),
            timestamp_ms: B4_TIMESTAMP_MS + 999,
            authority: Authority::Root,
            descriptor,
            revocation_key: None,
            valid_until_ms: None,
            contact: Default::default(),
            extensions: Default::default(),
        };
        sign_record(&body, &seed).expect("signs")
    };
    let mut state = ClientState::new();
    state.restore_cached(&did, &newer).expect("cache newer");
    let transport = MockTransport::new();
    transport.on(
        &resolve_url(R1),
        cbor_ok(resolve_response_with(&b11_generation(), &[rr_full(&older)])),
    );
    let resolution = run(&transport, &[R1], &did, &mut state);
    assert_eq!(
        found(&resolution).record.envelope_bytes(),
        older.as_slice(),
        "the operation's winner is the only admissible candidate"
    );
    let cached = state.get(&did).unwrap().cached.as_ref().unwrap();
    assert_eq!(
        cached.timestamp_ms,
        B4_TIMESTAMP_MS + 999,
        "the cached later record was not rolled back"
    );
}

#[test]
fn sec_8_2_root_revoked_transition_replaces_the_cache_even_at_lower_timestamp() {
    // The revocation record's timestamp is *below* the cached Root record's:
    // authority transition, not ordering, drives the replacement.
    use followee::record::{Authority, AuthorityDescriptor, RecordBody, sign_record};
    let root_seed = {
        let mut s = [0u8; 32];
        s[0] = 0x91;
        s
    };
    let revocation_seed = {
        let mut s = [0u8; 32];
        s[0] = 0x92;
        s
    };
    let revocation_public = followee::crypto::ed25519_public_key(&revocation_seed);
    let descriptor = AuthorityDescriptor {
        root_key: followee::crypto::ed25519_public_key(&root_seed),
        revocation_commitment: followee::record::revocation_commitment(&revocation_public),
    };
    let did = descriptor.did();
    let root_record = sign_record(
        &RecordBody {
            id: did.clone(),
            timestamp_ms: B4_TIMESTAMP_MS + 500,
            authority: Authority::Root,
            descriptor: descriptor.clone(),
            revocation_key: None,
            valid_until_ms: None,
            contact: Default::default(),
            extensions: Default::default(),
        },
        &root_seed,
    )
    .expect("root signs");
    let revoked_record = sign_record(
        &RecordBody {
            id: did.clone(),
            timestamp_ms: B4_TIMESTAMP_MS,
            authority: Authority::RootRevoked,
            descriptor,
            revocation_key: Some(revocation_public),
            valid_until_ms: None,
            contact: Default::default(),
            extensions: Default::default(),
        },
        &revocation_seed,
    )
    .expect("revocation signs");

    let mut state = ClientState::new();
    state
        .restore_cached(did.as_str(), &root_record)
        .expect("cache root");
    let transport = MockTransport::new();
    transport.on(
        &resolve_url(R1),
        cbor_ok(resolve_response_with(
            &b11_generation(),
            &[rr_full(&revoked_record)],
        )),
    );
    let resolution = run(&transport, &[R1], did.as_str(), &mut state);
    assert_eq!(resolution.authority_state, AuthorityState::RootRevoked);
    let entry = state.get(did.as_str()).unwrap();
    assert_eq!(entry.sticky, AuthorityState::RootRevoked);
    let cached = entry.cached.as_ref().unwrap();
    assert_eq!(
        cached.authority,
        followee::record::Authority::RootRevoked,
        "the transition replaces the cached Root record despite its lower timestamp"
    );
    assert_eq!(cached.envelope, revoked_record);
}

#[test]
fn sec_11_5_direct_wins_never_create_a_routing_hint() {
    // Path compression is lazy and applies only after reference traversal:
    // a winner obtained directly from a configured relay stores no route.
    let transport = MockTransport::new();
    transport.on(
        &resolve_url(R1),
        cbor_ok(resolve_response_with(
            &b11_generation(),
            &[rr_full(&fx_bytes("root_record_envelope"))],
        )),
    );
    let mut state = ClientState::new();
    let resolution = run(&transport, &[R1], alice_did().as_str(), &mut state);
    found(&resolution);
    assert_eq!(resolution.compressed_route, None);
    assert_eq!(
        state.get(alice_did().as_str()).unwrap().route,
        None,
        "no routing hint for a depth-zero win"
    );
}
