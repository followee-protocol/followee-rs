//! Migration presentation states (specification sections 7.4 and
//! 14.2–14.4; IMPLEMENTATION.md section 13 Milestone 5): all three
//! normative states, the distinction between one-way and reciprocal
//! claims, shared aggregate budgets across migration hops, and the
//! absence of any automatic re-following or durable-DID mutation.
#![allow(clippy::arithmetic_side_effects)]

mod common;

use common::*;
use followee::clock::ManualClock;
use followee::relay::client::{NetworkPolicy, RelayClient};
use followee::resolver::{
    ClientState, MigrationCheck, MigrationDirection, MigrationState, OperationScope,
    ResolveOutcome, ResolverBudgets, ResolverConfig, check_migration, resolve_did_in_scope,
};

const R1: &str = "http://127.0.0.1:9401/";
const R2: &str = "http://127.0.0.1:9402/";

fn resolve_url(base: &str) -> String {
    format!("{base}v1/resolve")
}

fn config(relays: &[&str], budgets: ResolverBudgets) -> ResolverConfig {
    ResolverConfig {
        relays: relays.iter().map(|r| (*r).to_owned()).collect(),
        budgets,
    }
}

/// Resolves alice through the shared scope and immediately checks her
/// winning record's migration claims within the same scope.
fn run_checks(
    transport: &MockTransport,
    config: &ResolverConfig,
    state: &mut ClientState,
) -> Vec<MigrationCheck> {
    let clock = ManualClock::new(RELAY_NOW_MS);
    let client = RelayClient::new(transport, NetworkPolicy::Development, &clock);
    let mut scope = OperationScope::new(&config.budgets, RELAY_NOW_MS);
    let resolution = resolve_did_in_scope(
        alice_did().as_str(),
        config,
        &client,
        &clock,
        state,
        &mut scope,
    )
    .expect("target DID parses");
    let ResolveOutcome::Found(found) = &resolution.outcome else {
        panic!("alice must resolve, got {:?}", resolution.outcome);
    };
    check_migration(
        found,
        &alice_did(),
        config,
        &client,
        &clock,
        state,
        &mut scope,
    )
}

fn alice_with_successor(valid_until_ms: Option<u64>) -> Vec<u8> {
    alice_record_with_contact(
        RELAY_NOW_MS - 1_000,
        valid_until_ms,
        contact_with_migration(None, Some(&bob_did())),
    )
}

fn bob_with_predecessor(valid_until_ms: Option<u64>) -> Vec<u8> {
    bob_record_with_contact(
        RELAY_NOW_MS - 1_000,
        valid_until_ms,
        contact_with_migration(Some(&alice_did()), None),
    )
}

fn bob_without_migration() -> Vec<u8> {
    bob_record_with_contact(RELAY_NOW_MS - 1_000, None, contact_claiming(&[]))
}

#[test]
fn sec_14_2_reciprocal_fresh_records_are_verified() {
    let transport = MockTransport::new();
    transport.on(
        &resolve_url(R1),
        cbor_ok(resolve_response_with(
            &b11_generation(),
            &[rr_full(&alice_with_successor(None))],
        )),
    );
    transport.on(
        &resolve_url(R1),
        cbor_ok(resolve_response_with(
            &b11_generation(),
            &[rr_full(&bob_with_predecessor(None))],
        )),
    );
    let mut state = ClientState::new();
    let checks = run_checks(
        &transport,
        &config(&[R1], ResolverBudgets::default()),
        &mut state,
    );
    assert_eq!(checks.len(), 1);
    assert_eq!(checks[0].direction, MigrationDirection::Successor);
    assert_eq!(checks[0].counterpart, bob_did().as_str());
    assert_eq!(checks[0].state, MigrationState::Verified);
    assert_eq!(checks[0].reason, "reciprocal");
}

#[test]
fn sec_14_2_one_way_claim_is_checked_but_unverified() {
    let transport = MockTransport::new();
    transport.on(
        &resolve_url(R1),
        cbor_ok(resolve_response_with(
            &b11_generation(),
            &[rr_full(&alice_with_successor(None))],
        )),
    );
    transport.on(
        &resolve_url(R1),
        cbor_ok(resolve_response_with(
            &b11_generation(),
            &[rr_full(&bob_without_migration())],
        )),
    );
    let mut state = ClientState::new();
    let checks = run_checks(
        &transport,
        &config(&[R1], ResolverBudgets::default()),
        &mut state,
    );
    assert_eq!(checks[0].state, MigrationState::CheckedButUnverified);
    assert_eq!(checks[0].reason, "nonReciprocal");
}

#[test]
fn sec_14_3_predecessor_impersonation_is_suppressed_not_presented() {
    // Alice's record self-asserts famous Bob as predecessor; Bob's winning
    // fresh record does not reciprocate. The claim is Checked but
    // unverified — never presented as provenance or succession.
    let alice = alice_record_with_contact(
        RELAY_NOW_MS - 1_000,
        None,
        contact_with_migration(Some(&bob_did()), None),
    );
    let transport = MockTransport::new();
    transport.on(
        &resolve_url(R1),
        cbor_ok(resolve_response_with(&b11_generation(), &[rr_full(&alice)])),
    );
    transport.on(
        &resolve_url(R1),
        cbor_ok(resolve_response_with(
            &b11_generation(),
            &[rr_full(&bob_without_migration())],
        )),
    );
    let mut state = ClientState::new();
    let checks = run_checks(
        &transport,
        &config(&[R1], ResolverBudgets::default()),
        &mut state,
    );
    assert_eq!(checks[0].direction, MigrationDirection::Predecessor);
    assert_eq!(checks[0].state, MigrationState::CheckedButUnverified);
    assert_ne!(checks[0].state, MigrationState::Verified);
}

#[test]
fn sec_14_2_absent_counterpart_is_not_checked_not_a_negative_result() {
    let transport = MockTransport::new();
    transport.on(
        &resolve_url(R1),
        cbor_ok(resolve_response_with(
            &b11_generation(),
            &[rr_full(&alice_with_successor(None))],
        )),
    );
    transport.on(
        &resolve_url(R1),
        cbor_ok(resolve_response_with(&b11_generation(), &[rr_absent()])),
    );
    let mut state = ClientState::new();
    let checks = run_checks(
        &transport,
        &config(&[R1], ResolverBudgets::default()),
        &mut state,
    );
    assert_eq!(checks[0].state, MigrationState::NotChecked);
    assert_eq!(checks[0].reason, "noAdmissibleCounterpart");
}

#[test]
fn sec_14_2_unavailable_counterpart_is_not_checked() {
    let transport = MockTransport::new();
    transport.on(
        &resolve_url(R1),
        cbor_ok(resolve_response_with(
            &b11_generation(),
            &[rr_full(&alice_with_successor(None))],
        )),
    );
    transport.on(&resolve_url(R1), status_only(500));
    let mut state = ClientState::new();
    let checks = run_checks(
        &transport,
        &config(&[R1], ResolverBudgets::default()),
        &mut state,
    );
    assert_eq!(checks[0].state, MigrationState::NotChecked);
    assert_eq!(checks[0].reason, "counterpartUnavailable");
}

#[test]
fn sec_14_2_stale_claimant_is_checked_but_unverified() {
    // Specification v0.9.1 (resolving SQ-20): alice's own winning record
    // is stale but admissible, and Bob's fresh record reciprocates. The
    // check must complete — the counterpart is resolved — and the
    // completed check fails with claimantStale. Staleness alone must
    // never produce NotChecked.
    let transport = MockTransport::new();
    transport.on(
        &resolve_url(R1),
        cbor_ok(resolve_response_with(
            &b11_generation(),
            &[rr_full(&alice_with_successor(Some(RELAY_NOW_MS - 1)))],
        )),
    );
    transport.on(
        &resolve_url(R1),
        cbor_ok(resolve_response_with(
            &b11_generation(),
            &[rr_full(&bob_with_predecessor(None))],
        )),
    );
    let mut state = ClientState::new();
    let checks = run_checks(
        &transport,
        &config(&[R1], ResolverBudgets::default()),
        &mut state,
    );
    assert_eq!(checks[0].state, MigrationState::CheckedButUnverified);
    assert_eq!(checks[0].reason, "claimantStale");
    assert_ne!(checks[0].state, MigrationState::Verified, "suppressed");
    assert_eq!(
        transport.requests().len(),
        2,
        "the counterpart was resolved: the check completed"
    );
    // Durable identity and sticky state are untouched by the failed
    // check: alice's entry still caches her own (stale) winning record.
    let cached = state
        .get(alice_did().as_str())
        .and_then(|s| s.cached.as_ref())
        .expect("alice cached");
    assert_eq!(
        cached.envelope,
        alice_with_successor(Some(RELAY_NOW_MS - 1))
    );
    assert_eq!(
        state.get(alice_did().as_str()).expect("entry").sticky,
        followee::ordering::AuthorityState::Root
    );
}

#[test]
fn sec_14_2_stale_counterpart_is_checked_but_unverified_even_when_reciprocal() {
    // Specification v0.9.1 (resolving SQ-20): Bob's winning admissible
    // record reciprocates but is stale. The check completed against both
    // winning admissible records, so the state is CheckedButUnverified
    // with counterpartStale — not NotChecked, and never Verified.
    let transport = MockTransport::new();
    transport.on(
        &resolve_url(R1),
        cbor_ok(resolve_response_with(
            &b11_generation(),
            &[rr_full(&alice_with_successor(None))],
        )),
    );
    transport.on(
        &resolve_url(R1),
        cbor_ok(resolve_response_with(
            &b11_generation(),
            &[rr_full(&bob_with_predecessor(Some(RELAY_NOW_MS - 1)))],
        )),
    );
    let mut state = ClientState::new();
    let checks = run_checks(
        &transport,
        &config(&[R1], ResolverBudgets::default()),
        &mut state,
    );
    assert_eq!(checks[0].state, MigrationState::CheckedButUnverified);
    assert_eq!(checks[0].reason, "counterpartStale");
    assert_ne!(checks[0].state, MigrationState::Verified, "suppressed");
    // Durable identity and sticky state are untouched for both DIDs;
    // Bob's entry carries only his own locally verified record.
    let alice_cached = state
        .get(alice_did().as_str())
        .and_then(|s| s.cached.as_ref())
        .expect("alice cached");
    assert_eq!(alice_cached.envelope, alice_with_successor(None));
    assert_eq!(
        state.get(alice_did().as_str()).expect("entry").sticky,
        followee::ordering::AuthorityState::Root
    );
    assert_eq!(
        state.get(bob_did().as_str()).expect("entry").sticky,
        followee::ordering::AuthorityState::Root,
        "no sticky mutation from a failed migration check"
    );
}

#[test]
fn sec_14_2_stale_and_non_reciprocal_claims_stay_checked_but_unverified() {
    // A stale claimant with a non-reciprocating counterpart is still a
    // completed, failed check; the claimant-side reason takes precedence
    // in diagnostics but the state is identical.
    let transport = MockTransport::new();
    transport.on(
        &resolve_url(R1),
        cbor_ok(resolve_response_with(
            &b11_generation(),
            &[rr_full(&alice_with_successor(Some(RELAY_NOW_MS - 1)))],
        )),
    );
    transport.on(
        &resolve_url(R1),
        cbor_ok(resolve_response_with(
            &b11_generation(),
            &[rr_full(&bob_without_migration())],
        )),
    );
    let mut state = ClientState::new();
    let checks = run_checks(
        &transport,
        &config(&[R1], ResolverBudgets::default()),
        &mut state,
    );
    assert_eq!(checks[0].state, MigrationState::CheckedButUnverified);
    assert_eq!(checks[0].reason, "claimantStale");
}

#[test]
fn sec_14_1_migration_hop_budget_is_enforced() {
    let transport = MockTransport::new();
    transport.on(
        &resolve_url(R1),
        cbor_ok(resolve_response_with(
            &b11_generation(),
            &[rr_full(&alice_with_successor(None))],
        )),
    );
    let budgets = ResolverBudgets {
        max_migration_hops: 0,
        ..ResolverBudgets::default()
    };
    let mut state = ClientState::new();
    let checks = run_checks(&transport, &config(&[R1], budgets), &mut state);
    assert_eq!(checks[0].state, MigrationState::NotChecked);
    assert_eq!(checks[0].reason, "migrationHopBudget");
    assert_eq!(transport.requests().len(), 1, "no hop request was issued");
}

#[test]
fn sec_14_1_one_counterpart_in_both_directions_spends_one_hop() {
    // Alice claims Bob as both predecessor and successor; Bob's record
    // reciprocates only the successor direction (predecessor = alice).
    let alice = alice_record_with_contact(
        RELAY_NOW_MS - 1_000,
        None,
        contact_with_migration(Some(&bob_did()), Some(&bob_did())),
    );
    let transport = MockTransport::new();
    transport.on(
        &resolve_url(R1),
        cbor_ok(resolve_response_with(&b11_generation(), &[rr_full(&alice)])),
    );
    transport.on(
        &resolve_url(R1),
        cbor_ok(resolve_response_with(
            &b11_generation(),
            &[rr_full(&bob_with_predecessor(None))],
        )),
    );
    let mut state = ClientState::new();
    let checks = run_checks(
        &transport,
        &config(&[R1], ResolverBudgets::default()),
        &mut state,
    );
    assert_eq!(checks.len(), 2);
    // Direction Predecessor requires bob.successor = alice: absent.
    assert_eq!(checks[0].direction, MigrationDirection::Predecessor);
    assert_eq!(checks[0].state, MigrationState::CheckedButUnverified);
    // Direction Successor requires bob.predecessor = alice: present.
    assert_eq!(checks[1].direction, MigrationDirection::Successor);
    assert_eq!(checks[1].state, MigrationState::Verified);
    assert_eq!(
        transport.requests().len(),
        2,
        "one alice resolution plus exactly one shared bob resolution"
    );
}

#[test]
fn sec_14_1_migration_hops_share_the_distinct_relay_budget() {
    // Two configured relays but a distinct-relay budget of one: the
    // primary resolution consumes it on R1; the migration hop may re-use
    // R1 (already contacted) but can never reach R2.
    let transport = MockTransport::new();
    transport.on(
        &resolve_url(R1),
        cbor_ok(resolve_response_with(
            &b11_generation(),
            &[rr_full(&alice_with_successor(None))],
        )),
    );
    // R1's answer for bob: absent. R2 would have bob's record but must
    // never be contacted.
    transport.on(
        &resolve_url(R1),
        cbor_ok(resolve_response_with(&b11_generation(), &[rr_absent()])),
    );
    transport.on(
        &resolve_url(R2),
        cbor_ok(resolve_response_with(
            &b11_generation(),
            &[rr_full(&bob_with_predecessor(None))],
        )),
    );
    let budgets = ResolverBudgets {
        max_relays_visited: 1,
        ..ResolverBudgets::default()
    };
    let mut state = ClientState::new();
    let checks = run_checks(&transport, &config(&[R1, R2], budgets), &mut state);
    // The counterpart could not be completely resolved within the shared
    // budgets: not a negative result.
    assert_eq!(checks[0].state, MigrationState::NotChecked);
    assert_eq!(checks[0].reason, "counterpartUnavailable");
    assert!(
        transport.requests().iter().all(|r| !r.url.starts_with(R2)),
        "the migration hop never reset or bypassed the distinct-relay budget"
    );
}

#[test]
fn sec_7_4_verified_migration_never_re_follows_or_mutates_the_durable_did() {
    let alice = alice_with_successor(None);
    let transport = MockTransport::new();
    transport.on(
        &resolve_url(R1),
        cbor_ok(resolve_response_with(&b11_generation(), &[rr_full(&alice)])),
    );
    transport.on(
        &resolve_url(R1),
        cbor_ok(resolve_response_with(
            &b11_generation(),
            &[rr_full(&bob_with_predecessor(None))],
        )),
    );
    let mut state = ClientState::new();
    let checks = run_checks(
        &transport,
        &config(&[R1], ResolverBudgets::default()),
        &mut state,
    );
    assert_eq!(checks[0].state, MigrationState::Verified);
    // Alice's entry still caches Alice's own record: nothing replaced the
    // followed identity with the successor.
    let cached = state
        .get(alice_did().as_str())
        .and_then(|s| s.cached.as_ref())
        .expect("alice cached");
    assert_eq!(cached.envelope, alice);
    // Bob's entry is ordinary per-DID cache from his own verification —
    // routing/cache state, not a following-list mutation.
    assert!(state.get(bob_did().as_str()).is_some());
}
