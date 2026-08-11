//! Synchronization-receiver tests (specification sections 12.6, 12.7, 13.3,
//! 16.16, 20.2; Appendix B.11.5 and B.11.7): the production receiver drives
//! the production client over exact published bytes, reuses the ordinary
//! ingress path, advances the peer cursor exactly, and isolates every
//! rejected, losing, premature, or Ref entry — on both storage backends.
#![allow(clippy::arithmetic_side_effects)]

mod common;

use common::*;
use followee::error::VerifyError;
use followee::ordering::AuthorityState;
use followee::record::Authority;
use followee::relay::client::{
    BudgetMeter, ClientError, NetworkPolicy, OperationBudget, RelayClient,
};
use followee::relay::sync::{SyncError, SyncOptions, SyncReport};
use followee::store::sqlite::SqliteStore;
use followee::store::{
    EntryPayload, MemoryStore, OrderingMeta, PeerState, RelayStore, StoredEntry,
};

const PEER_BASE: &str = "http://127.0.0.1:9001/";
const PEER_INFO_URL: &str = "http://127.0.0.1:9001/v1/info";
const PEER_CHANGES_URL: &str = "http://127.0.0.1:9001/v1/changes";
const PEER_ID: [u8; 16] = [0x77; 16];

fn wide_meter() -> BudgetMeter {
    BudgetMeter::new(BUDGET)
}

const BUDGET: OperationBudget = OperationBudget {
    deadline_ms: None,
    max_response_bytes: 64 * 1024 * 1024,
    max_requests: 64,
};

fn peer_info_body() -> Vec<u8> {
    info_response(&PEER_ID, &[0xC7; 16], &b11_generation())
}

/// Seeds the receiver with Alice's exact B.4 entry at `lastUpdated = 41`
/// and local update counter 41, Bob absent (the B.11.5/B.11.7 initial
/// state), by committing Alice through the store contract 41 times.
fn seed_b11_receiver(t: &TestRelay) {
    let envelope = fx_bytes("root_record_envelope");
    let meta = OrderingMeta {
        authority: Authority::Root,
        timestamp_ms: B4_TIMESTAMP_MS,
        body_digest: fx32("root_body_digest"),
    };
    t.relay
        .with_store(|store| {
            for _ in 0..41 {
                store.commit_current(
                    alice_did().as_str(),
                    &envelope,
                    AuthorityState::Root,
                    meta,
                )?;
            }
            store.set_peer_state(&PeerState {
                relay_id: PEER_ID,
                endpoint: PEER_BASE.to_owned(),
                cursor: Some(b"v08-0000".to_vec()),
            })
        })
        .expect("seed");
    assert_eq!(
        t.relay.with_store(|s| s.last_update_number()).unwrap(),
        41,
        "seeded local update counter"
    );
}

fn alice_entry(t: &TestRelay) -> Option<StoredEntry> {
    t.relay
        .with_store(|store| store.entry(alice_did().as_str()))
        .expect("read Alice")
}

fn stored_cursor(t: &TestRelay) -> Option<Vec<u8>> {
    t.relay
        .with_store(|store| store.peer_state(&PEER_ID))
        .expect("read peer")
        .and_then(|p| p.cursor)
}

/// The exact B.11.5 response bytes: `[Alice -> B.8 @1001, Bob -> B.9 @1002]`
/// with `nextCursor = "v08-0002"`.
fn b11_5_response() -> Vec<u8> {
    let response = changes_success_with(
        &b11_generation(),
        &[
            ch_entry(
                alice_did().as_str(),
                rr_full(&fx_bytes("b8_envelope")),
                1001,
            ),
            ch_entry(bob_did().as_str(), rr_full(&fx_bytes("bob_envelope")), 1002),
        ],
        b"v08-0002",
        false,
    );
    assert_eq!(response.len(), 879, "B.11.5 stated response length");
    assert_eq!(
        hex::encode(followee::crypto::sha256(&response)),
        "3337aa0be1d6b8cbf856a31657490398a4b778de586e0b292da68c5c26c200f2",
        "B.11.5 stated response digest"
    );
    response
}

/// The exact B.11.7 three-entry over-limit response bytes.
fn b11_7_response() -> Vec<u8> {
    let response = changes_success_with(
        &b11_generation(),
        &[
            ch_entry(
                alice_did().as_str(),
                rr_full(&fx_bytes("b8_envelope")),
                1001,
            ),
            ch_entry(bob_did().as_str(), rr_full(&fx_bytes("bob_envelope")), 1002),
            ch_entry(attacker_did().as_str(), rr_ref(0), 1003),
        ],
        b"v08-0003",
        false,
    );
    assert_eq!(response.len(), 945, "B.11.7 stated response length");
    assert_eq!(
        hex::encode(followee::crypto::sha256(&response)),
        "334740ea2ce15b4b70dfcdd88f4cfc7f31bfd53f1b7615aa08df1c4137f4d795",
        "B.11.7 stated response digest"
    );
    response
}

fn sync(
    t: &TestRelay,
    transport: &MockTransport,
    options: &SyncOptions,
) -> Result<SyncReport, SyncError> {
    let client = RelayClient::new(transport, NetworkPolicy::Development, &*t.clock);
    let mut meter = wide_meter();
    t.relay.sync_once(&client, PEER_BASE, options, &mut meter)
}

fn b11_options() -> SyncOptions {
    SyncOptions {
        item_limit: 2,
        byte_limit: 1_048_576,
        max_pages: 1,
    }
}

/// Runs one scenario against both production backends (contract parity).
fn on_both_backends(scenario: impl Fn(TestRelay)) {
    scenario(memory_relay());
    let sqlite = SqliteStore::open_in_memory(test_identity()).expect("sqlite");
    scenario(relay_over(Box::new(sqlite)));
}

// ---------------------------------------------------------------------------
// B.11.5: isolation and exact cursor progress.
// ---------------------------------------------------------------------------

#[test]
fn sec_b11_5_cursor_advances_exactly_and_only_bob_receives_an_update() {
    on_both_backends(|t| {
        seed_b11_receiver(&t);
        let before = alice_entry(&t).expect("Alice seeded");

        let transport = MockTransport::new();
        transport.on(PEER_INFO_URL, cbor_ok(peer_info_body()));
        transport.on(PEER_CHANGES_URL, cbor_ok(b11_5_response()));
        let report = sync(&t, &transport, &b11_options()).expect("accepted response");

        // The receiver sent the exact published B.11.5 request bytes.
        assert_eq!(
            transport.requests()[1].body,
            fx_bytes_at("b11", "b11_5/request_bytes"),
            "exact B.11.5 request: stored cursor v08-0000, itemLimit 2"
        );

        // 1. Alice's complete local entry is byte-for-byte unchanged.
        let after = alice_entry(&t).expect("Alice still present");
        assert_eq!(
            after, before,
            "envelope, authority state, ordering, lastUpdated"
        );
        assert_eq!(
            after.payload,
            EntryPayload::Full(fx_bytes("root_record_envelope"))
        );
        assert_eq!(after.last_updated, 41);

        // 2–3. Bob is admitted as current Root state with the sole new
        // local update number 42; sender lastUpdated values 1001/1002 are
        // never copied into local metadata.
        let bob = t
            .relay
            .with_store(|s| s.entry(bob_did().as_str()))
            .unwrap()
            .expect("Bob admitted");
        assert_eq!(bob.payload, EntryPayload::Full(fx_bytes("bob_envelope")));
        assert_eq!(bob.authority_state, AuthorityState::Root);
        assert_eq!(bob.last_updated, 42);
        assert_eq!(t.relay.with_store(|s| s.last_update_number()).unwrap(), 42);

        // 4. The stored peer cursor equals the exact returned bytes.
        assert_eq!(stored_cursor(&t), Some(b"v08-0002".to_vec()));
        assert_eq!(hex::encode(b"v08-0002"), "7630382d30303032");

        // 5. The B.8 rejection affected only itself.
        assert_eq!(report.admitted.len(), 1);
        assert_eq!(report.admitted[0].did, bob_did().as_str());
        assert_eq!(report.admitted[0].update_number, 42);
        assert_eq!(report.rejected.len(), 1);
        assert_eq!(report.rejected[0].entry_did, alice_did().as_str());
        assert_eq!(
            report.rejected[0].code,
            VerifyError::IdentityBindingMismatch.wire_code()
        );
        assert_eq!(report.pages, 1);
    });
}

#[test]
fn sec_13_3_duplicate_replay_of_the_same_range_is_idempotent() {
    on_both_backends(|t| {
        seed_b11_receiver(&t);
        let transport = MockTransport::new();
        transport.on(PEER_INFO_URL, cbor_ok(peer_info_body()));
        transport.on(PEER_CHANGES_URL, cbor_ok(b11_5_response()));
        sync(&t, &transport, &b11_options()).expect("first pass");

        // Crash model: the cursor write was lost; the same range replays.
        t.relay
            .with_store(|store| {
                store.set_peer_state(&PeerState {
                    relay_id: PEER_ID,
                    endpoint: PEER_BASE.to_owned(),
                    cursor: Some(b"v08-0000".to_vec()),
                })
            })
            .expect("rewind cursor");
        let transport = MockTransport::new();
        transport.on(PEER_INFO_URL, cbor_ok(peer_info_body()));
        transport.on(PEER_CHANGES_URL, cbor_ok(b11_5_response()));
        let replay = sync(&t, &transport, &b11_options()).expect("replay accepted");

        // Bob is now a duplicate: no admission, no update number, and the
        // cursor still advances to the exact returned value.
        assert!(
            replay.admitted.is_empty(),
            "duplicate admission is idempotent"
        );
        assert_eq!(replay.no_change, 1);
        assert_eq!(t.relay.with_store(|s| s.last_update_number()).unwrap(), 42);
        assert_eq!(stored_cursor(&t), Some(b"v08-0002".to_vec()));
    });
}

// ---------------------------------------------------------------------------
// B.11.7: complete rejection before any entry.
// ---------------------------------------------------------------------------

#[test]
fn sec_b11_7_over_item_limit_response_is_rejected_before_any_entry() {
    on_both_backends(|t| {
        seed_b11_receiver(&t);
        let before = alice_entry(&t).expect("Alice seeded");

        let transport = MockTransport::new();
        transport.on(PEER_INFO_URL, cbor_ok(peer_info_body()));
        transport.on(PEER_CHANGES_URL, cbor_ok(b11_7_response()));
        let error = sync(&t, &transport, &b11_options()).expect_err("rejected completely");
        assert!(
            matches!(
                error,
                SyncError::Client(ClientError::OuterResponse(VerifyError::SchemaViolation))
            ),
            "rejected at the wrapper layer: {error:?}"
        );

        // No entry was processed: Alice unchanged, Bob absent, counter 41,
        // stored peer cursor still the exact request cursor v08-0000.
        assert_eq!(alice_entry(&t).expect("Alice"), before);
        assert!(
            t.relay
                .with_store(|s| s.entry(bob_did().as_str()))
                .unwrap()
                .is_none(),
            "Bob was never admitted"
        );
        assert_eq!(t.relay.with_store(|s| s.last_update_number()).unwrap(), 41);
        assert_eq!(stored_cursor(&t), Some(b"v08-0000".to_vec()));
        assert_eq!(hex::encode(b"v08-0000"), "7630382d30303030");
    });
}

// ---------------------------------------------------------------------------
// Premature candidates, Ref hints, and losing input.
// ---------------------------------------------------------------------------

#[test]
fn sec_13_3_premature_and_invalid_candidates_advance_the_cursor_without_stalling() {
    on_both_backends(|t| {
        // One candidate premature under the receiver's clock, a later
        // identity valid: the premature entry must not stall it.
        let (premature_did, premature_envelope, _) =
            synthetic_record_at(1, RELAY_NOW_MS + 300_001, "Early");
        let transport = MockTransport::new();
        transport.on(PEER_INFO_URL, cbor_ok(peer_info_body()));
        transport.on(
            PEER_CHANGES_URL,
            cbor_ok(changes_success_with(
                &b11_generation(),
                &[
                    ch_entry(&premature_did, rr_full(&premature_envelope), 5),
                    ch_entry(bob_did().as_str(), rr_full(&fx_bytes("bob_envelope")), 6),
                ],
                b"cursor-a",
                false,
            )),
        );
        let report = sync(&t, &transport, &SyncOptions::default()).expect("accepted");
        assert_eq!(report.rejected.len(), 1);
        assert_eq!(report.rejected[0].code, 10, "premature wire code");
        assert_eq!(report.admitted.len(), 1, "Bob is not stalled");
        assert_eq!(stored_cursor(&t), Some(b"cursor-a".to_vec()));
        assert!(
            t.relay
                .with_store(|s| s.entry(&premature_did))
                .unwrap()
                .is_none(),
            "no state for the premature candidate"
        );

        // Once the receiver's clock reaches the timestamp, a re-sent
        // candidate is admissible (recovery is a later pull, not a stall).
        t.clock.advance(300_001);
        let transport = MockTransport::new();
        transport.on(PEER_INFO_URL, cbor_ok(peer_info_body()));
        transport.on(
            PEER_CHANGES_URL,
            cbor_ok(changes_success_with(
                &b11_generation(),
                &[ch_entry(&premature_did, rr_full(&premature_envelope), 7)],
                b"cursor-b",
                false,
            )),
        );
        let report = sync(&t, &transport, &SyncOptions::default()).expect("accepted");
        assert_eq!(
            report.admitted.len(),
            1,
            "previously premature candidate admitted"
        );
        assert_eq!(stored_cursor(&t), Some(b"cursor-b".to_vec()));
    });
}

#[test]
fn sec_13_3_ref_entries_are_discarded_routing_hints() {
    on_both_backends(|t| {
        let transport = MockTransport::new();
        transport.on(PEER_INFO_URL, cbor_ok(peer_info_body()));
        transport.on(
            PEER_CHANGES_URL,
            cbor_ok(changes_success_with(
                &b11_generation(),
                &[ch_entry(alice_did().as_str(), rr_ref(3), 9)],
                b"cursor-r",
                false,
            )),
        );
        let report = sync(&t, &transport, &SyncOptions::default()).expect("accepted");
        assert_eq!(report.refs_ignored, 1);
        assert!(report.admitted.is_empty());
        assert!(
            alice_entry(&t).is_none(),
            "a Ref never creates identity or authority state"
        );
        assert_eq!(t.relay.with_store(|s| s.last_update_number()).unwrap(), 0);
        assert_eq!(
            stored_cursor(&t),
            Some(b"cursor-r".to_vec()),
            "an unusable Ref does not stall the cursor"
        );
    });
}

#[test]
fn sec_13_3_losing_and_invalid_synchronized_input_changes_no_state() {
    on_both_backends(|t| {
        // Current state: Bob's B.9 record (timestamp 1785589201123).
        let transport = MockTransport::new();
        transport.on(PEER_INFO_URL, cbor_ok(peer_info_body()));
        transport.on(
            PEER_CHANGES_URL,
            cbor_ok(changes_success_with(
                &b11_generation(),
                &[ch_entry(
                    bob_did().as_str(),
                    rr_full(&fx_bytes("bob_envelope")),
                    1,
                )],
                b"c-1",
                false,
            )),
        );
        sync(&t, &transport, &SyncOptions::default()).expect("seeded Bob");
        let counter = t.relay.with_store(|s| s.last_update_number()).unwrap();

        // A losing (older) record for Bob and garbage candidate bytes.
        let (_, older_bob, _) = (
            (),
            {
                // Re-sign Bob's identity is impossible without his seed —
                // it is published test material, so sign an older record.
                use followee::record::{Authority, RecordBody, sign_record};
                let body = RecordBody {
                    id: bob_did(),
                    timestamp_ms: B9_TIMESTAMP_MS - 1000,
                    authority: Authority::Root,
                    descriptor: bob_descriptor(),
                    revocation_key: None,
                    valid_until_ms: None,
                    contact: bob_contact(),
                    extensions: Default::default(),
                };
                sign_record(&body, &bob_root_seed()).expect("signs")
            },
            (),
        );
        let transport = MockTransport::new();
        transport.on(PEER_INFO_URL, cbor_ok(peer_info_body()));
        transport.on(
            PEER_CHANGES_URL,
            cbor_ok(changes_success_with(
                &b11_generation(),
                &[
                    ch_entry(bob_did().as_str(), rr_full(&older_bob), 2),
                    ch_entry(alice_did().as_str(), rr_full(&[0xDE, 0xAD, 0xBE, 0xEF]), 3),
                ],
                b"c-2",
                false,
            )),
        );
        let report = sync(&t, &transport, &SyncOptions::default()).expect("accepted");
        assert_eq!(report.no_change, 1, "losing record: valid, no change");
        assert_eq!(report.rejected.len(), 1, "invalid candidate rejected alone");
        let bob = t
            .relay
            .with_store(|s| s.entry(bob_did().as_str()))
            .unwrap()
            .expect("Bob current");
        assert_eq!(
            bob.payload,
            EntryPayload::Full(fx_bytes("bob_envelope")),
            "current state unchanged"
        );
        assert_eq!(
            t.relay.with_store(|s| s.last_update_number()).unwrap(),
            counter,
            "no update-number change from losing or invalid input"
        );
        assert_eq!(stored_cursor(&t), Some(b"c-2".to_vec()), "cursor advanced");
    });
}

#[test]
fn sec_8_2_sticky_root_revoked_survives_synchronization_and_housekeeping() {
    on_both_backends(|t| {
        // Learn revocation through the ordinary ingress path.
        let response = t.relay.publish(&fx_bytes("root_revoked_envelope")).unwrap();
        assert_eq!(publish_outcome(&response).0, 0, "revocation admitted");

        // Housekeeping converts the entry Full -> Ref; sticky state stays.
        t.relay
            .with_store(|s| s.convert_to_ref(alice_did().as_str(), 0).map(|_| ()))
            .expect("housekeeping");

        // A synchronized Root record for Alice must be rejected by sticky
        // state (code 11) while a later identity still admits.
        let transport = MockTransport::new();
        transport.on(PEER_INFO_URL, cbor_ok(peer_info_body()));
        transport.on(
            PEER_CHANGES_URL,
            cbor_ok(changes_success_with(
                &b11_generation(),
                &[
                    ch_entry(
                        alice_did().as_str(),
                        rr_full(&fx_bytes("root_record_envelope")),
                        1,
                    ),
                    ch_entry(bob_did().as_str(), rr_full(&fx_bytes("bob_envelope")), 2),
                ],
                b"c-rr",
                false,
            )),
        );
        let report = sync(&t, &transport, &SyncOptions::default()).expect("accepted");
        assert_eq!(report.rejected.len(), 1);
        assert_eq!(report.rejected[0].code, 11, "rootRevoked sticky exclusion");
        assert_eq!(report.admitted.len(), 1, "Bob admitted independently");

        let alice = alice_entry(&t).expect("Alice entry retained");
        assert_eq!(alice.authority_state, AuthorityState::RootRevoked);
        assert_eq!(
            alice.payload,
            EntryPayload::Ref(0),
            "housekeeping preserved"
        );
        assert_eq!(stored_cursor(&t), Some(b"c-rr".to_vec()));
    });
}

// ---------------------------------------------------------------------------
// Cursor lifecycle: reset, invalid cursor, pagination, peer identity.
// ---------------------------------------------------------------------------

#[test]
fn sec_12_7_reset_required_discards_only_the_cursor_and_reenumerates() {
    on_both_backends(|t| {
        seed_b11_receiver(&t);
        let before = alice_entry(&t).expect("Alice seeded");

        let transport = MockTransport::new();
        transport.on(PEER_INFO_URL, cbor_ok(peer_info_body()));
        transport.on(PEER_CHANGES_URL, cbor_ok(changes_reset_body()));
        transport.on(
            PEER_CHANGES_URL,
            cbor_ok(changes_success_with(
                &b11_generation(),
                &[ch_entry(
                    bob_did().as_str(),
                    rr_full(&fx_bytes("bob_envelope")),
                    1,
                )],
                b"fresh-1",
                false,
            )),
        );
        let report = sync(&t, &transport, &SyncOptions::default()).expect("reset then page");
        assert!(report.reset_performed);
        assert_eq!(report.pages, 2);

        // The re-enumeration used a null cursor.
        let requests = transport.requests();
        let null_cursor_request = r_map(&[
            (r_uint(0), r_uint(1)),
            (r_uint(1), vec![0xf6]),
            (r_uint(2), r_uint(256)),
            (r_uint(3), r_uint(1_048_576)),
        ]);
        assert_eq!(requests[2].body, null_cursor_request);

        // Identity state was never deleted; only the cursor was replaced.
        assert_eq!(alice_entry(&t).expect("Alice"), before);
        assert_eq!(stored_cursor(&t), Some(b"fresh-1".to_vec()));
    });
}

#[test]
fn sec_12_7_repeated_reset_in_one_operation_fails() {
    on_both_backends(|t| {
        seed_b11_receiver(&t);
        let transport = MockTransport::new();
        transport.on(PEER_INFO_URL, cbor_ok(peer_info_body()));
        transport.on(PEER_CHANGES_URL, cbor_ok(changes_reset_body()));
        transport.on(PEER_CHANGES_URL, cbor_ok(changes_reset_body()));
        let error = sync(&t, &transport, &SyncOptions::default()).expect_err("repeated reset");
        assert!(matches!(error, SyncError::RepeatedReset));
    });
}

#[test]
fn sec_15_3_invalid_cursor_error_is_distinct_from_reset_and_keeps_the_cursor() {
    on_both_backends(|t| {
        seed_b11_receiver(&t);
        let transport = MockTransport::new();
        transport.on(PEER_INFO_URL, cbor_ok(peer_info_body()));
        transport.on(PEER_CHANGES_URL, cbor_ok(changes_error_body(18)));
        let error = sync(&t, &transport, &b11_options()).expect_err("peer error");
        assert!(matches!(error, SyncError::PeerChangesError(18)));
        assert_eq!(
            stored_cursor(&t),
            Some(b"v08-0000".to_vec()),
            "invalidCursor never clears the stored cursor; only ResetRequired does"
        );
    });
}

#[test]
fn sec_13_3_pagination_uses_each_returned_cursor_exactly() {
    on_both_backends(|t| {
        let transport = MockTransport::new();
        transport.on(PEER_INFO_URL, cbor_ok(peer_info_body()));
        transport.on(
            PEER_CHANGES_URL,
            cbor_ok(changes_success_with(
                &b11_generation(),
                &[ch_entry(
                    bob_did().as_str(),
                    rr_full(&fx_bytes("bob_envelope")),
                    1,
                )],
                b"page-1",
                true,
            )),
        );
        transport.on(
            PEER_CHANGES_URL,
            cbor_ok(changes_success_with(
                &b11_generation(),
                &[ch_entry(
                    alice_did().as_str(),
                    rr_full(&fx_bytes("root_record_envelope")),
                    2,
                )],
                b"page-2",
                false,
            )),
        );
        let report = sync(&t, &transport, &SyncOptions::default()).expect("two pages");
        assert_eq!(report.pages, 2);
        assert_eq!(report.admitted.len(), 2);
        let requests = transport.requests();
        let second_request = r_map(&[
            (r_uint(0), r_uint(1)),
            (r_uint(1), r_bstr(b"page-1")),
            (r_uint(2), r_uint(256)),
            (r_uint(3), r_uint(1_048_576)),
        ]);
        assert_eq!(
            requests[2].body, second_request,
            "page 2 used page 1's exact cursor"
        );
        assert_eq!(stored_cursor(&t), Some(b"page-2".to_vec()));
    });
}

#[test]
fn sec_12_7_peer_identity_is_the_relay_id_not_the_endpoint() {
    on_both_backends(|t| {
        // A different relay instance at the same endpoint: stored cursor for
        // PEER_ID must not be sent to it, and PEER_ID's state is untouched.
        t.relay
            .with_store(|store| {
                store.set_peer_state(&PeerState {
                    relay_id: PEER_ID,
                    endpoint: PEER_BASE.to_owned(),
                    cursor: Some(b"old-cursor".to_vec()),
                })
            })
            .expect("seed peer");
        let other_id = [0x88; 16];
        let transport = MockTransport::new();
        transport.on(
            PEER_INFO_URL,
            cbor_ok(info_response(&other_id, &[0xC8; 16], &b11_generation())),
        );
        transport.on(
            PEER_CHANGES_URL,
            cbor_ok(changes_success_with(
                &b11_generation(),
                &[],
                b"other-1",
                false,
            )),
        );
        sync(&t, &transport, &SyncOptions::default()).expect("fresh peer");
        let requests = transport.requests();
        let null_cursor_request = r_map(&[
            (r_uint(0), r_uint(1)),
            (r_uint(1), vec![0xf6]),
            (r_uint(2), r_uint(256)),
            (r_uint(3), r_uint(1_048_576)),
        ]);
        assert_eq!(
            requests[1].body, null_cursor_request,
            "new identity starts null"
        );
        let old = t
            .relay
            .with_store(|s| s.peer_state(&PEER_ID))
            .unwrap()
            .expect("old peer state retained");
        assert_eq!(old.cursor, Some(b"old-cursor".to_vec()));
        let new = t
            .relay
            .with_store(|s| s.peer_state(&other_id))
            .unwrap()
            .expect("new peer state stored");
        assert_eq!(new.cursor, Some(b"other-1".to_vec()));
    });
}

#[test]
fn sec_12_7_endpoint_change_keeps_the_same_peer_cursor() {
    on_both_backends(|t| {
        t.relay
            .with_store(|store| {
                store.set_peer_state(&PeerState {
                    relay_id: PEER_ID,
                    endpoint: PEER_BASE.to_owned(),
                    cursor: Some(b"kept".to_vec()),
                })
            })
            .expect("seed peer");
        // The same relay instance now lives at another loopback endpoint.
        let transport = MockTransport::new();
        transport.on("http://127.0.0.1:9002/v1/info", cbor_ok(peer_info_body()));
        transport.on(
            "http://127.0.0.1:9002/v1/changes",
            cbor_ok(changes_success_with(
                &b11_generation(),
                &[],
                b"kept-2",
                false,
            )),
        );
        let client = RelayClient::new(&transport, NetworkPolicy::Development, &*t.clock);
        let mut meter = wide_meter();
        t.relay
            .sync_once(
                &client,
                "http://127.0.0.1:9002/",
                &SyncOptions::default(),
                &mut meter,
            )
            .expect("sync from moved endpoint");
        let requests = transport.requests();
        let with_cursor = r_map(&[
            (r_uint(0), r_uint(1)),
            (r_uint(1), r_bstr(b"kept")),
            (r_uint(2), r_uint(256)),
            (r_uint(3), r_uint(1_048_576)),
        ]);
        assert_eq!(
            requests[1].body, with_cursor,
            "stable identity keeps its cursor"
        );
        let state = t
            .relay
            .with_store(|s| s.peer_state(&PEER_ID))
            .unwrap()
            .expect("peer state");
        assert_eq!(state.endpoint, "http://127.0.0.1:9002/", "endpoint updated");
        assert_eq!(state.cursor, Some(b"kept-2".to_vec()));
    });
}

// ---------------------------------------------------------------------------
// Backend parity and restart durability for peer state.
// ---------------------------------------------------------------------------

#[test]
fn sec_9_2_peer_state_contract_parity_across_backends() {
    let mut memory: Box<dyn RelayStore> = Box::new(MemoryStore::new(test_identity()));
    let mut sqlite: Box<dyn RelayStore> =
        Box::new(SqliteStore::open_in_memory(test_identity()).expect("sqlite"));
    for store in [&mut memory, &mut sqlite] {
        assert_eq!(store.peer_state(&PEER_ID).unwrap(), None);
        assert!(store.peer_states().unwrap().is_empty());
        let first = PeerState {
            relay_id: PEER_ID,
            endpoint: "http://127.0.0.1:9001/".to_owned(),
            cursor: None,
        };
        store.set_peer_state(&first).unwrap();
        assert_eq!(store.peer_state(&PEER_ID).unwrap(), Some(first.clone()));
        let updated = PeerState {
            relay_id: PEER_ID,
            endpoint: "http://127.0.0.1:9002/".to_owned(),
            cursor: Some(vec![1, 2, 3]),
        };
        store.set_peer_state(&updated).unwrap();
        assert_eq!(store.peer_state(&PEER_ID).unwrap(), Some(updated.clone()));
        let second = PeerState {
            relay_id: [0x88; 16],
            endpoint: "http://127.0.0.1:9003/".to_owned(),
            cursor: Some(vec![9]),
        };
        store.set_peer_state(&second).unwrap();
        assert_eq!(
            store.peer_states().unwrap(),
            vec![updated.clone(), second.clone()],
            "ascending relay-id order"
        );
    }
}

#[test]
fn sec_13_5_sqlite_peer_state_survives_restart() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("relay.db");
    let state = PeerState {
        relay_id: PEER_ID,
        endpoint: PEER_BASE.to_owned(),
        cursor: Some(b"durable".to_vec()),
    };
    {
        let mut store = SqliteStore::open(&path, test_identity()).expect("create");
        store.set_peer_state(&state).unwrap();
    }
    let store = SqliteStore::open(&path, test_identity()).expect("reopen");
    assert_eq!(store.peer_state(&PEER_ID).unwrap(), Some(state));
}

#[test]
fn sync_error_symbols_are_stable() {
    use followee::relay::client::{ClientError, TransportError};
    let table: [(SyncError, &str); 5] = [
        (
            SyncError::Client(ClientError::Transport(TransportError::TimedOut)),
            "transportTimeout",
        ),
        (
            SyncError::Store(followee::store::StoreError::Backend("x".to_owned())),
            "storage",
        ),
        (SyncError::Internal("x".to_owned()), "internal"),
        (SyncError::PeerChangesError(18), "peerChangesError"),
        (SyncError::RepeatedReset, "repeatedReset"),
    ];
    for (error, symbol) in table {
        assert_eq!(error.symbol(), symbol);
    }
}

#[test]
fn sec_13_3_max_pages_bounds_the_operation_exactly() {
    on_both_backends(|t| {
        let transport = MockTransport::new();
        transport.on(PEER_INFO_URL, cbor_ok(peer_info_body()));
        // Two pages queued, both claiming hasMore: with max_pages = 1 only
        // the first may be fetched.
        for cursor in [b"p1", b"p2"] {
            transport.on(
                PEER_CHANGES_URL,
                cbor_ok(changes_success_with(&b11_generation(), &[], cursor, true)),
            );
        }
        let options = SyncOptions {
            item_limit: 16,
            byte_limit: 1024 * 1024,
            max_pages: 1,
        };
        let report = sync(&t, &transport, &options).expect("bounded");
        assert_eq!(report.pages, 1, "exactly max_pages pages fetched");
        assert!(report.has_more, "further work reported, not fetched");
        assert_eq!(
            transport
                .requests()
                .iter()
                .filter(|r| r.url == PEER_CHANGES_URL)
                .count(),
            1,
            "one changes request only"
        );
        assert_eq!(stored_cursor(&t), Some(b"p1".to_vec()));
    });
}
