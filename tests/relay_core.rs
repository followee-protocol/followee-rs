//! Relay admission, serving, and changes semantics through the
//! transport-independent relay API (specification sections 5.4, 8.2, 11–13;
//! IMPLEMENTATION.md section 13 Milestone 3 acceptance).
#![allow(clippy::arithmetic_side_effects)]

mod common;

use common::*;
use followee::record::sign_record;
use followee::store::EntryPayload;
use followee::timestamp::MAX_FUTURE_SKEW_MS;

/// Signs a B.4-derived Alice Root record with the given timestamp and
/// display name.
fn alice_root(timestamp_ms: u64, name: &str) -> Vec<u8> {
    let mut body = b4_body();
    body.timestamp_ms = timestamp_ms;
    body.contact.display_name = Some(name.to_owned());
    sign_record(&body, &root_seed()).expect("signs")
}

/// Signs a B.5-derived Alice RootRevoked record with the given timestamp.
fn alice_revoked(timestamp_ms: u64) -> Vec<u8> {
    let mut body = b5_body();
    body.timestamp_ms = timestamp_ms;
    sign_record(&body, &revocation_seed()).expect("signs")
}

fn publish(relay: &TestRelay, record: &[u8]) -> (u64, Option<u64>) {
    publish_outcome(&relay.relay.publish(record).expect("publish completes"))
}

fn last_update(relay: &TestRelay) -> u64 {
    relay
        .relay
        .with_store(|s| s.last_update_number())
        .expect("store readable")
}

fn resolve_results(relay: &TestRelay, dids: &[&str]) -> Vec<TestValue> {
    let response = relay
        .relay
        .resolve(&resolve_request(dids))
        .expect("resolve completes");
    let value = decode_value(&response);
    value.get(2).expect("results").as_array().to_vec()
}

// ---------------------------------------------------------------------------
// Section 13.1/13.2: admission outcomes and the update-number rule.
// ---------------------------------------------------------------------------

#[test]
fn sec_13_1_first_valid_record_is_admitted_current() {
    let t = memory_relay();
    let (status, code) = publish(&t, &fx_bytes("root_record_envelope"));
    assert_eq!((status, code), (0, None), "admitted and current");
    assert_eq!(last_update(&t), 1, "one update number assigned");
}

#[test]
fn sec_13_2_duplicate_and_losing_records_are_no_change_without_update_number() {
    let t = memory_relay();
    let newer = alice_root(B4_TIMESTAMP_MS + 10, "Alice Example");
    assert_eq!(publish(&t, &newer).0, 0);
    let counter = last_update(&t);

    // Exact duplicate: valid, no change, no number (section 8.4).
    assert_eq!(publish(&t, &newer), (1, None), "duplicate is no-change");
    // Older timestamp: losing, no change, no number.
    assert_eq!(
        publish(&t, &fx_bytes("root_record_envelope")),
        (1, None),
        "losing record is no-change"
    );
    assert_eq!(last_update(&t), counter, "no update number was assigned");
}

#[test]
fn sec_13_2_update_number_increments_exactly_on_state_change() {
    let t = memory_relay();
    assert_eq!(last_update(&t), 0);
    assert_eq!(publish(&t, &fx_bytes("root_record_envelope")).0, 0);
    assert_eq!(last_update(&t), 1, "greater timestamp replaces state");
    assert_eq!(publish(&t, &alice_root(B4_TIMESTAMP_MS + 5, "Alice")).0, 0);
    assert_eq!(last_update(&t), 2);
    // Invalid input never increments: flip one signature bit.
    let mut bad = fx_bytes("root_record_envelope");
    let last = bad.len() - 1;
    bad[last] ^= 0x01;
    assert_eq!(publish(&t, &bad), (2, Some(9)), "invalidSignature");
    assert_eq!(last_update(&t), 2, "rejected input assigned no number");
}

#[test]
fn sec_8_3_equal_time_lower_digest_wins_and_increments() {
    let t = memory_relay();
    // B.6: "Alice B" (digest 81…) then "Alice A" (digest 6f…) at one time.
    let b = alice_root(B4_TIMESTAMP_MS, "Alice B");
    let a = alice_root(B4_TIMESTAMP_MS, "Alice A");
    assert_eq!(publish(&t, &b).0, 0);
    assert_eq!(
        publish(&t, &a),
        (0, None),
        "lower digest wins at equal time"
    );
    assert_eq!(last_update(&t), 2, "equal-time replacement is a map change");
    assert_eq!(publish(&t, &b), (1, None), "higher digest then loses");
    assert_eq!(last_update(&t), 2);
}

#[test]
fn sec_13_1_premature_record_is_rejected_with_code_10() {
    let t = memory_relay();
    let now = RELAY_NOW_MS;
    let at_bound = alice_root(now + MAX_FUTURE_SKEW_MS, "Alice");
    let beyond = alice_root(now + MAX_FUTURE_SKEW_MS + 1, "Alice");
    assert_eq!(publish(&t, &beyond), (2, Some(10)), "premature");
    assert_eq!(last_update(&t), 0, "no state change for premature input");
    assert_eq!(publish(&t, &at_bound).0, 0, "exact bound is admissible");
}

#[test]
fn sec_8_2_root_revoked_has_absolute_precedence_and_is_sticky() {
    let t = memory_relay();
    // A Root record with a much later timestamp is already current.
    let late_root = alice_root(B4_TIMESTAMP_MS + 100, "Alice");
    assert_eq!(publish(&t, &late_root).0, 0);
    // The earlier-timestamp RootRevoked record still wins the transition.
    let revoked = alice_revoked(B4_TIMESTAMP_MS);
    assert_eq!(publish(&t, &revoked).0, 0, "revocation transition wins");
    let counter = last_update(&t);
    // Every Root record afterwards is excluded by sticky state: code 11.
    assert_eq!(publish(&t, &late_root), (2, Some(11)));
    let much_later_root = alice_root(B4_TIMESTAMP_MS + 500, "Alice");
    assert_eq!(publish(&t, &much_later_root), (2, Some(11)));
    assert_eq!(last_update(&t), counter, "excluded Root assigned no number");
    // A later RootRevoked record still orders within the revoked state.
    let later_revoked = alice_revoked(B4_TIMESTAMP_MS + 1);
    assert_eq!(publish(&t, &later_revoked).0, 0);
    // An older RootRevoked record loses without a transition.
    assert_eq!(publish(&t, &revoked), (1, None));
}

#[test]
fn sec_11_2_conversion_to_ref_preserves_sticky_state_and_metadata() {
    let t = memory_relay();
    assert_eq!(publish(&t, &alice_revoked(B4_TIMESTAMP_MS)).0, 0);
    let counter = last_update(&t);
    let converted = t
        .relay
        .with_store(|s| s.convert_to_ref(&fx_str("followee_did"), 3))
        .expect("conversion");
    assert!(converted);
    // Housekeeping assigned no update number (section 13.2).
    assert_eq!(last_update(&t), counter);
    // Sticky revocation still excludes Root records.
    assert_eq!(
        publish(&t, &alice_root(B4_TIMESTAMP_MS + 500, "Alice")),
        (2, Some(11)),
        "sticky revocation survives Full-to-Ref conversion"
    );
    // The entry now resolves as a reference under the response generation.
    let results = resolve_results(&t, &[&fx_str("followee_did")]);
    assert_eq!(results[0].get(0).expect("kind").as_uint(), 1, "Ref result");
    assert_eq!(results[0].get(1).expect("index").as_uint(), 3);
}

#[test]
fn sec_11_2_retained_metadata_prevents_same_authority_rollback_through_a_ref() {
    let t = memory_relay();
    let newer = alice_root(B4_TIMESTAMP_MS + 10, "Alice");
    assert_eq!(publish(&t, &newer).0, 0);
    t.relay
        .with_store(|s| s.convert_to_ref(&fx_str("followee_did"), 0))
        .expect("conversion");
    // The older B.4 record must not roll the reference entry back.
    assert_eq!(
        publish(&t, &fx_bytes("root_record_envelope")),
        (1, None),
        "retained ordering metadata prevents rollback"
    );
    // A genuinely newer record replaces the reference with full bytes.
    let newest = alice_root(B4_TIMESTAMP_MS + 20, "Alice");
    assert_eq!(publish(&t, &newest).0, 0);
    let results = resolve_results(&t, &[&fx_str("followee_did")]);
    assert_eq!(results[0].get(0).expect("kind").as_uint(), 0, "Full again");
}

#[test]
fn sec_8_5_dropping_the_entry_makes_the_relay_a_fresh_observer() {
    let t = memory_relay();
    assert_eq!(publish(&t, &alice_revoked(B4_TIMESTAMP_MS)).0, 0);
    assert_eq!(
        publish(&t, &fx_bytes("root_record_envelope")),
        (2, Some(11))
    );
    t.relay
        .with_store(|s| s.drop_entry(&fx_str("followee_did")))
        .expect("drop");
    // Dropping the entire entry drops local sticky state (section 11.3):
    // re-admission begins as a fresh observation.
    assert_eq!(
        publish(&t, &fx_bytes("root_record_envelope")).0,
        0,
        "fresh observer admits a Root record again"
    );
}

#[test]
fn sec_b9_admissions_are_keyed_per_did() {
    let t = memory_relay();
    assert_eq!(publish(&t, &fx_bytes("root_record_envelope")).0, 0);
    assert_eq!(publish(&t, &fx_bytes("bob_envelope")).0, 0);
    // Revoking Alice never touches Bob's entry or state.
    assert_eq!(publish(&t, &alice_revoked(B4_TIMESTAMP_MS + 1)).0, 0);
    let results = resolve_results(&t, &[&fx_str("followee_did"), &fx_str("bob_did")]);
    assert_eq!(results[0].get(0).expect("kind").as_uint(), 0);
    assert_eq!(results[1].get(0).expect("kind").as_uint(), 0);
    assert_eq!(
        results[1].get(1).expect("bytes").as_bytes(),
        fx_bytes("bob_envelope").as_slice(),
        "Bob's exact admitted bytes are served unchanged"
    );
}

#[test]
fn sec_13_1_oversized_and_malformed_candidates_are_rejected_cheaply() {
    let t = memory_relay();
    let oversized = vec![0u8; 16 * 1024 + 1];
    assert_eq!(publish(&t, &oversized), (2, Some(3)), "recordTooLarge");
    assert_eq!(publish(&t, b"\xff"), (2, Some(4)), "invalidCbor");
    let (status, code) = publish(&t, &fx_bytes("b8_envelope"));
    assert_eq!(
        (status, code),
        (2, Some(7)),
        "B.8 descriptor substitution fails identity binding at ingress"
    );
    assert_eq!(last_update(&t), 0);
}

// ---------------------------------------------------------------------------
// Section 12.3: resolve alignment and the serve-time future recheck.
// ---------------------------------------------------------------------------

#[test]
fn sec_12_3_results_align_with_duplicates_and_unknown_dids() {
    let t = memory_relay();
    assert_eq!(publish(&t, &fx_bytes("root_record_envelope")).0, 0);
    let alice = fx_str("followee_did");
    let attacker = fx_str("attacker_did");
    let results = resolve_results(&t, &[&alice, &attacker, &alice]);
    assert_eq!(results.len(), 3, "exactly one result per occurrence");
    assert_eq!(results[0].get(0).expect("kind").as_uint(), 0, "Full");
    assert_eq!(results[1].get(0).expect("kind").as_uint(), 2, "Absent");
    assert_eq!(results[2].get(0).expect("kind").as_uint(), 0, "Full again");
}

#[test]
fn sec_12_3_locally_premature_current_record_is_error_not_absent() {
    let t = memory_relay();
    assert_eq!(publish(&t, &fx_bytes("root_record_envelope")).0, 0);
    let counter = last_update(&t);

    // A backwards clock correction makes the stored record premature.
    t.clock.set(B4_TIMESTAMP_MS - MAX_FUTURE_SKEW_MS - 1);
    let results = resolve_results(&t, &[&fx_str("followee_did")]);
    assert_eq!(results[0].get(0).expect("kind").as_uint(), 3, "Error");
    assert_eq!(
        results[0].get(2).expect("code").as_uint(),
        10,
        "premature, never Absent"
    );

    // Serving-time classification mutated nothing (section 5.4).
    let entry = t
        .relay
        .with_store(|s| s.entry(&fx_str("followee_did")))
        .expect("store readable")
        .expect("entry retained");
    assert_eq!(entry.last_updated, counter, "lastUpdated unchanged");
    assert!(matches!(entry.payload, EntryPayload::Full(_)));
    assert_eq!(last_update(&t), counter, "no update number assigned");

    // Once the record is no longer premature it is served as Full again.
    t.clock.set(RELAY_NOW_MS);
    let results = resolve_results(&t, &[&fx_str("followee_did")]);
    assert_eq!(results[0].get(0).expect("kind").as_uint(), 0, "Full again");
}

// ---------------------------------------------------------------------------
// Sections 12.6/12.7: changes statuses, pagination, coalescing, cursors.
// ---------------------------------------------------------------------------

fn changes_value(t: &TestRelay, cursor: Option<&[u8]>, items: u64, bytes: u64) -> TestValue {
    let response = t
        .relay
        .changes(&changes_request(cursor, items, bytes))
        .expect("changes completes");
    decode_value(&response)
}

#[test]
fn sec_12_6_success_pagination_without_gaps_and_exact_coalescing() {
    let t = memory_relay();
    assert_eq!(publish(&t, &fx_bytes("root_record_envelope")).0, 0);
    assert_eq!(publish(&t, &fx_bytes("bob_envelope")).0, 0);
    // Alice updates twice more: three changes coalesce into one tuple.
    assert_eq!(publish(&t, &alice_root(B4_TIMESTAMP_MS + 1, "Alice")).0, 0);
    assert_eq!(publish(&t, &alice_root(B4_TIMESTAMP_MS + 2, "Alice")).0, 0);

    // Page 1: null cursor, one item.
    let page1 = changes_value(&t, None, 1, 1 << 20);
    assert_eq!(page1.get(1).expect("status").as_uint(), 0);
    let entries1 = page1.get(2).expect("entries").as_array().to_vec();
    assert_eq!(entries1.len(), 1, "itemLimit respected");
    assert_eq!(page1.get(4), Some(&TestValue::Bool(true)), "hasMore");
    let cursor1 = page1.get(3).expect("nextCursor").as_bytes().to_vec();

    // Page 2 from the returned cursor: the remaining tuple, then empty.
    let page2 = changes_value(&t, Some(&cursor1), 10, 1 << 20);
    let entries2 = page2.get(2).expect("entries").as_array().to_vec();
    assert_eq!(entries2.len(), 1);
    assert_eq!(page2.get(4), Some(&TestValue::Bool(false)));

    // Exactly two current tuples exist in total: Bob(2) and Alice(4);
    // Alice's three updates appear only as her current tuple.
    let all = changes_value(&t, None, 10, 1 << 20);
    let entries = all.get(2).expect("entries").as_array().to_vec();
    assert_eq!(entries.len(), 2, "one current tuple per DID");
    let firsts: Vec<u64> = entries.iter().map(|e| e.as_array()[2].as_uint()).collect();
    assert_eq!(firsts, vec![2, 4], "increasing lastUpdated order");
    assert_eq!(
        entries[1].as_array()[0],
        TestValue::Text(fx_str("followee_did")),
        "Alice's tuple carries her latest update number"
    );

    // The empty tail: nextCursor represents the supplied position.
    let cursor_all = all.get(3).expect("nextCursor").as_bytes().to_vec();
    let tail = changes_value(&t, Some(&cursor_all), 10, 1 << 20);
    assert_eq!(tail.get(2).expect("entries").as_array().len(), 0);
    assert_eq!(
        tail.get(3).expect("nextCursor").as_bytes(),
        cursor_all.as_slice(),
        "no-entry response keeps the supplied position"
    );
}

#[test]
fn sec_12_6_status_dependent_field_combinations() {
    let t = memory_relay();
    assert_eq!(publish(&t, &fx_bytes("root_record_envelope")).0, 0);

    // Success: labels 0–5 exactly, errorCode absent.
    let success = changes_value(&t, None, 10, 1 << 20);
    assert_eq!(success.labels(), vec![0, 1, 2, 3, 4, 5]);
    assert_eq!(success.get(1).expect("status").as_uint(), 0);
    assert!(success.get(6).is_none(), "errorCode forbidden on success");

    // Error status 2: labels 0, 1, 6 exactly; entries/cursor/hasMore/
    // generation forbidden. Malformed cursor produces invalidCursor (18).
    let error = changes_value(&t, Some(&[0xAB; 5]), 10, 1 << 20);
    assert_eq!(error.labels(), vec![0, 1, 6]);
    assert_eq!(error.get(1).expect("status").as_uint(), 2);
    assert_eq!(error.get(6).expect("errorCode").as_uint(), 18);

    // Reset status 1: exactly labels 0 and 1 (covered byte-exactly below).
    let foreign = raw_cursor(&[0x11; 16], 0);
    let reset = changes_value(&t, Some(&foreign), 10, 1 << 20);
    assert_eq!(reset.labels(), vec![0, 1]);
}

#[test]
fn sec_12_6_reset_is_status_1_only() {
    let t = memory_relay();
    // A structurally valid cursor from a foreign generation is the only
    // reset signal; no reset error code exists in v1.
    let foreign = raw_cursor(&[0x11; 16], 3);
    let reset = changes_value(&t, Some(&foreign), 10, 1 << 20);
    assert_eq!(reset.get(1).expect("status").as_uint(), 1);
    assert!(reset.get(6).is_none(), "no errorCode accompanies reset");
}

#[test]
fn sec_12_6_reset_response_is_exactly_labels_0_and_1() {
    let t = memory_relay();
    let foreign = raw_cursor(&[0x11; 16], 3);
    let response = t
        .relay
        .changes(&changes_request(Some(&foreign), 10, 1 << 20))
        .expect("changes completes");
    // Byte-exact: {0: 1, 1: 1} in deterministic encoding.
    assert_eq!(response, vec![0xa2, 0x00, 0x01, 0x01, 0x01]);
}

#[test]
fn sec_12_6_byte_limit_never_advances_past_an_omitted_entry() {
    let t = memory_relay();
    assert_eq!(publish(&t, &fx_bytes("root_record_envelope")).0, 0);
    assert_eq!(publish(&t, &fx_bytes("bob_envelope")).0, 0);

    // A byteLimit that fits one full entry but not two: the second is
    // omitted, hasMore is true, and the cursor stops at the included entry.
    let one_entry = changes_value(&t, None, 10, 600);
    assert_eq!(one_entry.get(1).expect("status").as_uint(), 0);
    let entries = one_entry.get(2).expect("entries").as_array().to_vec();
    assert_eq!(entries.len(), 1, "second entry cannot fit 600 bytes");
    assert_eq!(one_entry.get(4), Some(&TestValue::Bool(true)));
    let cursor = one_entry.get(3).expect("nextCursor").as_bytes().to_vec();

    // Continuing from that cursor yields the omitted entry: no gap.
    let rest = changes_value(&t, Some(&cursor), 10, 1 << 20);
    let entries = rest.get(2).expect("entries").as_array().to_vec();
    assert_eq!(entries.len(), 1, "omitted entry appears on the next page");
    assert_eq!(entries[0].as_array()[0], TestValue::Text(fx_str("bob_did")));

    // A byteLimit too small for even one entry: responseTooLarge, not an
    // unchanged success cursor loop.
    let too_small = changes_value(&t, None, 10, 400);
    assert_eq!(too_small.get(1).expect("status").as_uint(), 2);
    assert_eq!(too_small.get(6).expect("errorCode").as_uint(), 16);
}

#[test]
fn sec_12_6_byte_budget_binds_exactly_at_the_24_entry_head_boundary() {
    // The CBOR array head widens from one to two bytes at 24 entries; the
    // budget accounting must be exact at that transition. Publish thirty
    // small identities, measure the exact 24-entry response, then show a
    // one-byte-smaller budget omits an entry rather than overshooting.
    let t = memory_relay();
    for index in 0..30 {
        let (_, record) = synthetic_identity_record(index, 0);
        assert_eq!(
            publish_outcome(&t.relay.publish(&record).expect("publish")).0,
            0
        );
    }
    let response_24 = t
        .relay
        .changes(&changes_request(None, 24, 1 << 20))
        .expect("changes");
    assert_eq!(
        decode_value(&response_24)
            .get(2)
            .expect("entries")
            .as_array()
            .len(),
        24
    );
    let l24 = response_24.len() as u64;

    // byteLimit exactly l24 with a generous item limit: 24 entries fit.
    let exact = t
        .relay
        .changes(&changes_request(None, 1024, l24))
        .expect("changes");
    assert!(exact.len() as u64 <= l24);
    assert_eq!(
        decode_value(&exact)
            .get(2)
            .expect("entries")
            .as_array()
            .len(),
        24,
        "exactly the measured 24 entries fit"
    );

    // One byte less: the 24th entry no longer fits; the response must both
    // shrink and stay within the budget.
    let under = t
        .relay
        .changes(&changes_request(None, 1024, l24 - 1))
        .expect("changes");
    assert!(
        (under.len() as u64) < l24,
        "response ({}) exceeds byteLimit ({})",
        under.len(),
        l24 - 1
    );
    assert_eq!(
        decode_value(&under)
            .get(2)
            .expect("entries")
            .as_array()
            .len(),
        23,
        "the boundary entry is omitted, not overshot"
    );
}

#[test]
fn sec_12_7_generation_reset_permits_bounded_reenumeration() {
    let t = memory_relay();
    assert_eq!(publish(&t, &fx_bytes("root_record_envelope")).0, 0);
    assert_eq!(publish(&t, &fx_bytes("bob_envelope")).0, 0);
    let before = changes_value(&t, None, 10, 1 << 20);
    let old_cursor = before.get(3).expect("nextCursor").as_bytes().to_vec();

    t.relay
        .with_store(|s| s.reset_cursor_generation([0x99; 16]))
        .expect("reset");

    // The pre-reset cursor now requires reset…
    let reset = changes_value(&t, Some(&old_cursor), 10, 1 << 20);
    assert_eq!(reset.get(1).expect("status").as_uint(), 1);
    // …and a null-cursor scan re-enumerates every retained current entry
    // without deleting identity state (section 12.7).
    let rescan = changes_value(&t, None, 10, 1 << 20);
    assert_eq!(rescan.get(2).expect("entries").as_array().len(), 2);
}
