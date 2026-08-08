//! Randomized relay state-machine properties (IMPLEMENTATION.md section
//! 11.3): the implementation is compared against a deliberately simple
//! same-language model over random admission sequences, on both storage
//! backends, and cursor pagination is checked for gaps and duplicates under
//! random page sizes. The model shares no production code; it is a direct
//! transcription of specification sections 8.2–8.4 and 13.1–13.2.
#![allow(clippy::arithmetic_side_effects)]

mod common;

use common::*;
use followee::record::sign_record;
use followee::store::MemoryStore;
use followee::store::sqlite::SqliteStore;
use proptest::prelude::*;
use std::collections::BTreeMap;

/// One candidate in the generated pool, with everything the model needs to
/// predict the relay's decision.
#[derive(Debug, Clone)]
struct Candidate {
    bytes: Vec<u8>,
    did: &'static str,
    revoked: bool,
    timestamp_ms: u64,
    digest: [u8; 32],
    valid: bool,
    premature: bool,
}

fn digest_of(envelope: &[u8]) -> [u8; 32] {
    // The body digest over the attached payload: d2 84 43 a1 01 32 a0 +
    // payload byte-string head (2 or 3 bytes) … signature trailer (66).
    let head = 7;
    let payload_head = match envelope[head] {
        0x58 => 2,
        0x59 => 3,
        other => panic!("unexpected payload head {other:#x}"),
    };
    followee::crypto::sha256(&envelope[head + payload_head..envelope.len() - 66])
}

/// A fixed pool of pre-signed candidates: Root and RootRevoked records for
/// Alice at several timestamps and equal-time digest pairs, Bob records for
/// cross-DID isolation, one premature record, and one invalid mutation.
fn candidate_pool() -> Vec<Candidate> {
    let alice: &'static str = Box::leak(fx_str("followee_did").into_boxed_str());
    let bob: &'static str = Box::leak(fx_str("bob_did").into_boxed_str());
    let mut pool = Vec::new();

    let mut push = |bytes: Vec<u8>, did, revoked, ts, valid, premature| {
        let digest = digest_of(&bytes);
        pool.push(Candidate {
            bytes,
            did,
            revoked,
            timestamp_ms: ts,
            digest,
            valid,
            premature,
        });
    };

    for (offset, name) in [(0, "Alice A"), (0, "Alice B"), (2, "Alice"), (7, "Alice")] {
        let mut body = b4_body();
        body.timestamp_ms = B4_TIMESTAMP_MS + offset;
        body.contact.display_name = Some(name.to_owned());
        let bytes = sign_record(&body, &root_seed()).expect("signs");
        push(bytes, alice, false, B4_TIMESTAMP_MS + offset, true, false);
    }
    for offset in [1, 5] {
        let mut body = b5_body();
        body.timestamp_ms = B4_TIMESTAMP_MS + offset;
        let bytes = sign_record(&body, &revocation_seed()).expect("signs");
        push(bytes, alice, true, B4_TIMESTAMP_MS + offset, true, false);
    }
    for offset in [0, 3] {
        let mut body = b9_body();
        body.timestamp_ms += offset;
        let bytes = sign_record(&body, &bob_root_seed()).expect("signs");
        push(bytes, bob, false, B9_TIMESTAMP_MS + offset, true, false);
    }
    // Premature beyond the recipient bound.
    let premature_ts = RELAY_NOW_MS + 300_001;
    let mut body = b4_body();
    body.timestamp_ms = premature_ts;
    let bytes = sign_record(&body, &root_seed()).expect("signs");
    push(bytes, alice, false, premature_ts, true, true);
    // Invalid: one flipped signature bit.
    let mut bad = fx_bytes("root_record_envelope");
    let last = bad.len() - 1;
    bad[last] ^= 0x01;
    push(bad, alice, false, B4_TIMESTAMP_MS, false, false);

    pool
}

/// The deliberately simple model of sections 8.2–8.4 and 13.1–13.2.
#[derive(Default)]
struct Model {
    /// Per DID: sticky revoked flag and the current (revoked, ts, digest).
    entries: BTreeMap<&'static str, (bool, bool, u64, [u8; 32])>,
    counter: u64,
    /// Per DID last-updated numbers, for feed prediction.
    numbers: BTreeMap<&'static str, u64>,
}

impl Model {
    /// Predicts `(status, errorCode)` and applies the state change.
    fn publish(&mut self, c: &Candidate) -> (u64, Option<u64>) {
        if !c.valid {
            return (2, Some(9));
        }
        if c.premature {
            return (2, Some(10));
        }
        if let Some((sticky, cur_revoked, cur_ts, cur_digest)) = self.entries.get(c.did).copied() {
            if sticky && !c.revoked {
                return (2, Some(11));
            }
            let transition = c.revoked && !cur_revoked;
            if !transition {
                let wins = match c.timestamp_ms.cmp(&cur_ts) {
                    std::cmp::Ordering::Greater => true,
                    std::cmp::Ordering::Less => false,
                    std::cmp::Ordering::Equal => c.digest < cur_digest,
                };
                if !wins {
                    return (1, None);
                }
            }
        }
        self.counter += 1;
        self.entries
            .insert(c.did, (c.revoked, c.revoked, c.timestamp_ms, c.digest));
        self.numbers.insert(c.did, self.counter);
        (0, None)
    }
}

fn run_sequence(t: &TestRelay, pool: &[Candidate], picks: &[usize], page_size: u64) {
    let mut model = Model::default();
    for &pick in picks {
        let candidate = &pool[pick % pool.len()];
        let actual = publish_outcome(&t.relay.publish(&candidate.bytes).expect("publish"));
        let expected = model.publish(candidate);
        prop_assert_eq_outer(actual, expected, candidate);
        let counter = t
            .relay
            .with_store(|s| s.last_update_number())
            .expect("counter");
        assert_eq!(
            counter, model.counter,
            "update number changes iff admitted current state changes"
        );
    }

    // Cursor pagination without gaps or duplicates, at a random page size:
    // walking the feed must enumerate exactly the model's current tuples in
    // increasing lastUpdated order.
    let mut collected: Vec<(String, u64)> = Vec::new();
    let mut cursor: Option<Vec<u8>> = None;
    loop {
        let response = t
            .relay
            .changes(&changes_request(cursor.as_deref(), page_size, 1 << 20))
            .expect("changes");
        let value = decode_value(&response);
        assert_eq!(value.get(1).expect("status").as_uint(), 0);
        for entry in value.get(2).expect("entries").as_array() {
            let parts = entry.as_array();
            let did = match &parts[0] {
                TestValue::Text(text) => text.clone(),
                other => panic!("expected DID text, got {other:?}"),
            };
            collected.push((did, parts[2].as_uint()));
        }
        let has_more = value.get(4) == Some(&TestValue::Bool(true));
        cursor = Some(value.get(3).expect("nextCursor").as_bytes().to_vec());
        if !has_more {
            break;
        }
    }
    let mut expected: Vec<(String, u64)> = model
        .numbers
        .iter()
        .map(|(did, number)| ((*did).to_owned(), *number))
        .collect();
    expected.sort_by_key(|(_, number)| *number);
    assert_eq!(collected, expected, "feed has no gaps and no duplicates");
}

/// Plain assertion with candidate context (proptest macros are unavailable
/// inside helper functions without a Result plumbing detour).
fn prop_assert_eq_outer(actual: (u64, Option<u64>), expected: (u64, Option<u64>), c: &Candidate) {
    assert_eq!(
        actual, expected,
        "publish outcome diverged from the model for candidate \
         did={} revoked={} ts={} valid={} premature={}",
        c.did, c.revoked, c.timestamp_ms, c.valid, c.premature
    );
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 64, ..ProptestConfig::default() })]

    #[test]
    fn sec_13_2_relay_matches_the_simple_model_on_memory(
        picks in proptest::collection::vec(0usize..16, 1..40),
        page_size in 1u64..5,
    ) {
        let pool = candidate_pool();
        let t = relay_over(Box::new(MemoryStore::new(test_identity())));
        run_sequence(&t, &pool, &picks, page_size);
    }

    #[test]
    fn sec_13_2_relay_matches_the_simple_model_on_sqlite(
        picks in proptest::collection::vec(0usize..16, 1..24),
        page_size in 1u64..5,
    ) {
        let pool = candidate_pool();
        let t = relay_over(Box::new(
            SqliteStore::open_in_memory(test_identity()).expect("sqlite"),
        ));
        run_sequence(&t, &pool, &picks, page_size);
    }
}
