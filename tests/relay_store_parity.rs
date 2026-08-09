//! Black-box storage-backend parity: the memory and SQLite backends must be
//! observationally identical through the complete relay surface and the
//! store contract itself (IMPLEMENTATION.md section 9.2), and the SQLite
//! backend must survive an ungraceful drop-and-reopen with every committed
//! observation intact.
#![allow(clippy::arithmetic_side_effects)]

mod common;

use common::*;
use followee::record::sign_record;
use followee::store::sqlite::SqliteStore;
use followee::store::{DirectoryEntry, MemoryStore, RelayStore};

fn alice_root(timestamp_ms: u64, name: &str) -> Vec<u8> {
    let mut body = b4_body();
    body.timestamp_ms = timestamp_ms;
    body.contact.display_name = Some(name.to_owned());
    sign_record(&body, &root_seed()).expect("signs")
}

fn alice_revoked(timestamp_ms: u64) -> Vec<u8> {
    let mut body = b5_body();
    body.timestamp_ms = timestamp_ms;
    sign_record(&body, &revocation_seed()).expect("signs")
}

/// Drives one scripted mixed workload through a relay, returning every
/// observable protocol byte sequence in order.
fn drive(t: &TestRelay) -> Vec<Vec<u8>> {
    let mut observed = Vec::new();
    let mut push = |bytes: Vec<u8>| observed.push(bytes);

    // Admissions: valid, duplicate, losing, equal-time, invalid, premature,
    // revocation, post-revocation, second identity.
    for record in [
        fx_bytes("root_record_envelope"),
        fx_bytes("root_record_envelope"),
        alice_root(B4_TIMESTAMP_MS, "Alice B"),
        alice_root(B4_TIMESTAMP_MS, "Alice A"),
        alice_root(B4_TIMESTAMP_MS + 3, "Alice"),
        alice_root(B4_TIMESTAMP_MS - 5, "Alice"),
        fx_bytes("b8_envelope"),
        alice_root(RELAY_NOW_MS + 300_001, "Alice"),
        fx_bytes("bob_envelope"),
        alice_revoked(B4_TIMESTAMP_MS + 1),
        alice_root(B4_TIMESTAMP_MS + 50, "Alice"),
    ] {
        push(t.relay.publish(&record).expect("publish"));
    }

    // Metadata and resolution.
    push(t.relay.info().expect("info"));
    push(t.relay.directory().expect("directory"));
    push(
        t.relay
            .resolve(&resolve_request(&[
                &fx_str("followee_did"),
                &fx_str("bob_did"),
                "did:flw:not-a-multibase",
                &fx_str("followee_did"),
            ]))
            .expect("resolve"),
    );

    // Changes pagination in single steps.
    let mut cursor: Option<Vec<u8>> = None;
    loop {
        let response = t
            .relay
            .changes(&changes_request(cursor.as_deref(), 1, 1 << 20))
            .expect("changes");
        push(response.clone());
        let value = decode_value(&response);
        let has_more = value.get(4) == Some(&TestValue::Bool(true));
        cursor = Some(value.get(3).expect("nextCursor").as_bytes().to_vec());
        if !has_more {
            break;
        }
    }

    // Housekeeping surfaces.
    t.relay
        .with_store(|s| {
            s.set_directory(
                vec![DirectoryEntry {
                    index: 4,
                    relay_id: [0x11; 16],
                    endpoint: "https://peer.example/".to_owned(),
                    capabilities: 3,
                }],
                [0x42; 16],
            )
        })
        .expect("set directory");
    t.relay
        .with_store(|s| s.convert_to_ref(&fx_str("bob_did"), 4))
        .expect("convert");
    push(t.relay.directory().expect("directory"));
    push(
        t.relay
            .resolve(&resolve_request(&[&fx_str("bob_did")]))
            .expect("resolve ref"),
    );
    push(
        t.relay
            .changes(&changes_request(None, 10, 1 << 20))
            .expect("changes after housekeeping"),
    );
    observed
}

#[test]
fn impl_9_2_backends_are_observationally_identical_through_the_relay() {
    let memory = drive(&relay_over(Box::new(MemoryStore::new(test_identity()))));
    let sqlite = drive(&relay_over(Box::new(
        SqliteStore::open_in_memory(test_identity()).expect("sqlite"),
    )));
    assert_eq!(
        memory.len(),
        sqlite.len(),
        "same number of observable responses"
    );
    for (index, (m, s)) in memory.iter().zip(&sqlite).enumerate() {
        assert_eq!(m, s, "observation {index} differs between backends");
    }
}

#[test]
fn impl_9_2_store_contract_parity_on_direct_operations() {
    let mut memory: Box<dyn RelayStore> = Box::new(MemoryStore::new(test_identity()));
    let mut sqlite: Box<dyn RelayStore> =
        Box::new(SqliteStore::open_in_memory(test_identity()).expect("sqlite"));

    for store in [&mut memory, &mut sqlite] {
        assert_eq!(store.identity().expect("identity"), test_identity());
        assert_eq!(store.last_update_number().expect("counter"), 0);
        assert!(store.entry("did:flw:zMissing").expect("entry").is_none());
        assert!(!store.convert_to_ref("did:flw:zMissing", 0).expect("ref"));
        assert!(!store.drop_entry("did:flw:zMissing").expect("drop"));
        let (rows, has_more) = store.changes_after(0, 10).expect("changes");
        assert!(rows.is_empty() && !has_more);
    }

    // Same commits produce the same numbers, entries, and feed rows.
    let meta = followee::store::OrderingMeta {
        authority: followee::record::Authority::Root,
        timestamp_ms: B4_TIMESTAMP_MS,
        body_digest: fx32("root_body_digest"),
    };
    for store in [&mut memory, &mut sqlite] {
        for (did, envelope) in [
            ("did:flw:zA", &b"first-envelope"[..]),
            ("did:flw:zB", &b"second-envelope"[..]),
            ("did:flw:zA", &b"first-envelope-v2"[..]),
        ] {
            store
                .commit_current(
                    did,
                    envelope,
                    followee::ordering::AuthorityState::Root,
                    meta,
                )
                .expect("commit");
        }
    }
    // Effectful operations report the same outcomes on both backends.
    for store in [&mut memory, &mut sqlite] {
        assert!(
            store.convert_to_ref("did:flw:zB", 9).expect("convert"),
            "existing entry converts"
        );
        let entry = store.entry("did:flw:zB").expect("entry").expect("present");
        assert!(matches!(
            entry.payload,
            followee::store::EntryPayload::Ref(9)
        ));
        assert!(
            store.drop_entry("did:flw:zB").expect("drop"),
            "existing entry drops"
        );
        assert!(store.entry("did:flw:zB").expect("entry").is_none());
        // Re-establish zB so the shared assertions below see two entries.
        store
            .commit_current(
                "did:flw:zB",
                b"second-envelope",
                followee::ordering::AuthorityState::Root,
                meta,
            )
            .expect("commit");
        store
            .reset_cursor_generation([0x77; 16])
            .expect("reset generation");
        assert_eq!(
            store.identity().expect("identity").cursor_generation,
            [0x77; 16],
            "generation reset persisted"
        );
    }

    for store in [&memory, &sqlite] {
        assert_eq!(store.last_update_number().expect("counter"), 4);
        let entry = store.entry("did:flw:zA").expect("entry").expect("present");
        assert_eq!(entry.last_updated, 3, "recommit reassigns the number");
        let (rows, has_more) = store.changes_after(0, 10).expect("changes");
        assert_eq!(rows.len(), 2, "coalesced to current tuples");
        assert_eq!(rows[0].did, "did:flw:zA");
        assert_eq!(rows[1].did, "did:flw:zB");
        assert!(!has_more);
        let (rows, has_more) = store.changes_after(3, 10).expect("changes");
        assert_eq!(rows.len(), 1, "cursor position filters strictly after");
        assert!(!has_more);
        let (rows, has_more) = store.changes_after(0, 1).expect("changes");
        assert_eq!(rows.len(), 1);
        assert!(has_more, "more eligible tuples remained");
    }
}

#[test]
fn sec_13_1_sqlite_commits_survive_an_ungraceful_reopen() {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("relay.db");

    // Commit through the full relay, then drop everything without any
    // explicit shutdown: the transaction boundary is the durability point.
    {
        let store = SqliteStore::open(&path, test_identity()).expect("create");
        let t = relay_over(Box::new(store));
        assert_eq!(
            publish_outcome(
                &t.relay
                    .publish(&fx_bytes("root_record_envelope"))
                    .expect("ok")
            )
            .0,
            0
        );
        assert_eq!(
            publish_outcome(
                &t.relay
                    .publish(&alice_revoked(B4_TIMESTAMP_MS + 1))
                    .expect("ok")
            )
            .0,
            0
        );
        // No graceful close: the relay and its connection are dropped here.
    }

    let store = SqliteStore::open(&path, test_identity()).expect("reopen");
    assert_eq!(store.last_update_number().expect("counter"), 2);
    let entry = store
        .entry(&fx_str("followee_did"))
        .expect("entry")
        .expect("retained");
    assert_eq!(
        entry.authority_state,
        followee::ordering::AuthorityState::RootRevoked,
        "sticky revocation persisted before acknowledgement"
    );
    assert_eq!(entry.last_updated, 2);
}
