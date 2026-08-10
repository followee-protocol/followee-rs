//! Deterministic concurrent-ingress cursor-visibility tests (specification
//! v0.9 sections 12.6, 13.2, 16.17, and 20.2; IMPLEMENTATION.md sections 9.2,
//! 9.3, 11.3, and 11.6).
//!
//! The v0.9 invariant: no successful `v1/changes` response may return a
//! `nextCursor` at or beyond a position whose eventual visibility remains
//! undecided. These tests force the hazardous interleaving deterministically:
//! a writer is paused inside the write-critical section — after the final
//! current-state comparison and sticky-authority recheck, immediately before
//! the indivisible update-number allocation and commit — while a competing
//! writer and a `changes` reader attempt to proceed.
//!
//! Coordination uses channels and a gate wrapped around the production
//! store's `commit_current`, never sleeps: the pause point is reached by the
//! production `Relay::publish` path over a production backend, and every
//! "not yet completed" assertion is an ordering fact (completion requires
//! the store lock the paused writer holds), not a timing sample. The
//! `recv_timeout` calls exist only to convert a would-be deadlock into a
//! test failure; passing runs block on events, never on the clock.
//!
//! The unlocked-gap tests exercise the other half of the v0.9 section 13.2
//! boundary: publication is two-phase, so a `changes` reader must complete
//! while another publication is paused after state-independent preparation
//! but before the store lock — verification work never denies readers
//! service, and doing so is invariant-safe because the paused writer holds
//! no allocated position.
#![allow(clippy::arithmetic_side_effects)]

mod common;

use common::*;
use followee::ordering::AuthorityState;
use followee::record::{Authority, sign_record};
use followee::relay::RelayError;
use followee::store::sqlite::SqliteStore;
use followee::store::{
    ChangeRow, DirectoryEntry, MemoryStore, OrderingMeta, RelayIdentity, RelayStore, StoreError,
    StoredEntry,
};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::thread;
use std::time::Duration;

/// Deadlock-to-failure conversion bound; passing runs never wait this long.
const HANG_GUARD: Duration = Duration::from_secs(60);

/// Orchestrator instruction for a writer paused at the gate.
enum GateCommand {
    /// Proceed into the backend's atomic allocation-and-commit.
    Commit,
    /// Abort before allocation, as a storage failure would: the admission
    /// must leave no observable trace and no sequence hole.
    Cancel,
}

/// A production-backend wrapper whose `commit_current` can pause one writer
/// at the narrowest point the conforming architecture exposes: inside the
/// relay's write-critical section, after every state-dependent admission
/// check, before the backend's indivisible number-allocation-and-commit.
/// (Pausing *between* allocation and commit is impossible by construction —
/// both backends perform them as one atomic operation — which is exactly the
/// structural property under test.) Every operation delegates to the real
/// backend, so the exercised admission, storage, and feed behaviour is the
/// production path.
struct GatedStore {
    inner: Box<dyn RelayStore>,
    armed: Arc<AtomicBool>,
    paused_tx: Sender<String>,
    command_rx: Receiver<GateCommand>,
    committed_tx: Sender<(String, u64)>,
}

impl RelayStore for GatedStore {
    fn identity(&self) -> Result<RelayIdentity, StoreError> {
        self.inner.identity()
    }

    fn entry(&self, did: &str) -> Result<Option<StoredEntry>, StoreError> {
        self.inner.entry(did)
    }

    fn commit_current(
        &mut self,
        did: &str,
        envelope: &[u8],
        authority_state: AuthorityState,
        ordering: OrderingMeta,
    ) -> Result<u64, StoreError> {
        if self.armed.swap(false, Ordering::SeqCst) {
            self.paused_tx
                .send(did.to_owned())
                .expect("orchestrator holds the pause receiver");
            match self.command_rx.recv_timeout(HANG_GUARD) {
                Ok(GateCommand::Commit) => {}
                Ok(GateCommand::Cancel) => {
                    return Err(StoreError::Backend(
                        "deterministic cancellation injected before allocation".to_owned(),
                    ));
                }
                Err(_) => {
                    return Err(StoreError::Backend(
                        "gate release timed out; orchestration bug".to_owned(),
                    ));
                }
            }
        }
        let number = self
            .inner
            .commit_current(did, envelope, authority_state, ordering)?;
        self.committed_tx
            .send((did.to_owned(), number))
            .expect("orchestrator holds the commit receiver");
        Ok(number)
    }

    fn convert_to_ref(&mut self, did: &str, relay_index: u32) -> Result<bool, StoreError> {
        self.inner.convert_to_ref(did, relay_index)
    }

    fn drop_entry(&mut self, did: &str) -> Result<bool, StoreError> {
        self.inner.drop_entry(did)
    }

    fn changes_after(
        &self,
        position: u64,
        max: usize,
    ) -> Result<(Vec<ChangeRow>, bool), StoreError> {
        self.inner.changes_after(position, max)
    }

    fn last_update_number(&self) -> Result<u64, StoreError> {
        self.inner.last_update_number()
    }

    fn directory(&self) -> Result<Vec<DirectoryEntry>, StoreError> {
        self.inner.directory()
    }

    fn set_directory(
        &mut self,
        entries: Vec<DirectoryEntry>,
        new_generation: [u8; 16],
    ) -> Result<(), StoreError> {
        self.inner.set_directory(entries, new_generation)
    }

    fn reset_cursor_generation(&mut self, new_generation: [u8; 16]) -> Result<(), StoreError> {
        self.inner.reset_cursor_generation(new_generation)
    }
}

/// A gated production relay plus the orchestration endpoints.
struct Harness {
    relay: TestRelay,
    armed: Arc<AtomicBool>,
    paused_rx: Receiver<String>,
    command_tx: Sender<GateCommand>,
    committed_rx: Receiver<(String, u64)>,
}

fn gated_relay(backend: Box<dyn RelayStore>) -> Harness {
    let armed = Arc::new(AtomicBool::new(false));
    let (paused_tx, paused_rx) = channel();
    let (command_tx, command_rx) = channel();
    let (committed_tx, committed_rx) = channel();
    let relay = relay_over(Box::new(GatedStore {
        inner: backend,
        armed: Arc::clone(&armed),
        paused_tx,
        command_rx,
        committed_tx,
    }));
    Harness {
        relay,
        armed,
        paused_rx,
        command_tx,
        committed_rx,
    }
}

/// Signs a B.4-derived Alice Root record with the given timestamp and name.
fn alice_root(timestamp_ms: u64, name: &str) -> Vec<u8> {
    let mut body = b4_body();
    body.timestamp_ms = timestamp_ms;
    body.contact.display_name = Some(name.to_owned());
    sign_record(&body, &root_seed()).expect("signs")
}

/// Decodes a successful `changes` response into
/// `(entries as (did, lastUpdated), nextCursor bytes, hasMore)`.
fn changes_view(response: &[u8]) -> (Vec<(String, u64)>, Vec<u8>, bool) {
    let value = decode_value(response);
    assert_eq!(value.get(0).expect("version").as_uint(), 1);
    assert_eq!(value.get(1).expect("status").as_uint(), 0, "success status");
    let entries = value
        .get(2)
        .expect("entries")
        .as_array()
        .iter()
        .map(|entry| {
            let parts = entry.as_array();
            let did = match &parts[0] {
                TestValue::Text(text) => text.clone(),
                other => panic!("expected DID text, got {other:?}"),
            };
            (did, parts[2].as_uint())
        })
        .collect();
    let cursor = value.get(3).expect("nextCursor").as_bytes().to_vec();
    let has_more = value.get(4) == Some(&TestValue::Bool(true));
    (entries, cursor, has_more)
}

/// The exact cursor this relay must return for `position`.
fn cursor_at(position: u64) -> Vec<u8> {
    raw_cursor(&test_identity().cursor_generation, position)
}

/// Spawns a thread that publishes `record`, reporting the start of its
/// attempt and its completion through the given endpoints.
#[allow(clippy::type_complexity)]
fn spawn_publisher(
    relay: &TestRelay,
    record: Vec<u8>,
    started_tx: Sender<()>,
    done: Arc<AtomicBool>,
) -> thread::JoinHandle<Result<Vec<u8>, RelayError>> {
    let relay = Arc::clone(&relay.relay);
    thread::spawn(move || {
        started_tx.send(()).expect("orchestrator listens");
        let result = relay.publish(&record);
        done.store(true, Ordering::SeqCst);
        result
    })
}

/// Spawns a thread that requests `changes` from the null cursor, reporting
/// the start of its attempt and its completion through the given endpoints.
#[allow(clippy::type_complexity)]
fn spawn_reader(
    relay: &TestRelay,
    started_tx: Sender<()>,
    done: Arc<AtomicBool>,
) -> thread::JoinHandle<Result<Vec<u8>, RelayError>> {
    let relay = Arc::clone(&relay.relay);
    thread::spawn(move || {
        started_tx.send(()).expect("orchestrator listens");
        let result = relay.changes(&changes_request(None, 10, 1 << 20));
        done.store(true, Ordering::SeqCst);
        result
    })
}

/// The section 20.2 principal interleaving: writer A is paused undecided in
/// the write-critical section, writer B attempts another winning update, a
/// reader attempts a successful cursor, and the test proves that no cursor
/// can pass A while A remains capable of becoming visible; A then commits,
/// B commits in the observable order, and paging from the earlier cursor
/// observes every committed current entry without a gap.
fn success_cursor_cannot_overtake_a_paused_undecided_writer(backend: Box<dyn RelayStore>) {
    let h = gated_relay(backend);
    let alice = fx_bytes("root_record_envelope");
    let bob = fx_bytes("bob_envelope");

    // Step 1: A reaches the gate — admission decided, number unallocated,
    // commit undecided, still capable of becoming visible.
    h.armed.store(true, Ordering::SeqCst);
    let (a_started_tx, _a_started_rx) = channel();
    let a_done = Arc::new(AtomicBool::new(false));
    let a = spawn_publisher(&h.relay, alice, a_started_tx, Arc::clone(&a_done));
    let paused_did = h
        .paused_rx
        .recv_timeout(HANG_GUARD)
        .expect("A reaches the write-critical gate");
    assert_eq!(paused_did, fx_str("followee_did"), "A carries Alice");

    // Step 2: B attempts another winning update for a second DID.
    let (b_started_tx, b_started_rx) = channel();
    let b_done = Arc::new(AtomicBool::new(false));
    let b = spawn_publisher(&h.relay, bob, b_started_tx, Arc::clone(&b_done));
    b_started_rx
        .recv_timeout(HANG_GUARD)
        .expect("B starts its attempt");

    // Step 3: a reader attempts to obtain a successful cursor.
    let (r_started_tx, r_started_rx) = channel();
    let r_done = Arc::new(AtomicBool::new(false));
    let r = spawn_reader(&h.relay, r_started_tx, Arc::clone(&r_done));
    r_started_rx
        .recv_timeout(HANG_GUARD)
        .expect("reader starts its attempt");

    // Step 4: while A remains undecided it holds the relay's store lock
    // inside `commit_current`, and every publish and every successful
    // `changes` response requires that lock. B and the reader started their
    // attempts strictly after A reached the gate and the lock has not been
    // released since, so their incompleteness is an ordering guarantee:
    // no cursor has been or can be returned past the undecided A.
    assert!(!a_done.load(Ordering::SeqCst), "A is paused, not committed");
    assert!(
        !b_done.load(Ordering::SeqCst),
        "B cannot admit while A is undecided"
    );
    assert!(
        !r_done.load(Ordering::SeqCst),
        "no cursor can be returned while A is undecided"
    );
    assert!(
        h.committed_rx.try_recv().is_err(),
        "nothing has committed yet"
    );

    // Step 5: release A; it allocates update number 1 and commits.
    h.command_tx
        .send(GateCommand::Commit)
        .expect("A waits at the gate");
    let a_response = a.join().expect("A thread").expect("A publish completes");
    assert_eq!(publish_outcome(&a_response), (0, None), "A admitted");
    assert_eq!(
        h.committed_rx
            .recv_timeout(HANG_GUARD)
            .expect("A committed"),
        (fx_str("followee_did"), 1),
        "A holds the first update number"
    );

    // Step 6: B commits in the implementation's observable order — strictly
    // after A, allocating the next contiguous number inside its own commit.
    let b_response = b.join().expect("B thread").expect("B publish completes");
    assert_eq!(publish_outcome(&b_response), (0, None), "B admitted");
    assert_eq!(
        h.committed_rx
            .recv_timeout(HANG_GUARD)
            .expect("B committed"),
        (fx_str("bob_did"), 2),
        "B follows A with no gap"
    );

    // The reader unblocked after A's release. The store lock admits exactly
    // two serializations — before or after B's commit — and each has one
    // exact conforming response; anything else (an empty response with an
    // advanced cursor, a response containing Bob but not Alice, a cursor
    // beyond the returned range) is a visibility violation.
    let r_response = r.join().expect("reader thread").expect("changes completes");
    let (r_entries, r_cursor, r_has_more) = changes_view(&r_response);
    let alice_did = fx_str("followee_did");
    let bob_did = fx_str("bob_did");
    match r_entries.as_slice() {
        [(did, 1)] if *did == alice_did => {
            assert_eq!(r_cursor, cursor_at(1), "cursor covers exactly Alice");
        }
        [(did_a, 1), (did_b, 2)] if *did_a == alice_did && *did_b == bob_did => {
            assert_eq!(r_cursor, cursor_at(2), "cursor covers exactly both");
        }
        other => panic!("nonconforming reader view: {other:?}"),
    }
    assert!(!r_has_more, "no eligible entry was omitted");

    // Step 7: paging from the earlier cursor observes every committed
    // current entry with no gap.
    let follow_up = h
        .relay
        .relay
        .changes(&changes_request(Some(&r_cursor), 10, 1 << 20))
        .expect("changes completes");
    let (mut seen, _, follow_up_more) = changes_view(&follow_up);
    assert!(!follow_up_more);
    let mut union = r_entries.clone();
    union.append(&mut seen);
    assert_eq!(
        union,
        vec![(alice_did.clone(), 1), (bob_did.clone(), 2)],
        "the client observes every committed entry exactly once, in order"
    );

    // Coalescing is preserved: a third update replaces Alice's tuple, and a
    // DID updated several times appears only as its current tuple. The
    // exact stepwise walk also proves the cursor never advances past an
    // omitted eligible entry.
    let a2_response = h
        .relay
        .relay
        .publish(&alice_root(B4_TIMESTAMP_MS + 50, "Alice v2"))
        .expect("publish completes");
    assert_eq!(publish_outcome(&a2_response), (0, None));
    assert_eq!(
        h.committed_rx.recv_timeout(HANG_GUARD).expect("committed"),
        (alice_did.clone(), 3)
    );
    let (page, cursor, has_more) = changes_view(
        &h.relay
            .relay
            .changes(&changes_request(None, 1, 1 << 20))
            .expect("changes"),
    );
    assert_eq!(
        page,
        vec![(bob_did.clone(), 2)],
        "Alice's old tuple is gone"
    );
    assert_eq!(cursor, cursor_at(2));
    assert!(has_more);
    let (page, cursor, has_more) = changes_view(
        &h.relay
            .relay
            .changes(&changes_request(Some(&cursor), 1, 1 << 20))
            .expect("changes"),
    );
    assert_eq!(
        page,
        vec![(alice_did.clone(), 3)],
        "current Alice tuple only"
    );
    assert_eq!(cursor, cursor_at(3));
    assert!(!has_more);
    let (page, cursor, has_more) = changes_view(
        &h.relay
            .relay
            .changes(&changes_request(Some(&cursor), 1, 1 << 20))
            .expect("changes"),
    );
    assert!(page.is_empty() && !has_more);
    assert_eq!(
        cursor,
        cursor_at(3),
        "an empty page represents the supplied position"
    );

    // A client still paging from the reader's earlier cursor also converges
    // on every current tuple without a gap.
    let (from_earlier, _, _) = changes_view(
        &h.relay
            .relay
            .changes(&changes_request(Some(&r_cursor), 10, 1 << 20))
            .expect("changes"),
    );
    let expected = if r_cursor == cursor_at(1) {
        vec![(bob_did.clone(), 2), (alice_did.clone(), 3)]
    } else {
        vec![(alice_did.clone(), 3)]
    };
    assert_eq!(from_earlier, expected);

    let final_counter = h
        .relay
        .relay
        .with_store(|s| s.last_update_number())
        .expect("store readable");
    assert_eq!(final_counter, 3, "exactly three numbers were ever assigned");
}

/// Cancellation of the paused writer must leave no observable trace and no
/// permanently blocking sequence hole: the next winner takes the same
/// number, and readers converge on a contiguous committed prefix.
fn cancelled_writer_creates_no_permanently_blocking_hole(backend: Box<dyn RelayStore>) {
    let h = gated_relay(backend);
    let alice = fx_bytes("root_record_envelope");
    let bob = fx_bytes("bob_envelope");

    h.armed.store(true, Ordering::SeqCst);
    let (a_started_tx, _a_started_rx) = channel();
    let a_done = Arc::new(AtomicBool::new(false));
    let a = spawn_publisher(&h.relay, alice, a_started_tx, Arc::clone(&a_done));
    h.paused_rx
        .recv_timeout(HANG_GUARD)
        .expect("A reaches the write-critical gate");

    let (b_started_tx, b_started_rx) = channel();
    let b_done = Arc::new(AtomicBool::new(false));
    let b = spawn_publisher(&h.relay, bob, b_started_tx, Arc::clone(&b_done));
    b_started_rx.recv_timeout(HANG_GUARD).expect("B starts");
    let (r_started_tx, r_started_rx) = channel();
    let r_done = Arc::new(AtomicBool::new(false));
    let r = spawn_reader(&h.relay, r_started_tx, Arc::clone(&r_done));
    r_started_rx
        .recv_timeout(HANG_GUARD)
        .expect("reader starts");
    assert!(!b_done.load(Ordering::SeqCst) && !r_done.load(Ordering::SeqCst));

    // Cancel A at the gate: the admission fails as a storage fault, before
    // any number was allocated.
    h.command_tx
        .send(GateCommand::Cancel)
        .expect("A waits at the gate");
    let a_result = a.join().expect("A thread");
    assert!(
        matches!(a_result, Err(RelayError::Internal(_))),
        "the cancelled admission surfaces as an internal failure: {a_result:?}"
    );

    // B proceeds and takes update number 1: the cancelled writer consumed
    // no position, so there is no hole for a cursor to be blocked behind.
    let b_response = b.join().expect("B thread").expect("B publish completes");
    assert_eq!(publish_outcome(&b_response), (0, None));
    assert_eq!(
        h.committed_rx
            .recv_timeout(HANG_GUARD)
            .expect("B committed"),
        (fx_str("bob_did"), 1),
        "the first committed observation is B at number 1"
    );

    // The reader returns one of the two conforming serializations around
    // B's commit, each with the exact cursor for its returned range.
    let r_response = r.join().expect("reader thread").expect("changes completes");
    let (r_entries, r_cursor, _) = changes_view(&r_response);
    let bob_did = fx_str("bob_did");
    match r_entries.as_slice() {
        [] => assert_eq!(
            r_cursor,
            cursor_at(0),
            "an empty view keeps the supplied position"
        ),
        [(did, 1)] if *did == bob_did => assert_eq!(r_cursor, cursor_at(1)),
        other => panic!("nonconforming reader view: {other:?}"),
    }

    // Alice re-admits with the next contiguous number; nothing is blocked.
    let a2_response = h
        .relay
        .relay
        .publish(&fx_bytes("root_record_envelope"))
        .expect("publish completes");
    assert_eq!(publish_outcome(&a2_response), (0, None));
    assert_eq!(
        h.committed_rx.recv_timeout(HANG_GUARD).expect("committed"),
        (fx_str("followee_did"), 2)
    );
    let (all, cursor, has_more) = changes_view(
        &h.relay
            .relay
            .changes(&changes_request(None, 10, 1 << 20))
            .expect("changes"),
    );
    assert_eq!(
        all,
        vec![(bob_did, 1), (fx_str("followee_did"), 2)],
        "the committed prefix is contiguous"
    );
    assert_eq!(cursor, cursor_at(2));
    assert!(!has_more);
}

fn sqlite_backend() -> (tempfile::TempDir, Box<dyn RelayStore>) {
    let dir = tempfile::tempdir().expect("temp dir");
    let store =
        SqliteStore::open(&dir.path().join("relay.db"), test_identity()).expect("sqlite opens");
    (dir, Box::new(store))
}

#[test]
fn sec_12_6_success_cursor_cannot_overtake_a_paused_undecided_writer_memory() {
    success_cursor_cannot_overtake_a_paused_undecided_writer(Box::new(MemoryStore::new(
        test_identity(),
    )));
}

#[test]
fn sec_12_6_success_cursor_cannot_overtake_a_paused_undecided_writer_sqlite() {
    let (_dir, backend) = sqlite_backend();
    success_cursor_cannot_overtake_a_paused_undecided_writer(backend);
}

#[test]
fn sec_12_6_cancelled_writer_creates_no_permanently_blocking_hole_memory() {
    cancelled_writer_creates_no_permanently_blocking_hole(Box::new(MemoryStore::new(
        test_identity(),
    )));
}

#[test]
fn sec_12_6_cancelled_writer_creates_no_permanently_blocking_hole_sqlite() {
    let (_dir, backend) = sqlite_backend();
    cancelled_writer_creates_no_permanently_blocking_hole(backend);
}

/// A SQLite transaction that fails after the counter row was already updated
/// must roll the allocation back: process or storage failure between
/// allocation and commit cannot create a permanently blocking hole
/// (specification sections 12.6 and 13.2). The oversized ordering timestamp
/// makes the entry-row parameter conversion fail deterministically after the
/// in-transaction counter update; such a timestamp is unreachable through
/// the relay path, where the section 5.4 future bound rejects it first.
#[test]
fn sec_13_2_sqlite_commit_failure_rolls_back_the_allocated_update_number() {
    let dir = tempfile::tempdir().expect("temp dir");
    let mut store =
        SqliteStore::open(&dir.path().join("relay.db"), test_identity()).expect("sqlite opens");

    let poisoned_meta = OrderingMeta {
        authority: Authority::Root,
        timestamp_ms: u64::MAX,
        body_digest: [0u8; 32],
    };
    let result = store.commit_current(
        "did:flw:zRollback",
        b"envelope",
        AuthorityState::Root,
        poisoned_meta,
    );
    assert!(result.is_err(), "the commit transaction fails");
    assert_eq!(
        store.last_update_number().expect("counter readable"),
        0,
        "the allocated number rolled back with the transaction"
    );
    assert!(
        store
            .entry("did:flw:zRollback")
            .expect("readable")
            .is_none(),
        "no entry became visible"
    );
    let (rows, has_more) = store.changes_after(0, 10).expect("changes readable");
    assert!(rows.is_empty() && !has_more, "the feed is empty");

    // The next successful commit takes the same number: no hole.
    let good_meta = OrderingMeta {
        authority: Authority::Root,
        timestamp_ms: B4_TIMESTAMP_MS,
        body_digest: [1u8; 32],
    };
    let number = store
        .commit_current(
            "did:flw:zRollback",
            b"envelope",
            AuthorityState::Root,
            good_meta,
        )
        .expect("commit succeeds");
    assert_eq!(number, 1, "the rolled-back number is reused, not skipped");
    let (rows, _) = store.changes_after(0, 10).expect("changes readable");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].last_updated, 1);
}

// ---------------------------------------------------------------------------
// v0.9 section 13.2 lock-boundary regression: preparation holds no lock.
// ---------------------------------------------------------------------------

/// Builds a relay whose production `publish` pauses — when armed — in the
/// unlocked gap after phase-1 preparation, immediately before the store
/// lock. The hook carries no protocol data and makes no decision; it only
/// delays the calling thread at a point the scheduler could already
/// preempt, so pausing there is behaviour production can exhibit anyway.
fn relay_with_gap_pause(
    backend: Box<dyn RelayStore>,
) -> (
    Arc<followee::relay::Relay>,
    Arc<AtomicBool>,
    Receiver<()>,
    Sender<()>,
) {
    let armed = Arc::new(AtomicBool::new(false));
    let (gap_entered_tx, gap_entered_rx) = channel();
    let (release_tx, release_rx) = channel::<()>();
    let release_rx = std::sync::Mutex::new(release_rx);
    let armed_in_hook = Arc::clone(&armed);
    let mut relay = followee::relay::Relay::new(
        backend,
        Box::new(SharedClock(Arc::new(followee::clock::ManualClock::new(
            RELAY_NOW_MS,
        )))),
        followee::relay::RelayConfig {
            base_uri: "http://127.0.0.1/".to_owned(),
            development_mode: true,
        },
    )
    .expect("valid test configuration");
    relay.set_publish_gap_hook(Box::new(move || {
        if armed_in_hook.swap(false, Ordering::SeqCst) {
            gap_entered_tx
                .send(())
                .expect("orchestrator holds the gap receiver");
            release_rx
                .lock()
                .expect("no poisoning")
                .recv_timeout(HANG_GUARD)
                .expect("gap release arrives");
        }
    }));
    (Arc::new(relay), armed, gap_entered_rx, release_tx)
}

/// While a publication is paused *after* its state-independent preparation
/// and *before* the store lock, a `changes` reader completes with the exact
/// committed prefix: verification work excludes no reader. This is safe
/// under the section 12.6 invariant because the paused writer holds no
/// allocated position — allocation happens only inside the locked commit it
/// has not reached — and it pins the corrected lock boundary: were the lock
/// taken before preparation, the reader would deadlock and this test would
/// fail by its hang guard.
fn reader_completes_while_a_publication_prepares_unlocked(backend: Box<dyn RelayStore>) {
    let (relay, armed, gap_entered_rx, release_tx) = relay_with_gap_pause(backend);

    // Seed one committed entry so the reader's view is nonempty and exact.
    let seed = relay
        .publish(&fx_bytes("bob_envelope"))
        .expect("publish completes");
    assert_eq!(publish_outcome(&seed), (0, None), "seed admitted");

    // Writer A completes phase 1 (size, CBOR, schema, binding, signature,
    // future bound) and pauses in the unlocked gap.
    armed.store(true, Ordering::SeqCst);
    let a_relay = Arc::clone(&relay);
    let a = thread::spawn(move || a_relay.publish(&fx_bytes("root_record_envelope")));
    gap_entered_rx
        .recv_timeout(HANG_GUARD)
        .expect("A reaches the unlocked gap after preparation");

    // The reader completes while A remains paused there.
    let r_relay = Arc::clone(&relay);
    let (r_done_tx, r_done_rx) = channel();
    thread::spawn(move || {
        let response = r_relay.changes(&changes_request(None, 10, 1 << 20));
        r_done_tx
            .send(response)
            .expect("orchestrator holds the reader receiver");
    });
    let response = r_done_rx
        .recv_timeout(HANG_GUARD)
        .expect("the reader completes while the publication is paused unlocked")
        .expect("changes completes");
    let (entries, cursor, has_more) = changes_view(&response);
    assert_eq!(
        entries,
        vec![(fx_str("bob_did"), 1)],
        "exact committed prefix"
    );
    assert_eq!(cursor, cursor_at(1), "cursor covers exactly that prefix");
    assert!(!has_more);

    // Release A: it acquires the lock, decides, and commits as update 2;
    // nothing was lost or reordered by the unlocked pause.
    release_tx.send(()).expect("A waits in the gap");
    let a_response = a.join().expect("A thread").expect("publish completes");
    assert_eq!(publish_outcome(&a_response), (0, None), "A admitted");
    let (all, cursor, has_more) = changes_view(
        &relay
            .changes(&changes_request(None, 10, 1 << 20))
            .expect("changes completes"),
    );
    assert_eq!(
        all,
        vec![(fx_str("bob_did"), 1), (fx_str("followee_did"), 2)],
        "contiguous committed order"
    );
    assert_eq!(cursor, cursor_at(2));
    assert!(!has_more);
}

#[test]
fn sec_13_2_reader_completes_while_a_publication_prepares_unlocked_memory() {
    reader_completes_while_a_publication_prepares_unlocked(Box::new(MemoryStore::new(
        test_identity(),
    )));
}

#[test]
fn sec_13_2_reader_completes_while_a_publication_prepares_unlocked_sqlite() {
    let (_dir, backend) = sqlite_backend();
    reader_completes_while_a_publication_prepares_unlocked(backend);
}
