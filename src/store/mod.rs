//! Relay persistent-state contract and backends (specification sections 11.1,
//! 12.7, and 13; IMPLEMENTATION.md section 9.2).
//!
//! The contract is deliberately narrow and observable: a store persists the
//! relay identity, the partial current map, sticky authority state, retained
//! ordering metadata, per-entry `lastUpdated` numbers, the relay directory,
//! and the update counter. Every admission *decision* — verification,
//! precedence, premature classification, update-number policy — lives in
//! [`crate::relay`], so both backends run identical protocol logic and can be
//! compared black-box. The database schema is an implementation detail and
//! never leaks into the wire protocol.
//!
//! Two backends implement the same contract: [`MemoryStore`] (volatile, for
//! tests and ephemeral relays) and [`sqlite::SqliteStore`] (durable, with
//! explicit transactions making current-state replacement, sticky
//! authority-state changes, and update-number assignment atomic).

pub mod sqlite;

use crate::ordering::AuthorityState;
use crate::record::Authority;
use std::collections::BTreeMap;

/// Storage failure. Memory operations are infallible; SQLite surfaces I/O and
/// integrity failures here. The relay maps these to `internalError`.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// The underlying database reported a failure.
    #[error("storage backend failure: {0}")]
    Backend(String),
    /// A persisted value violates the store's own invariants (for example a
    /// counter that does not fit the persisted integer type).
    #[error("storage invariant violated: {0}")]
    Corrupt(String),
}

/// The relay's persistent identity (specification sections 12.2 and 12.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelayIdentity {
    /// Stable 16-byte relay instance identifier.
    pub relay_id: [u8; 16],
    /// Current 16-byte cursor generation.
    pub cursor_generation: [u8; 16],
    /// Current 16-byte directory generation.
    pub directory_generation: [u8; 16],
}

impl RelayIdentity {
    /// Generates a fresh identity from the injected randomness source.
    /// Generations are opaque equality tokens with no ordering semantics
    /// (specification section 11.4).
    ///
    /// # Errors
    ///
    /// Returns [`crate::random::RandomError`] when the source fails.
    pub fn generate(
        rng: &dyn crate::random::RandomSource,
    ) -> Result<Self, crate::random::RandomError> {
        let mut relay_id = [0u8; 16];
        let mut cursor_generation = [0u8; 16];
        let mut directory_generation = [0u8; 16];
        rng.fill(&mut relay_id)?;
        rng.fill(&mut cursor_generation)?;
        rng.fill(&mut directory_generation)?;
        Ok(RelayIdentity {
            relay_id,
            cursor_generation,
            directory_generation,
        })
    }
}

/// Ordering metadata retained for a current entry (specification sections 8.3
/// and 11.2). Retained even after Full-to-Ref conversion so a later full
/// candidate cannot roll back the same authority state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OrderingMeta {
    /// The entry's authority state as signed.
    pub authority: Authority,
    /// The entry's ordering timestamp.
    pub timestamp_ms: u64,
    /// The entry's 32-byte body digest.
    pub body_digest: [u8; 32],
}

/// The stored payload tier (specification section 11.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntryPayload {
    /// Exact admitted complete envelope bytes.
    Full(Vec<u8>),
    /// Routing reference: a relay index meaningful only with the current
    /// directory generation. Never an authority or validity assertion.
    Ref(u32),
}

/// One current-map entry (specification section 11.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredEntry {
    /// Full bytes or reference.
    pub payload: EntryPayload,
    /// Locally learned sticky authority state.
    pub authority_state: AuthorityState,
    /// Retained ordering metadata; present for every locally admitted entry,
    /// possibly absent for an entry whose metadata was not retained.
    pub ordering: Option<OrderingMeta>,
    /// Relay-local update number assigned when this entry last changed.
    pub last_updated: u64,
}

/// One relay-directory row (specification section 11.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectoryEntry {
    /// Unsigned integer index, meaningful only with the current generation.
    pub index: u32,
    /// The peer's 16-byte relay instance identifier.
    pub relay_id: [u8; 16],
    /// The peer's advertised base URI.
    pub endpoint: String,
    /// The peer's capability bit mask.
    pub capabilities: u64,
}

/// One `v1/changes` feed row: a current tuple with its assigned number.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangeRow {
    /// The entry's canonical Followee DID.
    pub did: String,
    /// The entry's current payload tier.
    pub payload: EntryPayload,
    /// The relay-local update number (`lastUpdated`).
    pub last_updated: u64,
}

/// Persisted synchronization state for one peer relay (specification
/// sections 12.7 and 13.3; IMPLEMENTATION.md section 9.2).
///
/// The peer is identified by its stable 16-byte relay instance identifier,
/// not by its endpoint: a cursor is meaningful only to the relay instance
/// that issued it, so an endpoint change under the same identifier keeps the
/// cursor, while a different identifier at the same endpoint is a different
/// peer whose state is independent. Cursor-generation changes are signalled
/// by the peer itself (`ResetRequired`) and clear only the cursor, never
/// independently verified local identity state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerState {
    /// The peer's stable 16-byte relay instance identifier.
    pub relay_id: [u8; 16],
    /// The base URI the peer was last synchronized from.
    pub endpoint: String,
    /// The exact opaque cursor bytes returned by the peer's last accepted
    /// `v1/changes` success response, or `None` before the first success or
    /// after a cursor-generation reset.
    pub cursor: Option<Vec<u8>>,
}

/// The storage contract shared by every backend.
///
/// All mutating operations must be atomic and durable to the backend's
/// ability before returning: specification section 13.1 requires a winning
/// record and a newly learned RootRevoked transition to be persisted before
/// an admission acknowledgement is returned.
pub trait RelayStore: Send {
    /// The persisted relay identity.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when the backend cannot read its state.
    fn identity(&self) -> Result<RelayIdentity, StoreError>;

    /// Loads the current entry for `did`, if any.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when the backend cannot read its state.
    fn entry(&self, did: &str) -> Result<Option<StoredEntry>, StoreError>;

    /// Atomically replaces the current entry for `did` with a winning full
    /// record, persists the given authority state, assigns the next
    /// relay-local update number, and returns it. This is the only operation
    /// that assigns update numbers (specification section 13.2).
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when the backend cannot persist atomically.
    fn commit_current(
        &mut self,
        did: &str,
        envelope: &[u8],
        authority_state: AuthorityState,
        ordering: OrderingMeta,
    ) -> Result<u64, StoreError>;

    /// Converts a Full entry to a reference for storage housekeeping,
    /// preserving sticky authority state, retained ordering metadata, and
    /// `lastUpdated`. Never assigns an update number (specification sections
    /// 11.2 and 13.2). Returns `false` when no entry exists.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when the backend cannot persist the change.
    fn convert_to_ref(&mut self, did: &str, relay_index: u32) -> Result<bool, StoreError>;

    /// Drops the complete entry, including its sticky authority state; later
    /// re-admission begins as a fresh observation (specification section
    /// 11.3). Returns `false` when no entry exists.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when the backend cannot persist the change.
    fn drop_entry(&mut self, did: &str) -> Result<bool, StoreError>;

    /// Returns up to `max` current tuples whose `lastUpdated` lies strictly
    /// after `position`, in increasing `lastUpdated` order, plus whether more
    /// eligible tuples remained (specification section 12.6).
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when the backend cannot read its state.
    fn changes_after(
        &self,
        position: u64,
        max: usize,
    ) -> Result<(Vec<ChangeRow>, bool), StoreError>;

    /// The greatest assigned relay-local update number, or `0` when none has
    /// been assigned.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when the backend cannot read its state.
    fn last_update_number(&self) -> Result<u64, StoreError>;

    /// The current relay directory rows in increasing index order.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when the backend cannot read its state.
    fn directory(&self) -> Result<Vec<DirectoryEntry>, StoreError>;

    /// Replaces the directory under a freshly generated generation value
    /// (specification section 11.4: reusing or changing existing indices
    /// requires a new random generation).
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when the backend cannot persist the change.
    fn set_directory(
        &mut self,
        entries: Vec<DirectoryEntry>,
        new_generation: [u8; 16],
    ) -> Result<(), StoreError>;

    /// Adopts a new cursor generation after an incompatible restore or
    /// renumbering (specification sections 12.7 and 13.5). Per-entry numbers
    /// are preserved as compatible positions, so an initial null-cursor scan
    /// still enumerates every retained current entry.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when the backend cannot persist the change.
    fn reset_cursor_generation(&mut self, new_generation: [u8; 16]) -> Result<(), StoreError>;

    /// Loads the persisted synchronization state for the peer with this
    /// relay instance identifier, if any.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when the backend cannot read its state.
    fn peer_state(&self, relay_id: &[u8; 16]) -> Result<Option<PeerState>, StoreError>;

    /// Atomically inserts or replaces the synchronization state for
    /// `state.relay_id`, durable before returning: the peer cursor is
    /// persisted only after the response's accepted entries were durably
    /// processed, so a crash replays a range safely instead of skipping it
    /// (specification section 13.3).
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when the backend cannot persist the change.
    fn set_peer_state(&mut self, state: &PeerState) -> Result<(), StoreError>;

    /// Every persisted peer synchronization state, in ascending
    /// relay-identifier order.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when the backend cannot read its state.
    fn peer_states(&self) -> Result<Vec<PeerState>, StoreError>;
}

/// Volatile in-memory backend.
#[derive(Debug)]
pub struct MemoryStore {
    identity: RelayIdentity,
    entries: BTreeMap<String, StoredEntry>,
    directory: Vec<DirectoryEntry>,
    peers: BTreeMap<[u8; 16], PeerState>,
    next_update_number: u64,
}

impl MemoryStore {
    /// Creates an empty store with the given identity.
    #[must_use]
    pub fn new(identity: RelayIdentity) -> Self {
        MemoryStore {
            identity,
            entries: BTreeMap::new(),
            directory: Vec::new(),
            peers: BTreeMap::new(),
            next_update_number: 1,
        }
    }
}

impl RelayStore for MemoryStore {
    fn identity(&self) -> Result<RelayIdentity, StoreError> {
        Ok(self.identity)
    }

    fn entry(&self, did: &str) -> Result<Option<StoredEntry>, StoreError> {
        Ok(self.entries.get(did).cloned())
    }

    fn commit_current(
        &mut self,
        did: &str,
        envelope: &[u8],
        authority_state: AuthorityState,
        ordering: OrderingMeta,
    ) -> Result<u64, StoreError> {
        let number = self.next_update_number;
        self.next_update_number = self
            .next_update_number
            .checked_add(1)
            .ok_or_else(|| StoreError::Corrupt("update counter exhausted".to_owned()))?;
        self.entries.insert(
            did.to_owned(),
            StoredEntry {
                payload: EntryPayload::Full(envelope.to_vec()),
                authority_state,
                ordering: Some(ordering),
                last_updated: number,
            },
        );
        Ok(number)
    }

    fn convert_to_ref(&mut self, did: &str, relay_index: u32) -> Result<bool, StoreError> {
        match self.entries.get_mut(did) {
            Some(entry) => {
                entry.payload = EntryPayload::Ref(relay_index);
                Ok(true)
            }
            None => Ok(false),
        }
    }

    fn drop_entry(&mut self, did: &str) -> Result<bool, StoreError> {
        Ok(self.entries.remove(did).is_some())
    }

    fn changes_after(
        &self,
        position: u64,
        max: usize,
    ) -> Result<(Vec<ChangeRow>, bool), StoreError> {
        let mut eligible: Vec<&str> = self
            .entries
            .iter()
            .filter(|(_, e)| e.last_updated > position)
            .map(|(did, _)| did.as_str())
            .collect();
        eligible.sort_by_key(|did| self.entries[*did].last_updated);
        let has_more = eligible.len() > max;
        let rows = eligible
            .into_iter()
            .take(max)
            .map(|did| {
                let entry = &self.entries[did];
                ChangeRow {
                    did: did.to_owned(),
                    payload: entry.payload.clone(),
                    last_updated: entry.last_updated,
                }
            })
            .collect();
        Ok((rows, has_more))
    }

    fn last_update_number(&self) -> Result<u64, StoreError> {
        // next_update_number starts at 1 and is bumped after each
        // assignment, so the greatest assigned number is one less.
        Ok(self.next_update_number.saturating_sub(1))
    }

    fn directory(&self) -> Result<Vec<DirectoryEntry>, StoreError> {
        Ok(self.directory.clone())
    }

    fn set_directory(
        &mut self,
        mut entries: Vec<DirectoryEntry>,
        new_generation: [u8; 16],
    ) -> Result<(), StoreError> {
        entries.sort_by_key(|e| e.index);
        self.directory = entries;
        self.identity.directory_generation = new_generation;
        Ok(())
    }

    fn reset_cursor_generation(&mut self, new_generation: [u8; 16]) -> Result<(), StoreError> {
        self.identity.cursor_generation = new_generation;
        Ok(())
    }

    fn peer_state(&self, relay_id: &[u8; 16]) -> Result<Option<PeerState>, StoreError> {
        Ok(self.peers.get(relay_id).cloned())
    }

    fn set_peer_state(&mut self, state: &PeerState) -> Result<(), StoreError> {
        self.peers.insert(state.relay_id, state.clone());
        Ok(())
    }

    fn peer_states(&self) -> Result<Vec<PeerState>, StoreError> {
        Ok(self.peers.values().cloned().collect())
    }
}
