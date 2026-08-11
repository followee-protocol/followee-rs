//! Durable SQLite backend for the relay store contract.
//!
//! Every mutating contract operation runs inside one SQLite transaction, so
//! current-state replacement, sticky authority-state changes, and relay-local
//! update-number assignment are atomic and persisted before the call returns
//! (IMPLEMENTATION.md section 9.2; specification section 13.1). Reopening the
//! same database restores the identity, generations, entries, sticky states,
//! and counter exactly.

use super::{
    ChangeRow, DirectoryEntry, EntryPayload, OrderingMeta, PeerState, RelayIdentity, RelayStore,
    StoreError, StoredEntry,
};
use crate::ordering::AuthorityState;
use crate::record::Authority;
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use std::path::Path;

/// SQLite-backed relay store.
pub struct SqliteStore {
    conn: Connection,
}

impl std::fmt::Debug for SqliteStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SqliteStore").finish_non_exhaustive()
    }
}

fn backend<E: std::fmt::Display>(e: E) -> StoreError {
    StoreError::Backend(e.to_string())
}

fn to_i64(v: u64, what: &str) -> Result<i64, StoreError> {
    i64::try_from(v).map_err(|_| StoreError::Corrupt(format!("{what} exceeds the i64 range")))
}

fn to_u64(v: i64, what: &str) -> Result<u64, StoreError> {
    u64::try_from(v).map_err(|_| StoreError::Corrupt(format!("{what} is negative")))
}

fn blob16(v: Vec<u8>, what: &str) -> Result<[u8; 16], StoreError> {
    v.try_into()
        .map_err(|_| StoreError::Corrupt(format!("{what} is not 16 bytes")))
}

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS meta (
  key   TEXT PRIMARY KEY,
  value BLOB NOT NULL
) STRICT;
CREATE TABLE IF NOT EXISTS entries (
  did             TEXT PRIMARY KEY,
  kind            INTEGER NOT NULL,
  envelope        BLOB,
  ref_index       INTEGER,
  authority_state INTEGER NOT NULL,
  ord_authority   INTEGER,
  ord_timestamp   INTEGER,
  ord_digest      BLOB,
  last_updated    INTEGER NOT NULL
) STRICT;
CREATE INDEX IF NOT EXISTS entries_last_updated ON entries(last_updated);
CREATE TABLE IF NOT EXISTS directory (
  idx          INTEGER PRIMARY KEY,
  relay_id     BLOB NOT NULL,
  endpoint     TEXT NOT NULL,
  capabilities INTEGER NOT NULL
) STRICT;
CREATE TABLE IF NOT EXISTS peers (
  relay_id BLOB PRIMARY KEY,
  endpoint TEXT NOT NULL,
  cursor   BLOB
) STRICT;
";

impl SqliteStore {
    /// Creates a new database at `path`, persisting `identity`, or opens an
    /// existing one, ignoring `identity` in favour of the persisted values
    /// (restart preserves identity, generations, and state).
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when the database cannot be created or read.
    pub fn open(path: &Path, identity: RelayIdentity) -> Result<Self, StoreError> {
        let conn = Connection::open(path).map_err(backend)?;
        Self::init(conn, identity)
    }

    /// Creates a fresh in-process database. Durability tests use [`open`];
    /// this constructor supports fast contract tests over the same code.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when the database cannot be initialised.
    ///
    /// [`open`]: SqliteStore::open
    pub fn open_in_memory(identity: RelayIdentity) -> Result<Self, StoreError> {
        let conn = Connection::open_in_memory().map_err(backend)?;
        Self::init(conn, identity)
    }

    fn init(conn: Connection, identity: RelayIdentity) -> Result<Self, StoreError> {
        conn.pragma_update(None, "journal_mode", "WAL")
            .map_err(backend)?;
        conn.pragma_update(None, "synchronous", "FULL")
            .map_err(backend)?;
        conn.pragma_update(None, "foreign_keys", "ON")
            .map_err(backend)?;
        // The `followee relay sync` operator command opens the same database
        // as a running `relay serve` process. Writers from both processes
        // serialize through SQLite's write lock; a bounded busy timeout turns
        // momentary contention into a short wait instead of an error.
        conn.busy_timeout(std::time::Duration::from_secs(5))
            .map_err(backend)?;
        conn.execute_batch(SCHEMA).map_err(backend)?;
        let store = SqliteStore { conn };
        // Persist the identity only on first initialisation; an existing
        // database keeps its stored identity.
        if store.meta_blob("relay_id")?.is_none() {
            store.put_meta("relay_id", &identity.relay_id)?;
            store.put_meta("cursor_generation", &identity.cursor_generation)?;
            store.put_meta("directory_generation", &identity.directory_generation)?;
            store.put_meta("next_update_number", &1u64.to_be_bytes())?;
        }
        Ok(store)
    }

    fn meta_blob(&self, key: &str) -> Result<Option<Vec<u8>>, StoreError> {
        self.conn
            .query_row("SELECT value FROM meta WHERE key = ?1", [key], |row| {
                row.get::<_, Vec<u8>>(0)
            })
            .optional()
            .map_err(backend)
    }

    fn require_meta16(&self, key: &str) -> Result<[u8; 16], StoreError> {
        let value = self
            .meta_blob(key)?
            .ok_or_else(|| StoreError::Corrupt(format!("meta key {key} missing")))?;
        blob16(value, key)
    }

    fn put_meta(&self, key: &str, value: &[u8]) -> Result<(), StoreError> {
        self.conn
            .execute(
                "INSERT INTO meta (key, value) VALUES (?1, ?2)
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                params![key, value],
            )
            .map_err(backend)?;
        Ok(())
    }

    fn next_update_number(&self) -> Result<u64, StoreError> {
        let raw = self
            .meta_blob("next_update_number")?
            .ok_or_else(|| StoreError::Corrupt("update counter missing".to_owned()))?;
        let bytes: [u8; 8] = raw
            .try_into()
            .map_err(|_| StoreError::Corrupt("update counter is not 8 bytes".to_owned()))?;
        Ok(u64::from_be_bytes(bytes))
    }
}

fn state_to_i64(state: AuthorityState) -> i64 {
    match state {
        AuthorityState::Unknown => 0,
        AuthorityState::Root => 1,
        AuthorityState::RootRevoked => 2,
    }
}

fn state_from_i64(v: i64) -> Result<AuthorityState, StoreError> {
    match v {
        0 => Ok(AuthorityState::Unknown),
        1 => Ok(AuthorityState::Root),
        2 => Ok(AuthorityState::RootRevoked),
        other => Err(StoreError::Corrupt(format!(
            "unknown authority state {other}"
        ))),
    }
}

type EntryRow = (
    i64,
    Option<Vec<u8>>,
    Option<i64>,
    i64,
    Option<i64>,
    Option<i64>,
    Option<Vec<u8>>,
    i64,
);

fn entry_from_row(row: EntryRow) -> Result<StoredEntry, StoreError> {
    let (kind, envelope, ref_index, state, ord_auth, ord_ts, ord_digest, last_updated) = row;
    let payload = match kind {
        0 => EntryPayload::Full(
            envelope.ok_or_else(|| StoreError::Corrupt("full entry without bytes".to_owned()))?,
        ),
        1 => {
            let index = ref_index
                .ok_or_else(|| StoreError::Corrupt("ref entry without index".to_owned()))?;
            EntryPayload::Ref(
                u32::try_from(index)
                    .map_err(|_| StoreError::Corrupt("ref index out of range".to_owned()))?,
            )
        }
        other => return Err(StoreError::Corrupt(format!("unknown entry kind {other}"))),
    };
    let ordering = match (ord_auth, ord_ts, ord_digest) {
        (Some(auth), Some(ts), Some(digest)) => Some(OrderingMeta {
            authority: match auth {
                0 => Authority::Root,
                1 => Authority::RootRevoked,
                other => {
                    return Err(StoreError::Corrupt(format!(
                        "unknown ordering authority {other}"
                    )));
                }
            },
            timestamp_ms: to_u64(ts, "ordering timestamp")?,
            body_digest: digest
                .try_into()
                .map_err(|_| StoreError::Corrupt("ordering digest is not 32 bytes".to_owned()))?,
        }),
        (None, None, None) => None,
        _ => {
            return Err(StoreError::Corrupt(
                "partially present ordering metadata".to_owned(),
            ));
        }
    };
    Ok(StoredEntry {
        payload,
        authority_state: state_from_i64(state)?,
        ordering,
        last_updated: to_u64(last_updated, "last_updated")?,
    })
}

impl RelayStore for SqliteStore {
    fn identity(&self) -> Result<RelayIdentity, StoreError> {
        Ok(RelayIdentity {
            relay_id: self.require_meta16("relay_id")?,
            cursor_generation: self.require_meta16("cursor_generation")?,
            directory_generation: self.require_meta16("directory_generation")?,
        })
    }

    fn entry(&self, did: &str) -> Result<Option<StoredEntry>, StoreError> {
        let row: Option<EntryRow> = self
            .conn
            .query_row(
                "SELECT kind, envelope, ref_index, authority_state,
                        ord_authority, ord_timestamp, ord_digest, last_updated
                 FROM entries WHERE did = ?1",
                [did],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                        row.get(7)?,
                    ))
                },
            )
            .optional()
            .map_err(backend)?;
        row.map(entry_from_row).transpose()
    }

    fn commit_current(
        &mut self,
        did: &str,
        envelope: &[u8],
        authority_state: AuthorityState,
        ordering: OrderingMeta,
    ) -> Result<u64, StoreError> {
        // Immediate mode takes the write lock at BEGIN, so update-number
        // allocation and commit form one allocation-through-commit critical
        // section across processes as well as threads (specification v0.9
        // sections 12.6 and 13.2): no other writer can allocate between this
        // transaction's read of the counter and its commit, and numbers are
        // therefore assigned in commit order.
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(backend)?;
        let raw: Vec<u8> = tx
            .query_row(
                "SELECT value FROM meta WHERE key = 'next_update_number'",
                [],
                |row| row.get(0),
            )
            .map_err(backend)?;
        let bytes: [u8; 8] = raw
            .try_into()
            .map_err(|_| StoreError::Corrupt("update counter is not 8 bytes".to_owned()))?;
        let number = u64::from_be_bytes(bytes);
        let next = number
            .checked_add(1)
            .ok_or_else(|| StoreError::Corrupt("update counter exhausted".to_owned()))?;
        tx.execute(
            "UPDATE meta SET value = ?1 WHERE key = 'next_update_number'",
            params![next.to_be_bytes()],
        )
        .map_err(backend)?;
        tx.execute(
            "INSERT INTO entries
               (did, kind, envelope, ref_index, authority_state,
                ord_authority, ord_timestamp, ord_digest, last_updated)
             VALUES (?1, 0, ?2, NULL, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(did) DO UPDATE SET
               kind = 0, envelope = excluded.envelope, ref_index = NULL,
               authority_state = excluded.authority_state,
               ord_authority = excluded.ord_authority,
               ord_timestamp = excluded.ord_timestamp,
               ord_digest = excluded.ord_digest,
               last_updated = excluded.last_updated",
            params![
                did,
                envelope,
                state_to_i64(authority_state),
                match ordering.authority {
                    Authority::Root => 0i64,
                    Authority::RootRevoked => 1i64,
                },
                to_i64(ordering.timestamp_ms, "ordering timestamp")?,
                ordering.body_digest,
                to_i64(number, "update number")?,
            ],
        )
        .map_err(backend)?;
        tx.commit().map_err(backend)?;
        Ok(number)
    }

    fn convert_to_ref(&mut self, did: &str, relay_index: u32) -> Result<bool, StoreError> {
        let changed = self
            .conn
            .execute(
                "UPDATE entries SET kind = 1, envelope = NULL, ref_index = ?2 WHERE did = ?1",
                params![did, i64::from(relay_index)],
            )
            .map_err(backend)?;
        Ok(changed > 0)
    }

    fn drop_entry(&mut self, did: &str) -> Result<bool, StoreError> {
        let changed = self
            .conn
            .execute("DELETE FROM entries WHERE did = ?1", [did])
            .map_err(backend)?;
        Ok(changed > 0)
    }

    fn changes_after(
        &self,
        position: u64,
        max: usize,
    ) -> Result<(Vec<ChangeRow>, bool), StoreError> {
        // Fetch one extra row to report has_more without a second query.
        let fetch = max
            .checked_add(1)
            .ok_or_else(|| StoreError::Corrupt("changes fetch bound overflow".to_owned()))?;
        let mut statement = self
            .conn
            .prepare(
                "SELECT did, kind, envelope, ref_index, last_updated
                 FROM entries WHERE last_updated > ?1
                 ORDER BY last_updated ASC LIMIT ?2",
            )
            .map_err(backend)?;
        let mapped = statement
            .query_map(
                params![
                    to_i64(position, "cursor position")?,
                    to_i64(fetch as u64, "fetch bound")?
                ],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, Option<Vec<u8>>>(2)?,
                        row.get::<_, Option<i64>>(3)?,
                        row.get::<_, i64>(4)?,
                    ))
                },
            )
            .map_err(backend)?;
        let mut rows = Vec::new();
        for item in mapped {
            let (did, kind, envelope, ref_index, last_updated) = item.map_err(backend)?;
            let payload = match kind {
                0 => {
                    EntryPayload::Full(envelope.ok_or_else(|| {
                        StoreError::Corrupt("full entry without bytes".to_owned())
                    })?)
                }
                1 => EntryPayload::Ref(
                    ref_index
                        .and_then(|i| u32::try_from(i).ok())
                        .ok_or_else(|| StoreError::Corrupt("ref entry without index".to_owned()))?,
                ),
                other => return Err(StoreError::Corrupt(format!("unknown entry kind {other}"))),
            };
            rows.push(ChangeRow {
                did,
                payload,
                last_updated: to_u64(last_updated, "last_updated")?,
            });
        }
        let has_more = rows.len() > max;
        rows.truncate(max);
        Ok((rows, has_more))
    }

    fn last_update_number(&self) -> Result<u64, StoreError> {
        Ok(self.next_update_number()?.saturating_sub(1))
    }

    fn directory(&self) -> Result<Vec<DirectoryEntry>, StoreError> {
        let mut statement = self
            .conn
            .prepare("SELECT idx, relay_id, endpoint, capabilities FROM directory ORDER BY idx")
            .map_err(backend)?;
        let mapped = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            })
            .map_err(backend)?;
        let mut entries = Vec::new();
        for item in mapped {
            let (index, relay_id, endpoint, capabilities) = item.map_err(backend)?;
            entries.push(DirectoryEntry {
                index: u32::try_from(index)
                    .map_err(|_| StoreError::Corrupt("directory index out of range".to_owned()))?,
                relay_id: blob16(relay_id, "directory relay id")?,
                endpoint,
                capabilities: to_u64(capabilities, "directory capabilities")?,
            });
        }
        Ok(entries)
    }

    fn set_directory(
        &mut self,
        entries: Vec<DirectoryEntry>,
        new_generation: [u8; 16],
    ) -> Result<(), StoreError> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(backend)?;
        tx.execute("DELETE FROM directory", []).map_err(backend)?;
        for entry in entries {
            tx.execute(
                "INSERT INTO directory (idx, relay_id, endpoint, capabilities)
                 VALUES (?1, ?2, ?3, ?4)",
                params![
                    i64::from(entry.index),
                    entry.relay_id,
                    entry.endpoint,
                    to_i64(entry.capabilities, "directory capabilities")?,
                ],
            )
            .map_err(backend)?;
        }
        tx.execute(
            "UPDATE meta SET value = ?1 WHERE key = 'directory_generation'",
            params![new_generation],
        )
        .map_err(backend)?;
        tx.commit().map_err(backend)?;
        Ok(())
    }

    fn reset_cursor_generation(&mut self, new_generation: [u8; 16]) -> Result<(), StoreError> {
        self.put_meta("cursor_generation", &new_generation)
    }

    fn peer_state(&self, relay_id: &[u8; 16]) -> Result<Option<PeerState>, StoreError> {
        self.conn
            .query_row(
                "SELECT endpoint, cursor FROM peers WHERE relay_id = ?1",
                [relay_id.as_slice()],
                |row| {
                    Ok(PeerState {
                        relay_id: *relay_id,
                        endpoint: row.get::<_, String>(0)?,
                        cursor: row.get::<_, Option<Vec<u8>>>(1)?,
                    })
                },
            )
            .optional()
            .map_err(backend)
    }

    fn set_peer_state(&mut self, state: &PeerState) -> Result<(), StoreError> {
        self.conn
            .execute(
                "INSERT INTO peers (relay_id, endpoint, cursor) VALUES (?1, ?2, ?3)
                 ON CONFLICT(relay_id) DO UPDATE SET
                   endpoint = excluded.endpoint, cursor = excluded.cursor",
                params![state.relay_id.as_slice(), state.endpoint, state.cursor],
            )
            .map_err(backend)?;
        Ok(())
    }

    fn peer_states(&self) -> Result<Vec<PeerState>, StoreError> {
        let mut statement = self
            .conn
            .prepare("SELECT relay_id, endpoint, cursor FROM peers ORDER BY relay_id")
            .map_err(backend)?;
        let mapped = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<Vec<u8>>>(2)?,
                ))
            })
            .map_err(backend)?;
        let mut states = Vec::new();
        for item in mapped {
            let (relay_id, endpoint, cursor) = item.map_err(backend)?;
            states.push(PeerState {
                relay_id: blob16(relay_id, "peer relay id")?,
                endpoint,
                cursor,
            });
        }
        Ok(states)
    }
}
