//! Current-state synchronization receiver (specification sections 12.6,
//! 12.7, 13.3, and 16.16; IMPLEMENTATION.md section 9.4).
//!
//! Synchronization consumes a peer's `v1/changes` feed through the strict
//! production client and passes every Full entry through the relay's
//! ordinary two-phase ingress — the identical prepare-and-admit path used
//! by `v1/publish` — so no verifier, ordering,
//! sticky-authority, or update-number logic exists here and `commit_current`
//! remains the sole update-number assigner. Ref entries are unverified
//! routing hints and are never imported as authority or identity state.
//!
//! The receiver is explicitly triggered (an operator command or test); there
//! is no timer-driven scheduler. The peer's exact opaque `nextCursor` is
//! persisted only after every accepted entry in that response is durably
//! processed, so a crash can replay a range (idempotently) but can never
//! skip an admissible entry.

use super::client::{BudgetMeter, ClientError, RelayClient};
use super::wire::{ReceivedChangePayload, ReceivedChangesResponse};
use super::{AdmissionOutcome, Relay, RelayError};
use crate::store::{PeerState, StoreError};

/// Options for one explicit synchronization operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyncOptions {
    /// `itemLimit` sent with every `v1/changes` request (1..=1024).
    pub item_limit: u64,
    /// `byteLimit` sent with every `v1/changes` request (1..=4 MiB).
    pub byte_limit: u64,
    /// Maximum feed pages fetched in this operation. Bounds the initial
    /// null-cursor enumeration as well as incremental catch-up.
    pub max_pages: u32,
}

impl Default for SyncOptions {
    fn default() -> Self {
        SyncOptions {
            item_limit: 256,
            byte_limit: 1024 * 1024,
            max_pages: 16,
        }
    }
}

/// Synchronization failure. Client and storage failures are infrastructure;
/// a peer-reported protocol error is preserved with its wire code. No
/// variant mutates identity state or the stored peer cursor.
#[derive(Debug, thiserror::Error)]
pub enum SyncError {
    /// The strict client rejected or failed the exchange (including a
    /// rejected outer response, which supplies no trustworthy cursor).
    #[error(transparent)]
    Client(#[from] ClientError),
    /// Storage failure.
    #[error(transparent)]
    Store(#[from] StoreError),
    /// Relay-internal failure (lock or clock).
    #[error("sync failed: {0}")]
    Internal(String),
    /// The peer answered `v1/changes` with a status-2 protocol error. The
    /// stored cursor is untouched: `invalidCursor` (code 18) remains
    /// distinct from `ResetRequired`, which is handled by discarding only
    /// the cursor and re-enumerating.
    #[error("peer reported changes error code {0}")]
    PeerChangesError(u64),
    /// The peer demanded a second cursor reset within one operation.
    #[error("peer demanded repeated cursor resets in one operation")]
    RepeatedReset,
}

impl SyncError {
    /// Stable symbolic name for machine consumption.
    #[must_use]
    pub fn symbol(&self) -> &'static str {
        match self {
            SyncError::Client(e) => e.symbol(),
            SyncError::Store(_) => "storage",
            SyncError::Internal(_) => "internal",
            SyncError::PeerChangesError(_) => "peerChangesError",
            SyncError::RepeatedReset => "repeatedReset",
        }
    }
}

/// One admitted change from a synchronization operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmittedChange {
    /// The admitted record's verified DID (from its signed body, never from
    /// the sender's entry label).
    pub did: String,
    /// The new local relay-local update number.
    pub update_number: u64,
}

/// One rejected or deferred candidate from a synchronization operation.
/// Rejection affects only this candidate (specification section 13.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RejectedChange {
    /// The sender's entry DID label (unverified routing data).
    pub entry_did: String,
    /// The section 15.3 wire error code, including `premature` (10) for a
    /// locally premature candidate under the receiver's injected clock.
    pub code: u64,
}

/// Report of one completed synchronization operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncReport {
    /// The peer's stable relay instance identifier.
    pub peer_relay_id: [u8; 16],
    /// Feed pages fetched.
    pub pages: u32,
    /// Records admitted as current, in processing order.
    pub admitted: Vec<AdmittedChange>,
    /// Valid duplicate or losing candidates (no state change).
    pub no_change: u64,
    /// Rejected or locally premature candidates (no state change).
    pub rejected: Vec<RejectedChange>,
    /// Ref entries discarded as unverified routing hints.
    pub refs_ignored: u64,
    /// Whether the peer demanded a cursor reset during this operation.
    pub reset_performed: bool,
    /// The exact stored peer cursor after the operation.
    pub final_cursor: Option<Vec<u8>>,
    /// Whether the peer reported more entries after the final page.
    pub has_more: bool,
}

impl Relay {
    /// Runs one explicit synchronization pass against `peer_base`.
    ///
    /// The peer's identity is read from `v1/info`; its stored state is keyed
    /// by that stable relay instance identifier, so an endpoint change keeps
    /// the cursor while a different relay at the same endpoint starts fresh.
    /// Every accepted success response advances the stored cursor to the
    /// exact returned `nextCursor` — regardless of how many candidates were
    /// admitted, rejected, or premature — after all its entries are durably
    /// processed. `ResetRequired` discards only the stored cursor and
    /// re-enumerates from null within the same bounded operation; it never
    /// deletes independently verified local identity state.
    ///
    /// The store lock is never held across a network exchange, so a serving
    /// relay can synchronize concurrently with ordinary operations.
    ///
    /// # Errors
    ///
    /// Returns a [`SyncError`]; the stored peer cursor is mutated only by
    /// accepted success responses and by `ResetRequired`.
    pub fn sync_once(
        &self,
        client: &RelayClient<'_>,
        peer_base: &str,
        options: &SyncOptions,
        meter: &mut BudgetMeter,
    ) -> Result<SyncReport, SyncError> {
        let peer_info = client.info(peer_base, meter)?.value;
        let peer_relay_id = peer_info.relay_id;

        let mut cursor: Option<Vec<u8>> = self
            .with_store(|store| store.peer_state(&peer_relay_id))
            .map_err(internal)?
            .and_then(|state| state.cursor);

        let mut report = SyncReport {
            peer_relay_id,
            pages: 0,
            admitted: Vec::new(),
            no_change: 0,
            rejected: Vec::new(),
            refs_ignored: 0,
            reset_performed: false,
            final_cursor: cursor.clone(),
            has_more: false,
        };

        while report.pages < options.max_pages {
            let response = client
                .changes(
                    peer_base,
                    cursor.as_deref(),
                    options.item_limit,
                    options.byte_limit,
                    meter,
                )?
                .value;
            report.pages = report.pages.saturating_add(1);

            match response {
                ReceivedChangesResponse::ResetRequired => {
                    // Discard only this peer cursor; identity state is
                    // untouched (specification section 12.7).
                    if report.reset_performed {
                        return Err(SyncError::RepeatedReset);
                    }
                    report.reset_performed = true;
                    cursor = None;
                    self.persist_peer(&peer_relay_id, peer_base, None)?;
                    report.final_cursor = None;
                    continue;
                }
                ReceivedChangesResponse::Error(code) => {
                    // Includes invalidCursor (18): a protocol error, not a
                    // reset; the stored cursor is deliberately untouched.
                    return Err(SyncError::PeerChangesError(code));
                }
                ReceivedChangesResponse::Success {
                    entries,
                    next_cursor,
                    has_more,
                    directory_generation: _,
                } => {
                    // Process every entry first; each admission is durable
                    // through commit_current before the cursor moves.
                    for entry in entries {
                        match entry.payload {
                            ReceivedChangePayload::Ref(_) => {
                                // An unverified routing hint: never imported
                                // as authority state, never an update-number
                                // change. Discarding it is conforming
                                // (section 13.3) and must not stall the
                                // cursor.
                                report.refs_ignored = report.refs_ignored.saturating_add(1);
                            }
                            ReceivedChangePayload::Full(candidate) => {
                                self.ingress_synchronized(&candidate, &entry.did, &mut report)?;
                            }
                        }
                    }
                    // All accepted entries in this response are durably
                    // processed: store and use the exact returned cursor.
                    cursor = Some(next_cursor.clone());
                    self.persist_peer(&peer_relay_id, peer_base, Some(next_cursor))?;
                    report.final_cursor = cursor.clone();
                    report.has_more = has_more;
                    if !has_more {
                        break;
                    }
                }
            }
        }
        Ok(report)
    }

    /// Runs one synchronized Full candidate through the ordinary two-phase
    /// ingress. Phase 1 (bounded, state-independent, including the
    /// future-bound check under the receiver's own injected clock) runs
    /// without the lock; phase 2 is the ordinary locked admission. A
    /// rejected, duplicate, losing, or locally premature candidate affects
    /// only itself and never blocks later entries or the cursor.
    fn ingress_synchronized(
        &self,
        candidate: &[u8],
        entry_did: &str,
        report: &mut SyncReport,
    ) -> Result<(), SyncError> {
        let now_ms = self
            .now_ms()
            .map_err(|e| SyncError::Internal(e.to_string()))?;
        let prepared = match Relay::prepare(candidate, now_ms) {
            Ok(prepared) => prepared,
            Err(code) => {
                report.rejected.push(RejectedChange {
                    entry_did: entry_did.to_owned(),
                    code,
                });
                return Ok(());
            }
        };
        let did = prepared.verified.body().id.as_str().to_owned();
        let outcome = self
            .with_store(|store| {
                Relay::admit_prepared(store, &prepared).map_err(|e| match e {
                    RelayError::Internal(message) => StoreError::Backend(message),
                    RelayError::BadRequest => {
                        StoreError::Corrupt("unexpected admission classification".to_owned())
                    }
                })
            })
            .map_err(internal)?;
        match outcome {
            AdmissionOutcome::AdmittedCurrent(update_number) => {
                report.admitted.push(AdmittedChange { did, update_number });
            }
            AdmissionOutcome::NoChange => {
                report.no_change = report.no_change.saturating_add(1);
            }
            AdmissionOutcome::Rejected(code) => {
                report.rejected.push(RejectedChange {
                    entry_did: entry_did.to_owned(),
                    code,
                });
            }
        }
        Ok(())
    }

    /// Durably upserts the peer synchronization state.
    fn persist_peer(
        &self,
        relay_id: &[u8; 16],
        endpoint: &str,
        cursor: Option<Vec<u8>>,
    ) -> Result<(), SyncError> {
        self.with_store(|store| {
            store.set_peer_state(&PeerState {
                relay_id: *relay_id,
                endpoint: endpoint.to_owned(),
                cursor,
            })
        })
        .map_err(internal)
    }
}

fn internal(e: RelayError) -> SyncError {
    SyncError::Internal(e.to_string())
}
