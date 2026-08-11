//! Single-relay protocol core: admission, resolution, changes, metadata
//! (specification sections 11–13; IMPLEMENTATION.md section 9).
//!
//! The relay is transport-independent: every operation takes and returns
//! protocol bytes, and [`http`] wires them to the mandatory HTTP profile.
//! Records are untrusted bytes until they pass the reviewed production
//! verification core ([`crate::verify::verify_record_for_target`]); ordering
//! decisions delegate to [`crate::ordering`]; time comes only from the
//! injected [`Clock`]. Storage is behind the [`RelayStore`] contract so the
//! memory and SQLite backends run identical protocol logic.
//!
//! Publication is two-phase (specification v0.9 section 13.2): every
//! bounded, state-independent step — size bounds, deterministic-CBOR and
//! schema processing, descriptor binding, strict signature verification,
//! and the future-bound classification — runs *outside* the store lock,
//! producing a private prepared-candidate value. The lock is held only for the short
//! state-dependent critical section: sticky-authority recheck, current-state
//! comparison, and the atomic update-number allocation-and-commit, after
//! which the tuple is `v1/changes`-eligible before the lock is released.

pub mod client;
pub mod cursor;
pub mod http;
pub mod sync;
pub mod wire;

use crate::clock::Clock;
use crate::did::FolloweeDid;
use crate::error::VerifyError;
use crate::limits::{MAX_BODY_DEPTH, MAX_BODY_MEMBERS, MAX_RECORD_BYTES};
use crate::ordering::{AuthorityState, compare_ordering_keys};
use crate::record::Authority;
use crate::store::{EntryPayload, OrderingMeta, RelayStore, StoreError};
use crate::timestamp::{TimeStatus, time_status};
use crate::{cbor, cose, record};
use std::cmp::Ordering;
use std::sync::Mutex;
pub use wire::OuterRequestFault;

/// Capability bits advertised by this relay: Relay Resolver (`0x01`),
/// current-state synchronization (`0x02`), and ingress publication (`0x04`)
/// (specification section 12.2).
pub const RELAY_CAPABILITIES: u64 = 0x01 | 0x02 | 0x04;

/// Section 15.3 wire error codes used by relay results beyond the
/// [`VerifyError`] vocabulary.
pub(crate) mod wire_code {
    /// `premature` (code 10).
    pub const PREMATURE: u64 = 10;
    /// `rootRevoked` (code 11).
    pub const ROOT_REVOKED: u64 = 11;
    /// `responseTooLarge` (code 16).
    pub const RESPONSE_TOO_LARGE: u64 = 16;
    /// `invalidCursor` (code 18).
    pub const INVALID_CURSOR: u64 = 18;
}

/// Relay configuration.
#[derive(Debug, Clone)]
pub struct RelayConfig {
    /// Advertised canonical base URI, ending in `/`. Conforming public mode
    /// requires HTTPS (the process may sit behind a TLS reverse proxy).
    pub base_uri: String,
    /// Explicitly non-conforming local development mode: permits a plain
    /// `http` base URI and loopback binding only (IMPLEMENTATION.md
    /// section 9.5).
    pub development_mode: bool,
}

/// Configuration rejection.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum ConfigError {
    /// The base URI must end with `/` (specification section 12.1).
    #[error("relay base URI must end with '/'")]
    BaseUriMissingSlash,
    /// Conforming mode requires an HTTPS base URI; development mode must be
    /// selected explicitly for plain HTTP.
    #[error("non-HTTPS base URI requires explicit development mode")]
    InsecureBaseUri,
}

/// Operational relay failure surfaced to the transport layer.
#[derive(Debug, thiserror::Error)]
pub enum RelayError {
    /// The outer request failed section 6.1 or top-level schema validation;
    /// the transport answers HTTP `400` with no per-item results.
    #[error("outer request rejected before protocol processing")]
    BadRequest,
    /// The relay could not complete processing (storage or clock failure);
    /// the transport answers HTTP `500`.
    #[error("internal relay failure: {0}")]
    Internal(String),
}

impl From<StoreError> for RelayError {
    fn from(e: StoreError) -> Self {
        RelayError::Internal(e.to_string())
    }
}

/// The publish outcome statuses (specification section 12.5).
const PUBLISH_ADMITTED: u64 = 0;
const PUBLISH_NO_CHANGE: u64 = 1;
const PUBLISH_REJECTED: u64 = 2;

/// A single-process Followee relay over one storage backend.
pub struct Relay {
    store: Mutex<Box<dyn RelayStore>>,
    clock: Box<dyn Clock + Send + Sync>,
    config: RelayConfig,
    /// Test-support pause point between phase-1 preparation and the store
    /// lock; `None` in every production construction path.
    publish_gap_hook: Option<Box<dyn Fn() + Send + Sync>>,
}

impl std::fmt::Debug for Relay {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Relay")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

fn poisoned(_: impl std::fmt::Debug) -> RelayError {
    RelayError::Internal("store lock poisoned".to_owned())
}

impl Relay {
    /// Creates a relay over an initialised store.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] for an invalid configuration.
    pub fn new(
        store: Box<dyn RelayStore>,
        clock: Box<dyn Clock + Send + Sync>,
        config: RelayConfig,
    ) -> Result<Self, ConfigError> {
        if !config.base_uri.ends_with('/') {
            return Err(ConfigError::BaseUriMissingSlash);
        }
        let https = config.base_uri.starts_with("https://");
        let http = config.base_uri.starts_with("http://");
        if !https && !(http && config.development_mode) {
            return Err(ConfigError::InsecureBaseUri);
        }
        Ok(Relay {
            store: Mutex::new(store),
            clock,
            config,
            publish_gap_hook: None,
        })
    }

    /// Installs a deterministic test-support hook that `publish` runs after
    /// phase-1 state-independent preparation and immediately before it
    /// acquires the store lock.
    ///
    /// This exists so concurrency tests can hold a publication in the
    /// unlocked gap without sleeps. It cannot affect production behaviour:
    /// no production construction path installs one, the hook receives no
    /// protocol data and returns nothing — it makes no protocol decision —
    /// and it runs while no lock is held, so it can only delay the calling
    /// thread at a point where the scheduler may already preempt it
    /// arbitrarily.
    #[doc(hidden)]
    pub fn set_publish_gap_hook(&mut self, hook: Box<dyn Fn() + Send + Sync>) {
        self.publish_gap_hook = Some(hook);
    }

    /// Whether this relay runs in the explicitly non-conforming development
    /// mode.
    #[must_use]
    pub fn development_mode(&self) -> bool {
        self.config.development_mode
    }

    fn now_ms(&self) -> Result<u64, RelayError> {
        self.clock
            .now_ms()
            .map_err(|e| RelayError::Internal(e.to_string()))
    }

    /// `GET v1/info` (specification section 12.2).
    ///
    /// # Errors
    ///
    /// Returns [`RelayError::Internal`] on storage failure.
    pub fn info(&self) -> Result<Vec<u8>, RelayError> {
        let store = self.store.lock().map_err(poisoned)?;
        let identity = store.identity()?;
        Ok(wire::encode_info(
            &identity,
            RELAY_CAPABILITIES,
            &self.config.base_uri,
        ))
    }

    /// `GET v1/directory` (specification section 12.4).
    ///
    /// # Errors
    ///
    /// Returns [`RelayError::Internal`] on storage failure.
    pub fn directory(&self) -> Result<Vec<u8>, RelayError> {
        let store = self.store.lock().map_err(poisoned)?;
        let identity = store.identity()?;
        let entries = store.directory()?;
        Ok(wire::encode_directory(
            &identity.directory_generation,
            &entries,
        ))
    }

    /// `POST v1/resolve` (specification section 12.3): one aligned result per
    /// requested DID, duplicates preserved, opaque Full bytes, serve-time
    /// future recheck under the injected clock.
    ///
    /// # Errors
    ///
    /// Returns [`RelayError::BadRequest`] for an outer request fault and
    /// [`RelayError::Internal`] on storage or clock failure.
    pub fn resolve(&self, request: &[u8]) -> Result<Vec<u8>, RelayError> {
        let parsed = wire::parse_resolve_request(request).map_err(|_| RelayError::BadRequest)?;
        let now_ms = self.now_ms()?;
        let store = self.store.lock().map_err(poisoned)?;
        let identity = store.identity()?;

        // Aligned results with a shared response-byte budget: a Full that no
        // longer fits the advertised response bound degrades to the aligned
        // per-DID Error(responseTooLarge) from section 15.3, never to Absent
        // and never by shifting positions.
        let mut encoded: Vec<Vec<u8>> = Vec::with_capacity(parsed.dids.len());
        let mut budget_used: usize = 0;
        for did_text in &parsed.dids {
            let result = self.resolve_one(&**store, did_text, now_ms)?;
            let mut bytes = wire::encode_resolve_result(&result);
            let fits = budget_used
                .checked_add(bytes.len())
                .is_some_and(|total| total <= wire::MAX_RESOLVE_RESPONSE_BYTES);
            if !fits {
                bytes = wire::encode_resolve_result(&wire::ResolveResult::Error(
                    wire_code::RESPONSE_TOO_LARGE,
                ));
            }
            budget_used = budget_used.saturating_add(bytes.len());
            encoded.push(bytes);
        }
        Ok(wire::encode_resolve_response(
            &identity.directory_generation,
            &encoded,
        ))
    }

    fn resolve_one(
        &self,
        store: &dyn RelayStore,
        did_text: &str,
        now_ms: u64,
    ) -> Result<wire::ResolveResult, RelayError> {
        // A syntactically malformed DID as valid UTF-8 is protocol input:
        // the aligned per-DID Error result, never an outer fault
        // (specification section 15.4; Appendix B.11.6).
        let did = match FolloweeDid::parse(did_text) {
            Ok(did) => did,
            Err(e) => return Ok(wire::ResolveResult::Error(VerifyError::from(e).wire_code())),
        };
        let Some(entry) = store.entry(did.as_str())? else {
            return Ok(wire::ResolveResult::Absent);
        };
        match entry.payload {
            EntryPayload::Ref(index) => Ok(wire::ResolveResult::Ref(index)),
            EntryPayload::Full(bytes) => {
                // Serve-time future recheck (specification section 5.4): a
                // stored record that has become premature is not returned as
                // Full or conflated with Absent, and serving does not mutate
                // the entry.
                let timestamp = stored_timestamp(&entry.ordering, &bytes)
                    .ok_or_else(|| RelayError::Internal("stored entry unreadable".to_owned()))?;
                if time_status(timestamp, now_ms) == TimeStatus::Premature {
                    Ok(wire::ResolveResult::Error(wire_code::PREMATURE))
                } else {
                    Ok(wire::ResolveResult::Full(bytes))
                }
            }
        }
    }

    /// `POST v1/publish` (specification sections 12.5, 13.1, and 13.2):
    /// two-phase ingress. Phase 1 verifies the untrusted candidate through
    /// the production core with no lock held; phase 2 acquires the store
    /// lock only for the state-dependent admission decision and the atomic
    /// allocation-and-commit, so a publication mid-verification never
    /// excludes competing writers or `v1/changes` readers.
    ///
    /// Record-level faults are protocol results (`status 2` with the section
    /// 15.3 code), not HTTP `400`: the record itself is the protocol item,
    /// and the section 12.1 outer-CBOR rule exists to protect per-item batch
    /// alignment in `application/cbor` wrappers.
    ///
    /// # Errors
    ///
    /// Returns [`RelayError::Internal`] on storage or clock failure.
    pub fn publish(&self, candidate: &[u8]) -> Result<Vec<u8>, RelayError> {
        let now_ms = self.now_ms()?;
        // Phase 1: every bounded, state-independent step, outside the lock.
        let prepared = match Self::prepare(candidate, now_ms) {
            Ok(prepared) => prepared,
            Err(code) => {
                return Ok(wire::encode_publish_response(PUBLISH_REJECTED, Some(code)));
            }
        };
        if let Some(hook) = &self.publish_gap_hook {
            hook();
        }
        // Phase 2: the short state-dependent write-critical section.
        let mut store = self.store.lock().map_err(poisoned)?;
        let outcome = Self::admit_prepared(&mut **store, &prepared)?;
        drop(store);
        Ok(match outcome {
            AdmissionOutcome::AdmittedCurrent(_) => {
                wire::encode_publish_response(PUBLISH_ADMITTED, None)
            }
            AdmissionOutcome::NoChange => wire::encode_publish_response(PUBLISH_NO_CHANGE, None),
            AdmissionOutcome::Rejected(code) => {
                wire::encode_publish_response(PUBLISH_REJECTED, Some(code))
            }
        })
    }

    /// Phase 1 of the section 13.1 ingress algorithm: steps 1–3, every
    /// bounded, state-independent operation, run with no lock held. On
    /// rejection, returns the section 15.3 wire error code.
    fn prepare(candidate: &[u8], now_ms: u64) -> Result<PreparedCandidate, u64> {
        // Step 1: cheap envelope-size limit before deep parsing.
        if candidate.len() > MAX_RECORD_BYTES {
            return Err(VerifyError::RecordTooLarge.wire_code());
        }
        // Step 2: the complete section 8.1 verification algorithm, through
        // the reviewed production core. The record's own signed `id` is the
        // publication subject; verification then enforces that the carried
        // descriptor reproduces it.
        let claimed_id = claimed_body_id(candidate).map_err(|e| e.wire_code())?;
        let verified = crate::verify::verify_record_for_target(&claimed_id, candidate)
            .map_err(|e| e.wire_code())?;

        // Step 3: reject a premature record rather than retain a future
        // queue (specification section 5.4). The bound depends on the
        // injected clock, never on relay state.
        if time_status(verified.timestamp_ms(), now_ms) == TimeStatus::Premature {
            return Err(wire_code::PREMATURE);
        }
        Ok(PreparedCandidate { verified })
    }

    /// Phase 2 of the section 13.1 ingress algorithm: steps 4–8, the
    /// state-dependent write-critical section, run with the store lock held.
    /// It consumes only the verification evidence carried by `prepared`;
    /// every state-dependent condition is decided here, atomically with the
    /// update-number allocation-and-commit (specification v0.9 sections
    /// 12.6 and 13.2).
    fn admit_prepared(
        store: &mut dyn RelayStore,
        prepared: &PreparedCandidate,
    ) -> Result<AdmissionOutcome, RelayError> {
        let verified = &prepared.verified;
        let entry = store.entry(verified.body().id.as_str())?;

        // Step 4: sticky exclusion. Section 13.1 "drops" a Root record when
        // local authority state is RootRevoked — distinct from step 7's
        // "returns no-change" for duplicate/losing records — and section 8.2
        // forbids admitting it, so the wire outcome is a rejection with the
        // dedicated code 11.
        let sticky = entry
            .as_ref()
            .map_or(AuthorityState::Unknown, |e| e.authority_state);
        if sticky == AuthorityState::RootRevoked && verified.authority() == Authority::Root {
            return Ok(AdmissionOutcome::Rejected(wire_code::ROOT_REVOKED));
        }

        // Steps 6–7: timestamp and body-digest comparison within the
        // applicable authority state, against retained ordering metadata
        // (which survives Full-to-Ref conversion, section 11.2).
        if let Some(meta) = entry.as_ref().and_then(|e| e.ordering) {
            let transition =
                verified.authority() == Authority::RootRevoked && meta.authority == Authority::Root;
            if !transition {
                match compare_ordering_keys(
                    verified.timestamp_ms(),
                    verified.body_digest(),
                    meta.timestamp_ms,
                    &meta.body_digest,
                ) {
                    Ordering::Greater => {}
                    // Duplicate (equal digest) or losing record: valid, no
                    // current-state change, no update number (section 13.2).
                    Ordering::Equal | Ordering::Less => return Ok(AdmissionOutcome::NoChange),
                }
            }
        }

        // Steps 5 and 8: atomically persist the winner, its authority state,
        // and a new relay-local update number — assigned only inside this
        // committing operation — before acknowledging; the tuple is
        // `v1/changes`-eligible before the lock is released.
        let authority_state = match verified.authority() {
            Authority::Root => AuthorityState::Root,
            Authority::RootRevoked => AuthorityState::RootRevoked,
        };
        let number = store.commit_current(
            verified.body().id.as_str(),
            verified.envelope_bytes(),
            authority_state,
            OrderingMeta {
                authority: verified.authority(),
                timestamp_ms: verified.timestamp_ms(),
                body_digest: *verified.body_digest(),
            },
        )?;
        Ok(AdmissionOutcome::AdmittedCurrent(number))
    }

    /// `POST v1/changes` (specification sections 12.6 and 12.7).
    ///
    /// # Errors
    ///
    /// Returns [`RelayError::BadRequest`] for an outer request fault and
    /// [`RelayError::Internal`] on storage failure.
    pub fn changes(&self, request: &[u8]) -> Result<Vec<u8>, RelayError> {
        let parsed = wire::parse_changes_request(request).map_err(|_| RelayError::BadRequest)?;
        let store = self.store.lock().map_err(poisoned)?;
        let identity = store.identity()?;

        let position = match &parsed.cursor {
            None => 0,
            Some(bytes) => match cursor::decode(bytes, &identity.cursor_generation) {
                cursor::CursorDecode::Position(position) => position,
                cursor::CursorDecode::ForeignGeneration => {
                    return Ok(wire::encode_changes_reset());
                }
                cursor::CursorDecode::Malformed => {
                    return Ok(wire::encode_changes_error(wire_code::INVALID_CURSOR));
                }
            },
        };

        let max_items = usize::try_from(parsed.item_limit)
            .map_err(|_| RelayError::Internal("item limit conversion".to_owned()))?;
        let (rows, mut has_more) = store.changes_after(position, max_items)?;

        // Byte budgeting: the complete success response must fit byteLimit.
        // The cursor length is fixed and `hasMore` encodes in one byte
        // either way, so the non-entry overhead is constant apart from the
        // entry-array head; include entries greedily in lastUpdated order
        // and never advance the cursor past an omitted eligible entry.
        let probe = wire::encode_changes_success(
            &[],
            &cursor::encode(&identity.cursor_generation, 0),
            true,
            &identity.directory_generation,
        );
        // The probe's zero-entry array head is one byte; item counts are
        // capped at 1,024, so the real head is at most two bytes.
        let base_len = (probe.len() as u64).saturating_sub(1);
        let array_head_len = |count: usize| -> u64 { if count < 24 { 1 } else { 2 } };

        let mut included: Vec<Vec<u8>> = Vec::new();
        let mut entries_len: u64 = 0;
        let mut last_included_position = position;
        let mut omitted_by_bytes = false;
        for row in &rows {
            let encoded = wire::encode_change_entry(row);
            let count = included.len().saturating_add(1);
            let total = base_len
                .saturating_add(array_head_len(count))
                .saturating_add(entries_len)
                .saturating_add(encoded.len() as u64);
            if total <= parsed.byte_limit {
                entries_len = entries_len.saturating_add(encoded.len() as u64);
                last_included_position = row.last_updated;
                included.push(encoded);
            } else {
                omitted_by_bytes = true;
                break;
            }
        }
        if omitted_by_bytes {
            has_more = true;
            if included.is_empty() {
                // The next single entry cannot fit within byteLimit: a
                // responseTooLarge error rather than an unchanged success
                // cursor loop (specification section 12.6).
                return Ok(wire::encode_changes_error(wire_code::RESPONSE_TOO_LARGE));
            }
        }

        let next_cursor = cursor::encode(&identity.cursor_generation, last_included_position);
        let response = wire::encode_changes_success(
            &included,
            &next_cursor,
            has_more,
            &identity.directory_generation,
        );
        debug_assert!(u64::try_from(response.len()).is_ok_and(|len| len <= parsed.byte_limit));
        Ok(response)
    }

    /// Runs `operation` with exclusive store access: local operator and test
    /// surface for seeding, eviction housekeeping, and restore behaviour.
    /// Not part of the wire protocol.
    ///
    /// # Errors
    ///
    /// Propagates the operation's [`StoreError`] and lock poisoning as
    /// [`RelayError`].
    pub fn with_store<T>(
        &self,
        operation: impl FnOnce(&mut dyn RelayStore) -> Result<T, StoreError>,
    ) -> Result<T, RelayError> {
        let mut store = self.store.lock().map_err(poisoned)?;
        operation(&mut **store).map_err(RelayError::from)
    }
}

/// A candidate that has completed every bounded, state-independent
/// admission step (section 13.1 steps 1–3) through the reviewed production
/// verification core, outside the store lock. Only [`Relay::prepare`]
/// constructs one — [`crate::verify::VerifiedRecord`] is itself
/// unfabricable — so the locked phase consumes verification evidence,
/// never caller-supplied metadata.
struct PreparedCandidate {
    verified: crate::verify::VerifiedRecord,
}

/// The section 13.1 admission outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AdmissionOutcome {
    /// Winning record committed with this new relay-local update number.
    AdmittedCurrent(u64),
    /// Valid duplicate or losing record; no state change, no update number.
    NoChange,
    /// Rejected with the given section 15.3 wire error code.
    Rejected(u64),
}

/// Extracts the signed body `id` claimed by an untrusted candidate, applying
/// the same layered envelope, CBOR, and schema classification as full
/// verification (which then runs over the identical bytes).
fn claimed_body_id(candidate: &[u8]) -> Result<String, VerifyError> {
    let parts = cose::parse_envelope(candidate)?;
    let payload = &candidate[parts.payload.clone()];
    cbor::validate(payload, MAX_BODY_DEPTH, MAX_BODY_MEMBERS)?;
    let parsed = record::parse_record_body(payload)?;
    Ok(parsed.id_text)
}

/// The stored record timestamp for serve-time rechecks: retained ordering
/// metadata when present, otherwise re-derived from the stored envelope.
fn stored_timestamp(ordering: &Option<OrderingMeta>, envelope: &[u8]) -> Option<u64> {
    if let Some(meta) = ordering {
        return Some(meta.timestamp_ms);
    }
    let parts = cose::parse_envelope(envelope).ok()?;
    let payload = &envelope[parts.payload.clone()];
    record::parse_record_body(payload)
        .ok()
        .map(|body| body.timestamp_ms)
}
