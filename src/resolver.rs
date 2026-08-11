//! Multi-relay client resolution with reference traversal (specification
//! sections 9.2, 14.1, and 15.5; IMPLEMENTATION.md section 10).
//!
//! The resolver queries configured relays through the strict production
//! client under one aggregate operation budget shared across the entire
//! traversal: deadline, total response bytes, request count, distinct
//! relays visited, and reference depth. No relay hop, reference, or retry
//! resets any budget. Scheduling is deterministic — a FIFO work queue in
//! configuration order — so tests can enumerate schedules exactly.
//!
//! Every Full candidate is verified locally through the reviewed production
//! core ([`crate::verify::verify_record_for_target`]) for the requested DID
//! and classified under the client's own injected clock. Candidates are
//! combined through the reviewed production selection entry point
//! ([`crate::ordering::select_current`]) with the explicit target DID and
//! retained sticky state; no ordering or authority rule is reproduced here.
//!
//! Absent, per-DID Error, and rejected outer responses yield neither a
//! candidate nor a reference target, never change cached identity or sticky
//! state, and never terminate the operation while a selected unqueried
//! relay remains within the shared budgets. Ref results are bounded,
//! unverified routing hints; lazy path compression stores only a routing
//! hint, and only after a locally verified successful traversal.

use crate::clock::Clock;
use crate::did::FolloweeDid;
use crate::error::VerifyError;
use crate::ordering::{AuthorityState, select_current};
use crate::relay::client::{
    BudgetMeter, ClientError, OperationBudget, ReceivedResult, RelayClient,
};
use crate::timestamp::{Freshness, TimeStatus, freshness, time_status};
use crate::verify::{VerifiedRecord, verify_record_for_target};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

/// Aggregate operation budgets with the specification section 14.1 v1
/// defaults. One instance covers one complete resolution operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolverBudgets {
    /// Initial configured relays queried.
    pub initial_relays: usize,
    /// Maximum distinct relay base URIs visited.
    pub max_relays_visited: usize,
    /// Maximum reference depth.
    pub max_ref_depth: u32,
    /// Maximum concurrent requests. The deterministic scheduler issues
    /// requests sequentially, which satisfies any bound of at least one.
    pub max_concurrent_requests: usize,
    /// Maximum total response bytes across the operation.
    pub max_total_response_bytes: u64,
    /// Resolution deadline duration in milliseconds.
    pub deadline_duration_ms: u64,
}

impl Default for ResolverBudgets {
    fn default() -> Self {
        ResolverBudgets {
            initial_relays: 3,
            max_relays_visited: 16,
            max_ref_depth: 8,
            max_concurrent_requests: 4,
            max_total_response_bytes: 1024 * 1024,
            deadline_duration_ms: 10_000,
        }
    }
}

/// Resolver configuration: the configured relay list and budgets.
#[derive(Debug, Clone)]
pub struct ResolverConfig {
    /// Configured relay base URIs, queried in order.
    pub relays: Vec<String>,
    /// Aggregate operation budgets.
    pub budgets: ResolverBudgets,
}

/// Locally cached, independently verified current record metadata for one
/// DID. Only a winner that passed complete local verification is stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CachedRecord {
    /// The exact verified envelope bytes.
    pub envelope: Vec<u8>,
    /// The record's authority value.
    pub authority: crate::record::Authority,
    /// The record's ordering timestamp.
    pub timestamp_ms: u64,
    /// The record's body digest.
    pub body_digest: [u8; 32],
}

/// Client-side state for one DID. Sticky authority state and the cached
/// record are identity state; the route hint is replaceable routing state
/// (lazy path compression) and is never identity evidence.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DidState {
    /// Retained sticky authority state (monotonic once RootRevoked).
    pub sticky: AuthorityState,
    /// The last locally verified winning record, if any.
    pub cached: Option<CachedRecord>,
    /// Compressed routing hint: the base URI where the last verified winner
    /// was found through reference traversal.
    pub route: Option<String>,
}

/// Client-side state keyed by DID. State for different DIDs is independent:
/// no operation for one DID reads or writes another's entry.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClientState {
    entries: BTreeMap<String, DidState>,
}

impl ClientState {
    /// Creates empty state.
    #[must_use]
    pub fn new() -> Self {
        ClientState::default()
    }

    /// The state entry for `did`, if present.
    #[must_use]
    pub fn get(&self, did: &str) -> Option<&DidState> {
        self.entries.get(did)
    }

    /// Records retained sticky RootRevoked state for `did` (for state
    /// loaded from an operator-supplied source). Sticky state is monotonic:
    /// this can only set RootRevoked, never clear it.
    pub fn assume_root_revoked(&mut self, did: &str) {
        self.entries.entry(did.to_owned()).or_default().sticky = AuthorityState::RootRevoked;
    }

    /// Restores a cached record for `did` after re-verifying the supplied
    /// envelope bytes through the complete production verification
    /// algorithm. Invalid bytes are rejected and change nothing.
    ///
    /// # Errors
    ///
    /// Returns the [`VerifyError`] from verification.
    pub fn restore_cached(&mut self, did: &str, envelope: &[u8]) -> Result<(), VerifyError> {
        let record = verify_record_for_target(did, envelope)?;
        let entry = self.entries.entry(did.to_owned()).or_default();
        entry.cached = Some(CachedRecord {
            envelope: record.envelope_bytes().to_vec(),
            authority: record.authority(),
            timestamp_ms: record.timestamp_ms(),
            body_digest: *record.body_digest(),
        });
        Ok(())
    }

    /// Restores a routing hint for `did`. Routing state only.
    pub fn restore_route(&mut self, did: &str, route: &str) {
        self.entries.entry(did.to_owned()).or_default().route = Some(route.to_owned());
    }

    /// Iterates over `(did, state)` pairs in DID order.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &DidState)> {
        self.entries
            .iter()
            .map(|(did, state)| (did.as_str(), state))
    }
}

/// One traversal diagnostic event. Diagnostics describe the reporting relay
/// or the local decision only; they are never identity evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiagEvent {
    /// The relay returned a Full candidate that verified locally.
    VerifiedCandidate,
    /// The relay returned a Full candidate rejected by local verification.
    RejectedCandidate(VerifyError),
    /// The relay returned a Full candidate that is premature under the
    /// client's own clock (a local classification, never imported).
    PrematureCandidate,
    /// The relay reported local absence.
    Absent,
    /// The relay reported a per-DID error code (diagnostic for that relay
    /// only; an `Error(premature)` reflects that relay's clock and is never
    /// transferred to any candidate).
    RelayError(u64),
    /// The relay returned a reference to the given relay index.
    Ref(u32),
    /// The outer response was rejected at the wrapper layer; it is neither
    /// Absent nor Error and yields no candidate or reference target.
    RejectedOuterResponse(VerifyError),
    /// Transport, policy, HTTP-status, or cardinality failure.
    RequestFailed(&'static str),
    /// A reference target was unusable (missing directory entry or a
    /// directory generation that no longer matches).
    UnusableRef,
    /// A reference target was refused by cycle detection.
    CycleRefused,
    /// The shared budgets stopped the traversal before this target.
    BudgetStopped(&'static str),
}

/// One diagnostic row: the relay base URI it concerns and the event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diagnostic {
    /// The relay base URI.
    pub base_uri: String,
    /// What happened.
    pub event: DiagEvent,
}

/// The winning result of a completed resolution.
#[derive(Debug, Clone)]
pub struct ResolvedRecord {
    /// The locally verified winning record.
    pub record: VerifiedRecord,
    /// Whether the record is stale under the client's clock.
    pub stale: bool,
    /// The base URI of the relay that supplied the winner.
    pub source: String,
}

/// The outcome of one resolution operation (specification section 15.5).
#[derive(Debug, Clone)]
pub enum ResolveOutcome {
    /// A locally verified winning record was selected.
    Found(Box<ResolvedRecord>),
    /// The operation completed — every selected relay was consulted — and
    /// no admissible record was found. Never proof of non-existence.
    NotFound,
    /// Budgets were exhausted or selected relays were unavailable before
    /// the operation could complete.
    TemporarilyUnavailable,
}

/// The complete result of one resolution operation.
#[derive(Debug, Clone)]
pub struct Resolution {
    /// The outcome.
    pub outcome: ResolveOutcome,
    /// The authority state retained for the DID after this operation.
    pub authority_state: AuthorityState,
    /// Distinct relay base URIs consulted.
    pub relays_consulted: usize,
    /// The stored routing hint after lazy path compression, if any.
    pub compressed_route: Option<String>,
    /// Traversal diagnostics in schedule order.
    pub diagnostics: Vec<Diagnostic>,
}

/// Normalizes an HTTPS/HTTP relay base URI for traversal accounting only
/// (specification section 14.1): lowercases scheme and ASCII host, removes
/// a default port, removes dot segments, and normalizes percent-encodings
/// of unreserved characters. Never used to rewrite the URI actually
/// requested.
#[must_use]
pub fn normalize_base_uri(uri: &str) -> String {
    match iri_string::types::UriStr::new(uri) {
        Ok(parsed) => {
            let normalized = parsed.normalize().to_string();
            // `normalize` applies RFC 3986 syntax-based normalization
            // (case, percent-encoding, dot segments); default-port removal
            // is scheme-aware and done here.
            let (https, rest) = match normalized.split_once("://") {
                Some(("https", rest)) => (true, rest),
                Some(("http", rest)) => (false, rest),
                _ => return normalized,
            };
            let default = if https { ":443" } else { ":80" };
            let scheme = if https { "https" } else { "http" };
            match rest.split_once('/') {
                Some((authority, path)) => {
                    let authority = authority.strip_suffix(default).unwrap_or(authority);
                    format!("{scheme}://{authority}/{path}")
                }
                None => {
                    let authority = rest.strip_suffix(default).unwrap_or(rest);
                    format!("{scheme}://{authority}")
                }
            }
        }
        Err(_) => uri.to_owned(),
    }
}

/// One queued traversal target.
#[derive(Debug, Clone)]
struct Target {
    base_uri: String,
    depth: u32,
}

/// A verified candidate with its source for path compression.
struct SourcedCandidate {
    record: VerifiedRecord,
    source: String,
    via_reference: bool,
}

/// Resolves `target_did` through the configured relays under one shared
/// aggregate budget, updating `state` for that DID only.
///
/// # Errors
///
/// Returns `invalidDid`/`unsupportedHash` for a malformed target; every
/// network condition is reported inside [`Resolution`] instead.
pub fn resolve_did(
    target_did: &str,
    config: &ResolverConfig,
    client: &RelayClient<'_>,
    clock: &dyn Clock,
    state: &mut ClientState,
) -> Result<Resolution, VerifyError> {
    let target = FolloweeDid::parse(target_did)?;
    let now_ms = clock.now_ms().map_err(|_| VerifyError::SchemaViolation);
    // A clock failure is a local environment failure: surface it as
    // TemporarilyUnavailable rather than inventing a protocol error.
    let Ok(now_ms) = now_ms else {
        return Ok(Resolution {
            outcome: ResolveOutcome::TemporarilyUnavailable,
            authority_state: state
                .get(target.as_str())
                .map_or(AuthorityState::Unknown, |s| s.sticky),
            relays_consulted: 0,
            compressed_route: None,
            diagnostics: Vec::new(),
        });
    };

    let budgets = config.budgets;
    let mut meter = BudgetMeter::new(OperationBudget {
        deadline_ms: Some(now_ms.saturating_add(budgets.deadline_duration_ms)),
        max_response_bytes: budgets.max_total_response_bytes,
        // Each visited relay needs at most a resolve plus a directory fetch.
        max_requests: (budgets.max_relays_visited as u64)
            .saturating_mul(2)
            .saturating_add(2),
    });

    let sticky = state
        .get(target.as_str())
        .map_or(AuthorityState::Unknown, |s| s.sticky);

    // The operation's selected relays: the stored routing hint (routing
    // state only — its answer still gets full verification) followed by the
    // first `initial_relays` configured relays, deduplicated by normalized
    // URI in deterministic order.
    let mut queue: VecDeque<Target> = VecDeque::new();
    let mut enqueued: BTreeSet<String> = BTreeSet::new();
    if let Some(route) = state.get(target.as_str()).and_then(|s| s.route.clone()) {
        if enqueued.insert(normalize_base_uri(&route)) {
            queue.push_back(Target {
                base_uri: route,
                depth: 0,
            });
        }
    }
    for base in config.relays.iter().take(budgets.initial_relays) {
        if enqueued.insert(normalize_base_uri(base)) {
            queue.push_back(Target {
                base_uri: base.clone(),
                depth: 0,
            });
        }
    }

    let mut visited: BTreeSet<String> = BTreeSet::new();
    // Cycle detection over (relay instance identifier, DID) for reference
    // targets, alongside the normalized-URI visited set: together these
    // cover the section 14.1 (relay id, normalized base URI, DID) tuple for
    // one target DID.
    let mut ref_relay_ids: BTreeSet<[u8; 16]> = BTreeSet::new();
    let mut diagnostics: Vec<Diagnostic> = Vec::new();
    let mut candidates: Vec<SourcedCandidate> = Vec::new();
    let mut incomplete = false;

    while let Some(target_relay) = queue.pop_front() {
        let normalized = normalize_base_uri(&target_relay.base_uri);
        if visited.contains(&normalized) {
            continue;
        }
        if visited.len() >= budgets.max_relays_visited {
            diagnostics.push(Diagnostic {
                base_uri: target_relay.base_uri.clone(),
                event: DiagEvent::BudgetStopped("visited-relay budget"),
            });
            incomplete = true;
            continue;
        }
        // Every newly contacted base URI counts against the distinct-relay
        // budget, whatever it later advertises.
        visited.insert(normalized);

        let outcome = client.resolve(&target_relay.base_uri, &[target.as_str()], &mut meter);
        let response = match outcome {
            Ok(response) => response,
            Err(ClientError::OuterResponse(fault)) => {
                // A rejected outer response is neither Absent nor Error: no
                // candidate, no reference target, no state change, budgets
                // charged, traversal continues (section 14.1).
                diagnostics.push(Diagnostic {
                    base_uri: target_relay.base_uri.clone(),
                    event: DiagEvent::RejectedOuterResponse(fault),
                });
                incomplete = true;
                continue;
            }
            Err(ClientError::BudgetExhausted(which)) => {
                diagnostics.push(Diagnostic {
                    base_uri: target_relay.base_uri.clone(),
                    event: DiagEvent::BudgetStopped(which),
                });
                incomplete = true;
                continue;
            }
            Err(error) => {
                diagnostics.push(Diagnostic {
                    base_uri: target_relay.base_uri.clone(),
                    event: DiagEvent::RequestFailed(error.symbol()),
                });
                incomplete = true;
                continue;
            }
        };

        // Exactly one result for the one requested DID (cardinality already
        // enforced by the client); interpret it against that request index.
        let result = response.value.results.into_iter().next();
        match result {
            Some(ReceivedResult::Full(bytes)) => {
                // Local verification for the requested DID, classified under
                // the client's own clock and sticky state. A failure
                // discards only this candidate.
                match verify_record_for_target(target.as_str(), &bytes) {
                    Ok(record) => {
                        if time_status(record.timestamp_ms(), now_ms) == TimeStatus::Premature {
                            diagnostics.push(Diagnostic {
                                base_uri: target_relay.base_uri.clone(),
                                event: DiagEvent::PrematureCandidate,
                            });
                        } else {
                            diagnostics.push(Diagnostic {
                                base_uri: target_relay.base_uri.clone(),
                                event: DiagEvent::VerifiedCandidate,
                            });
                            candidates.push(SourcedCandidate {
                                record,
                                source: target_relay.base_uri.clone(),
                                via_reference: target_relay.depth > 0,
                            });
                        }
                    }
                    Err(error) => {
                        diagnostics.push(Diagnostic {
                            base_uri: target_relay.base_uri.clone(),
                            event: DiagEvent::RejectedCandidate(error),
                        });
                    }
                }
            }
            Some(ReceivedResult::Ref(index)) => {
                diagnostics.push(Diagnostic {
                    base_uri: target_relay.base_uri.clone(),
                    event: DiagEvent::Ref(index),
                });
                let next_depth = target_relay.depth.saturating_add(1);
                if next_depth > budgets.max_ref_depth {
                    diagnostics.push(Diagnostic {
                        base_uri: target_relay.base_uri.clone(),
                        event: DiagEvent::BudgetStopped("reference-depth budget"),
                    });
                    incomplete = true;
                    continue;
                }
                // A Ref is interpreted only with the matching directory
                // generation (section 12.3).
                match client.directory(&target_relay.base_uri, &mut meter) {
                    Ok(directory) => {
                        let usable = directory.value.directory_generation
                            == response.value.directory_generation;
                        let entry = directory
                            .value
                            .entries
                            .iter()
                            .find(|e| e.index == index)
                            .cloned();
                        match (usable, entry) {
                            (true, Some(entry)) => {
                                let entry_normalized = normalize_base_uri(&entry.endpoint);
                                if visited.contains(&entry_normalized)
                                    || !ref_relay_ids.insert(entry.relay_id)
                                {
                                    diagnostics.push(Diagnostic {
                                        base_uri: entry.endpoint.clone(),
                                        event: DiagEvent::CycleRefused,
                                    });
                                } else {
                                    queue.push_back(Target {
                                        base_uri: entry.endpoint,
                                        depth: next_depth,
                                    });
                                }
                            }
                            _ => {
                                diagnostics.push(Diagnostic {
                                    base_uri: target_relay.base_uri.clone(),
                                    event: DiagEvent::UnusableRef,
                                });
                                incomplete = true;
                            }
                        }
                    }
                    Err(error) => {
                        diagnostics.push(Diagnostic {
                            base_uri: target_relay.base_uri.clone(),
                            event: DiagEvent::RequestFailed(error.symbol()),
                        });
                        incomplete = true;
                    }
                }
            }
            Some(ReceivedResult::Absent) => {
                // Local absence at that relay: no candidate, no reference,
                // no state change, traversal continues.
                diagnostics.push(Diagnostic {
                    base_uri: target_relay.base_uri.clone(),
                    event: DiagEvent::Absent,
                });
            }
            Some(ReceivedResult::Error(code)) => {
                // Diagnostic from that relay only; in particular a
                // premature classification is never imported into any
                // candidate (section 14.1).
                diagnostics.push(Diagnostic {
                    base_uri: target_relay.base_uri.clone(),
                    event: DiagEvent::RelayError(code),
                });
            }
            None => {
                // Unreachable after cardinality enforcement for one DID.
                diagnostics.push(Diagnostic {
                    base_uri: target_relay.base_uri.clone(),
                    event: DiagEvent::RequestFailed("cardinalityMismatch"),
                });
                incomplete = true;
            }
        }
    }

    // Combine candidates through the reviewed production selection entry
    // point with the explicit target and retained sticky state.
    let verified: Vec<VerifiedRecord> = candidates.iter().map(|c| c.record.clone()).collect();
    let selection = select_current(&target, &verified, now_ms, sticky);
    let authority_state = selection.authority_state;

    // Sticky RootRevoked state is monotonic: persist a learned transition;
    // Absent, Error, and rejected responses never changed it above.
    if authority_state == AuthorityState::RootRevoked {
        state.assume_root_revoked(target.as_str());
    }

    let winner = selection.winner.cloned();
    let mut compressed_route = state.get(target.as_str()).and_then(|s| s.route.clone());
    let relays_consulted = visited.len();

    let outcome = match winner {
        Some(record) => {
            let source = candidates
                .iter()
                .find(|c| c.record.body_digest() == record.body_digest())
                .map(|c| (c.source.clone(), c.via_reference))
                .unwrap_or_default();
            let entry = state.entries.entry(target.as_str().to_owned()).or_default();
            // Record the verified authority state. RootRevoked stickiness is
            // monotonic (already persisted above); a Root winner records
            // "only Root records verified so far" and can never downgrade a
            // retained RootRevoked state, because selection under that
            // sticky state cannot produce a Root winner.
            entry.sticky = authority_state;
            // Cache replacement follows ordering: never automatically
            // replace a cached same-authority record with an earlier one
            // (section 14.1); the RootRevoked transition always replaces.
            let replace = match &entry.cached {
                None => true,
                Some(cached) => {
                    let transition = record.authority() == crate::record::Authority::RootRevoked
                        && cached.authority == crate::record::Authority::Root;
                    transition
                        || crate::ordering::compare_ordering_keys(
                            record.timestamp_ms(),
                            record.body_digest(),
                            cached.timestamp_ms,
                            &cached.body_digest,
                        ) == std::cmp::Ordering::Greater
                }
            };
            if replace {
                entry.cached = Some(CachedRecord {
                    envelope: record.envelope_bytes().to_vec(),
                    authority: record.authority(),
                    timestamp_ms: record.timestamp_ms(),
                    body_digest: *record.body_digest(),
                });
            }
            // Lazy path compression: only after a locally verified
            // successful traversal, and only routing state.
            if source.1 {
                entry.route = Some(source.0.clone());
                compressed_route = entry.route.clone();
            }
            ResolveOutcome::Found(Box::new(ResolvedRecord {
                stale: freshness(record.body().valid_until_ms, now_ms) == Freshness::Stale,
                record,
                source: source.0,
            }))
        }
        None => {
            if incomplete || !queue.is_empty() {
                ResolveOutcome::TemporarilyUnavailable
            } else {
                ResolveOutcome::NotFound
            }
        }
    };

    Ok(Resolution {
        outcome,
        authority_state,
        relays_consulted,
        compressed_route,
        diagnostics,
    })
}
