//! Network-facing CLI commands (IMPLEMENTATION.md sections 8 and 13
//! Milestone 4): `relay publish`, `relay resolve`, `relay changes`,
//! `relay sync`, and the multi-relay `resolve`.
//!
//! These handlers marshal arguments and format one machine-readable JSON
//! object; every protocol decision — CBOR schemas, verification, candidate
//! ordering, cursors, budgets, traversal — lives in the production client
//! ([`crate::relay::client`]), the synchronization receiver
//! ([`crate::relay::sync`]), and the resolver ([`crate::resolver`]).
//! No secret key material exists in any of these commands.

use super::{
    CliError, RelayChangesArgs, RelayPublishArgs, RelayResolveArgs, RelaySyncArgs, ResolveArgs,
    read_record_bounded,
};
use crate::clock::Clock;
use crate::error::wire_error_symbol;
use crate::random::RandomSource;
use crate::relay::client::{
    BudgetMeter, HttpTransport, OperationBudget, ReceivedChangePayload, ReceivedResult, RelayClient,
};
use crate::relay::sync::SyncOptions;
use crate::relay::wire::ReceivedChangesResponse;
use crate::resolver::{
    ClientState, DiagEvent, MigrationCheck, MigrationState, OperationScope, ResolveOutcome,
    ResolverBudgets, ResolverConfig, check_migration, resolve_did, resolve_did_in_scope,
};
use crate::timestamp::{Freshness, TimeStatus, freshness, time_status};
use crate::verify::verify_record_for_target;
use serde_json::{Value, json};
use std::path::Path;

/// Renders a wire error code as `{"code": n, "symbol": "..."}`.
fn code_json(code: u64) -> Value {
    match wire_error_symbol(code) {
        Some(symbol) => json!({ "code": code, "symbol": symbol }),
        None => json!({ "code": code }),
    }
}

/// A generous single-command budget: the direct commands are one-shot
/// operator operations, so the meter mainly enforces the response bounds
/// and a request cap covering redirects.
fn command_budget(max_response_bytes: u64) -> BudgetMeter {
    BudgetMeter::new(OperationBudget {
        deadline_ms: None,
        max_response_bytes,
        max_requests: 16,
    })
}

/// `followee relay publish`: transports one already signed record through
/// the production client. The record bytes are opaque here.
pub(super) fn relay_publish(args: &RelayPublishArgs, clock: &dyn Clock) -> Result<Value, CliError> {
    let record = read_record_bounded(&args.record)?;
    let transport = HttpTransport;
    let client = RelayClient::new(&transport, args.policy.policy(), clock)
        .with_default_timeout_ms(args.timeout_ms);
    let mut meter = command_budget(1024 * 1024);
    let outcome = client.publish(&args.relay, &record, &mut meter)?;
    let response = outcome.value;
    let status_name = match response.status {
        0 => "admitted",
        1 => "noChange",
        _ => "rejected",
    };
    if response.status == 2 {
        let detail = response
            .error_code
            .and_then(wire_error_symbol)
            .map(|symbol| format!(": {symbol}"))
            .unwrap_or_default();
        return Err(CliError::PublishRejected(detail));
    }
    Ok(json!({
        "relay": args.relay,
        "recordFile": args.record.display().to_string(),
        "status": status_name,
    }))
}

/// `followee relay resolve`: one aligned batch against one relay. Every
/// Full candidate is locally verified for the DID at its request index
/// through the production verification core and classified under the
/// injected clock; nothing shifts positions.
pub(super) fn relay_resolve(args: &RelayResolveArgs, clock: &dyn Clock) -> Result<Value, CliError> {
    let transport = HttpTransport;
    let client = RelayClient::new(&transport, args.policy.policy(), clock)
        .with_default_timeout_ms(args.timeout_ms);
    let mut meter = command_budget(2 * 1024 * 1024);
    let dids: Vec<&str> = args.dids.iter().map(String::as_str).collect();
    let outcome = client.resolve(&args.relay, &dids, &mut meter)?;
    let now_ms = super::now_for(clock, args.now_ms)?;

    let results: Vec<Value> = outcome
        .value
        .results
        .into_iter()
        .zip(&args.dids)
        .map(|(result, did)| match result {
            ReceivedResult::Full(bytes) => match verify_record_for_target(did, &bytes) {
                Ok(record) => json!({
                    "kind": "full",
                    "verified": true,
                    "did": record.body().id.as_str(),
                    "authority": super::authority_name(record.authority()),
                    "timestampMs": record.timestamp_ms(),
                    "bodyDigest": hex::encode(record.body_digest()),
                    "timeStatus": match time_status(record.timestamp_ms(), now_ms) {
                        TimeStatus::Admissible => "admissible",
                        TimeStatus::Premature => "premature",
                    },
                    "freshness": match freshness(record.body().valid_until_ms, now_ms) {
                        Freshness::Fresh => "fresh",
                        Freshness::Stale => "stale",
                    },
                    "recordHex": hex::encode(&bytes),
                }),
                // An invalid candidate is discarded with its classification;
                // it is not Absent and does not affect other indices.
                Err(error) => json!({
                    "kind": "full",
                    "verified": false,
                    "error": error.symbol(),
                }),
            },
            ReceivedResult::Ref(index) => json!({ "kind": "ref", "relayIndex": index }),
            ReceivedResult::Absent => json!({ "kind": "absent" }),
            ReceivedResult::Error(code) => json!({ "kind": "error", "error": code_json(code) }),
        })
        .collect();

    Ok(json!({
        "relay": args.relay,
        "directoryGeneration": hex::encode(outcome.value.directory_generation),
        "results": results,
    }))
}

/// `followee relay changes`: one page of a peer's feed through the
/// production client, with status-dependent field validation already
/// enforced by the client. Full entries stay opaque (reported as hex).
pub(super) fn relay_changes(args: &RelayChangesArgs, clock: &dyn Clock) -> Result<Value, CliError> {
    let cursor = args
        .cursor
        .as_deref()
        .map(hex::decode)
        .transpose()
        .map_err(|_| CliError::Usage("cursor must be hex".to_owned()))?;
    let transport = HttpTransport;
    let client = RelayClient::new(&transport, args.policy.policy(), clock)
        .with_default_timeout_ms(args.timeout_ms);
    let mut meter = command_budget(args.byte_limit.saturating_add(64 * 1024));
    let outcome = client.changes(
        &args.relay,
        cursor.as_deref(),
        args.item_limit,
        args.byte_limit,
        &mut meter,
    )?;
    let body = match outcome.value {
        ReceivedChangesResponse::Success {
            entries,
            next_cursor,
            has_more,
            directory_generation,
        } => {
            let rows: Vec<Value> = entries
                .into_iter()
                .map(|entry| {
                    let payload = match entry.payload {
                        ReceivedChangePayload::Full(bytes) => json!({
                            "kind": "full",
                            "recordHex": hex::encode(bytes),
                        }),
                        ReceivedChangePayload::Ref(index) => json!({
                            "kind": "ref",
                            "relayIndex": index,
                        }),
                    };
                    json!({
                        "did": entry.did,
                        "payload": payload,
                        "lastUpdated": entry.last_updated,
                    })
                })
                .collect();
            json!({
                "status": "success",
                "entries": rows,
                "nextCursorHex": hex::encode(next_cursor),
                "hasMore": has_more,
                "directoryGeneration": hex::encode(directory_generation),
            })
        }
        ReceivedChangesResponse::ResetRequired => json!({ "status": "resetRequired" }),
        ReceivedChangesResponse::Error(code) => json!({
            "status": "error",
            "error": code_json(code),
        }),
    };
    let mut object = body.as_object().cloned().unwrap_or_default();
    object.insert("relay".to_owned(), Value::String(args.relay.clone()));
    Ok(Value::Object(object))
}

/// `followee relay sync`: one explicit synchronization pass through the
/// production receiver over a local relay SQLite database. All protocol
/// decisions live in [`crate::relay::sync`].
pub(super) fn relay_sync(args: &RelaySyncArgs, rng: &dyn RandomSource) -> Result<Value, CliError> {
    // The receiver clock: the operating-system clock in production, or the
    // explicit override for deterministic operation.
    let clock: Box<dyn Clock + Send + Sync> = match args.now_ms {
        Some(now_ms) => Box::new(crate::clock::ManualClock::new(now_ms)),
        None => Box::new(crate::clock::SystemClock),
    };

    let fresh = crate::store::RelayIdentity::generate(rng)
        .map_err(|e| CliError::Environment(e.to_string()))?;
    let store = crate::store::sqlite::SqliteStore::open(&args.database, fresh)
        .map_err(|e| CliError::Environment(e.to_string()))?;
    // This process serves nothing: the base URI and development mode only
    // satisfy the relay constructor and never reach the network.
    let sync_clock: Box<dyn Clock + Send + Sync> = match args.now_ms {
        Some(now_ms) => Box::new(crate::clock::ManualClock::new(now_ms)),
        None => Box::new(crate::clock::SystemClock),
    };
    let relay = crate::relay::Relay::new(
        Box::new(store),
        sync_clock,
        crate::relay::RelayConfig {
            base_uri: "http://127.0.0.1/".to_owned(),
            development_mode: true,
        },
    )
    .map_err(|e| CliError::Environment(e.to_string()))?;

    let transport = HttpTransport;
    let client = RelayClient::new(&transport, args.policy.policy(), clock.as_ref())
        .with_default_timeout_ms(args.timeout_ms);
    let options = SyncOptions {
        item_limit: args.item_limit,
        byte_limit: args.byte_limit,
        max_pages: args.max_pages,
    };
    let mut meter = BudgetMeter::new(OperationBudget {
        deadline_ms: None,
        max_response_bytes: args
            .byte_limit
            .saturating_mul(u64::from(args.max_pages))
            .saturating_add(64 * 1024),
        max_requests: u64::from(args.max_pages).saturating_add(4),
    });
    let report = relay.sync_once(&client, &args.peer, &options, &mut meter)?;

    Ok(json!({
        "database": args.database.display().to_string(),
        "peer": args.peer,
        "peerRelayId": hex::encode(report.peer_relay_id),
        "pages": report.pages,
        "admitted": report
            .admitted
            .iter()
            .map(|a| json!({ "did": a.did, "updateNumber": a.update_number }))
            .collect::<Vec<_>>(),
        "noChange": report.no_change,
        "rejected": report
            .rejected
            .iter()
            .map(|r| {
                let mut row = json!({ "entryDid": r.entry_did });
                if let Some(object) = row.as_object_mut() {
                    object.insert("error".to_owned(), code_json(r.code));
                }
                row
            })
            .collect::<Vec<_>>(),
        "refsIgnored": report.refs_ignored,
        "resetPerformed": report.reset_performed,
        "finalCursorHex": report.final_cursor.as_deref().map(hex::encode),
        "hasMore": report.has_more,
    }))
}

// ---------------------------------------------------------------------------
// Multi-relay resolve and its client-state file
// ---------------------------------------------------------------------------

/// Loads client state from an optional JSON file. Cached envelopes are
/// re-verified through the production core before restoration; entries that
/// fail are silently dropped (the file is local input, not evidence).
pub(super) fn load_state(path: Option<&Path>) -> Result<ClientState, CliError> {
    let mut state = ClientState::new();
    let Some(path) = path else {
        return Ok(state);
    };
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(state),
        Err(source) => {
            return Err(CliError::Io {
                path: path.to_path_buf(),
                source,
            });
        }
    };
    let value: Value = serde_json::from_str(&text)
        .map_err(|e| CliError::Usage(format!("state file does not parse: {e}")))?;
    let Some(dids) = value.get("dids").and_then(Value::as_object) else {
        return Ok(state);
    };
    for (did, entry) in dids {
        if entry.get("authorityState").and_then(Value::as_str) == Some("rootRevoked") {
            state.assume_root_revoked(did);
        }
        if let Some(route) = entry.get("route").and_then(Value::as_str) {
            state.restore_route(did, route);
        }
        if let Some(hex_text) = entry.get("cachedEnvelopeHex").and_then(Value::as_str) {
            if let Ok(bytes) = hex::decode(hex_text) {
                // Invalid bytes change nothing.
                let _ = state.restore_cached(did, &bytes);
            }
        }
    }
    Ok(state)
}

/// Serializes client state to its JSON file form.
pub(super) fn state_to_json(state: &ClientState) -> Value {
    let mut dids = serde_json::Map::new();
    for (did, entry) in state.iter() {
        let mut object = serde_json::Map::new();
        object.insert(
            "authorityState".to_owned(),
            Value::String(
                match entry.sticky {
                    crate::ordering::AuthorityState::Unknown => "unknown",
                    crate::ordering::AuthorityState::Root => "root",
                    crate::ordering::AuthorityState::RootRevoked => "rootRevoked",
                }
                .to_owned(),
            ),
        );
        if let Some(route) = &entry.route {
            object.insert("route".to_owned(), Value::String(route.clone()));
        }
        if let Some(cached) = &entry.cached {
            object.insert(
                "cachedEnvelopeHex".to_owned(),
                Value::String(hex::encode(&cached.envelope)),
            );
        }
        dids.insert(did.to_owned(), Value::Object(object));
    }
    json!({ "version": 1, "dids": dids })
}

pub(super) fn diag_json(event: &DiagEvent) -> Value {
    match event {
        DiagEvent::VerifiedCandidate => json!({ "event": "verifiedCandidate" }),
        DiagEvent::RejectedCandidate(error) => {
            json!({ "event": "rejectedCandidate", "error": error.symbol() })
        }
        DiagEvent::PrematureCandidate => json!({ "event": "prematureCandidate" }),
        DiagEvent::Absent => json!({ "event": "absent" }),
        DiagEvent::RelayError(code) => json!({ "event": "relayError", "error": code_json(*code) }),
        DiagEvent::Ref(index) => json!({ "event": "ref", "relayIndex": index }),
        DiagEvent::RejectedOuterResponse(error) => {
            json!({ "event": "rejectedOuterResponse", "error": error.symbol() })
        }
        DiagEvent::RequestFailed(symbol) => json!({ "event": "requestFailed", "error": symbol }),
        DiagEvent::UnusableRef => json!({ "event": "unusableRef" }),
        DiagEvent::CycleRefused => json!({ "event": "cycleRefused" }),
        DiagEvent::BudgetStopped(which) => json!({ "event": "budgetStopped", "budget": which }),
    }
}

/// Renders one migration check (specification sections 14.2 and 14.3):
/// only the Verified state may drive migration-oriented presentation, and
/// even then nothing is re-followed automatically.
pub(super) fn migration_check_json(check: &MigrationCheck) -> Value {
    let mut object = serde_json::Map::new();
    object.insert(
        "direction".to_owned(),
        Value::String(check.direction.name().to_owned()),
    );
    object.insert(
        "counterpart".to_owned(),
        Value::String(check.counterpart.clone()),
    );
    object.insert(
        "state".to_owned(),
        Value::String(check.state.name().to_owned()),
    );
    object.insert("reason".to_owned(), Value::String(check.reason.to_owned()));
    // Section 14.3: anything short of Verified is suppressed, never shown
    // as "formerly" / provenance / succession.
    object.insert(
        "presentable".to_owned(),
        Value::Bool(check.state == MigrationState::Verified),
    );
    if let Some(resolution) = &check.counterpart_resolution {
        let outcome = match &resolution.outcome {
            ResolveOutcome::Found(found) => json!({
                "outcome": "found",
                "stale": found.stale,
            }),
            ResolveOutcome::NotFound => json!({ "outcome": "notFound" }),
            ResolveOutcome::TemporarilyUnavailable => {
                json!({ "outcome": "temporarilyUnavailable" })
            }
        };
        let mut summary = outcome.as_object().cloned().unwrap_or_default();
        summary.insert(
            "relaysConsulted".to_owned(),
            Value::Number(resolution.relays_consulted.into()),
        );
        object.insert("counterpartResolution".to_owned(), Value::Object(summary));
    }
    Value::Object(object)
}

/// `followee resolve`: the production multi-relay resolver. This handler
/// only loads and saves state and formats the result.
pub(super) fn resolve_multi(args: &ResolveArgs, clock: &dyn Clock) -> Result<Value, CliError> {
    let mut state = load_state(args.state.as_deref())?;
    let transport = HttpTransport;
    let client = RelayClient::new(&transport, args.policy.policy(), clock);

    // The deterministic --now-ms override drives the complete operation
    // through a manual clock so classification and deadlines agree.
    let manual;
    let effective_clock: &dyn Clock = match args.now_ms {
        Some(now_ms) => {
            manual = crate::clock::ManualClock::new(now_ms);
            &manual
        }
        None => clock,
    };

    let config = ResolverConfig {
        relays: args.relays.clone(),
        budgets: ResolverBudgets {
            deadline_duration_ms: args.deadline_ms,
            ..ResolverBudgets::default()
        },
    };
    // One shared operation scope covers the resolution and any migration
    // checks: one deadline, byte, request, distinct-relay, and hop budget
    // (specification section 14.1). A clock failure surfaces through the
    // ordinary resolve path as temporarilyUnavailable.
    let (resolution, migration) = match effective_clock.now_ms() {
        Err(_) => (
            resolve_did(&args.did, &config, &client, effective_clock, &mut state)
                .map_err(CliError::Verify)?,
            None,
        ),
        Ok(now_ms) => {
            let mut scope = OperationScope::new(&config.budgets, now_ms);
            let resolution = resolve_did_in_scope(
                &args.did,
                &config,
                &client,
                effective_clock,
                &mut state,
                &mut scope,
            )
            .map_err(CliError::Verify)?;
            let migration = if args.check_migration {
                match &resolution.outcome {
                    ResolveOutcome::Found(found) => {
                        let target = crate::did::FolloweeDid::parse(&args.did)
                            .map_err(|e| CliError::Verify(e.into()))?;
                        Some(check_migration(
                            found,
                            &target,
                            &config,
                            &client,
                            effective_clock,
                            &mut state,
                            &mut scope,
                        ))
                    }
                    _ => None,
                }
            } else {
                None
            };
            (resolution, migration)
        }
    };

    if let Some(path) = &args.state {
        let text = format!("{}\n", state_to_json(&state));
        std::fs::write(path, text).map_err(|source| CliError::Io {
            path: path.clone(),
            source,
        })?;
    }

    let diagnostics: Vec<Value> = resolution
        .diagnostics
        .iter()
        .map(|d| {
            let mut object = diag_json(&d.event).as_object().cloned().unwrap_or_default();
            object.insert("relay".to_owned(), Value::String(d.base_uri.clone()));
            Value::Object(object)
        })
        .collect();
    let authority_state = match resolution.authority_state {
        crate::ordering::AuthorityState::Unknown => "unknown",
        crate::ordering::AuthorityState::Root => "root",
        crate::ordering::AuthorityState::RootRevoked => "rootRevoked",
    };
    let base = |outcome: &str| {
        json!({
            "did": args.did,
            "outcome": outcome,
            "authorityState": authority_state,
            "relaysConsulted": resolution.relays_consulted,
            "compressedRoute": resolution.compressed_route,
            "diagnostics": diagnostics,
        })
    };

    match resolution.outcome {
        ResolveOutcome::Found(found) => {
            let mut object = base("found").as_object().cloned().unwrap_or_default();
            object.insert(
                "record".to_owned(),
                json!({
                    "authority": super::authority_name(found.record.authority()),
                    "timestampMs": found.record.timestamp_ms(),
                    "bodyDigest": hex::encode(found.record.body_digest()),
                    "stale": found.stale,
                    "source": found.source,
                    "recordHex": hex::encode(found.record.envelope_bytes()),
                }),
            );
            if let Some(checks) = migration {
                object.insert(
                    "migration".to_owned(),
                    Value::Array(checks.iter().map(migration_check_json).collect()),
                );
            }
            Ok(Value::Object(object))
        }
        ResolveOutcome::NotFound => Err(CliError::ResolutionFailed {
            symbol: "notFound",
            detail: Box::new(base("notFound")),
        }),
        ResolveOutcome::TemporarilyUnavailable => Err(CliError::ResolutionFailed {
            symbol: "temporarilyUnavailable",
            detail: Box::new(base("temporarilyUnavailable")),
        }),
    }
}
