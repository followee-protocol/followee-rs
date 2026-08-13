//! Handle-facing CLI commands (IMPLEMENTATION.md sections 8 and 13
//! Milestone 5): `handle resolve`, `handle verify`, and `handle serve`.
//!
//! These handlers marshal arguments and format one machine-readable JSON
//! object; every protocol decision — handle grammar, WebFinger discovery,
//! JRD bounds, record verification, bootstrap selection, sticky state,
//! inverse binding — lives in the production [`crate::webfinger`],
//! [`crate::verify`], [`crate::ordering`], and [`crate::resolver`]
//! components. Discovery results are reported exactly: a domain mapping is
//! never labelled as record verification, and a handle is reported
//! verified only when the production check binds both directions to the
//! same DID. No secret key material exists in any of these commands.

use super::{CliError, HandleResolveArgs, HandleServeArgs, HandleVerifyArgs, read_record_bounded};
use crate::clock::Clock;
use crate::ordering::AuthorityState;
use crate::relay::client::{BudgetMeter, HttpTransport, OperationBudget, RelayClient};
use crate::resolver::{
    OperationScope, ResolveOutcome, ResolverBudgets, ResolverConfig, resolve_did_in_scope,
};
use crate::timestamp::{Freshness, TimeStatus, freshness, time_status};
use crate::verify::{VerifiedRecord, verify_record_for_target};
use crate::webfinger::{
    BootstrapOutcome, CandidateStatus, Discovery, Handle, HandleVerification, InverseOutcome,
    WebFingerClient,
};
use serde_json::{Value, json};
use std::io::Write;
use std::path::PathBuf;

/// Requests-per-lookup allowance: one WebFinger fetch plus bounded
/// redirects plus bootstrap fetches, all charged to one meter.
const HANDLE_REQUEST_BUDGET: u64 = 16;
/// Response-byte allowance for one handle operation: JRD plus a few
/// records is well under this; the per-response caps are tighter still.
const HANDLE_BYTE_BUDGET: u64 = 512 * 1024;

fn authority_state_name(state: AuthorityState) -> &'static str {
    match state {
        AuthorityState::Unknown => "unknown",
        AuthorityState::Root => "root",
        AuthorityState::RootRevoked => "rootRevoked",
    }
}

fn discovery_json(discovery: &Discovery) -> Value {
    json!({
        // The mapping is the domain's claim for the exact canonical
        // resource; "discovered" deliberately does not say "verified".
        "status": "discovered",
        "resource": discovery.resource,
        "did": discovery.did.as_str(),
        "recordLinks": discovery.record_links,
        "contacted": discovery.contacted,
    })
}

fn record_facts(record: &VerifiedRecord, now_ms: u64) -> Value {
    json!({
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
    })
}

fn bootstrap_json(outcome: &BootstrapOutcome, now_ms: u64) -> Value {
    let candidates: Vec<Value> = outcome
        .candidates
        .iter()
        .map(|candidate| {
            let status = match &candidate.status {
                CandidateStatus::FetchFailed(error) => json!({
                    "status": "fetchFailed",
                    "error": error.symbol(),
                }),
                CandidateStatus::Rejected(error) => json!({
                    "status": "rejected",
                    "error": error.symbol(),
                }),
                CandidateStatus::Premature => json!({ "status": "premature" }),
                CandidateStatus::Verified {
                    authority,
                    timestamp_ms,
                    body_digest,
                    stale,
                } => json!({
                    "status": "verified",
                    "authority": super::authority_name(*authority),
                    "timestampMs": timestamp_ms,
                    "bodyDigest": hex::encode(body_digest),
                    "stale": stale,
                }),
            };
            let mut object = status.as_object().cloned().unwrap_or_default();
            object.insert("url".to_owned(), Value::String(candidate.url.clone()));
            Value::Object(object)
        })
        .collect();
    let winner = outcome.winner.as_ref().map(|winner| {
        let mut facts = record_facts(&winner.record, now_ms)
            .as_object()
            .cloned()
            .unwrap_or_default();
        facts.insert("source".to_owned(), Value::String(winner.source.clone()));
        facts.insert(
            "recordHex".to_owned(),
            Value::String(hex::encode(winner.record.envelope_bytes())),
        );
        Value::Object(facts)
    });
    json!({
        "candidates": candidates,
        "authorityState": authority_state_name(outcome.authority_state),
        "winner": winner,
    })
}

/// Raw migration claims from a record, reported as claims only: `handle
/// resolve` contacts no relays, so every claim is Not checked (deferred).
/// The reciprocal check is `followee resolve --check-migration`.
fn migration_claims_json(record: &VerifiedRecord) -> Vec<Value> {
    let Some(migration) = record.body().contact.migration.as_ref() else {
        return Vec::new();
    };
    let mut claims = Vec::new();
    for (direction, did) in [
        ("predecessor", migration.predecessor.as_ref()),
        ("successor", migration.successor.as_ref()),
    ] {
        if let Some(did) = did {
            claims.push(json!({
                "direction": direction,
                "counterpart": did.as_str(),
                "state": "notChecked",
                "reason": "deferred",
                "presentable": false,
            }));
        }
    }
    claims
}

fn handle_meter(clock: &dyn Clock, deadline_duration_ms: Option<u64>) -> BudgetMeter {
    let deadline_ms = deadline_duration_ms
        .and_then(|duration| clock.now_ms().ok().map(|now| now.saturating_add(duration)));
    BudgetMeter::new(OperationBudget {
        deadline_ms,
        max_response_bytes: HANDLE_BYTE_BUDGET,
        max_requests: HANDLE_REQUEST_BUDGET,
    })
}

fn save_state(
    path: Option<&PathBuf>,
    state: &crate::resolver::ClientState,
) -> Result<(), CliError> {
    if let Some(path) = path {
        let text = format!("{}\n", super::network::state_to_json(state));
        std::fs::write(path, text).map_err(|source| CliError::Io {
            path: path.clone(),
            source,
        })?;
    }
    Ok(())
}

/// `followee handle resolve`: production WebFinger discovery with the
/// exact-subject and link-cardinality rules, plus optional bootstrap.
pub(super) fn handle_resolve(
    args: &HandleResolveArgs,
    clock: &dyn Clock,
) -> Result<Value, CliError> {
    let handle = Handle::parse(&args.handle).map_err(crate::webfinger::WebFingerError::Handle)?;
    let mut state = super::network::load_state(args.state.as_deref())?;
    let now_ms = super::now_for(clock, args.now_ms)?;
    let manual;
    let effective_clock: &dyn Clock = match args.now_ms {
        Some(now) => {
            manual = crate::clock::ManualClock::new(now);
            &manual
        }
        None => clock,
    };

    let transport = HttpTransport;
    let client = WebFingerClient::new(&transport, args.policy.policy(), effective_clock)
        .with_default_timeout_ms(args.timeout_ms);
    let mut meter = handle_meter(effective_clock, None);

    let discovery = client.lookup(&handle, args.endpoint.as_deref(), &mut meter)?;

    let mut output = serde_json::Map::new();
    output.insert("handle".to_owned(), Value::String(handle.to_string()));
    output.insert("discovery".to_owned(), discovery_json(&discovery));

    if !args.no_bootstrap && !discovery.record_links.is_empty() {
        let sticky = state
            .get(discovery.did.as_str())
            .map_or(AuthorityState::Unknown, |s| s.sticky);
        let bootstrap = client.bootstrap(&discovery, now_ms, sticky, &mut meter);
        // A learned RootRevoked transition is persisted; a winner enters
        // the cache through the one production cache-update rule. Nothing
        // else in the bootstrap changes local state.
        if bootstrap.authority_state == AuthorityState::RootRevoked {
            state.assume_root_revoked(discovery.did.as_str());
        }
        if let Some(winner) = &bootstrap.winner {
            state.record_selection(
                discovery.did.as_str(),
                bootstrap.authority_state,
                &winner.record,
            );
        }
        output.insert(
            "migration".to_owned(),
            Value::Array(
                bootstrap
                    .winner
                    .as_ref()
                    .map(|w| migration_claims_json(&w.record))
                    .unwrap_or_default(),
            ),
        );
        output.insert("bootstrap".to_owned(), bootstrap_json(&bootstrap, now_ms));
    }

    save_state(args.state.as_ref(), &state)?;
    Ok(Value::Object(output))
}

/// `followee handle verify`: local record verification (from a file or
/// through the production resolver) combined with inverse WebFinger
/// discovery; verified only when both directions bind the exact handle to
/// the same DID (specification section 10.4).
pub(super) fn handle_verify(args: &HandleVerifyArgs, clock: &dyn Clock) -> Result<Value, CliError> {
    let handle = Handle::parse(&args.handle).map_err(crate::webfinger::WebFingerError::Handle)?;
    match (&args.record, args.relays.is_empty()) {
        (Some(_), false) => {
            return Err(CliError::Usage(
                "--record and --relay are alternative record sources; give one".to_owned(),
            ));
        }
        (None, true) => {
            return Err(CliError::Usage(
                "a record source is required: --record FILE or --relay URI".to_owned(),
            ));
        }
        _ => {}
    }

    let mut state = super::network::load_state(args.state.as_deref())?;
    let now_ms = super::now_for(clock, args.now_ms)?;
    let manual;
    let effective_clock: &dyn Clock = match args.now_ms {
        Some(now) => {
            manual = crate::clock::ManualClock::new(now);
            &manual
        }
        None => clock,
    };
    let transport = HttpTransport;
    let policy = args.policy.policy();

    // One shared operation scope covers the record resolution (when the
    // resolver supplies the record) and the inverse WebFinger lookup.
    let budgets = ResolverBudgets {
        deadline_duration_ms: args.deadline_ms,
        ..ResolverBudgets::default()
    };
    let mut scope = OperationScope::new(&budgets, now_ms);

    let (record, source, resolution_detail) = match &args.record {
        Some(path) => {
            let bytes = read_record_bounded(path)?;
            let record = verify_record_for_target(&args.did, &bytes)?;
            (record, json!("file"), None)
        }
        None => {
            let relay_client = RelayClient::new(&transport, policy, effective_clock)
                .with_default_timeout_ms(args.timeout_ms);
            let config = ResolverConfig {
                relays: args.relays.clone(),
                budgets,
            };
            let resolution = resolve_did_in_scope(
                &args.did,
                &config,
                &relay_client,
                effective_clock,
                &mut state,
                &mut scope,
            )
            .map_err(CliError::Verify)?;
            match resolution.outcome {
                ResolveOutcome::Found(found) => {
                    let detail = json!({
                        "source": found.source,
                        "relaysConsulted": resolution.relays_consulted,
                    });
                    (found.record, json!("resolver"), Some(detail))
                }
                ResolveOutcome::NotFound => {
                    save_state(args.state.as_ref(), &state)?;
                    return Err(CliError::ResolutionFailed {
                        symbol: "notFound",
                        detail: Box::new(json!({
                            "did": args.did,
                            "outcome": "notFound",
                        })),
                    });
                }
                ResolveOutcome::TemporarilyUnavailable => {
                    save_state(args.state.as_ref(), &state)?;
                    return Err(CliError::ResolutionFailed {
                        symbol: "temporarilyUnavailable",
                        detail: Box::new(json!({
                            "did": args.did,
                            "outcome": "temporarilyUnavailable",
                        })),
                    });
                }
            }
        }
    };

    let webfinger = WebFingerClient::new(&transport, policy, effective_clock)
        .with_default_timeout_ms(args.timeout_ms);
    let verification: HandleVerification =
        webfinger.verify_handle(&handle, &record, args.endpoint.as_deref(), scope.meter());

    save_state(args.state.as_ref(), &state)?;

    let mut record_json = record_facts(&record, now_ms)
        .as_object()
        .cloned()
        .unwrap_or_default();
    record_json.insert("source".to_owned(), source);
    if let Some(detail) = resolution_detail {
        record_json.insert("resolution".to_owned(), detail);
    }
    let inverse = match &verification.inverse {
        InverseOutcome::Matched { discovery } => json!({
            "status": "matched",
            "did": discovery.did.as_str(),
        }),
        InverseOutcome::Mismatched { discovery } => json!({
            "status": "mismatched",
            "did": discovery.did.as_str(),
        }),
        InverseOutcome::Failed(error) => json!({
            "status": "failed",
            "error": error.symbol(),
        }),
    };
    let detail = json!({
        "handle": handle.to_string(),
        "resource": handle.resource(),
        "did": args.did,
        "record": Value::Object(record_json),
        "claim": {
            "present": verification.claim.is_some(),
            "entry": verification.claim,
        },
        "inverse": inverse,
        "handleVerified": verification.verified,
    });
    if verification.verified {
        Ok(detail)
    } else {
        Err(CliError::HandleUnverified {
            detail: Box::new(detail),
        })
    }
}

/// `followee handle serve --check`: the predeployment consistency gate.
/// The classification lives in the production
/// [`crate::webfinger::authority::AuthorityConfig::deployment_consistency`];
/// this handler only renders the report and maps failure to a nonzero
/// exit.
fn deployment_check(
    config: &crate::webfinger::authority::AuthorityConfig,
    path: &std::path::Path,
) -> Result<Value, CliError> {
    let report = config.deployment_consistency();
    let entries: Vec<Value> = report
        .entries
        .iter()
        .map(|entry| {
            json!({
                "local": entry.local,
                "resource": entry.resource,
                "did": entry.did,
                "hasRecord": entry.has_record,
                "recordVerified": entry.record_verified,
                "claimed": entry.claimed,
                "ok": entry.ok,
            })
        })
        .collect();
    let detail = json!({
        "configFile": path.display().to_string(),
        "domain": config.domain(),
        "entries": entries,
        "consistent": report.consistent,
    });
    if report.consistent {
        Ok(detail)
    } else {
        Err(CliError::DeploymentInconsistent {
            detail: Box::new(detail),
        })
    }
}

/// `followee handle serve`: the minimal demonstration authority over a
/// validated configuration, until an interrupt or termination signal.
///
/// The startup object is the command's one protocol-defined stdout line;
/// the non-conforming development-mode notice and the shutdown message go
/// to stderr. No secret material exists in this command.
pub(super) fn handle_serve(
    args: &HandleServeArgs,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> Result<Option<Value>, CliError> {
    let config = crate::webfinger::authority::AuthorityConfig::load(&args.config)?;
    if args.check {
        return deployment_check(&config, &args.config).map(Some);
    }
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| CliError::Environment(e.to_string()))?;
    runtime.block_on(async {
        let listener = tokio::net::TcpListener::bind(&args.listen)
            .await
            .map_err(|source| CliError::Io {
                path: PathBuf::from(&args.listen),
                source,
            })?;
        let bound = listener
            .local_addr()
            .map_err(|e| CliError::Environment(e.to_string()))?;
        let base_uri = match &args.base_uri {
            Some(uri) => uri.clone(),
            None => format!("http://{bound}/"),
        };
        let authority = crate::webfinger::authority::HandleAuthority::new(config, base_uri.clone())
            .map_err(CliError::Usage)?;
        let development_mode = authority.development_mode();

        // The shutdown listener exists before readiness is advertised, so
        // a signal racing the startup object still shuts down cleanly.
        let shutdown = super::shutdown_signal();
        let startup = json!({
            "listen": bound.to_string(),
            "baseUri": base_uri,
            "domain": authority.config().domain(),
            "handles": authority.config().handle_count(),
            "records": authority.config().record_count(),
            "configFile": args.config.display().to_string(),
            "developmentMode": development_mode,
        });
        let _ = writeln!(stdout, "{startup}");
        let _ = stdout.flush();
        if development_mode {
            let _ = writeln!(
                stderr,
                "WARNING: development mode is explicitly non-conforming: plain \
                 HTTP on a loopback address only. The public demonstration \
                 requires an HTTPS base URI behind provider TLS termination."
            );
        }

        crate::webfinger::authority::serve_with_shutdown(
            std::sync::Arc::new(authority),
            listener,
            shutdown,
        )
        .await
        .map_err(|e| CliError::Environment(e.to_string()))?;
        let _ = writeln!(stderr, "handle authority stopped");
        Ok(None)
    })
}
