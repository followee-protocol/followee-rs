//! In-process tests for the handle CLI handlers against a real loopback
//! authority (and, for migration checks, a real loopback relay): the
//! production `HttpTransport`, the machine-readable JSON surfaces, stable
//! symbolic errors, and the state-file invariants under handle
//! disappearance and reassignment.
#![allow(clippy::arithmetic_side_effects)]

mod common;

use common::*;
use followee::cli::run;
use followee::clock::ManualClock;
use followee::random::DeterministicRandom;
use followee::relay::http::serve;
use serde_json::Value;
use std::net::SocketAddr;

fn start_relay_server(t: &TestRelay) -> SocketAddr {
    let relay = std::sync::Arc::clone(&t.relay);
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio runtime");
        rt.block_on(async move {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind loopback");
            tx.send(listener.local_addr().expect("local addr"))
                .expect("send addr");
            serve(relay, listener).await.expect("serve");
        });
    });
    rx.recv().expect("server address")
}

fn cli(args: &[&str]) -> (u8, Value) {
    let rng = DeterministicRandom::from_seed(7);
    let clock = ManualClock::new(RELAY_NOW_MS);
    let owned: Vec<String> = args.iter().map(|s| (*s).to_owned()).collect();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let code = run(&owned, &rng, &clock, &mut stdout, &mut stderr);
    let text = String::from_utf8(stdout).expect("stdout UTF-8");
    let json = serde_json::from_str(text.lines().next().unwrap_or("null")).unwrap_or(Value::Null);
    (code, json)
}

fn demo_config() -> String {
    format!(
        r#"{{"version":1,"domain":"example.com","handles":[
            {{"local":"alice","did":"{alice}","record":"alice.cose"}}
        ]}}"#,
        alice = alice_did().as_str()
    )
}

fn claiming_record() -> Vec<u8> {
    alice_record_with_contact(
        RELAY_NOW_MS - 1_000,
        None,
        contact_claiming(&["acct:alice@example.com"]),
    )
}

const NOW: &str = "1785589201123";

#[test]
fn handle_resolve_reports_discovery_and_bootstrap_without_overstating() {
    let (addr, _authority) = start_authority(&demo_config(), &[("alice.cose", claiming_record())]);
    let endpoint = format!("http://{addr}/");
    let (code, json) = cli(&[
        "handle",
        "resolve",
        "--handle",
        "alice@example.com",
        "--policy",
        "development",
        "--endpoint",
        &endpoint,
        "--now-ms",
        NOW,
    ]);
    assert_eq!(code, 0, "{json}");
    assert_eq!(json["discovery"]["status"], "discovered");
    assert_eq!(json["discovery"]["did"], alice_did().as_str());
    assert_eq!(
        json["discovery"]["subject"],
        Value::Null,
        "no invented fields"
    );
    assert_eq!(json["discovery"]["resource"], "acct:alice@example.com");
    assert_eq!(json["bootstrap"]["winner"]["authority"], "root");
    assert_eq!(json["bootstrap"]["winner"]["freshness"], "fresh");
    assert_eq!(json["bootstrap"]["candidates"][0]["status"], "verified");
    // Discovery is a mapping claim; the output nowhere labels the handle
    // itself as verified.
    assert!(json.get("handleVerified").is_none());
}

#[test]
fn handle_resolve_reports_mapping_faults_symbolically() {
    let (addr, _authority) = start_authority(&demo_config(), &[("alice.cose", claiming_record())]);
    let endpoint = format!("http://{addr}/");
    let (code, json) = cli(&[
        "handle",
        "resolve",
        "--handle",
        "nobody@example.com",
        "--policy",
        "development",
        "--endpoint",
        &endpoint,
        "--now-ms",
        NOW,
    ]);
    assert_eq!(code, 1);
    assert_eq!(json["error"]["symbol"], "handleNotFound");

    // The endpoint override is a development facility only.
    let (code, json) = cli(&[
        "handle",
        "resolve",
        "--handle",
        "alice@example.com",
        "--endpoint",
        &endpoint,
    ]);
    assert_eq!(code, 1);
    assert_eq!(json["error"]["symbol"], "endpointOverridePolicy");

    // An invalid handle never reaches the network.
    let (code, json) = cli(&["handle", "resolve", "--handle", "not a handle"]);
    assert_eq!(code, 1);
    assert_eq!(json["error"]["symbol"], "invalidHandle");
}

#[test]
fn handle_verify_binds_both_directions_from_a_record_file() {
    let (addr, _authority) = start_authority(&demo_config(), &[("alice.cose", claiming_record())]);
    let endpoint = format!("http://{addr}/");
    let dir = tempfile::tempdir().expect("tempdir");
    let record_path = dir.path().join("alice.cose");
    std::fs::write(&record_path, claiming_record()).expect("record written");

    let (code, json) = cli(&[
        "handle",
        "verify",
        "--handle",
        "alice@example.com",
        "--did",
        alice_did().as_str(),
        "--record",
        record_path.to_str().expect("utf-8"),
        "--policy",
        "development",
        "--endpoint",
        &endpoint,
        "--now-ms",
        NOW,
    ]);
    assert_eq!(code, 0, "{json}");
    assert_eq!(json["handleVerified"], true);
    assert_eq!(json["claim"]["present"], true);
    assert_eq!(json["inverse"]["status"], "matched");
    assert_eq!(json["record"]["source"], "file");
}

#[test]
fn handle_verify_requires_exactly_one_record_source() {
    // Neither source.
    let (code, json) = cli(&[
        "handle",
        "verify",
        "--handle",
        "alice@example.com",
        "--did",
        alice_did().as_str(),
    ]);
    assert_eq!(code, 2, "usage error");
    assert_eq!(json["error"]["symbol"], "usage");
    // Both sources at once are equally a usage error.
    let (code, json) = cli(&[
        "handle",
        "verify",
        "--handle",
        "alice@example.com",
        "--did",
        alice_did().as_str(),
        "--record",
        "somewhere.cose",
        "--relay",
        "http://127.0.0.1:9999/",
    ]);
    assert_eq!(code, 2, "usage error");
    assert_eq!(json["error"]["symbol"], "usage");
}

#[test]
fn handle_resolve_no_bootstrap_skips_record_fetches() {
    let (addr, _authority) = start_authority(&demo_config(), &[("alice.cose", claiming_record())]);
    let endpoint = format!("http://{addr}/");
    let (code, json) = cli(&[
        "handle",
        "resolve",
        "--handle",
        "alice@example.com",
        "--policy",
        "development",
        "--endpoint",
        &endpoint,
        "--no-bootstrap",
        "--now-ms",
        NOW,
    ]);
    assert_eq!(code, 0, "{json}");
    assert_eq!(json["discovery"]["did"], alice_did().as_str());
    assert!(
        json.get("bootstrap").is_none(),
        "--no-bootstrap fetches and reports nothing"
    );
    assert!(json.get("migration").is_none());
}

#[test]
fn handle_resolve_reports_migration_claims_as_not_checked() {
    // The bootstrap winner carries a migration claim: handle resolve
    // reports it as a deferred claim only (no relays are contacted).
    let record = alice_record_with_contact(
        RELAY_NOW_MS - 1_000,
        None,
        contact_with_migration(None, Some(&bob_did())),
    );
    let (addr, _authority) = start_authority(&demo_config(), &[("alice.cose", record)]);
    let endpoint = format!("http://{addr}/");
    let (code, json) = cli(&[
        "handle",
        "resolve",
        "--handle",
        "alice@example.com",
        "--policy",
        "development",
        "--endpoint",
        &endpoint,
        "--now-ms",
        NOW,
    ]);
    assert_eq!(code, 0, "{json}");
    assert_eq!(json["bootstrap"]["authorityState"], "root");
    let claims = json["migration"].as_array().expect("claims");
    assert_eq!(claims.len(), 1);
    assert_eq!(claims[0]["direction"], "successor");
    assert_eq!(claims[0]["counterpart"], bob_did().as_str());
    assert_eq!(claims[0]["state"], "notChecked");
    assert_eq!(claims[0]["reason"], "deferred");
    assert_eq!(claims[0]["presentable"], false);
}

#[test]
fn handle_resolve_budget_admits_a_near_cap_bootstrap_record() {
    // A record close to the 16 KiB envelope cap passes through the
    // handle-command budget: the budget is head-room, not a hidden cap.
    let mut pad = 13 * 1024;
    let (did, envelope) = loop {
        let (did, envelope) = synthetic_identity_record(42, pad);
        if envelope.len() >= 14 * 1024 {
            break (did, envelope);
        }
        pad += 1024;
    };
    let config = format!(
        r#"{{"version":1,"domain":"example.com","handles":[
            {{"local":"big","did":"{did}","record":"big.cose"}}
        ]}}"#
    );
    let (addr, _authority) = start_authority(&config, &[("big.cose", envelope)]);
    let endpoint = format!("http://{addr}/");
    let (code, json) = cli(&[
        "handle",
        "resolve",
        "--handle",
        "big@example.com",
        "--policy",
        "development",
        "--endpoint",
        &endpoint,
        "--now-ms",
        "1785589200124",
    ]);
    assert_eq!(code, 0, "{json}");
    assert_eq!(json["bootstrap"]["candidates"][0]["status"], "verified");
    assert_eq!(json["bootstrap"]["winner"]["authority"], "root");
    assert_eq!(json["bootstrap"]["authorityState"], "root");
}

#[test]
fn handle_verify_deadline_is_the_operation_deadline() {
    // With a zero deadline the resolver-supplied record source exhausts
    // the shared operation budget before any request; the default
    // deadline succeeds against the same relay.
    let t = memory_relay();
    let record = claiming_record();
    assert_eq!(
        publish_outcome(&t.relay.publish(&record).expect("publish")).0,
        0
    );
    let addr = start_relay_server(&t);
    let relay = format!("http://{addr}/");
    let (authority_addr, _authority) =
        start_authority(&demo_config(), &[("alice.cose", claiming_record())]);
    let endpoint = format!("http://{authority_addr}/");

    let base_args = |deadline: &'static str| {
        vec![
            "handle".to_owned(),
            "verify".to_owned(),
            "--handle".to_owned(),
            "alice@example.com".to_owned(),
            "--did".to_owned(),
            alice_did().as_str().to_owned(),
            "--relay".to_owned(),
            relay.clone(),
            "--policy".to_owned(),
            "development".to_owned(),
            "--endpoint".to_owned(),
            endpoint.clone(),
            "--now-ms".to_owned(),
            NOW.to_owned(),
            "--deadline-ms".to_owned(),
            deadline.to_owned(),
        ]
    };
    let run_owned = |args: Vec<String>| {
        let rng = followee::random::DeterministicRandom::from_seed(7);
        let clock = followee::clock::ManualClock::new(RELAY_NOW_MS);
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = run(&args, &rng, &clock, &mut stdout, &mut stderr);
        let text = String::from_utf8(stdout).expect("stdout UTF-8");
        let json: Value =
            serde_json::from_str(text.lines().next().unwrap_or("null")).unwrap_or(Value::Null);
        (code, json)
    };
    let (code, json) = run_owned(base_args("0"));
    assert_eq!(code, 1, "{json}");
    assert_eq!(json["error"]["symbol"], "temporarilyUnavailable");
    let (code, json) = run_owned(base_args("10000"));
    assert_eq!(code, 0, "{json}");
    assert_eq!(json["handleVerified"], true);
    assert_eq!(json["record"]["source"], "resolver");
}

#[test]
fn handle_verify_reports_unverified_directions_distinctly() {
    // The authority maps alice to Bob's DID (reassignment): inverse
    // mismatch, exit 1, complete detail.
    let reassigned = format!(
        r#"{{"version":1,"domain":"example.com","handles":[
            {{"local":"alice","did":"{bob}"}}
        ]}}"#,
        bob = bob_did().as_str()
    );
    let (addr, _authority) = start_authority(&reassigned, &[]);
    let endpoint = format!("http://{addr}/");
    let dir = tempfile::tempdir().expect("tempdir");
    let record_path = dir.path().join("alice.cose");
    std::fs::write(&record_path, claiming_record()).expect("record written");

    let (code, json) = cli(&[
        "handle",
        "verify",
        "--handle",
        "alice@example.com",
        "--did",
        alice_did().as_str(),
        "--record",
        record_path.to_str().expect("utf-8"),
        "--policy",
        "development",
        "--endpoint",
        &endpoint,
        "--now-ms",
        NOW,
    ]);
    assert_eq!(code, 1);
    assert_eq!(json["error"]["symbol"], "handleUnverified");
    let detail = &json["handleVerification"];
    assert_eq!(detail["claim"]["present"], true);
    assert_eq!(detail["inverse"]["status"], "mismatched");
    assert_eq!(detail["inverse"]["did"], bob_did().as_str());
    assert_eq!(detail["handleVerified"], false);
}

#[test]
fn handle_events_never_mutate_the_state_file_identity() {
    // Seed a state file with alice's cached record and sticky state
    // through an ordinary bootstrap.
    let (addr, _authority) = start_authority(&demo_config(), &[("alice.cose", claiming_record())]);
    let endpoint = format!("http://{addr}/");
    let dir = tempfile::tempdir().expect("tempdir");
    let state_path = dir.path().join("state.json");
    let state_arg = state_path.to_str().expect("utf-8").to_owned();
    let (code, _) = cli(&[
        "handle",
        "resolve",
        "--handle",
        "alice@example.com",
        "--policy",
        "development",
        "--endpoint",
        &endpoint,
        "--state",
        &state_arg,
        "--now-ms",
        NOW,
    ]);
    assert_eq!(code, 0);
    let seeded: Value =
        serde_json::from_str(&std::fs::read_to_string(&state_path).expect("state written"))
            .expect("state JSON");
    let cached = seeded["dids"][alice_did().as_str()]["cachedEnvelopeHex"]
        .as_str()
        .expect("cached envelope")
        .to_owned();
    assert_eq!(
        seeded["dids"][alice_did().as_str()]["authorityState"],
        "root",
        "a Root bootstrap winner never fabricates sticky revocation"
    );

    // The handle then disappears (a fresh authority without it).
    let empty = r#"{"version":1,"domain":"example.com","handles":[]}"#;
    let (addr2, _authority2) = start_authority(empty, &[]);
    let endpoint2 = format!("http://{addr2}/");
    let (code, json) = cli(&[
        "handle",
        "resolve",
        "--handle",
        "alice@example.com",
        "--policy",
        "development",
        "--endpoint",
        &endpoint2,
        "--state",
        &state_arg,
        "--now-ms",
        NOW,
    ]);
    assert_eq!(code, 1);
    assert_eq!(json["error"]["symbol"], "handleNotFound");
    let after: Value =
        serde_json::from_str(&std::fs::read_to_string(&state_path).expect("state present"))
            .expect("state JSON");
    assert_eq!(
        after["dids"][alice_did().as_str()]["cachedEnvelopeHex"]
            .as_str()
            .expect("still cached"),
        cached,
        "disappearance changed no cached identity"
    );

    // The handle is then reassigned to Bob's DID: alice's entry is still
    // untouched; bob gains no entry merely from a mapping.
    let reassigned = format!(
        r#"{{"version":1,"domain":"example.com","handles":[
            {{"local":"alice","did":"{bob}"}}
        ]}}"#,
        bob = bob_did().as_str()
    );
    let (addr3, _authority3) = start_authority(&reassigned, &[]);
    let endpoint3 = format!("http://{addr3}/");
    let (code, json) = cli(&[
        "handle",
        "resolve",
        "--handle",
        "alice@example.com",
        "--policy",
        "development",
        "--endpoint",
        &endpoint3,
        "--state",
        &state_arg,
        "--now-ms",
        NOW,
    ]);
    assert_eq!(code, 0, "{json}");
    assert_eq!(
        json["discovery"]["did"],
        bob_did().as_str(),
        "the domain now claims Bob for this handle"
    );
    let after: Value =
        serde_json::from_str(&std::fs::read_to_string(&state_path).expect("state present"))
            .expect("state JSON");
    assert_eq!(
        after["dids"][alice_did().as_str()]["cachedEnvelopeHex"]
            .as_str()
            .expect("still cached"),
        cached,
        "reassignment changed no cached identity for the followed DID"
    );
    assert!(
        after["dids"][bob_did().as_str()].is_null(),
        "a bare mapping claim creates no verified state for Bob"
    );
}

#[test]
fn handle_serve_check_gates_deployment_on_handle_claims() {
    let dir = tempfile::tempdir().expect("tempdir");
    // Consistent: the record claims the exact served handle.
    std::fs::write(dir.path().join("alice.cose"), claiming_record()).expect("record");
    let good = dir.path().join("good.json");
    std::fs::write(
        &good,
        format!(
            r#"{{"version":1,"domain":"example.com","handles":[
                {{"local":"alice","did":"{alice}","record":"alice.cose"}}
            ]}}"#,
            alice = alice_did().as_str()
        ),
    )
    .expect("config");
    let (code, json) = cli(&[
        "handle",
        "serve",
        "--config",
        good.to_str().expect("utf-8"),
        "--check",
    ]);
    assert_eq!(code, 0, "{json}");
    assert_eq!(json["consistent"], true);
    assert_eq!(json["entries"][0]["claimed"], "acct:alice@example.com");

    // Inconsistent: same record, different domain — changing the
    // configuration never changes the signed claim.
    let bad = dir.path().join("bad.json");
    std::fs::write(
        &bad,
        format!(
            r#"{{"version":1,"domain":"moved.example","handles":[
                {{"local":"alice","did":"{alice}","record":"alice.cose"}}
            ]}}"#,
            alice = alice_did().as_str()
        ),
    )
    .expect("config");
    let (code, json) = cli(&[
        "handle",
        "serve",
        "--config",
        bad.to_str().expect("utf-8"),
        "--check",
    ]);
    assert_eq!(code, 1);
    assert_eq!(json["error"]["symbol"], "deploymentInconsistent");
    assert_eq!(json["consistency"]["consistent"], false);
    assert_eq!(
        json["consistency"]["entries"][0]["resource"],
        "acct:alice@moved.example"
    );
    assert_eq!(json["consistency"]["entries"][0]["recordVerified"], true);
}

#[test]
fn handle_resolve_persists_a_learned_root_revoked_transition() {
    let revoked = alice_revoked_record(RELAY_NOW_MS - 1_000);
    let (addr, _authority) = start_authority(&demo_config(), &[("alice.cose", revoked)]);
    let endpoint = format!("http://{addr}/");
    let dir = tempfile::tempdir().expect("tempdir");
    let state_path = dir.path().join("state.json");
    let (code, json) = cli(&[
        "handle",
        "resolve",
        "--handle",
        "alice@example.com",
        "--policy",
        "development",
        "--endpoint",
        &endpoint,
        "--state",
        state_path.to_str().expect("utf-8"),
        "--now-ms",
        NOW,
    ]);
    assert_eq!(code, 0, "{json}");
    assert_eq!(json["bootstrap"]["authorityState"], "rootRevoked");
    let state: Value =
        serde_json::from_str(&std::fs::read_to_string(&state_path).expect("state written"))
            .expect("state JSON");
    assert_eq!(
        state["dids"][alice_did().as_str()]["authorityState"],
        "rootRevoked",
        "the irreversible transition is retained sticky state"
    );
}

#[test]
fn resolve_check_migration_reports_the_three_states_end_to_end() {
    // A real loopback relay carrying reciprocal fresh records.
    let t = memory_relay();
    let alice = alice_record_with_contact(
        RELAY_NOW_MS - 1_000,
        None,
        contact_with_migration(None, Some(&bob_did())),
    );
    let bob = bob_record_with_contact(
        RELAY_NOW_MS - 1_000,
        None,
        contact_with_migration(Some(&alice_did()), None),
    );
    assert_eq!(
        publish_outcome(&t.relay.publish(&alice).expect("publish")).0,
        0
    );
    assert_eq!(
        publish_outcome(&t.relay.publish(&bob).expect("publish")).0,
        0
    );
    let addr = start_relay_server(&t);
    let base = format!("http://{addr}/");

    let (code, json) = cli(&[
        "resolve",
        "--did",
        alice_did().as_str(),
        "--relay",
        &base,
        "--policy",
        "development",
        "--now-ms",
        NOW,
        "--check-migration",
    ]);
    assert_eq!(code, 0, "{json}");
    assert_eq!(json["outcome"], "found");
    let checks = json["migration"].as_array().expect("migration checks");
    assert_eq!(checks.len(), 1);
    assert_eq!(checks[0]["direction"], "successor");
    assert_eq!(checks[0]["counterpart"], bob_did().as_str());
    assert_eq!(checks[0]["state"], "verified");
    assert_eq!(checks[0]["presentable"], true);
    assert_eq!(checks[0]["counterpartResolution"]["outcome"], "found");

    // Without the flag, no migration key exists (and nothing is checked).
    let (code, json) = cli(&[
        "resolve",
        "--did",
        alice_did().as_str(),
        "--relay",
        &base,
        "--policy",
        "development",
        "--now-ms",
        NOW,
    ]);
    assert_eq!(code, 0);
    assert!(json.get("migration").is_none());

    // A one-way claim: replace Bob's record with a non-reciprocating one.
    let bob_plain = bob_record_with_contact(RELAY_NOW_MS, None, contact_claiming(&[]));
    assert_eq!(
        publish_outcome(&t.relay.publish(&bob_plain).expect("publish")).0,
        0
    );
    let (code, json) = cli(&[
        "resolve",
        "--did",
        alice_did().as_str(),
        "--relay",
        &base,
        "--policy",
        "development",
        "--now-ms",
        NOW,
        "--check-migration",
    ]);
    assert_eq!(code, 0);
    let checks = json["migration"].as_array().expect("migration checks");
    assert_eq!(checks[0]["state"], "checkedButUnverified");
    assert_eq!(checks[0]["reason"], "nonReciprocal");
    assert_eq!(checks[0]["presentable"], false);
}
