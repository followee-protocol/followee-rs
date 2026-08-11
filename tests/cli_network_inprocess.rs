//! In-process tests for the network CLI handlers against a real loopback
//! relay server: exercises the production `HttpTransport` and the handler
//! JSON surfaces with sizes and error shapes the shell tests do not reach.
#![allow(clippy::arithmetic_side_effects)]

mod common;

use common::*;
use followee::cli::run;
use followee::clock::ManualClock;
use followee::random::DeterministicRandom;
use followee::relay::http::serve;
use serde_json::Value;
use std::net::SocketAddr;

fn start_server(t: &TestRelay) -> SocketAddr {
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

#[test]
fn relay_resolve_handles_large_records_and_renders_error_codes() {
    let t = memory_relay();
    // A record padded to roughly 14 KiB, near the envelope cap.
    let (did, envelope) = synthetic_identity_record(9001, 13 * 1024);
    let response = t.relay.publish(&envelope).expect("publish");
    assert_eq!(publish_outcome(&response).0, 0, "admitted");
    let addr = start_server(&t);
    let base = format!("http://{addr}/");

    let (code, json) = cli(&[
        "relay",
        "resolve",
        "--relay",
        &base,
        "--did",
        &did,
        "--did",
        "did:flw:not-a-multibase",
        "--policy",
        "development",
        "--now-ms",
        &RELAY_NOW_MS.to_string(),
    ]);
    assert_eq!(code, 0);
    let results = json["results"].as_array().expect("results");
    assert_eq!(results.len(), 2, "aligned results");
    assert_eq!(results[0]["kind"], "full");
    assert_eq!(results[0]["verified"], true);
    assert_eq!(
        results[0]["recordHex"].as_str().expect("hex"),
        hex::encode(&envelope),
        "the near-cap record round-trips through the CLI budget"
    );
    // The malformed DID at index 1 renders its exact wire code and symbol.
    assert_eq!(results[1]["kind"], "error");
    assert_eq!(results[1]["error"]["code"], 0);
    assert_eq!(results[1]["error"]["symbol"], "invalidDid");
}

#[test]
fn relay_sync_moves_a_large_page_between_real_processes() {
    // Seed a source relay with enough padded records that one changes page
    // is a few hundred kilobytes.
    let source = memory_relay();
    let mut dids = Vec::new();
    for index in 0..40 {
        let (did, envelope) = synthetic_identity_record(9100 + index, 4 * 1024);
        let response = source.relay.publish(&envelope).expect("publish");
        assert_eq!(publish_outcome(&response).0, 0, "admitted");
        dids.push(did);
    }
    let addr = start_server(&source);
    let base = format!("http://{addr}/");

    let dir = tempfile::tempdir().expect("tempdir");
    let db = dir.path().join("receiver.db");
    let (code, json) = cli(&[
        "relay",
        "sync",
        "--database",
        db.to_str().expect("path"),
        "--peer",
        &base,
        "--policy",
        "development",
        "--now-ms",
        &RELAY_NOW_MS.to_string(),
    ]);
    assert_eq!(code, 0, "{json}");
    assert_eq!(json["admitted"].as_array().expect("admitted").len(), 40);
    assert!(json["finalCursorHex"].is_string());
    assert_eq!(json["hasMore"], false);
}

#[test]
fn resolve_state_read_failures_are_reported_not_swallowed() {
    // A state file that exists but cannot be read (invalid UTF-8): the
    // handler must surface the I/O failure before any network operation.
    // Only NotFound means "no state yet"; a later state *save* to this
    // path would succeed, so this isolates the read-error guard.
    let dir = tempfile::tempdir().expect("tempdir");
    let state = dir.path().join("state.json");
    std::fs::write(&state, [0xFF, 0xFE, 0xFD]).expect("seed unreadable state");
    let (code, json) = cli(&[
        "resolve",
        "--did",
        "did:flw:zQmPcGstBa7wW9hoYQbS6JZ4UxwZmoKr7YVf9y7qxiyD3Cm",
        "--relay",
        "http://127.0.0.1:9/",
        "--policy",
        "development",
        "--state",
        state.to_str().expect("path"),
    ]);
    assert_eq!(code, 1);
    assert_eq!(json["error"]["symbol"], "io");
    assert_eq!(
        std::fs::read(&state).expect("still present"),
        vec![0xFF, 0xFE, 0xFD],
        "the unreadable state file was not overwritten"
    );
}

#[test]
fn resolve_deadline_flag_reaches_the_shared_budget() {
    // With --deadline-ms 0 the operation budget expires before any request:
    // the diagnostics show a budget stop, not a transport failure.
    let (code, json) = cli(&[
        "resolve",
        "--did",
        "did:flw:zQmPcGstBa7wW9hoYQbS6JZ4UxwZmoKr7YVf9y7qxiyD3Cm",
        "--relay",
        "http://127.0.0.1:9/",
        "--policy",
        "development",
        "--deadline-ms",
        "0",
    ]);
    assert_eq!(code, 1);
    assert_eq!(json["error"]["symbol"], "temporarilyUnavailable");
    let diagnostics = json["resolution"]["diagnostics"].as_array().expect("diags");
    assert_eq!(diagnostics[0]["event"], "budgetStopped");
}
