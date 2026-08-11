//! Shell-level failure-classification tests for the network commands: the
//! binary distinguishes protocol rejection from transport and local
//! infrastructure failure with stable symbols and the existing exit-code
//! conventions (0 success, 1 operation failure, 2 usage), and never emits
//! secret material.
#![cfg(unix)]

use serde_json::Value;
use std::process::Command;

fn run(args: &[&str]) -> (i32, Value, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_followee"))
        .args(args)
        .output()
        .expect("binary runs");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: Value =
        serde_json::from_str(stdout.lines().next().unwrap_or_default()).unwrap_or(Value::Null);
    (
        output.status.code().expect("exit code"),
        json,
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

#[test]
fn transport_failure_is_symbolically_distinct_from_protocol_rejection() {
    // A loopback port nothing listens on: infrastructure, not protocol.
    let (code, json, _) = run(&[
        "relay",
        "resolve",
        "--relay",
        "http://127.0.0.1:9/",
        "--did",
        "did:flw:zQmPcGstBa7wW9hoYQbS6JZ4UxwZmoKr7YVf9y7qxiyD3Cm",
        "--policy",
        "development",
        "--timeout-ms",
        "1500",
    ]);
    assert_eq!(code, 1);
    assert_eq!(json["error"]["symbol"], "transport");
}

#[test]
fn public_policy_refuses_loopback_and_plain_http_without_contacting_it() {
    let (code, json, _) = run(&[
        "relay",
        "changes",
        "--relay",
        "http://127.0.0.1:9/",
        // Default policy is public.
    ]);
    assert_eq!(code, 1);
    assert_eq!(json["error"]["symbol"], "networkPolicy");
}

#[test]
fn multi_relay_resolve_reports_temporarily_unavailable_with_the_full_result() {
    let (code, json, _) = run(&[
        "resolve",
        "--did",
        "did:flw:zQmPcGstBa7wW9hoYQbS6JZ4UxwZmoKr7YVf9y7qxiyD3Cm",
        "--relay",
        "http://127.0.0.1:9/",
        "--policy",
        "development",
        "--deadline-ms",
        "1500",
    ]);
    assert_eq!(code, 1);
    assert_eq!(json["error"]["symbol"], "temporarilyUnavailable");
    assert_eq!(json["resolution"]["outcome"], "temporarilyUnavailable");
    assert_eq!(json["resolution"]["relaysConsulted"], 1);
}

#[test]
fn malformed_target_did_is_a_protocol_classification() {
    let (code, json, _) = run(&[
        "resolve",
        "--did",
        "did:flw:not-a-multibase",
        "--relay",
        "http://127.0.0.1:9/",
        "--policy",
        "development",
    ]);
    assert_eq!(code, 1);
    assert_eq!(json["error"]["symbol"], "invalidDid");
}

#[test]
fn sync_usage_errors_exit_two() {
    let output = Command::new(env!("CARGO_BIN_EXE_followee"))
        .args(["relay", "sync", "--peer", "http://127.0.0.1:9/"])
        .output()
        .expect("binary runs");
    assert_eq!(output.status.code(), Some(2), "missing --database is usage");
}
