//! Shell-level black-box tests for the `followee handle` commands
//! (IMPLEMENTATION.md section 13 Milestone 5): real binary, real
//! configuration files, real loopback sockets on port 0, the startup-JSON
//! contract, clean SIGTERM shutdown, development-mode loopback guard, and
//! the resolve/verify flows through the spawned binary.
#![cfg(unix)]
#![allow(clippy::arithmetic_side_effects)]

mod common;

use common::*;
use serde_json::Value;
use std::io::{BufRead, BufReader, Read};
use std::path::Path;
use std::process::{Child, Command, Stdio};

const NOW: &str = "1785589201123";

struct ServeInstance {
    child: Child,
    startup: Value,
    stdout: BufReader<std::process::ChildStdout>,
}

fn start_serve(config: &Path, extra: &[&str]) -> ServeInstance {
    let mut args = vec![
        "handle",
        "serve",
        "--config",
        config.to_str().expect("UTF-8 path"),
        "--listen",
        "127.0.0.1:0",
    ];
    args.extend_from_slice(extra);
    let mut child = Command::new(env!("CARGO_BIN_EXE_followee"))
        .args(&args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("binary starts");
    let mut stdout = BufReader::new(child.stdout.take().expect("stdout piped"));
    let mut line = String::new();
    stdout
        .read_line(&mut line)
        .expect("startup object readable");
    let startup: Value = serde_json::from_str(&line).expect("startup line is one JSON object");
    ServeInstance {
        child,
        startup,
        stdout,
    }
}

impl ServeInstance {
    fn stop_cleanly(mut self) {
        let pid = self.child.id().to_string();
        let status = Command::new("kill")
            .args(["-TERM", &pid])
            .status()
            .expect("kill runs");
        assert!(status.success(), "SIGTERM delivered");
        let exit = self.child.wait().expect("process exits");
        assert_eq!(exit.code(), Some(0), "graceful shutdown exits zero");
        let mut rest = String::new();
        self.stdout
            .read_to_string(&mut rest)
            .expect("stdout drains");
        assert!(
            rest.is_empty(),
            "stdout carried nothing after the startup object: {rest:?}"
        );
    }
}

fn run_cli(args: &[&str]) -> (i32, Value) {
    let output = Command::new(env!("CARGO_BIN_EXE_followee"))
        .args(args)
        .output()
        .expect("binary runs");
    let text = String::from_utf8(output.stdout).expect("stdout UTF-8");
    let json = serde_json::from_str(text.lines().next().unwrap_or("null")).unwrap_or(Value::Null);
    (output.status.code().expect("exit code"), json)
}

fn write_demo(dir: &Path) -> std::path::PathBuf {
    let record = alice_record_with_contact(
        RELAY_NOW_MS - 1_000,
        None,
        contact_claiming(&["acct:alice@example.com"]),
    );
    std::fs::write(dir.join("alice.cose"), &record).expect("record written");
    let config = dir.join("authority.json");
    std::fs::write(
        &config,
        format!(
            r#"{{"version":1,"domain":"example.com","handles":[
                {{"local":"alice","did":"{alice}","aliases":["Alice"],"record":"alice.cose"}}
            ]}}"#,
            alice = alice_did().as_str()
        ),
    )
    .expect("config written");
    config
}

#[test]
fn handle_serve_startup_contract_and_full_flow_through_the_binary() {
    let dir = tempfile::tempdir().expect("tempdir");
    let config = write_demo(dir.path());
    let serve = start_serve(&config, &[]);

    // Startup-object contract.
    let listen = serve.startup["listen"].as_str().expect("listen").to_owned();
    assert!(listen.starts_with("127.0.0.1:"), "loopback by default");
    assert_ne!(listen, "127.0.0.1:0", "the assigned port is reported");
    assert_eq!(serve.startup["developmentMode"], true);
    assert_eq!(serve.startup["domain"], "example.com");
    assert_eq!(serve.startup["handles"], 2);
    assert_eq!(serve.startup["records"], 2);
    let endpoint = format!("http://{listen}/");

    // handle resolve through the spawned binary.
    let (code, json) = run_cli(&[
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
    assert_eq!(json["discovery"]["did"], alice_did().as_str());
    assert_eq!(json["bootstrap"]["winner"]["authority"], "root");

    // handle verify through the spawned binary, record from disk.
    let record_path = dir.path().join("alice.cose");
    let (code, json) = run_cli(&[
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

    // An unlisted case variant is not resolvable.
    let (code, json) = run_cli(&[
        "handle",
        "resolve",
        "--handle",
        "ALICE@example.com",
        "--policy",
        "development",
        "--endpoint",
        &endpoint,
        "--now-ms",
        NOW,
    ]);
    assert_eq!(code, 1);
    assert_eq!(json["error"]["symbol"], "handleNotFound");

    serve.stop_cleanly();
}

#[test]
fn handle_serve_restart_reports_identical_configuration_state() {
    let dir = tempfile::tempdir().expect("tempdir");
    let config = write_demo(dir.path());
    let first = start_serve(&config, &[]);
    let first_startup = first.startup.clone();
    first.stop_cleanly();
    let second = start_serve(&config, &[]);
    for field in ["domain", "handles", "records", "developmentMode"] {
        assert_eq!(
            first_startup[field], second.startup[field],
            "{field} is deterministic across restart"
        );
    }
    second.stop_cleanly();
}

#[test]
fn handle_serve_refuses_an_invalid_configuration() {
    let dir = tempfile::tempdir().expect("tempdir");
    let config = dir.path().join("authority.json");
    // Case variants assigned to different DIDs: refused at load.
    std::fs::write(
        &config,
        format!(
            r#"{{"version":1,"domain":"example.com","handles":[
                {{"local":"alice","did":"{alice}"}},
                {{"local":"Alice","did":"{bob}"}}
            ]}}"#,
            alice = alice_did().as_str(),
            bob = bob_did().as_str()
        ),
    )
    .expect("config written");
    let (code, stdout) = run_expecting_exit(&[
        "handle",
        "serve",
        "--config",
        config.to_str().expect("utf-8"),
        "--listen",
        "127.0.0.1:0",
    ]);
    assert_eq!(code, Some(1));
    let json: Value =
        serde_json::from_str(stdout.lines().next().unwrap_or("null")).expect("error object");
    assert_eq!(json["error"]["symbol"], "authorityConfig");
}

/// Runs the binary expecting it to exit on its own within a bounded
/// wait. If it is still running — for example because a guard that must
/// refuse startup failed to fire — it is killed and `None` is returned,
/// so a broken guard fails the assertion instead of hanging the suite.
fn run_expecting_exit(args: &[&str]) -> (Option<i32>, String) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_followee"))
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("binary starts");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let code = loop {
        match child.try_wait().expect("wait works") {
            Some(status) => break status.code(),
            None if std::time::Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
            None => std::thread::sleep(std::time::Duration::from_millis(50)),
        }
    };
    let mut stdout = String::new();
    if let Some(mut pipe) = child.stdout.take() {
        let _ = pipe.read_to_string(&mut stdout);
    }
    (code, stdout)
}

#[test]
fn handle_serve_development_mode_refuses_non_loopback_binding() {
    let dir = tempfile::tempdir().expect("tempdir");
    let config = write_demo(dir.path());
    let (code, _) = run_expecting_exit(&[
        "handle",
        "serve",
        "--config",
        config.to_str().expect("utf-8"),
        "--listen",
        "0.0.0.0:0",
    ]);
    assert_eq!(
        code,
        Some(1),
        "development mode must not bind a public interface"
    );
}
