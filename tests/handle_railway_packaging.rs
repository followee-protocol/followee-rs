//! Railway packaging check (IMPLEMENTATION.md section 13 Milestone 5):
//! the shipped container entrypoint (`demo/public-authority/railway/`)
//! runs the production `followee handle serve` path with the reviewed
//! public configuration, honours an injected `PORT`, derives the public
//! base URI only from operator/provider configuration (never a request
//! header), starts successfully, serves the tested JRD semantics over a
//! real socket, and shuts down cleanly on SIGTERM — everything the
//! deployed image does except TLS termination, which Railway provides.
//!
//! The container image itself is not built here (a container runtime is
//! not assumed in every test environment); the Dockerfile copies exactly
//! the files this test exercises into the same `/app` layout, and its
//! external base images are asserted digest-pinned below.
#![cfg(unix)]
#![allow(clippy::arithmetic_side_effects)]

mod common;

use common::*;
use followee::clock::ManualClock;
use followee::relay::client::{BudgetMeter, HttpTransport, NetworkPolicy, OperationBudget};
use followee::webfinger::{Handle, WebFingerClient};
use serde_json::Value;
use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

/// The bootstrapped Railway public artifact facts (kept in lockstep with
/// `handle_deploy_artifact.rs`).
const RAILWAY_DOMAIN: &str = "handle-authority-production.up.railway.app";
const RAILWAY_BASE: &str = "https://handle-authority-production.up.railway.app/";
const RAILWAY_DID: &str = "did:flw:zQmV2sbfh2M5kHBAa9G1svAdh54bZqGKLUE3YJpBHj8qb4R";

fn artifact_dir() -> &'static Path {
    Path::new(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/demo/public-authority"
    ))
}

/// Recreates the image's `/app` layout in a temp directory and returns
/// (app_dir, PATH prepend dir containing the production binary as
/// `followee`), mirroring the Dockerfile COPY steps exactly.
fn stage_app(dir: &Path) -> (PathBuf, PathBuf) {
    let app = dir.join("app");
    std::fs::create_dir(&app).expect("app dir");
    std::fs::copy(
        artifact_dir().join("railway/authority.json"),
        app.join("authority.json"),
    )
    .expect("config staged");
    std::fs::copy(
        artifact_dir().join("railway/demo.cose"),
        app.join("demo.cose"),
    )
    .expect("record staged");
    let bin = dir.join("bin");
    std::fs::create_dir(&bin).expect("bin dir");
    std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_followee"), bin.join("followee"))
        .expect("binary linked");
    (app, bin)
}

fn spawn_entrypoint(app: &Path, bin: &Path, env: &[(&str, &str)]) -> Child {
    let path = format!(
        "{}:{}",
        bin.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let mut command = Command::new("sh");
    command
        .arg(artifact_dir().join("railway/entrypoint.sh"))
        .env_remove("PORT")
        .env_remove("FOLLOWEE_BASE_URI")
        .env_remove("RAILWAY_PUBLIC_DOMAIN")
        .env("PATH", path)
        .env("FOLLOWEE_CONFIG", app.join("authority.json"))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (name, value) in env {
        command.env(name, value);
    }
    command.spawn().expect("entrypoint starts")
}

#[test]
fn railway_entrypoint_serves_the_production_authority_on_the_injected_port() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (app, bin) = stage_app(dir.path());
    // PORT=0 proves the injected port is honoured verbatim: the startup
    // object must report the operating-system assignment on 0.0.0.0.
    let mut child = spawn_entrypoint(
        &app,
        &bin,
        &[("PORT", "0"), ("FOLLOWEE_BASE_URI", RAILWAY_BASE)],
    );
    let mut stdout = BufReader::new(child.stdout.take().expect("stdout piped"));
    let mut line = String::new();
    stdout.read_line(&mut line).expect("startup line");
    let startup: Value = serde_json::from_str(&line).expect("startup is one JSON object");

    let listen = startup["listen"].as_str().expect("listen");
    assert!(
        listen.starts_with("0.0.0.0:"),
        "binds all interfaces: {listen}"
    );
    let port: u16 = listen
        .rsplit(':')
        .next()
        .expect("port")
        .parse()
        .expect("numeric port");
    assert_ne!(port, 0, "the assigned port is reported");
    assert_eq!(startup["baseUri"], RAILWAY_BASE);
    assert_eq!(
        startup["developmentMode"], false,
        "an HTTPS base URI is conforming mode behind provider TLS"
    );
    assert_eq!(startup["domain"], RAILWAY_DOMAIN);

    // The tested JRD semantics through the production WebFinger client
    // over a real socket — the same probe the deployed domain receives.
    let endpoint = format!("http://127.0.0.1:{port}/");
    let transport = HttpTransport;
    let clock = ManualClock::new(RELAY_NOW_MS);
    let client = WebFingerClient::new(&transport, NetworkPolicy::Development, &clock);
    let mut meter = BudgetMeter::new(OperationBudget {
        deadline_ms: None,
        max_response_bytes: 1024 * 1024,
        max_requests: 16,
    });
    let handle = Handle::parse(&format!("demo@{RAILWAY_DOMAIN}")).expect("parses");
    let discovery = client
        .lookup(&handle, Some(&endpoint), &mut meter)
        .expect("discovers");
    assert_eq!(discovery.did.as_str(), RAILWAY_DID);
    assert_eq!(discovery.resource, format!("acct:demo@{RAILWAY_DOMAIN}"));
    assert_eq!(discovery.record_links.len(), 1);
    // Bootstrap record links advertise the configured public base, never
    // anything derived from this request.
    assert!(
        discovery.record_links[0].starts_with(RAILWAY_BASE),
        "{}",
        discovery.record_links[0]
    );
    let unknown = Handle::parse(&format!("nobody@{RAILWAY_DOMAIN}")).expect("parses");
    assert!(
        client
            .lookup(&unknown, Some(&endpoint), &mut meter)
            .is_err()
    );

    // Clean SIGTERM shutdown: the entrypoint exec'd the binary as the
    // process itself, so Railway's signal reaches it directly.
    let pid = child.id().to_string();
    assert!(
        Command::new("kill")
            .args(["-TERM", &pid])
            .status()
            .expect("kill runs")
            .success()
    );
    let exit = child.wait().expect("process exits");
    assert_eq!(exit.code(), Some(0), "graceful shutdown exits zero");
    let mut rest = String::new();
    stdout.read_to_string(&mut rest).expect("stdout drains");
    assert!(
        rest.is_empty(),
        "startup object is the only stdout: {rest:?}"
    );
}

#[test]
fn railway_entrypoint_derives_the_base_uri_from_the_provider_domain() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (app, bin) = stage_app(dir.path());
    let mut child = spawn_entrypoint(
        &app,
        &bin,
        &[("PORT", "0"), ("RAILWAY_PUBLIC_DOMAIN", RAILWAY_DOMAIN)],
    );
    let mut stdout = BufReader::new(child.stdout.take().expect("stdout piped"));
    let mut line = String::new();
    stdout.read_line(&mut line).expect("startup line");
    let startup: Value = serde_json::from_str(&line).expect("startup is one JSON object");
    assert_eq!(
        startup["baseUri"], RAILWAY_BASE,
        "the base URI derives from the provider-assigned domain variable"
    );
    let _ = Command::new("kill")
        .args(["-TERM", &child.id().to_string()])
        .status();
    assert_eq!(child.wait().expect("exits").code(), Some(0));
}

#[test]
fn railway_entrypoint_refuses_to_start_without_a_public_base() {
    // Without explicit operator configuration or the provider domain the
    // entrypoint must fail fast rather than advertise a guessed base.
    let dir = tempfile::tempdir().expect("tempdir");
    let (app, bin) = stage_app(dir.path());
    let mut child = spawn_entrypoint(&app, &bin, &[("PORT", "0")]);
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
    assert_eq!(code, Some(1), "missing base configuration is refused");
}

#[test]
fn railway_dockerfile_pins_every_external_base_image_by_digest() {
    // Immutable OCI manifest digests govern both stages; the readable
    // tag documents intent. A tag-only FROM would silently float.
    let dockerfile = std::fs::read_to_string(artifact_dir().join("railway/Dockerfile"))
        .expect("Dockerfile readable");
    let mut stage_aliases: Vec<String> = Vec::new();
    let mut external_froms = 0;
    for line in dockerfile.lines() {
        let line = line.trim();
        let Some(rest) = line.strip_prefix("FROM ") else {
            continue;
        };
        let mut parts = rest.split_whitespace();
        let reference = parts.next().expect("FROM has a reference");
        if let (Some("AS"), Some(alias)) = (parts.next(), parts.next()) {
            stage_aliases.push(alias.to_owned());
        }
        if stage_aliases[..stage_aliases.len().saturating_sub(1)]
            .iter()
            .any(|alias| alias == reference)
        {
            continue; // a prior build stage, not an external image
        }
        external_froms += 1;
        assert!(
            reference.starts_with("docker.io/library/"),
            "external FROM is fully qualified: {reference}"
        );
        let (name, digest) = reference
            .split_once("@sha256:")
            .unwrap_or_else(|| panic!("external FROM is digest-pinned: {reference}"));
        assert!(
            digest.len() == 64 && digest.bytes().all(|b| b.is_ascii_hexdigit()),
            "digest is 64 hex characters: {reference}"
        );
        assert!(
            name.rsplit('/').next().unwrap_or("").contains(':'),
            "the readable tag is retained beside the digest: {reference}"
        );
    }
    assert_eq!(
        external_froms, 2,
        "build and runtime stages are both pinned"
    );
}

#[test]
fn railway_entrypoint_honours_a_real_nonzero_injected_port() {
    // Reserve a concrete free port the way Railway supplies one, then
    // require the startup object to report exactly that port and the
    // authority to answer on it.
    let reserved = std::net::TcpListener::bind("127.0.0.1:0").expect("reserve port");
    let port = reserved.local_addr().expect("addr").port();
    drop(reserved);

    let dir = tempfile::tempdir().expect("tempdir");
    let (app, bin) = stage_app(dir.path());
    let port_text = port.to_string();
    let mut child = spawn_entrypoint(
        &app,
        &bin,
        &[
            ("PORT", port_text.as_str()),
            ("FOLLOWEE_BASE_URI", RAILWAY_BASE),
        ],
    );
    let mut stdout = BufReader::new(child.stdout.take().expect("stdout piped"));
    let mut line = String::new();
    stdout.read_line(&mut line).expect("startup line");
    let startup: Value = serde_json::from_str(&line).expect("startup is one JSON object");
    assert_eq!(
        startup["listen"],
        format!("0.0.0.0:{port}"),
        "the injected port is bound and reported exactly"
    );

    let endpoint = format!("http://127.0.0.1:{port}/");
    let transport = HttpTransport;
    let clock = ManualClock::new(RELAY_NOW_MS);
    let client = WebFingerClient::new(&transport, NetworkPolicy::Development, &clock);
    let mut meter = BudgetMeter::new(OperationBudget {
        deadline_ms: None,
        max_response_bytes: 1024 * 1024,
        max_requests: 16,
    });
    let handle = Handle::parse(&format!("demo@{RAILWAY_DOMAIN}")).expect("parses");
    let discovery = client
        .lookup(&handle, Some(&endpoint), &mut meter)
        .expect("reachable on the injected port");
    assert_eq!(discovery.did.as_str(), RAILWAY_DID);

    let pid = child.id().to_string();
    assert!(
        Command::new("kill")
            .args(["-TERM", &pid])
            .status()
            .expect("kill runs")
            .success()
    );
    assert_eq!(
        child.wait().expect("exits").code(),
        Some(0),
        "SIGTERM still exits cleanly on a concrete port"
    );
}
