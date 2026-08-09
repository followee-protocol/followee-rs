//! Shell-level black-box test for the `followee relay serve` operator
//! command (IMPLEMENTATION.md section 13 Milestone 3): real binary, real
//! temporary SQLite database, real loopback socket on port 0, startup-JSON
//! contract, clean SIGTERM shutdown, and identity/generation persistence
//! across restart.
#![cfg(unix)]
#![allow(clippy::arithmetic_side_effects)]

use serde_json::Value;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::process::{Child, Command, Stdio};

struct ServeInstance {
    child: Child,
    startup: Value,
    stdout: BufReader<std::process::ChildStdout>,
}

fn start_serve(database: &Path) -> ServeInstance {
    let mut child = Command::new(env!("CARGO_BIN_EXE_followee"))
        .args([
            "relay",
            "serve",
            "--database",
            database.to_str().expect("UTF-8 path"),
            "--listen",
            "127.0.0.1:0",
        ])
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
    /// Sends SIGTERM and waits, asserting a clean exit and empty remaining
    /// stdout (the startup object is the only protocol-defined output).
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

/// Minimal raw HTTP GET over one socket.
fn http_get(addr: &str, path: &str) -> (u16, Vec<u8>) {
    let mut stream = TcpStream::connect(addr).expect("connect");
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
    )
    .expect("request written");
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).expect("response read");
    let header_end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("headers complete");
    let status: u16 = std::str::from_utf8(&raw[..header_end])
        .expect("ASCII headers")
        .split_whitespace()
        .nth(1)
        .expect("status code")
        .parse()
        .expect("numeric status");
    (status, raw[header_end + 4..].to_vec())
}

/// Reads the CBOR relay-info map far enough to extract the 16-byte byte
/// strings at labels 1 (relay id), 6 (cursor generation), and 7 (directory
/// generation). Test-side decoding, independent of the crate.
fn info_identity_fields(body: &[u8]) -> (String, String, String) {
    fn head(b: &[u8], pos: &mut usize) -> (u8, u64) {
        let ib = b[*pos];
        *pos += 1;
        let (major, ai) = (ib >> 5, ib & 0x1f);
        let arg = match ai {
            0..=23 => u64::from(ai),
            24 => {
                let v = u64::from(b[*pos]);
                *pos += 1;
                v
            }
            25 => {
                let v = u64::from(u16::from_be_bytes([b[*pos], b[*pos + 1]]));
                *pos += 2;
                v
            }
            26 => {
                let v = u64::from(u32::from_be_bytes(
                    b[*pos..*pos + 4].try_into().expect("four bytes"),
                ));
                *pos += 4;
                v
            }
            other => panic!("unexpected additional information {other}"),
        };
        (major, arg)
    }
    fn skip(b: &[u8], pos: &mut usize) {
        let (major, arg) = head(b, pos);
        match major {
            0 | 1 | 7 => {}
            2 | 3 => *pos += arg as usize,
            4 => (0..arg).for_each(|_| skip(b, pos)),
            5 => (0..arg).for_each(|_| {
                skip(b, pos);
                skip(b, pos);
            }),
            other => panic!("unexpected major {other}"),
        }
    }
    let mut pos = 0;
    let (major, entries) = head(body, &mut pos);
    assert_eq!(major, 5, "info is a map");
    let mut fields = [None, None, None];
    for _ in 0..entries {
        let (key_major, label) = head(body, &mut pos);
        assert_eq!(key_major, 0, "integer labels");
        if matches!(label, 1 | 6 | 7) {
            let (value_major, len) = head(body, &mut pos);
            assert_eq!(value_major, 2, "16-byte byte string");
            assert_eq!(len, 16);
            let value = hex::encode(&body[pos..pos + 16]);
            pos += 16;
            fields[match label {
                1 => 0,
                6 => 1,
                _ => 2,
            }] = Some(value);
        } else {
            skip(body, &mut pos);
        }
    }
    (
        fields[0].clone().expect("relay id"),
        fields[1].clone().expect("cursor generation"),
        fields[2].clone().expect("directory generation"),
    )
}

#[test]
fn relay_serve_startup_info_shutdown_and_restart_persistence() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("relay.db");

    // First start: validate the startup object.
    let first = start_serve(&database);
    let listen = first.startup["listen"].as_str().expect("listen").to_owned();
    assert!(listen.starts_with("127.0.0.1:"), "loopback bind: {listen}");
    let port: u16 = listen
        .split(':')
        .nth(1)
        .expect("port")
        .parse()
        .expect("numeric");
    assert_ne!(port, 0, "port 0 request reports the actual assigned port");
    assert_eq!(first.startup["developmentMode"], Value::Bool(true));
    assert_eq!(
        first.startup["baseUri"].as_str().expect("base"),
        format!("http://{listen}/"),
    );
    let relay_id = first.startup["relayId"].as_str().expect("id").to_owned();
    let cursor_generation = first.startup["cursorGeneration"]
        .as_str()
        .expect("cursor generation")
        .to_owned();
    let directory_generation = first.startup["directoryGeneration"]
        .as_str()
        .expect("directory generation")
        .to_owned();
    assert_eq!(relay_id.len(), 32, "16 bytes of hex");

    // /v1/info over a real socket agrees with the startup identity.
    let (status, body) = http_get(&listen, "/v1/info");
    assert_eq!(status, 200);
    let (info_id, info_cursor, info_directory) = info_identity_fields(&body);
    assert_eq!(info_id, relay_id);
    assert_eq!(info_cursor, cursor_generation);
    assert_eq!(info_directory, directory_generation);

    // Clean SIGTERM shutdown.
    first.stop_cleanly();

    // Restart against the same database: identity and generations persist,
    // even though a fresh candidate identity was generated and discarded.
    let second = start_serve(&database);
    assert_eq!(second.startup["relayId"].as_str(), Some(relay_id.as_str()));
    assert_eq!(
        second.startup["cursorGeneration"].as_str(),
        Some(cursor_generation.as_str()),
    );
    assert_eq!(
        second.startup["directoryGeneration"].as_str(),
        Some(directory_generation.as_str()),
    );
    let second_listen = second.startup["listen"]
        .as_str()
        .expect("listen")
        .to_owned();
    let (status, body) = http_get(&second_listen, "/v1/info");
    assert_eq!(status, 200);
    let (info_id, _, _) = info_identity_fields(&body);
    assert_eq!(info_id, relay_id, "served identity survives restart");
    second.stop_cleanly();
}

#[test]
fn relay_serve_base_uri_selects_conforming_or_development_mode() {
    let dir = tempfile::tempdir().expect("temp dir");
    let spawn = |db: &str, base_uri: &str| -> ServeInstance {
        let mut child = Command::new(env!("CARGO_BIN_EXE_followee"))
            .args([
                "relay",
                "serve",
                "--database",
                dir.path().join(db).to_str().expect("UTF-8"),
                "--listen",
                "127.0.0.1:0",
                "--base-uri",
                base_uri,
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("binary starts");
        let mut stdout = BufReader::new(child.stdout.take().expect("stdout piped"));
        let mut line = String::new();
        stdout.read_line(&mut line).expect("startup readable");
        let startup: Value = serde_json::from_str(&line).expect("one JSON object");
        ServeInstance {
            child,
            startup,
            stdout,
        }
    };

    // An HTTPS base URI selects conforming (non-development) mode: intended
    // for operation behind a TLS reverse proxy, still bindable on loopback.
    let conforming = spawn("conforming.db", "https://relay.example/");
    assert_eq!(
        conforming.startup["developmentMode"],
        Value::Bool(false),
        "HTTPS base URI is conforming mode"
    );
    assert_eq!(
        conforming.startup["baseUri"].as_str(),
        Some("https://relay.example/")
    );
    let listen = conforming.startup["listen"]
        .as_str()
        .expect("listen")
        .to_owned();
    let (status, _) = http_get(&listen, "/v1/info");
    assert_eq!(status, 200);
    conforming.stop_cleanly();

    // An explicit plain-HTTP base URI stays development mode.
    let development = spawn("dev.db", "http://127.0.0.1/");
    assert_eq!(
        development.startup["developmentMode"],
        Value::Bool(true),
        "plain HTTP base URI is development mode"
    );
    development.stop_cleanly();
}
