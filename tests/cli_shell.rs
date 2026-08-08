//! Shell-level black-box acceptance tests (IMPLEMENTATION.md section 13
//! Milestone 2): the real `followee` binary is executed as a subprocess with
//! real files, covering the complete create → sign → verify → revoke →
//! select flow, separately stored revocation custody, sticky-revocation
//! selection, exit statuses, and secret redaction of every captured stream.
#![allow(clippy::arithmetic_side_effects)]

use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// A timestamp base safely past the revocation clock-sanity floor.
const T0: u64 = 1_785_589_200_000;

fn followee(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_followee"))
        .args(args)
        .output()
        .expect("binary runs")
}

fn stdout_json(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).unwrap_or(Value::Null)
}

fn path_str(path: &Path) -> &str {
    path.to_str().expect("UTF-8 path")
}

struct ShellIdentity {
    dir: tempfile::TempDir,
    did: String,
    root_key: PathBuf,
    revocation_key: PathBuf,
    identity: PathBuf,
    contact: PathBuf,
    transcripts: Vec<u8>,
}

impl ShellIdentity {
    fn create() -> Self {
        let dir = tempfile::tempdir().expect("temp dir");
        // Separate custody for the revocation seed: a distinct directory
        // standing in for removable media (IMPLEMENTATION.md section 7.4).
        let vault = dir.path().join("vault");
        std::fs::create_dir(&vault).expect("vault");
        let root_key = dir.path().join("root.seed");
        let revocation_key = vault.join("revocation.seed");
        let identity = dir.path().join("identity.json");
        let output = followee(&[
            "identity",
            "create",
            "--root-key",
            path_str(&root_key),
            "--revocation-key",
            path_str(&revocation_key),
            "--identity",
            path_str(&identity),
        ]);
        assert_eq!(output.status.code(), Some(0), "create succeeds");
        let did = stdout_json(&output)["did"]
            .as_str()
            .expect("did present")
            .to_owned();
        let contact = dir.path().join("contact.json");
        std::fs::write(
            &contact,
            r#"{"displayName": "Shell Test",
                "services": [{"id": "site", "type": "Website",
                              "endpoint": "https://example.com/"}]}"#,
        )
        .expect("contact");
        let mut transcripts = output.stdout.clone();
        transcripts.extend_from_slice(&output.stderr);
        ShellIdentity {
            dir,
            did,
            root_key,
            revocation_key,
            identity,
            contact,
            transcripts,
        }
    }

    fn run(&mut self, args: &[&str]) -> Output {
        let output = followee(args);
        self.transcripts.extend_from_slice(&output.stdout);
        self.transcripts.extend_from_slice(&output.stderr);
        output
    }

    fn sign_root(&mut self, out: &Path, timestamp_ms: u64) -> Output {
        let args: Vec<String> = vec![
            "record".into(),
            "sign-root".into(),
            "--identity".into(),
            path_str(&self.identity).into(),
            "--key".into(),
            path_str(&self.root_key).into(),
            "--contact".into(),
            path_str(&self.contact).into(),
            "--out".into(),
            path_str(out).into(),
            "--timestamp-ms".into(),
            timestamp_ms.to_string(),
        ];
        let refs: Vec<&str> = args.iter().map(String::as_str).collect();
        self.run(&refs)
    }

    fn revoke_root(&mut self, out: &Path, timestamp_ms: u64) -> Output {
        let args: Vec<String> = vec![
            "record".into(),
            "revoke-root".into(),
            "--identity".into(),
            path_str(&self.identity).into(),
            "--key".into(),
            path_str(&self.revocation_key).into(),
            "--contact".into(),
            path_str(&self.contact).into(),
            "--out".into(),
            path_str(out).into(),
            "--timestamp-ms".into(),
            timestamp_ms.to_string(),
        ];
        let refs: Vec<&str> = args.iter().map(String::as_str).collect();
        self.run(&refs)
    }

    fn seed_hexes(&self) -> [String; 2] {
        let read = |path: &Path| {
            std::fs::read_to_string(path)
                .expect("seed readable by test")
                .trim()
                .strip_prefix("followee-seed-v1:")
                .expect("tagged")
                .to_owned()
        };
        [read(&self.root_key), read(&self.revocation_key)]
    }
}

#[test]
fn milestone_2_acceptance_flow_end_to_end() {
    let mut id = ShellIdentity::create();

    // Key files exist with owner-only permissions; the identity file is
    // public and reproduces the DID.
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        for path in [&id.root_key, &id.revocation_key] {
            let mode = std::fs::metadata(path).expect("metadata").mode() & 0o777;
            assert_eq!(mode, 0o600, "{}: owner-only", path.display());
        }
    }
    assert!(id.did.starts_with("did:flw:z"));

    // Shell-level: create a DID, sign a record, and verify it.
    let root = id.dir.path().join("root.cose");
    let output = id.sign_root(&root, T0);
    assert_eq!(output.status.code(), Some(0));
    let output = id.run(&[
        "record",
        "verify",
        "--did",
        &id.did.clone(),
        "--record",
        path_str(&root),
    ]);
    assert_eq!(output.status.code(), Some(0));
    let verdict = stdout_json(&output);
    assert_eq!(verdict["verified"], Value::Bool(true));
    assert_eq!(verdict["authority"], "root");

    // The separately stored revocation key creates a winning RootRevoked
    // record.
    let revoked = id.dir.path().join("revoked.cose");
    let output = id.revoke_root(&revoked, T0 + 1);
    assert_eq!(output.status.code(), Some(0));
    let did = id.did.clone();
    let output = id.run(&[
        "record",
        "select",
        "--did",
        &did,
        "--now-ms",
        &(T0 + 10).to_string(),
        path_str(&root),
        path_str(&revoked),
    ]);
    assert_eq!(output.status.code(), Some(0));
    let selection = stdout_json(&output);
    assert_eq!(selection["authorityState"], "rootRevoked");
    assert_eq!(selection["winner"]["authority"], "rootRevoked");

    // A later Root record — later timestamp, signed after revocation —
    // cannot be selected while the RootRevoked candidate is in the pool,
    // in either order.
    let late_root = id.dir.path().join("late-root.cose");
    let output = id.sign_root(&late_root, T0 + 60_000);
    assert_eq!(output.status.code(), Some(0));
    for order in [[&late_root, &revoked, &root], [&root, &late_root, &revoked]] {
        let args: Vec<String> = vec![
            "record".into(),
            "select".into(),
            "--did".into(),
            did.clone(),
            "--now-ms".into(),
            (T0 + 120_000).to_string(),
        ]
        .into_iter()
        .chain(order.iter().map(|p| path_str(p).to_owned()))
        .collect();
        let refs: Vec<&str> = args.iter().map(String::as_str).collect();
        let output = id.run(&refs);
        let selection = stdout_json(&output);
        assert_eq!(
            selection["winner"]["authority"], "rootRevoked",
            "a later Root record is never selected after sticky revocation"
        );
        assert_eq!(
            selection["winner"]["timestampMs"].as_u64(),
            Some(T0 + 1),
            "the revoked record itself wins"
        );
    }

    // Retained sticky state alone excludes every Root record.
    let output = id.run(&[
        "record",
        "select",
        "--did",
        &did,
        "--now-ms",
        &(T0 + 120_000).to_string(),
        "--assume-root-revoked",
        path_str(&late_root),
    ]);
    let selection = stdout_json(&output);
    assert_eq!(selection["authorityState"], "rootRevoked");
    assert_eq!(
        selection["winner"],
        Value::Null,
        "no last-good-Root fallback"
    );

    // Failure paths return nonzero with stable symbols: refused overwrite
    // and a wrong-target verification.
    let output = id.sign_root(&root, T0 + 2);
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(stdout_json(&output)["error"]["symbol"], "outputExists");
    let output = id.run(&[
        "record",
        "verify",
        "--did",
        "did:flw:not-a-did",
        "--record",
        path_str(&root),
    ]);
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(stdout_json(&output)["error"]["symbol"], "invalidDid");
    let output = id.run(&["record", "select", "--did", &did]);
    assert_eq!(output.status.code(), Some(2), "missing candidates is usage");

    // Across every invocation above — ordinary, diagnostic, and failing —
    // neither seed's hex ever appeared on stdout or stderr.
    let transcripts = String::from_utf8_lossy(&id.transcripts).to_string();
    for seed_hex in id.seed_hexes() {
        assert!(
            !transcripts
                .to_lowercase()
                .contains(&seed_hex.to_lowercase()),
            "seed material leaked into process output"
        );
    }
    // The record files on disk contain public material only.
    for file in [&root, &revoked, &late_root] {
        let bytes = std::fs::read(file).expect("record");
        let rendered = hex::encode(bytes);
        for seed_hex in id.seed_hexes() {
            assert!(!rendered.contains(&seed_hex), "seed bytes inside a record");
        }
    }
}

#[test]
fn shell_second_create_refuses_overwrite_and_reports_symbol() {
    let mut id = ShellIdentity::create();
    let root = path_str(&id.root_key).to_owned();
    let revocation = path_str(&id.revocation_key).to_owned();
    let identity = path_str(&id.identity).to_owned();
    let output = id.run(&[
        "identity",
        "create",
        "--root-key",
        &root,
        "--revocation-key",
        &revocation,
        "--identity",
        &identity,
    ]);
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(stdout_json(&output)["error"]["symbol"], "keyFileExists");
}
