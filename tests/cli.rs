//! In-process CLI tests with injected clock, randomness, and captured
//! output streams (IMPLEMENTATION.md sections 7.4, 7.5, 8, and 13
//! Milestone 2). The shell-level acceptance flow lives in
//! `tests/cli_shell.rs`; this suite pins deterministic behaviour, error
//! classification, and secret redaction on every path.
#![allow(clippy::arithmetic_side_effects)]

use followee::cli::run;
use followee::clock::ManualClock;
use followee::random::DeterministicRandom;
use serde_json::Value;
use std::path::{Path, PathBuf};

/// A clock safely past the revocation sanity floor.
const NOW_MS: u64 = 1_785_589_200_000;

struct CliOutcome {
    code: u8,
    stdout: String,
    stderr: String,
    json: Value,
}

fn run_with(args: &[&str], rng_seed: u64, now_ms: u64) -> CliOutcome {
    let rng = DeterministicRandom::from_seed(rng_seed);
    let clock = ManualClock::new(now_ms);
    let owned: Vec<String> = args.iter().map(|s| (*s).to_owned()).collect();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let code = run(&owned, &rng, &clock, &mut stdout, &mut stderr);
    let stdout = String::from_utf8(stdout).expect("stdout is UTF-8");
    let stderr = String::from_utf8(stderr).expect("stderr is UTF-8");
    let json = serde_json::from_str(stdout.lines().next().unwrap_or("null")).unwrap_or(Value::Null);
    CliOutcome {
        code,
        stdout,
        stderr,
        json,
    }
}

fn path_str(path: &Path) -> &str {
    path.to_str().expect("UTF-8 path")
}

struct Identity {
    dir: tempfile::TempDir,
    did: String,
    root_key: PathBuf,
    revocation_key: PathBuf,
    identity: PathBuf,
    contact: PathBuf,
}

/// Creates a fresh identity plus a small valid contact JSON, from
/// deterministic randomness.
fn fresh_identity(rng_seed: u64) -> Identity {
    let dir = tempfile::tempdir().expect("temp dir");
    // The revocation seed goes to a separate subdirectory, standing in for
    // separate custody or removable media (IMPLEMENTATION.md section 7.4).
    let vault = dir.path().join("vault");
    std::fs::create_dir(&vault).expect("vault dir");
    let root_key = dir.path().join("root.seed");
    let revocation_key = vault.join("revocation.seed");
    let identity = dir.path().join("identity.json");
    let outcome = run_with(
        &[
            "identity",
            "create",
            "--root-key",
            path_str(&root_key),
            "--revocation-key",
            path_str(&revocation_key),
            "--identity",
            path_str(&identity),
        ],
        rng_seed,
        NOW_MS,
    );
    assert_eq!(outcome.code, 0, "create succeeds: {}", outcome.stderr);
    let did = outcome.json["did"]
        .as_str()
        .expect("did present")
        .to_owned();
    let contact = dir.path().join("contact.json");
    std::fs::write(
        &contact,
        r#"{"displayName": "Test", "summary": "Demo",
            "services": [{"id": "site", "type": "Website",
                          "endpoint": "https://example.com/"}]}"#,
    )
    .expect("contact written");
    Identity {
        dir,
        did,
        root_key,
        revocation_key,
        identity,
        contact,
    }
}

fn sign_root(id: &Identity, out: &Path, timestamp_ms: u64) -> CliOutcome {
    run_with(
        &[
            "record",
            "sign-root",
            "--identity",
            path_str(&id.identity),
            "--key",
            path_str(&id.root_key),
            "--contact",
            path_str(&id.contact),
            "--out",
            path_str(out),
            "--timestamp-ms",
            &timestamp_ms.to_string(),
        ],
        99,
        NOW_MS,
    )
}

fn revoke_root(id: &Identity, out: &Path, timestamp_ms: u64) -> CliOutcome {
    run_with(
        &[
            "record",
            "revoke-root",
            "--identity",
            path_str(&id.identity),
            "--key",
            path_str(&id.revocation_key),
            "--contact",
            path_str(&id.contact),
            "--out",
            path_str(out),
            "--timestamp-ms",
            &timestamp_ms.to_string(),
        ],
        99,
        NOW_MS,
    )
}

fn seed_hex(path: &Path) -> String {
    let text = std::fs::read_to_string(path).expect("seed file readable by test");
    text.trim()
        .strip_prefix("followee-seed-v1:")
        .expect("tagged format")
        .to_owned()
}

// ---------------------------------------------------------------------------
// identity create
// ---------------------------------------------------------------------------

#[test]
fn impl_7_2_identical_randomness_creates_identical_identities() {
    let a = fresh_identity(42);
    let b = fresh_identity(42);
    assert_eq!(a.did, b.did, "deterministic input, deterministic DID");
    let c = fresh_identity(43);
    assert_ne!(a.did, c.did);
}

#[test]
fn impl_7_4_create_refuses_shared_seed_path_and_existing_files() {
    let dir = tempfile::tempdir().expect("temp dir");
    let shared = dir.path().join("both.seed");
    let outcome = run_with(
        &[
            "identity",
            "create",
            "--root-key",
            path_str(&shared),
            "--revocation-key",
            path_str(&shared),
            "--identity",
            path_str(&dir.path().join("id.json")),
        ],
        1,
        NOW_MS,
    );
    assert_eq!(outcome.code, 2, "shared path is a usage error");
    assert_eq!(outcome.json["error"]["symbol"], "usage");

    // Existing files are never overwritten without --force, and the
    // refused invocation leaves every pre-existing file byte-identical.
    let id = fresh_identity(7);
    let snapshot = |paths: &[&Path]| -> Vec<Vec<u8>> {
        paths
            .iter()
            .map(|p| std::fs::read(p).expect("readable"))
            .collect()
    };
    let watched = [
        id.root_key.as_path(),
        id.revocation_key.as_path(),
        id.identity.as_path(),
    ];
    let before = snapshot(&watched);
    let outcome = run_with(
        &[
            "identity",
            "create",
            "--root-key",
            path_str(&id.root_key),
            "--revocation-key",
            path_str(&id.revocation_key),
            "--identity",
            path_str(&id.identity),
        ],
        8,
        NOW_MS,
    );
    assert_eq!(outcome.code, 1);
    assert_eq!(outcome.json["error"]["symbol"], "keyFileExists");
    assert_eq!(
        snapshot(&watched),
        before,
        "a refused create alters no pre-existing file"
    );
    // With --force the same invocation succeeds and rotates the identity.
    let outcome = run_with(
        &[
            "identity",
            "create",
            "--root-key",
            path_str(&id.root_key),
            "--revocation-key",
            path_str(&id.revocation_key),
            "--identity",
            path_str(&id.identity),
            "--force",
        ],
        8,
        NOW_MS,
    );
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert_ne!(outcome.json["did"].as_str().expect("did"), id.did);
}

#[test]
fn impl_7_4_create_warns_prominently_about_demonstration_custody() {
    let dir = tempfile::tempdir().expect("temp dir");
    let outcome = run_with(
        &[
            "identity",
            "create",
            "--root-key",
            path_str(&dir.path().join("r.seed")),
            "--revocation-key",
            path_str(&dir.path().join("v.seed")),
            "--identity",
            path_str(&dir.path().join("id.json")),
        ],
        1,
        NOW_MS,
    );
    assert_eq!(outcome.code, 0);
    assert!(
        outcome.stderr.contains("WARNING") && outcome.stderr.contains("demonstration custody"),
        "custody warning is prominent: {}",
        outcome.stderr
    );
    assert!(
        outcome.stderr.contains("separate custody"),
        "revocation custody guidance present"
    );
}

// ---------------------------------------------------------------------------
// signing
// ---------------------------------------------------------------------------

#[test]
fn sec_4_4_sign_root_produces_a_record_the_core_verifies() {
    let id = fresh_identity(11);
    let out = id.dir.path().join("root.cose");
    let outcome = sign_root(&id, &out, NOW_MS);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert_eq!(outcome.json["authority"], "root");
    let bytes = std::fs::read(&out).expect("record written");
    let record =
        followee::verify::verify_record_for_target(&id.did, &bytes).expect("core verifies");
    assert_eq!(record.timestamp_ms(), NOW_MS);
    assert_eq!(
        outcome.json["bodyDigest"].as_str().expect("digest"),
        hex::encode(record.body_digest()),
    );
}

#[test]
fn sec_5_3_default_timestamp_is_max_of_now_and_previous_plus_one() {
    let id = fresh_identity(12);
    let out = id.dir.path().join("root.cose");
    let outcome = run_with(
        &[
            "record",
            "sign-root",
            "--identity",
            path_str(&id.identity),
            "--key",
            path_str(&id.root_key),
            "--contact",
            path_str(&id.contact),
            "--out",
            path_str(&out),
            "--previous-timestamp-ms",
            &(NOW_MS + 50).to_string(),
        ],
        1,
        NOW_MS,
    );
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert_eq!(
        outcome.json["timestampMs"].as_u64(),
        Some(NOW_MS + 51),
        "max(now, previous + 1)"
    );
}

#[test]
fn impl_7_4_wrong_seed_files_fail_with_key_mismatch_before_signing() {
    let id = fresh_identity(13);
    let out = id.dir.path().join("never.cose");
    // Revocation seed offered as the root key.
    let outcome = run_with(
        &[
            "record",
            "sign-root",
            "--identity",
            path_str(&id.identity),
            "--key",
            path_str(&id.revocation_key),
            "--contact",
            path_str(&id.contact),
            "--out",
            path_str(&out),
        ],
        1,
        NOW_MS,
    );
    assert_eq!(outcome.code, 1);
    assert_eq!(outcome.json["error"]["symbol"], "keyMismatch");
    // Root seed offered as the revocation key.
    let outcome = run_with(
        &[
            "record",
            "revoke-root",
            "--identity",
            path_str(&id.identity),
            "--key",
            path_str(&id.root_key),
            "--contact",
            path_str(&id.contact),
            "--out",
            path_str(&out),
        ],
        1,
        NOW_MS,
    );
    assert_eq!(outcome.code, 1);
    assert_eq!(outcome.json["error"]["symbol"], "keyMismatch");
    assert!(!out.exists(), "no record is written on a refused signing");
}

#[test]
fn impl_7_4_published_appendix_b_seed_is_refused_by_production_signing() {
    let id = fresh_identity(14);
    // Overwrite the root seed file with Alice's published B.2 seed, keeping
    // the safe format and permissions.
    std::fs::write(
        &id.root_key,
        "followee-seed-v1:000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\n",
    )
    .expect("write");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&id.root_key, std::fs::Permissions::from_mode(0o600))
            .expect("chmod");
    }
    let out = id.dir.path().join("never.cose");
    let outcome = sign_root(&id, &out, NOW_MS);
    assert_eq!(outcome.code, 1);
    assert_eq!(outcome.json["error"]["symbol"], "publishedTestSeed");
    assert!(!out.exists());
}

#[test]
fn impl_7_5_contact_faults_fail_before_any_signature_exists() {
    let id = fresh_identity(15);
    let out = id.dir.path().join("never.cose");
    // Unknown field.
    std::fs::write(&id.contact, r#"{"displayNme": "typo"}"#).expect("write");
    let outcome = sign_root(&id, &out, NOW_MS);
    assert_eq!(outcome.code, 1);
    assert_eq!(outcome.json["error"]["symbol"], "contactJson");
    // Limit violation: the core schema rejects at signing time.
    let oversized = format!(r#"{{"displayName": "{}"}}"#, "x".repeat(257));
    std::fs::write(&id.contact, oversized).expect("write");
    let outcome = sign_root(&id, &out, NOW_MS);
    assert_eq!(outcome.code, 1);
    assert_eq!(outcome.json["error"]["symbol"], "schemaViolation");
    // Grammar violation from the v0.6 service rules.
    std::fs::write(
        &id.contact,
        r#"{"services": [{"id": "a", "type": "Website",
            "endpoint": "https://e.com/", "mediaType": "not a media type"}]}"#,
    )
    .expect("write");
    let outcome = sign_root(&id, &out, NOW_MS);
    assert_eq!(outcome.code, 1);
    assert_eq!(outcome.json["error"]["symbol"], "schemaViolation");
    assert!(
        !out.exists(),
        "no partial or invalid record is ever written"
    );
}

#[test]
fn sec_5_3_revocation_requires_a_sane_clock() {
    let id = fresh_identity(16);
    let out = id.dir.path().join("never.cose");
    let owned: Vec<String> = [
        "record",
        "revoke-root",
        "--identity",
        path_str(&id.identity),
        "--key",
        path_str(&id.revocation_key),
        "--contact",
        path_str(&id.contact),
        "--out",
        path_str(&out),
        "--timestamp-ms",
        "1785589200000",
    ]
    .iter()
    .map(|s| (*s).to_owned())
    .collect();
    // Clock before 2020: refused even with an explicit timestamp.
    let rng = DeterministicRandom::from_seed(1);
    let clock = ManualClock::new(1_000_000);
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let code = run(&owned, &rng, &clock, &mut stdout, &mut stderr);
    assert_eq!(code, 1);
    let json: Value = serde_json::from_slice(&stdout).expect("error JSON");
    assert_eq!(json["error"]["symbol"], "clockSanity");
    assert!(!out.exists());
}

#[test]
fn sec_5_3_revocation_clock_floor_boundary_is_exact() {
    // Exactly at the 2020-01-01 floor the sanity check passes; one
    // millisecond below it refuses.
    const FLOOR: u64 = 1_577_836_800_000;
    let id = fresh_identity(26);
    let out = id.dir.path().join("rv.cose");
    let base_args = |out: &Path| -> Vec<String> {
        [
            "record",
            "revoke-root",
            "--identity",
            path_str(&id.identity),
            "--key",
            path_str(&id.revocation_key),
            "--contact",
            path_str(&id.contact),
            "--out",
            path_str(out),
            "--timestamp-ms",
            "1785589200000",
        ]
        .iter()
        .map(|s| (*s).to_owned())
        .collect()
    };
    let run_at = |args: &[String], now: u64| -> (u8, Value) {
        let rng = DeterministicRandom::from_seed(1);
        let clock = ManualClock::new(now);
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = followee::cli::run(args, &rng, &clock, &mut stdout, &mut stderr);
        (code, serde_json::from_slice(&stdout).unwrap_or(Value::Null))
    };
    let (code, json) = run_at(&base_args(&out), FLOOR - 1);
    assert_eq!(code, 1);
    assert_eq!(json["error"]["symbol"], "clockSanity");
    assert!(!out.exists());
    let (code, _) = run_at(&base_args(&out), FLOOR);
    assert_eq!(code, 0, "the exact floor passes the sanity check");
    assert!(out.exists());
}

// ---------------------------------------------------------------------------
// verification, inspection, selection
// ---------------------------------------------------------------------------

#[test]
fn sec_8_1_verify_reports_classification_and_nonzero_exit_on_failure() {
    let id = fresh_identity(17);
    let out = id.dir.path().join("root.cose");
    assert_eq!(sign_root(&id, &out, NOW_MS).code, 0);

    let ok = run_with(
        &[
            "record",
            "verify",
            "--did",
            &id.did,
            "--record",
            path_str(&out),
        ],
        1,
        NOW_MS,
    );
    assert_eq!(ok.code, 0);
    assert_eq!(ok.json["verified"], Value::Bool(true));
    assert_eq!(ok.json["timeStatus"], "admissible");
    assert_eq!(ok.json["freshness"], "fresh");

    // Wrong target: exact protocol classification, exit 1.
    let other = fresh_identity(18);
    let wrong = run_with(
        &[
            "record",
            "verify",
            "--did",
            &other.did,
            "--record",
            path_str(&out),
        ],
        1,
        NOW_MS,
    );
    assert_eq!(wrong.code, 1);
    assert_eq!(wrong.json["error"]["symbol"], "identityBindingMismatch");

    // Corrupted record: invalid signature classification.
    let mut bytes = std::fs::read(&out).expect("record");
    let last = bytes.len() - 1;
    bytes[last] ^= 0x01;
    let bad = id.dir.path().join("bad.cose");
    std::fs::write(&bad, &bytes).expect("write");
    let corrupt = run_with(
        &[
            "record",
            "verify",
            "--did",
            &id.did,
            "--record",
            path_str(&bad),
        ],
        1,
        NOW_MS,
    );
    assert_eq!(corrupt.code, 1);
    assert_eq!(corrupt.json["error"]["symbol"], "invalidSignature");

    // Premature classification under an explicit recipient clock.
    let premature = run_with(
        &[
            "record",
            "verify",
            "--did",
            &id.did,
            "--record",
            path_str(&out),
            "--now-ms",
            &(NOW_MS - 300_001).to_string(),
        ],
        1,
        NOW_MS,
    );
    assert_eq!(
        premature.code, 0,
        "premature is a classification, not an error"
    );
    assert_eq!(premature.json["timeStatus"], "premature");
}

#[test]
fn impl_8_inspect_never_presents_unverified_claims_as_verified() {
    let id = fresh_identity(19);
    let out = id.dir.path().join("root.cose");
    assert_eq!(sign_root(&id, &out, NOW_MS).code, 0);

    // Without a target DID: raw claims, explicitly unverified.
    let raw = run_with(
        &["record", "inspect", "--record", path_str(&out)],
        1,
        NOW_MS,
    );
    assert_eq!(raw.code, 0);
    assert_eq!(raw.json["verification"]["status"], "unverified");
    assert_eq!(raw.json["claims"]["contact"]["displayName"], "Test");

    // Against the wrong DID: verification failed, claims stay unverified.
    let other = fresh_identity(20);
    let failed = run_with(
        &[
            "record",
            "inspect",
            "--record",
            path_str(&out),
            "--did",
            &other.did,
        ],
        1,
        NOW_MS,
    );
    assert_eq!(failed.code, 0, "inspection itself succeeded");
    assert_eq!(failed.json["verification"]["status"], "failed");
    assert_eq!(
        failed.json["verification"]["error"],
        "identityBindingMismatch"
    );

    // Against the right DID: verified facts appear.
    let verified = run_with(
        &[
            "record",
            "inspect",
            "--record",
            path_str(&out),
            "--did",
            &id.did,
        ],
        1,
        NOW_MS,
    );
    assert_eq!(verified.json["verification"]["status"], "verified");
    assert_eq!(verified.json["verification"]["authority"], "root");
}

#[test]
fn sec_8_2_selection_is_permutation_independent_and_revocation_sticky() {
    let id = fresh_identity(21);
    let root1 = id.dir.path().join("r1.cose");
    let revoked = id.dir.path().join("rv.cose");
    let root2 = id.dir.path().join("r2.cose");
    assert_eq!(sign_root(&id, &root1, NOW_MS).code, 0);
    assert_eq!(revoke_root(&id, &revoked, NOW_MS + 1).code, 0);
    // A LATER Root record, signed after the revocation.
    assert_eq!(sign_root(&id, &root2, NOW_MS + 1000).code, 0);
    // A valid record for a different DID, delivered into the same pool.
    let foreign = fresh_identity(22);
    let foreign_record = foreign.dir.path().join("f.cose");
    assert_eq!(sign_root(&foreign, &foreign_record, NOW_MS).code, 0);

    let files = [&root1, &revoked, &root2, &foreign_record];
    let mut orders: Vec<Vec<usize>> = vec![
        vec![0, 1, 2, 3],
        vec![3, 2, 1, 0],
        vec![2, 0, 3, 1],
        vec![1, 3, 0, 2],
    ];
    let mut winners = Vec::new();
    for order in orders.drain(..) {
        let mut args: Vec<String> = vec![
            "record".into(),
            "select".into(),
            "--did".into(),
            id.did.clone(),
            "--now-ms".into(),
            (NOW_MS + 2000).to_string(),
        ];
        for index in &order {
            args.push(path_str(files[*index]).to_owned());
        }
        let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
        let outcome = run_with(&arg_refs, 1, NOW_MS);
        assert_eq!(outcome.code, 0, "{}", outcome.stderr);
        assert_eq!(outcome.json["authorityState"], "rootRevoked");
        winners.push(outcome.json["winner"]["bodyDigest"].clone());
        // The later Root record is never the winner despite its later
        // timestamp, and the foreign record is rejected diagnostically.
        assert_eq!(
            outcome.json["winner"]["authority"], "rootRevoked",
            "a later Root record cannot be selected after sticky revocation"
        );
        let rejected = outcome.json["rejected"].as_array().expect("rejected list");
        assert_eq!(rejected.len(), 1);
        assert_eq!(rejected[0]["error"], "identityBindingMismatch");
    }
    winners.dedup();
    assert_eq!(
        winners.len(),
        1,
        "every permutation selects the same winner"
    );
}

#[test]
fn sec_8_2_retained_sticky_state_excludes_root_without_a_revoked_candidate() {
    let id = fresh_identity(23);
    let root = id.dir.path().join("r.cose");
    assert_eq!(sign_root(&id, &root, NOW_MS).code, 0);
    let outcome = run_with(
        &[
            "record",
            "select",
            "--did",
            &id.did,
            "--now-ms",
            &NOW_MS.to_string(),
            "--assume-root-revoked",
            path_str(&root),
        ],
        1,
        NOW_MS,
    );
    assert_eq!(outcome.code, 0);
    assert_eq!(outcome.json["authorityState"], "rootRevoked");
    assert_eq!(
        outcome.json["winner"],
        Value::Null,
        "no Root fallback exists"
    );
}

// ---------------------------------------------------------------------------
// secret redaction across every ordinary and failure path
// ---------------------------------------------------------------------------

#[test]
fn impl_7_4_no_output_or_failure_path_reveals_seed_material() {
    let id = fresh_identity(24);
    let root_hex = seed_hex(&id.root_key);
    let revocation_hex = seed_hex(&id.revocation_key);
    let out = id.dir.path().join("root.cose");

    let mut transcripts = String::new();
    let mut record = |outcome: CliOutcome| {
        transcripts.push_str(&outcome.stdout);
        transcripts.push_str(&outcome.stderr);
    };

    // Ordinary paths.
    record(sign_root(&id, &out, NOW_MS));
    record(run_with(
        &[
            "record",
            "verify",
            "--did",
            &id.did,
            "--record",
            path_str(&out),
        ],
        1,
        NOW_MS,
    ));
    record(run_with(
        &[
            "record",
            "inspect",
            "--record",
            path_str(&out),
            "--did",
            &id.did,
        ],
        1,
        NOW_MS,
    ));
    record(revoke_root(&id, &id.dir.path().join("rv.cose"), NOW_MS + 1));
    record(run_with(
        &[
            "record",
            "select",
            "--did",
            &id.did,
            "--now-ms",
            &(NOW_MS + 2).to_string(),
            path_str(&out),
        ],
        1,
        NOW_MS,
    ));

    // Failure and diagnostic paths: overwrite refusals, key mismatches,
    // malformed contact JSON, malformed record files, usage errors.
    record(sign_root(&id, &out, NOW_MS)); // outputExists
    record(run_with(
        &[
            "record",
            "sign-root",
            "--identity",
            path_str(&id.identity),
            "--key",
            path_str(&id.revocation_key),
            "--contact",
            path_str(&id.contact),
            "--out",
            path_str(&id.dir.path().join("x.cose")),
        ],
        1,
        NOW_MS,
    )); // keyMismatch
    std::fs::write(id.dir.path().join("bad.json"), "{").expect("write");
    record(run_with(
        &[
            "record",
            "sign-root",
            "--identity",
            path_str(&id.identity),
            "--key",
            path_str(&id.root_key),
            "--contact",
            path_str(&id.dir.path().join("bad.json")),
            "--out",
            path_str(&id.dir.path().join("y.cose")),
        ],
        1,
        NOW_MS,
    )); // contactJson
    std::fs::write(id.dir.path().join("junk.cose"), b"\xff\xff").expect("write");
    record(run_with(
        &[
            "record",
            "verify",
            "--did",
            &id.did,
            "--record",
            path_str(&id.dir.path().join("junk.cose")),
        ],
        1,
        NOW_MS,
    )); // verification failure
    record(run_with(&["record", "sign-root"], 1, NOW_MS)); // usage
    record(run_with(&["no-such-command"], 1, NOW_MS)); // usage
    record(run_with(&["--help"], 1, NOW_MS)); // help text

    assert!(
        !transcripts.contains(&root_hex),
        "root seed hex must never appear in any output"
    );
    assert!(
        !transcripts.contains(&revocation_hex),
        "revocation seed hex must never appear in any output"
    );
    // Case-insensitive belt and braces.
    let upper = transcripts.to_uppercase();
    assert!(!upper.contains(&root_hex.to_uppercase()));
    assert!(!upper.contains(&revocation_hex.to_uppercase()));
}

#[test]
fn oversized_and_bounded_record_reads_classify_cleanly() {
    let id = fresh_identity(25);
    let big = id.dir.path().join("big.cose");
    std::fs::write(&big, vec![0u8; 20 * 1024]).expect("write");
    let outcome = run_with(
        &[
            "record",
            "verify",
            "--did",
            &id.did,
            "--record",
            path_str(&big),
        ],
        1,
        NOW_MS,
    );
    assert_eq!(outcome.code, 1);
    assert_eq!(outcome.json["error"]["symbol"], "recordTooLarge");
}
