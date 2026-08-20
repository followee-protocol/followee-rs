//! Milestone 6 participant-output generator.
//!
//! Produces every participant-owned Followee v0.9.2 output required by the
//! neutral authoring subset — published-vector results, recipe-constructed
//! negative envelopes, Appendix B.11 wire-message reproductions, and the
//! blind-challenge rerun — before any coordinator comparison, and writes
//! them with a manifest of input and output hashes.
//!
//! Usage:
//!
//! ```text
//! cargo run --example interop_outputs -- <authoring-dir> <out-dir>
//! ```
//!
//! `<authoring-dir>` is the v0.9.2 bundle's `authoring/` directory; its
//! 12-file aggregate SHA-256 is verified before anything runs, so the
//! generator cannot silently consume other material. Every interface
//! operation runs through the production `followee::interop` engine — the
//! same engine `followee interop` serves — and every published expected
//! member is checked against our computed member; any mismatch aborts.
//! Outputs are deterministic: identical inputs and source produce
//! byte-identical files.
#![allow(clippy::arithmetic_side_effects)]

use followee::clock::ManualClock;
use followee::interop::{InteropConfig, handle_line};
use followee::ordering::AuthorityState;
use followee::record::Authority;
use followee::relay::client::{
    BudgetMeter, NetworkPolicy, OperationBudget, RelayClient, Transport, TransportError,
    TransportRequest, TransportResponse,
};
use followee::relay::sync::SyncOptions;
use followee::relay::{Relay, RelayConfig};
use followee::store::{EntryPayload, MemoryStore, OrderingMeta, PeerState, RelayIdentity};
use serde_json::{Value, json};
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// The required 12-file aggregate SHA-256 of the authoring subset
/// (`sha256sum` lines over the sorted `./`-relative file list, hashed).
/// Authoring **revision 2**: only `interface/INTERFACE.md` differs from
/// revision 1 (`cec54f10…89ae6b`); the specification and every vector
/// file are byte-identical.
const AUTHORING_AGGREGATE_SHA256: &str =
    "1b6514da0c1a0c5289e0909b648b5de73a302e91b346440624badacf5747855e";

/// The pinned specification SHA-256 (IMPLEMENTATION.md section 2).
const SPECIFICATION_SHA256: &str =
    "47af5fbf0c4505386b4e04d948ef89d013f878ea820fb02522817661d633633a";

/// Recipient clock for the published-negative `verifyRecord` runs: the
/// classification of every negative case is time-independent, and this is
/// the Appendix B.11.5 published `nowMs` at which every Appendix B record
/// is admissible.
const NEGATIVE_VERIFY_NOW_MS: &str = "1785589201123";

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(followee::crypto::sha256(bytes))
}

fn read(path: &Path) -> Vec<u8> {
    std::fs::read(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

fn read_json(path: &Path) -> Value {
    serde_json::from_slice(&read(path)).unwrap_or_else(|e| panic!("parse {}: {e}", path.display()))
}

fn main() {
    let mut args = std::env::args().skip(1);
    let authoring = PathBuf::from(
        args.next()
            .expect("usage: interop_outputs <authoring-dir> <out-dir>"),
    );
    let out_dir = PathBuf::from(
        args.next()
            .expect("usage: interop_outputs <authoring-dir> <out-dir>"),
    );

    let input_hashes = verify_authoring_subset(&authoring);
    std::fs::create_dir_all(&out_dir).expect("create output directory");

    let engine = Engine::new();
    let mut outputs: BTreeMap<String, String> = BTreeMap::new();
    fn write_group(
        out_dir: &Path,
        outputs: &mut BTreeMap<String, String>,
        name: &str,
        lines: &GroupLines,
    ) {
        for (suffix, content) in [
            ("requests", lines.requests.join("\n") + "\n"),
            ("responses", lines.responses.join("\n") + "\n"),
        ] {
            let file = format!("{name}.{suffix}.ndjson");
            let path = out_dir.join(&file);
            std::fs::write(&path, content.as_bytes()).expect("write output");
            outputs.insert(file, sha256_hex(content.as_bytes()));
        }
    }

    // Phase 1: published vectors through the interface operations.
    let identities = read_json(&authoring.join("vectors/published/identities.json"));
    let records = read_json(&authoring.join("vectors/published/records.json"));
    let negative = read_json(&authoring.join("vectors/published/envelopes-negative.json"));
    let wire = read_json(&authoring.join("vectors/published/wire-b11.json"));

    let identity_lines = engine.run_expected_cases(&identities, None);
    write_group(
        &out_dir,
        &mut outputs,
        "published-identities",
        &identity_lines,
    );
    eprintln!(
        "published identities: {} cases agree",
        identity_lines.requests.len()
    );

    let record_lines = engine.run_expected_cases(&records, None);
    write_group(&out_dir, &mut outputs, "published-records", &record_lines);
    eprintln!(
        "published records: {} cases agree",
        record_lines.requests.len()
    );

    let alice_did = expected_member(&identities, "identity-alice", "did");
    let negative_lines = engine.run_negative_cases(&negative, &records, &alice_did);
    write_group(
        &out_dir,
        &mut outputs,
        "published-negative",
        &negative_lines,
    );
    eprintln!(
        "published negative envelopes: {} cases agree",
        negative_lines.requests.len()
    );

    // Phase 2: Appendix B.11 wire messages.
    let report = wire_b11_report(&wire, &records, &negative, &identities);
    let report_text = serde_json::to_string_pretty(&report).expect("serialize") + "\n";
    std::fs::write(out_dir.join("wire-b11-report.json"), report_text.as_bytes())
        .expect("write report");
    outputs.insert(
        "wire-b11-report.json".to_owned(),
        sha256_hex(report_text.as_bytes()),
    );
    eprintln!(
        "wire B.11: {} messages reproduced",
        report.as_array().map_or(0, Vec::len)
    );

    // Phase 3: the blind-challenge rerun (maintenance confirmation).
    let challenge = engine.run_challenges(&authoring);
    write_group(
        &out_dir,
        &mut outputs,
        "challenge-identities",
        &challenge.identities,
    );
    write_group(
        &out_dir,
        &mut outputs,
        "challenge-records",
        &challenge.records,
    );
    write_group(
        &out_dir,
        &mut outputs,
        "challenge-verify",
        &challenge.verify,
    );
    write_group(
        &out_dir,
        &mut outputs,
        "challenge-selection",
        &challenge.selection,
    );
    eprintln!(
        "challenge rerun: {} identities, {} records, {} verifications, {} selections",
        challenge.identities.requests.len(),
        challenge.records.requests.len(),
        challenge.verify.requests.len(),
        challenge.selection.requests.len()
    );

    // Manifest: inputs, outputs, and fixed parameters. No wall-clock
    // values appear anywhere, so regeneration is byte-identical.
    let manifest = json!({
        "bundle": "followee-interop/v0.9.2",
        "role": "participant-owned outputs, produced before any coordinator comparison",
        "participant": {
            "implementation": "followee-rs",
            "repository": "https://github.com/followee-protocol/followee-rs",
            "toolchain": "rust 1.97.1 (rust-toolchain.toml pin)",
        },
        "specification": {
            "sha256": SPECIFICATION_SHA256,
            "revisionCommit": "f1d19fec0dba455d90d473bfad625d1c288e0c15",
            "repositoryCommit": "ac5a794f2fdadc13cddf5367fa3e047617e3e950",
        },
        "authoringSubset": {
            "aggregateSha256": AUTHORING_AGGREGATE_SHA256,
            "files": input_hashes,
        },
        "parameters": {
            "negativeVerifyNowMs": NEGATIVE_VERIFY_NOW_MS,
        },
        "outputs": outputs,
    });
    let manifest_text = serde_json::to_string_pretty(&manifest).expect("serialize") + "\n";
    std::fs::write(out_dir.join("MANIFEST.json"), manifest_text.as_bytes())
        .expect("write manifest");
    eprintln!(
        "manifest written to {}",
        out_dir.join("MANIFEST.json").display()
    );
}

/// Verifies the authoring subset holds exactly 12 files with the pinned
/// aggregate SHA-256, returning each file's hash.
fn verify_authoring_subset(authoring: &Path) -> BTreeMap<String, String> {
    let mut files: Vec<PathBuf> = Vec::new();
    fn walk(dir: &Path, files: &mut Vec<PathBuf>) {
        let mut entries: Vec<_> = std::fs::read_dir(dir)
            .unwrap_or_else(|e| panic!("read {}: {e}", dir.display()))
            .map(|entry| entry.expect("directory entry").path())
            .collect();
        entries.sort();
        for path in entries {
            if path.is_dir() {
                walk(&path, files);
            } else {
                files.push(path);
            }
        }
    }
    walk(authoring, &mut files);
    let mut relative: Vec<String> = files
        .iter()
        .map(|path| {
            format!(
                "./{}",
                path.strip_prefix(authoring)
                    .expect("under authoring")
                    .display()
            )
        })
        .collect();
    relative.sort();
    assert_eq!(
        relative.len(),
        12,
        "the authoring subset holds exactly 12 files"
    );

    let mut hashes = BTreeMap::new();
    let mut aggregate_input = String::new();
    for rel in &relative {
        let path = authoring.join(rel.trim_start_matches("./"));
        let hash = sha256_hex(&read(&path));
        aggregate_input.push_str(&format!("{hash}  {rel}\n"));
        hashes.insert(rel.clone(), hash);
    }
    let aggregate = sha256_hex(aggregate_input.as_bytes());
    assert_eq!(
        aggregate, AUTHORING_AGGREGATE_SHA256,
        "authoring subset aggregate hash mismatch: refusing to run"
    );
    assert_eq!(
        hashes
            .get("./specification/Followee-Specification.md")
            .map(String::as_str),
        Some(SPECIFICATION_SHA256),
        "pinned specification hash mismatch"
    );
    hashes
}

/// The recorded exact request and response lines of one output group.
struct GroupLines {
    requests: Vec<String>,
    responses: Vec<String>,
}

impl GroupLines {
    fn new() -> Self {
        GroupLines {
            requests: Vec::new(),
            responses: Vec::new(),
        }
    }
}

struct Engine {
    config: InteropConfig,
}

impl Engine {
    fn new() -> Self {
        Engine {
            config: InteropConfig {
                // Frozen outputs identify their revision through the
                // repository; hello is not part of the recorded outputs.
                implementation_commit: "recorded-at-freeze".to_owned(),
            },
        }
    }

    /// Runs one operation, recording the exact lines, and returns the
    /// parsed response.
    fn run(&self, group: &mut GroupLines, case_id: &str, operation: &str, input: Value) -> Value {
        let request = json!({
            "interfaceProtocol": "1",
            "caseId": case_id,
            "operation": operation,
            "input": input,
        })
        .to_string();
        let response_line = handle_line(&self.config, &request);
        let response: Value = serde_json::from_str(&response_line).expect("response JSON");
        assert_eq!(response["caseId"], case_id);
        group.requests.push(request);
        group.responses.push(response_line);
        response
    }

    /// Runs every case of a published-vector file, checking each published
    /// expected member against our computed member.
    fn run_expected_cases(&self, file: &Value, only_operation: Option<&str>) -> GroupLines {
        let mut lines = GroupLines::new();
        for case in file["cases"].as_array().expect("cases") {
            let operation = case["operation"].as_str().expect("operation");
            if only_operation.is_some_and(|wanted| wanted != operation) {
                continue;
            }
            let case_id = case["id"].as_str().expect("id");
            let response = self.run(&mut lines, case_id, operation, case["input"].clone());
            assert_eq!(response["status"], "accepted", "{case_id}: {response}");
            for (member, expected) in case["expected"].as_object().expect("expected") {
                assert_eq!(
                    &response["result"][member], expected,
                    "{case_id}: published member {member} must reproduce"
                );
            }
        }
        lines
    }

    /// Runs the published negative envelopes through `verifyRecord`,
    /// constructing recipe-defined envelopes and checking every published
    /// digest, length, and error classification.
    fn run_negative_cases(&self, negative: &Value, records: &Value, alice_did: &str) -> GroupLines {
        let mut lines = GroupLines::new();
        for case in negative["cases"].as_array().expect("cases") {
            let case_id = case["id"].as_str().expect("id");
            let envelope_hex = match case["envelopeHex"].as_str() {
                Some(published) => published.to_owned(),
                None => {
                    let construction = &case["construction"];
                    let base_case = construction["baseBody"]["case"].as_str().expect("case");
                    let base_field = construction["baseBody"]["field"].as_str().expect("field");
                    let base_hex = expected_member(records, base_case, base_field);
                    assert_eq!(
                        construction["mapHeadChange"], "a6-to-a7",
                        "{case_id}: the published recipe form"
                    );
                    let mut body = hex::decode(&base_hex).expect("base body hex");
                    assert_eq!(body[0], 0xA6);
                    body[0] = 0xA7;
                    body.extend_from_slice(
                        &hex::decode(construction["appendedBytesHex"].as_str().expect("appended"))
                            .expect("appended hex"),
                    );
                    // Cross-check the published digest and Sig_structure
                    // length for the constructed body.
                    assert_eq!(
                        sha256_hex(&body),
                        case["recordBodyDigestHex"].as_str().expect("digest"),
                        "{case_id}: constructed body reproduces the published digest"
                    );
                    let sig_structure_len = followee::sig_structure(&body).len().to_string();
                    assert_eq!(
                        Some(sig_structure_len.as_str()),
                        case["sigStructureLength"].as_str(),
                        "{case_id}: published Sig_structure length"
                    );
                    let signature = hex::decode(case["signatureHex"].as_str().expect("signature"))
                        .expect("signature hex");
                    hex::encode(assemble_envelope(&body, &signature))
                }
            };
            let response = self.run(
                &mut lines,
                case_id,
                "verifyRecord",
                json!({
                    "targetDid": alice_did,
                    "envelopeHex": envelope_hex,
                    "nowMs": NEGATIVE_VERIFY_NOW_MS,
                }),
            );
            assert_eq!(response["status"], "rejected", "{case_id}: {response}");
            assert_eq!(
                response["error"], case["expectedError"],
                "{case_id}: published error classification"
            );
        }
        lines
    }

    /// Runs the complete blind-challenge rerun per CHALLENGES.md: derive,
    /// author (materialising identity references from our own derivations),
    /// self-verify, and select over every enumerated permutation.
    fn run_challenges(&self, authoring: &Path) -> ChallengeOutputs {
        let identities_file =
            read_json(&authoring.join("vectors/challenge/challenge-identities.json"));
        let records_file = read_json(&authoring.join("vectors/challenge/challenge-records.json"));
        let selection_file =
            read_json(&authoring.join("vectors/challenge/challenge-selection.json"));

        // Step 1: derive every challenge identity.
        let mut identity_lines = GroupLines::new();
        let mut seeds: BTreeMap<String, (String, String)> = BTreeMap::new();
        let mut dids: BTreeMap<String, String> = BTreeMap::new();
        for case in identities_file["cases"].as_array().expect("cases") {
            let case_id = case["id"].as_str().expect("id");
            let name = case_id
                .strip_prefix("challenge-identity-")
                .expect("identity case id form")
                .to_owned();
            let response = self.run(
                &mut identity_lines,
                case_id,
                "deriveIdentity",
                case["input"].clone(),
            );
            assert_eq!(response["status"], "accepted", "{case_id}: {response}");
            seeds.insert(
                name.clone(),
                (
                    case["input"]["rootSeedHex"]
                        .as_str()
                        .expect("root seed")
                        .to_owned(),
                    case["input"]["revocationSeedHex"]
                        .as_str()
                        .expect("revocation seed")
                        .to_owned(),
                ),
            );
            dids.insert(
                name,
                response["result"]["did"].as_str().expect("did").to_owned(),
            );
        }

        // Step 2: author every challenge record, replacing identityRef
        // migration values with the DIDs we ourselves derived.
        let mut record_lines = GroupLines::new();
        let mut envelopes: BTreeMap<String, String> = BTreeMap::new();
        let mut record_identity: BTreeMap<String, String> = BTreeMap::new();
        for case in records_file["cases"].as_array().expect("cases") {
            let case_id = case["id"].as_str().expect("id");
            let identity = case["identityRef"].as_str().expect("identityRef");
            let (root_seed, revocation_seed) = seeds
                .get(identity)
                .unwrap_or_else(|| panic!("{case_id}: unknown identityRef {identity}"));
            let mut input = case["input"].clone();
            let object = input.as_object_mut().expect("input object");
            object.insert("rootSeedHex".to_owned(), json!(root_seed));
            object.insert("revocationSeedHex".to_owned(), json!(revocation_seed));
            materialize_identity_refs(&mut input, &dids);
            let response = self.run(&mut record_lines, case_id, "authorRecord", input);
            assert_eq!(response["status"], "accepted", "{case_id}: {response}");
            envelopes.insert(
                case_id.to_owned(),
                response["result"]["envelopeHex"]
                    .as_str()
                    .expect("envelope")
                    .to_owned(),
            );
            record_identity.insert(case_id.to_owned(), identity.to_owned());
        }

        // Step 3: self-verify each authored envelope at the file-level
        // verifyNowMs.
        let verify_now = records_file["verifyNowMs"].as_str().expect("verifyNowMs");
        let mut verify_lines = GroupLines::new();
        for (case_id, envelope) in &envelopes {
            let identity = &record_identity[case_id];
            let response = self.run(
                &mut verify_lines,
                &format!("{case_id}-verify"),
                "verifyRecord",
                json!({
                    "targetDid": dids[identity],
                    "envelopeHex": envelope,
                    "nowMs": verify_now,
                }),
            );
            assert_eq!(response["status"], "accepted", "{case_id}: {response}");
        }

        // Step 4: run every selection case, materialising challengeCase
        // references, and require permutation-group agreement.
        let mut selection_lines = GroupLines::new();
        let mut group_winners: BTreeMap<String, Value> = BTreeMap::new();
        for case in selection_file["cases"].as_array().expect("cases") {
            let case_id = case["id"].as_str().expect("id");
            let target = case["input"]["targetIdentityRef"]
                .as_str()
                .expect("target ref");
            let candidates: Vec<Value> = case["input"]["candidates"]
                .as_array()
                .expect("candidates")
                .iter()
                .map(|reference| {
                    let name = reference["challengeCase"].as_str().expect("challengeCase");
                    json!(envelopes[name])
                })
                .collect();
            let response = self.run(
                &mut selection_lines,
                case_id,
                "selectCurrent",
                json!({
                    "targetDid": dids[target],
                    "candidateEnvelopesHex": candidates,
                    "nowMs": case["input"]["nowMs"],
                    "stickyAuthority": case["input"]["stickyAuthority"],
                }),
            );
            assert_eq!(response["status"], "accepted", "{case_id}: {response}");
            if let Some(group) = case["permutationOf"].as_str() {
                let outcome = response["result"].clone();
                if let Some(first) = group_winners.get(group) {
                    assert_eq!(
                        first, &outcome,
                        "{case_id}: every permutation of {group} selects the same winner"
                    );
                } else {
                    group_winners.insert(group.to_owned(), outcome);
                }
            }
        }

        ChallengeOutputs {
            identities: identity_lines,
            records: record_lines,
            verify: verify_lines,
            selection: selection_lines,
        }
    }
}

struct ChallengeOutputs {
    identities: GroupLines,
    records: GroupLines,
    verify: GroupLines,
    selection: GroupLines,
}

/// Replaces every `{"identityRef": name}` object in the input tree with
/// the canonical DID this run derived for that identity (CHALLENGES.md
/// step 2).
fn materialize_identity_refs(value: &mut Value, dids: &BTreeMap<String, String>) {
    match value {
        Value::Object(members) => {
            if members.len() == 1
                && let Some(Value::String(name)) = members.get("identityRef")
            {
                let did = dids
                    .get(name)
                    .unwrap_or_else(|| panic!("unknown identityRef {name}"))
                    .clone();
                *value = Value::String(did);
                return;
            }
            for (_, member) in members.iter_mut() {
                materialize_identity_refs(member, dids);
            }
        }
        Value::Array(items) => {
            for item in items {
                materialize_identity_refs(item, dids);
            }
        }
        _ => {}
    }
}

/// Reads one published expected member from a vector file.
fn expected_member(file: &Value, case_id: &str, member: &str) -> String {
    file["cases"]
        .as_array()
        .expect("cases")
        .iter()
        .find(|case| case["id"] == case_id)
        .unwrap_or_else(|| panic!("case {case_id} present"))["expected"][member]
        .as_str()
        .unwrap_or_else(|| panic!("member {member} of {case_id}"))
        .to_owned()
}

// ---------------------------------------------------------------------------
// Raw CBOR emit helpers for recipe construction. Deliberately independent
// of the crate's writer, in the same spirit as the conformance suite's
// fixture builders: reproduced wire bytes are not produced by the code
// under test unless the case explicitly exercises production emission.
// ---------------------------------------------------------------------------

fn head(major: u8, arg: u64) -> Vec<u8> {
    let mut out = Vec::new();
    let m = major << 5;
    match arg {
        0..=23 => out.push(m | (arg as u8)),
        24..=255 => {
            out.push(m | 24);
            out.push(arg as u8);
        }
        256..=65_535 => {
            out.push(m | 25);
            out.extend_from_slice(&(arg as u16).to_be_bytes());
        }
        65_536..=4_294_967_295 => {
            out.push(m | 26);
            out.extend_from_slice(&(arg as u32).to_be_bytes());
        }
        _ => {
            out.push(m | 27);
            out.extend_from_slice(&arg.to_be_bytes());
        }
    }
    out
}

fn c_uint(v: u64) -> Vec<u8> {
    head(0, v)
}

fn c_bstr(bytes: &[u8]) -> Vec<u8> {
    let mut out = head(2, bytes.len() as u64);
    out.extend_from_slice(bytes);
    out
}

fn c_tstr(s: &str) -> Vec<u8> {
    let mut out = head(3, s.len() as u64);
    out.extend_from_slice(s.as_bytes());
    out
}

fn c_array(items: &[Vec<u8>]) -> Vec<u8> {
    let mut out = head(4, items.len() as u64);
    for item in items {
        out.extend_from_slice(item);
    }
    out
}

/// Map entries emitted in the exact given order (permits deliberate
/// duplicates for the B.11.1 invalid request).
fn c_map(entries: &[(Vec<u8>, Vec<u8>)]) -> Vec<u8> {
    let mut out = head(5, entries.len() as u64);
    for (key, value) in entries {
        out.extend_from_slice(key);
        out.extend_from_slice(value);
    }
    out
}

/// Assembles a complete tagged COSE envelope from raw body bytes and a
/// given 64-byte signature, exactly as specification section 6.2 states.
fn assemble_envelope(body: &[u8], signature: &[u8]) -> Vec<u8> {
    assert_eq!(signature.len(), 64);
    let mut out = vec![0xD2]; // tag 18
    out.push(0x84); // array(4)
    out.extend_from_slice(&[0x43, 0xA1, 0x01, 0x32]); // protected bytes
    out.push(0xA0); // empty unprotected map
    out.extend_from_slice(&c_bstr(body));
    out.extend_from_slice(&c_bstr(signature));
    out
}

// ---------------------------------------------------------------------------
// Appendix B.11 wire-message reproduction and production evidence
// ---------------------------------------------------------------------------

/// A canned-response transport keyed by exact URL, recording every request.
struct CannedTransport {
    responses: BTreeMap<String, Vec<u8>>,
    seen: RefCell<Vec<(String, Vec<u8>)>>,
}

impl CannedTransport {
    fn new(responses: BTreeMap<String, Vec<u8>>) -> Self {
        CannedTransport {
            responses,
            seen: RefCell::new(Vec::new()),
        }
    }
}

impl Transport for CannedTransport {
    fn execute(&self, request: &TransportRequest<'_>) -> Result<TransportResponse, TransportError> {
        self.seen
            .borrow_mut()
            .push((request.url.to_owned(), request.body.to_vec()));
        let body = self
            .responses
            .get(request.url)
            .unwrap_or_else(|| panic!("unexpected URL {}", request.url))
            .clone();
        Ok(TransportResponse {
            status: 200,
            content_type: Some("application/cbor".to_owned()),
            location: None,
            body,
        })
    }
}

fn expected_hex(case: &Value, member: &str) -> String {
    case[member]
        .as_str()
        .unwrap_or_else(|| panic!("member {member}"))
        .to_owned()
}

fn find_case<'a>(file: &'a Value, id: &str) -> &'a Value {
    file["cases"]
        .as_array()
        .expect("cases")
        .iter()
        .find(|case| case["id"] == id)
        .unwrap_or_else(|| panic!("case {id} present"))
}

/// A production relay seeded with the exact B.4 and B.9 records under the
/// published B.11 directory generation, through ordinary ingress.
fn seeded_relay(
    directory_generation: [u8; 16],
    alice_envelope: &[u8],
    bob_envelope: &[u8],
) -> Relay {
    let relay = Relay::new(
        Box::new(MemoryStore::new(RelayIdentity {
            relay_id: [0xAA; 16],
            cursor_generation: [0xC0; 16],
            directory_generation,
        })),
        Box::new(ManualClock::new(1_785_589_201_123)),
        RelayConfig {
            base_uri: "http://127.0.0.1/".to_owned(),
            development_mode: true,
        },
    )
    .expect("relay config");
    for envelope in [alice_envelope, bob_envelope] {
        let response = relay.publish(envelope).expect("publish");
        assert_eq!(response[..], [0xA2, 0x00, 0x01, 0x01, 0x00], "admitted");
    }
    relay
}

fn meter() -> BudgetMeter {
    BudgetMeter::new(OperationBudget {
        deadline_ms: None,
        max_response_bytes: 8 * 1024 * 1024,
        max_requests: 64,
    })
}

/// Reproduces every Appendix B.11 message, verifies the published lengths
/// and digests, and exercises the applicable production behaviour,
/// returning the report rows.
#[allow(clippy::too_many_lines)]
fn wire_b11_report(wire: &Value, records: &Value, negative: &Value, identities: &Value) -> Value {
    let directory_generation: [u8; 16] =
        hex::decode(wire["directoryGenerationHex"].as_str().expect("generation"))
            .expect("hex")
            .try_into()
            .expect("16 bytes");
    let alice_did = expected_member(identities, "identity-alice", "did");
    let bob_did = expected_member(identities, "identity-bob", "did");
    let attacker_did = expected_member(identities, "identity-attacker", "did");
    let alice_envelope =
        hex::decode(expected_member(records, "b4-root", "envelopeHex")).expect("hex");
    let bob_envelope =
        hex::decode(expected_member(records, "b9-bob-root", "envelopeHex")).expect("hex");
    let b8_envelope = hex::decode(expected_hex(
        find_case(negative, "b8-descriptor-substitution"),
        "envelopeHex",
    ))
    .expect("hex");

    let mut rows: Vec<Value> = Vec::new();
    let mut row = |id: &str, side: &str, bytes: &[u8], published_sha: &str, evidence: &str| {
        let sha = sha256_hex(bytes);
        assert_eq!(
            sha, published_sha,
            "{id} {side}: published digest reproduces"
        );
        rows.push(json!({
            "id": id,
            "side": side,
            "length": bytes.len().to_string(),
            "sha256": sha,
            "bytesHex": hex::encode(bytes),
            "matchesPublished": true,
            "productionEvidence": evidence,
        }));
    };

    let full = |envelope: &[u8]| c_map(&[(c_uint(0), c_uint(0)), (c_uint(1), c_bstr(envelope))]);
    let clock = ManualClock::new(1_785_589_201_123);

    // B.11.1: invalid outer request (duplicate top-level label 1).
    {
        let case = find_case(wire, "b11-1-invalid-outer-request");
        let built = c_map(&[
            (c_uint(0), c_uint(1)),
            (c_uint(1), c_array(&[c_tstr(&alice_did)])),
            (c_uint(1), c_array(&[c_tstr(&bob_did)])),
        ]);
        assert_eq!(hex::encode(&built), expected_hex(case, "requestBytesHex"));
        assert_eq!(
            followee::validate_cbor(&built, 8, 256),
            Err(followee::error::VerifyError::InvalidCbor),
            "duplicate labels are basic invalidity"
        );
        row(
            "b11-1-invalid-outer-request",
            "request",
            &built,
            &expected_hex(case, "requestSha256"),
            "production classification invalidCbor; served HTTP 400 with no per-item body (tests/relay_http.rs)",
        );
    }

    // B.11.2: invalid outer response rejected by the production client.
    {
        let case = find_case(wire, "b11-2-invalid-outer-response");
        let built = hex::decode(expected_hex(case, "responseBytesHex")).expect("hex");
        let transport = CannedTransport::new(BTreeMap::from([(
            "http://127.0.0.1:9001/v1/resolve".to_owned(),
            built.clone(),
        )]));
        let client = RelayClient::new(&transport, NetworkPolicy::Development, &clock);
        let outcome = client.resolve("http://127.0.0.1:9001/", &[&alice_did], &mut meter());
        let rejected = matches!(
            outcome,
            Err(followee::relay::client::ClientError::OuterResponse(
                followee::error::VerifyError::NonDeterministicCbor
            ))
        );
        assert!(
            rejected,
            "production client rejects as nonDeterministicCbor"
        );
        row(
            "b11-2-invalid-outer-response",
            "response",
            &built,
            &expected_hex(case, "responseSha256"),
            "production client rejects the complete response as nonDeterministicCbor; never Absent",
        );
    }

    // B.11.3: candidate isolation. The production client emits the exact
    // published request bytes and isolates the invalid candidate.
    {
        let case = find_case(wire, "b11-3-resolve-candidate-isolation");
        let response = c_map(&[
            (c_uint(0), c_uint(1)),
            (c_uint(1), c_bstr(&directory_generation)),
            (
                c_uint(2),
                c_array(&[full(&b8_envelope), full(&bob_envelope)]),
            ),
        ]);
        let transport = CannedTransport::new(BTreeMap::from([(
            "http://127.0.0.1:9001/v1/resolve".to_owned(),
            response.clone(),
        )]));
        let client = RelayClient::new(&transport, NetworkPolicy::Development, &clock);
        let outcome = client
            .resolve(
                "http://127.0.0.1:9001/",
                &[&alice_did, &bob_did],
                &mut meter(),
            )
            .expect("wrapper accepted");
        let sent = transport.seen.borrow()[0].1.clone();
        assert_eq!(
            hex::encode(&sent),
            expected_hex(case, "requestBytesHex"),
            "production client emits the exact published request bytes"
        );
        row(
            "b11-3-resolve-candidate-isolation",
            "request",
            &sent,
            &expected_hex(case, "requestSha256"),
            "emitted by the production RelayClient",
        );
        // Index 0 (B.8) fails complete verification; index 1 verifies.
        use followee::relay::client::ReceivedResult;
        let results = &outcome.value.results;
        let first_rejected = matches!(&results[0], ReceivedResult::Full(bytes)
            if followee::verify::verify_record_for_target(&alice_did, bytes)
                == Err(followee::error::VerifyError::IdentityBindingMismatch));
        let second_ok = matches!(&results[1], ReceivedResult::Full(bytes)
            if followee::verify::verify_record_for_target(&bob_did, bytes).is_ok());
        assert!(first_rejected && second_ok, "positional isolation");
        row(
            "b11-3-resolve-candidate-isolation",
            "response",
            &response,
            &expected_hex(case, "responseSha256"),
            "wrapper accepted; index 0 discarded as identityBindingMismatch; index 1 retained",
        );
    }

    // B.11.4: duplicate DIDs and cardinality, served by the production
    // relay from ordinary ingress state.
    {
        let case = find_case(wire, "b11-4-duplicate-dids-cardinality");
        let request = hex::decode(expected_hex(case, "requestBytesHex")).expect("hex");
        let relay = seeded_relay(directory_generation, &alice_envelope, &bob_envelope);
        let response = relay.publish_free_resolve(&request);
        row(
            "b11-4-duplicate-dids-cardinality",
            "request",
            &request,
            &expected_hex(case, "requestSha256"),
            "published request bytes",
        );
        row(
            "b11-4-duplicate-dids-cardinality",
            "response",
            &response,
            &expected_hex(case, "responseSha256"),
            "emitted by the production relay from ordinary verified ingress state",
        );
    }

    // B.11.5: changes isolation and cursor progress through the production
    // synchronization receiver.
    {
        let case = find_case(wire, "b11-5-changes-isolation-cursor");
        let request = hex::decode(expected_hex(case, "requestBytesHex")).expect("hex");
        let state = &case["initialReceiverState"];
        let next_cursor = b"v08-0002";
        let response = c_map(&[
            (c_uint(0), c_uint(1)),
            (c_uint(1), c_uint(0)),
            (
                c_uint(2),
                c_array(&[
                    c_array(&[c_tstr(&alice_did), full(&b8_envelope), c_uint(1001)]),
                    c_array(&[c_tstr(&bob_did), full(&bob_envelope), c_uint(1002)]),
                ]),
            ),
            (c_uint(3), c_bstr(next_cursor)),
            (c_uint(4), vec![0xF4]),
            (c_uint(5), c_bstr(&directory_generation)),
        ]);
        row(
            "b11-5-changes-isolation-cursor",
            "request",
            &request,
            &expected_hex(case, "requestSha256"),
            "published request bytes (opaque cursor v08-0000, itemLimit 2)",
        );

        let receiver = b11_receiver(state, &alice_envelope);
        let report = run_sync(&receiver, &clock, response.clone(), 2);
        let sync_report = report.expect("accepted success response");
        let post = &case["requiredPostState"];
        let alice_after = receiver
            .with_store(|store| store.entry(&alice_did))
            .expect("read")
            .expect("alice retained");
        assert!(
            matches!(&alice_after.payload, EntryPayload::Full(bytes) if *bytes == alice_envelope),
            "Alice byte-for-byte unchanged"
        );
        assert_eq!(
            alice_after.last_updated.to_string(),
            state["alice"]["lastUpdated"]
        );
        let bob_after = receiver
            .with_store(|store| store.entry(&bob_did))
            .expect("read")
            .expect("bob admitted");
        assert_eq!(bob_after.last_updated.to_string(), post["bobLastUpdated"]);
        let counter = receiver
            .with_store(|store| store.last_update_number())
            .expect("read");
        assert_eq!(counter.to_string(), post["localUpdateCounter"]);
        assert_eq!(
            hex::encode(sync_report.final_cursor.expect("cursor stored")),
            post["peerCursorHex"].as_str().expect("cursor"),
            "stored peer cursor is the exact returned bytes"
        );
        row(
            "b11-5-changes-isolation-cursor",
            "response",
            &response,
            &expected_hex(case, "responseSha256"),
            "processed by the production synchronization receiver: Alice unchanged, Bob admitted at 42, cursor v08-0002",
        );
    }

    // B.11.6: malformed DID inside a valid batch, served by the production
    // relay.
    {
        let case = find_case(wire, "b11-6-malformed-did-in-batch");
        let request = hex::decode(expected_hex(case, "requestBytesHex")).expect("hex");
        let relay = seeded_relay(directory_generation, &alice_envelope, &bob_envelope);
        let response = relay.publish_free_resolve(&request);
        row(
            "b11-6-malformed-did-in-batch",
            "request",
            &request,
            &expected_hex(case, "requestSha256"),
            "published request bytes",
        );
        row(
            "b11-6-malformed-did-in-batch",
            "response",
            &response,
            &expected_hex(case, "responseSha256"),
            "emitted by the production relay: HTTP 200 semantics with the aligned per-DID Error(invalidDid)",
        );
    }

    // B.11.7: item-limit overflow rejected by the production receiver
    // before any entry is processed.
    {
        let case = find_case(wire, "b11-7-changes-item-limit-overflow");
        let state = find_case(wire, "b11-5-changes-isolation-cursor");
        let response = c_map(&[
            (c_uint(0), c_uint(1)),
            (c_uint(1), c_uint(0)),
            (
                c_uint(2),
                c_array(&[
                    c_array(&[c_tstr(&alice_did), full(&b8_envelope), c_uint(1001)]),
                    c_array(&[c_tstr(&bob_did), full(&bob_envelope), c_uint(1002)]),
                    c_array(&[
                        c_tstr(&attacker_did),
                        c_map(&[(c_uint(0), c_uint(1)), (c_uint(1), c_uint(0))]),
                        c_uint(1003),
                    ]),
                ]),
            ),
            (c_uint(3), c_bstr(b"v08-0003")),
            (c_uint(4), vec![0xF4]),
            (c_uint(5), c_bstr(&directory_generation)),
        ]);
        let receiver = b11_receiver(&state["initialReceiverState"], &alice_envelope);
        let outcome = run_sync(&receiver, &clock, response.clone(), 2);
        assert!(outcome.is_err(), "over-limit response rejected completely");
        let counter = receiver
            .with_store(|store| store.last_update_number())
            .expect("read");
        assert_eq!(counter, 41, "no entry processed");
        let cursor = receiver
            .with_store(|store| store.peer_state(&[0xEE; 16]))
            .expect("read")
            .expect("peer state")
            .cursor;
        assert_eq!(
            cursor.as_deref(),
            Some(b"v08-0000".as_slice()),
            "cursor unchanged"
        );
        row(
            "b11-7-changes-item-limit-overflow",
            "response",
            &response,
            &expected_hex(case, "responseSha256"),
            "rejected by the production receiver before any entry; cursor v08-0003 never stored",
        );
    }

    Value::Array(rows)
}

/// Builds the B.11.5/B.11.7 initial receiver: Alice's exact B.4 entry at
/// `lastUpdated = 41`, counter 41, Bob absent, peer cursor `v08-0000`.
fn b11_receiver(state: &Value, alice_envelope: &[u8]) -> Relay {
    let now: u64 = state["nowMs"]
        .as_str()
        .expect("nowMs")
        .parse()
        .expect("u64");
    let relay = Relay::new(
        Box::new(MemoryStore::new(RelayIdentity {
            relay_id: [0xAB; 16],
            cursor_generation: [0xC2; 16],
            directory_generation: [0xD0; 16],
        })),
        Box::new(ManualClock::new(now)),
        RelayConfig {
            base_uri: "http://127.0.0.1/".to_owned(),
            development_mode: true,
        },
    )
    .expect("relay config");
    // The B.4 record's own signed Alice DID, established through complete
    // production verification of the envelope being seeded.
    let alice_did = followee::verify::verify_record_for_target(
        "did:flw:zQmPcGstBa7wW9hoYQbS6JZ4UxwZmoKr7YVf9y7qxiyD3Cm",
        alice_envelope,
    )
    .expect("B.4 verifies")
    .body()
    .id
    .clone();
    let verified = followee::verify::verify_record(&alice_did, alice_envelope).expect("B.4");
    let target_updates: u64 = state["alice"]["lastUpdated"]
        .as_str()
        .expect("lastUpdated")
        .parse()
        .expect("u64");
    relay
        .with_store(|store| {
            for _ in 0..target_updates {
                store.commit_current(
                    alice_did.as_str(),
                    verified.envelope_bytes(),
                    AuthorityState::Root,
                    OrderingMeta {
                        authority: Authority::Root,
                        timestamp_ms: verified.timestamp_ms(),
                        body_digest: *verified.body_digest(),
                    },
                )?;
            }
            store.set_peer_state(&PeerState {
                relay_id: [0xEE; 16],
                endpoint: "http://127.0.0.1:9001/".to_owned(),
                cursor: Some(
                    hex::decode(state["peerCursorHex"].as_str().expect("cursor")).expect("hex"),
                ),
            })
        })
        .expect("seed");
    relay
}

/// Runs one production `sync_once` pass against a canned peer serving the
/// given changes response.
fn run_sync(
    receiver: &Relay,
    clock: &ManualClock,
    changes_response: Vec<u8>,
    item_limit: u64,
) -> Result<followee::relay::sync::SyncReport, followee::relay::sync::SyncError> {
    let info = c_map(&[
        (c_uint(0), c_uint(1)),
        (c_uint(1), c_bstr(&[0xEE; 16])),
        (c_uint(2), c_uint(0x01 | 0x02)),
        (c_uint(3), c_array(&[c_uint(1)])),
        (c_uint(4), c_array(&[vec![0x32]])), // -19
        (
            c_uint(5),
            c_map(&[
                (c_uint(0), c_uint(16 * 1024)),
                (c_uint(1), c_uint(256)),
                (c_uint(2), c_uint(1024 * 1024)),
                (c_uint(3), c_uint(1024)),
                (c_uint(4), c_uint(4 * 1024 * 1024)),
            ]),
        ),
        (c_uint(6), c_bstr(&[0xC5; 16])),
        (c_uint(7), c_bstr(&[0xD5; 16])),
        (c_uint(8), c_tstr("http://127.0.0.1:9001/")),
    ]);
    let transport = CannedTransport::new(BTreeMap::from([
        ("http://127.0.0.1:9001/v1/info".to_owned(), info),
        (
            "http://127.0.0.1:9001/v1/changes".to_owned(),
            changes_response,
        ),
    ]));
    let client = RelayClient::new(&transport, NetworkPolicy::Development, clock);
    receiver.sync_once(
        &client,
        "http://127.0.0.1:9001/",
        &SyncOptions {
            item_limit,
            byte_limit: 1024 * 1024,
            max_pages: 1,
        },
        &mut meter(),
    )
}

/// Extension trait alias: `Relay::resolve` under a name that makes the
/// report's provenance clear.
trait PublishFreeResolve {
    fn publish_free_resolve(&self, request: &[u8]) -> Vec<u8>;
}

impl PublishFreeResolve for Relay {
    /// Serves `v1/resolve` for the already seeded relay: no further
    /// publication happens while reproducing response bytes.
    fn publish_free_resolve(&self, request: &[u8]) -> Vec<u8> {
        self.resolve(request).expect("resolve")
    }
}
