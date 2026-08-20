//! Neutral interoperability interface conformance (Milestone 6; the
//! v0.9.2 authoring subset's INTERFACE.md).
//!
//! Exercises the `followee::interop` engine — the surface behind
//! `followee interop` — against the published Appendix B values, the
//! interface's input-contract rules, and the specification v0.9.2
//! publish-response status-dependent union through the neutral
//! `receivePublishResponse` operation (which decodes through the exact
//! production `relay::wire::parse_publish_response` path).

mod common;

use common::{fx_bytes, fx_str, r_array, r_map, r_tstr, r_uint, root_seed};
use followee::interop::{InteropConfig, handle_line};
use serde_json::{Value, json};

fn config() -> InteropConfig {
    InteropConfig {
        implementation_commit: "test".to_owned(),
    }
}

/// Sends one request object and parses the response line.
fn call(operation: &str, input: Value) -> Value {
    let request = json!({
        "interfaceProtocol": "1",
        "caseId": format!("case-{operation}"),
        "operation": operation,
        "input": input,
    });
    let response = handle_line(&config(), &request.to_string());
    serde_json::from_str(&response).expect("response is valid JSON")
}

fn expect_accepted(operation: &str, input: Value) -> Value {
    let response = call(operation, input);
    assert_eq!(
        response["status"], "accepted",
        "{operation} should be accepted: {response}"
    );
    assert_eq!(response["interfaceProtocol"], "1");
    assert_eq!(response["caseId"], format!("case-{operation}"));
    response["result"].clone()
}

fn expect_rejected(operation: &str, input: Value, error: &str) {
    let response = call(operation, input);
    assert_eq!(
        response["status"], "rejected",
        "{operation} should be rejected: {response}"
    );
    assert_eq!(response["error"], error, "{response}");
}

fn expect_input_error(operation: &str, input: Value) {
    let response = call(operation, input);
    assert_eq!(
        response["status"], "error",
        "{operation} should be an input-contract error: {response}"
    );
    assert_eq!(response["errorSymbol"], "followee-rs.inputContract");
}

fn alice_contact() -> Value {
    json!({
        "displayName": "Alice Example",
        "summary": "Writer",
        "avatar": null,
        "alsoKnownAs": ["acct:alice@example.com"],
        "services": [{
            "id": "feed",
            "type": "Feed",
            "endpoint": "https://alice.example/feed.xml",
            "mediaType": "application/atom+xml",
            "label": "Writing",
            "language": null,
            "rel": null
        }],
        "migration": null,
        "extensions": {}
    })
}

// ---------------------------------------------------------------------------
// Envelope and input-contract framing
// ---------------------------------------------------------------------------

#[test]
fn interface_envelope_enforces_the_input_contract() {
    let cfg = config();
    // Unknown envelope member.
    let response = handle_line(
        &cfg,
        r#"{"interfaceProtocol":"1","caseId":"c","operation":"hello","input":{},"extra":"x"}"#,
    );
    let parsed: Value = serde_json::from_str(&response).expect("json");
    assert_eq!(parsed["status"], "error");
    assert_eq!(parsed["caseId"], "c", "caseId echoed even on violations");

    // Duplicate members are rejected by the strict parser.
    let response = handle_line(
        &cfg,
        r#"{"interfaceProtocol":"1","interfaceProtocol":"1","caseId":"c","operation":"hello","input":{}}"#,
    );
    let parsed: Value = serde_json::from_str(&response).expect("json");
    assert_eq!(parsed["status"], "error");

    // Bare JSON numbers are rejected anywhere.
    let response = handle_line(
        &cfg,
        r#"{"interfaceProtocol":"1","caseId":"c","operation":"nextTimestamp","input":{"nowMs":1000,"previousTimestampMs":null}}"#,
    );
    let parsed: Value = serde_json::from_str(&response).expect("json");
    assert_eq!(parsed["status"], "error");

    // Unsupported interface protocol and unknown operation.
    let response = handle_line(
        &cfg,
        r#"{"interfaceProtocol":"2","caseId":"c","operation":"hello","input":{}}"#,
    );
    let parsed: Value = serde_json::from_str(&response).expect("json");
    assert_eq!(parsed["status"], "error");
    let parsed: Value = serde_json::from_str(&handle_line(
        &cfg,
        r#"{"interfaceProtocol":"1","caseId":"c","operation":"frobnicate","input":{}}"#,
    ))
    .expect("json");
    assert_eq!(parsed["status"], "error");
}

#[test]
fn interface_hello_reports_the_participant_metadata() {
    let result = expect_accepted("hello", json!({}));
    assert_eq!(result["implementation"], "followee-rs");
    assert_eq!(
        result["implementationRepository"],
        "https://github.com/followee-protocol/followee-rs"
    );
    assert_eq!(result["implementationCommit"], "test");
    assert_eq!(
        result["specificationCommit"],
        "f1d19fec0dba455d90d473bfad625d1c288e0c15"
    );
    assert_eq!(result["interfaceProtocols"], json!(["1"]));
    let operations = result["operations"].as_array().expect("array");
    assert!(
        operations.iter().any(|op| op == "receivePublishResponse"),
        "operations must include receivePublishResponse: {operations:?}"
    );
    assert_eq!(operations.len(), 9);
}

#[test]
fn interface_serve_lines_bounds_lines_and_continues() {
    let cfg = config();
    let hello = r#"{"interfaceProtocol":"1","caseId":"after","operation":"hello","input":{}}"#;
    let oversized = format!(
        "{{\"interfaceProtocol\":\"1\",\"caseId\":\"big\",\"operation\":\"hello\",\"input\":{{\"x\":\"{}\"}}}}\n{hello}\n",
        "a".repeat(1024 * 1024 + 16)
    );
    let mut reader = std::io::BufReader::new(oversized.as_bytes());
    let mut out = Vec::new();
    followee::interop::serve_lines(&cfg, &mut reader, &mut out).expect("io");
    let lines: Vec<Value> = String::from_utf8(out)
        .expect("utf8")
        .lines()
        .map(|line| serde_json::from_str(line).expect("json"))
        .collect();
    assert_eq!(lines.len(), 2);
    assert_eq!(lines[0]["status"], "error", "oversized line reported");
    assert_eq!(lines[1]["status"], "accepted", "loop continues after it");
    assert_eq!(lines[1]["caseId"], "after");
}

// ---------------------------------------------------------------------------
// deriveIdentity (Appendix B.2, B.3, B.8.1, B.9)
// ---------------------------------------------------------------------------

#[test]
fn sec_b2_b3_derive_identity_reproduces_every_published_alice_value() {
    let result = expect_accepted(
        "deriveIdentity",
        json!({
            "rootSeedHex": fx_str("root_seed"),
            "revocationSeedHex": fx_str("revocation_seed"),
        }),
    );
    assert_eq!(result["rootPublicKeyHex"], fx_str("root_public_key"));
    assert_eq!(
        result["revocationPublicKeyHex"],
        fx_str("revocation_public_key")
    );
    assert_eq!(
        result["revocationPublicKeyCborHex"],
        fx_str("revocation_public_key_cbor")
    );
    assert_eq!(
        result["revocationCommitmentHex"],
        fx_str("revocation_commitment")
    );
    assert_eq!(
        result["authorityDescriptorCborHex"],
        fx_str("authority_descriptor_cbor")
    );
    assert_eq!(
        result["authorityDescriptorDigestHex"],
        fx_str("descriptor_digest")
    );
    assert_eq!(result["multihashHex"], fx_str("multihash_bytes"));
    assert_eq!(result["did"], fx_str("followee_did"));
}

#[test]
fn sec_b9_derive_identity_reproduces_bob() {
    let result = expect_accepted(
        "deriveIdentity",
        json!({
            "rootSeedHex": fx_str("bob_root_seed"),
            "revocationSeedHex": fx_str("bob_revocation_seed"),
        }),
    );
    assert_eq!(result["rootPublicKeyHex"], fx_str("bob_root_public_key"));
    assert_eq!(
        result["revocationCommitmentHex"],
        fx_str("bob_revocation_commitment")
    );
    assert_eq!(
        result["authorityDescriptorCborHex"],
        fx_str("bob_descriptor_cbor")
    );
    assert_eq!(result["multihashHex"], fx_str("bob_multihash_bytes"));
    assert_eq!(result["did"], fx_str("bob_did"));
}

#[test]
fn sec_b8_derive_identity_reproduces_the_attacker_identity() {
    let result = expect_accepted(
        "deriveIdentity",
        json!({
            "rootSeedHex": fx_str("attacker_root_seed"),
            "revocationSeedHex": fx_str("attacker_revocation_seed"),
        }),
    );
    assert_eq!(
        result["rootPublicKeyHex"],
        fx_str("attacker_root_public_key")
    );
    assert_eq!(
        result["revocationCommitmentHex"],
        fx_str("attacker_revocation_commitment")
    );
    assert_eq!(
        result["authorityDescriptorCborHex"],
        fx_str("attacker_descriptor_cbor")
    );
    assert_eq!(result["did"], fx_str("attacker_did"));
}

#[test]
fn derive_identity_enforces_the_hex_conventions() {
    // Uppercase hex violates the lowercase binary-value convention.
    expect_input_error(
        "deriveIdentity",
        json!({
            "rootSeedHex": fx_str("root_seed").to_uppercase(),
            "revocationSeedHex": fx_str("revocation_seed"),
        }),
    );
    // Wrong length.
    expect_input_error(
        "deriveIdentity",
        json!({"rootSeedHex": "00", "revocationSeedHex": fx_str("revocation_seed")}),
    );
    // Unknown member.
    expect_input_error(
        "deriveIdentity",
        json!({
            "rootSeedHex": fx_str("root_seed"),
            "revocationSeedHex": fx_str("revocation_seed"),
            "extra": "x",
        }),
    );
}

// ---------------------------------------------------------------------------
// authorRecord (Appendix B.4, B.5, B.9)
// ---------------------------------------------------------------------------

#[test]
fn sec_b4_author_record_reproduces_the_published_root_record() {
    let result = expect_accepted(
        "authorRecord",
        json!({
            "rootSeedHex": fx_str("root_seed"),
            "revocationSeedHex": fx_str("revocation_seed"),
            "authority": "root",
            "timestampMs": "1785589200123",
            "validUntilMs": null,
            "contact": alice_contact(),
            "extensions": {},
            "signingSeed": "root",
        }),
    );
    assert_eq!(result["did"], fx_str("followee_did"));
    assert_eq!(result["recordBodyCborHex"], fx_str("root_record_body"));
    assert_eq!(result["recordBodyDigestHex"], fx_str("root_body_digest"));
    assert_eq!(result["sigStructureHex"], fx_str("root_sig_structure"));
    assert_eq!(result["signatureHex"], fx_str("root_signature"));
    assert_eq!(result["envelopeHex"], fx_str("root_record_envelope"));
}

#[test]
fn sec_b5_author_record_reproduces_the_published_root_revoked_record() {
    let result = expect_accepted(
        "authorRecord",
        json!({
            "rootSeedHex": fx_str("root_seed"),
            "revocationSeedHex": fx_str("revocation_seed"),
            "authority": "rootRevoked",
            "timestampMs": "1785589201123",
            "validUntilMs": null,
            "contact": alice_contact(),
            "extensions": {},
            "signingSeed": "revocation",
        }),
    );
    assert_eq!(result["recordBodyCborHex"], fx_str("root_revoked_body"));
    assert_eq!(
        result["recordBodyDigestHex"],
        fx_str("root_revoked_body_digest")
    );
    assert_eq!(result["signatureHex"], fx_str("root_revoked_signature"));
    assert_eq!(result["envelopeHex"], fx_str("root_revoked_envelope"));
}

#[test]
fn sec_b9_author_record_reproduces_bob() {
    let result = expect_accepted(
        "authorRecord",
        json!({
            "rootSeedHex": fx_str("bob_root_seed"),
            "revocationSeedHex": fx_str("bob_revocation_seed"),
            "authority": "root",
            "timestampMs": "1785589201123",
            "validUntilMs": null,
            "contact": {
                "displayName": "Bob Example",
                "summary": "Reader",
                "avatar": null,
                "alsoKnownAs": ["acct:bob@example.net"],
                "services": [{
                    "id": "feed",
                    "type": "Feed",
                    "endpoint": "https://bob.example/feed.xml",
                    "mediaType": "application/atom+xml",
                    "label": "Reading",
                    "language": null,
                    "rel": null
                }],
                "migration": null,
                "extensions": {}
            },
            "extensions": {},
            "signingSeed": "root",
        }),
    );
    assert_eq!(result["did"], fx_str("bob_did"));
    assert_eq!(result["recordBodyCborHex"], fx_str("bob_record_body"));
    assert_eq!(result["recordBodyDigestHex"], fx_str("bob_body_digest"));
    assert_eq!(result["sigStructureHex"], fx_str("bob_sig_structure"));
    assert_eq!(result["signatureHex"], fx_str("bob_signature"));
    assert_eq!(result["envelopeHex"], fx_str("bob_envelope"));
}

#[test]
fn author_record_rejects_incoherent_pairings_and_invalid_bodies() {
    // Incoherent authority/signingSeed is an input-contract violation.
    for (authority, seed) in [("root", "revocation"), ("rootRevoked", "root")] {
        expect_input_error(
            "authorRecord",
            json!({
                "rootSeedHex": fx_str("root_seed"),
                "revocationSeedHex": fx_str("revocation_seed"),
                "authority": authority,
                "timestampMs": "1785589200123",
                "validUntilMs": null,
                "contact": alice_contact(),
                "extensions": {},
                "signingSeed": seed,
            }),
        );
    }
    // A schema-invalid body is a protocol rejection through the production
    // authoring validation: validUntil before timestamp.
    expect_rejected(
        "authorRecord",
        json!({
            "rootSeedHex": fx_str("root_seed"),
            "revocationSeedHex": fx_str("revocation_seed"),
            "authority": "root",
            "timestampMs": "1785589200123",
            "validUntilMs": "1000",
            "contact": alice_contact(),
            "extensions": {},
            "signingSeed": "root",
        }),
        "schemaViolation",
    );
    // A malformed migration DID is the contact-schema classification.
    expect_rejected(
        "authorRecord",
        json!({
            "rootSeedHex": fx_str("root_seed"),
            "revocationSeedHex": fx_str("revocation_seed"),
            "authority": "root",
            "timestampMs": "1785589200123",
            "validUntilMs": null,
            "contact": {"migration": {"predecessor": "did:flw:not-valid", "successor": null}},
            "extensions": {},
            "signingSeed": "root",
        }),
        "schemaViolation",
    );
}

// ---------------------------------------------------------------------------
// verifyRecord, including the exact I2 record projection
// ---------------------------------------------------------------------------

#[test]
fn sec_b4_verify_record_result_carries_the_exact_i2_projection() {
    let result = expect_accepted(
        "verifyRecord",
        json!({
            "targetDid": fx_str("followee_did"),
            "envelopeHex": fx_str("root_record_envelope"),
            "nowMs": "1785589200123",
        }),
    );
    assert_eq!(result["envelopeHex"], fx_str("root_record_envelope"));
    assert_eq!(result["recordBodyCborHex"], fx_str("root_record_body"));
    assert_eq!(result["recordBodyDigestHex"], fx_str("root_body_digest"));
    assert_eq!(result["id"], fx_str("followee_did"));
    assert_eq!(result["timestampMs"], "1785589200123");
    assert_eq!(result["authority"], "root");
    assert_eq!(result["validUntilMs"], Value::Null);
    assert_eq!(result["premature"], false);
    assert_eq!(result["stale"], false);
    // The complete `record` member of authoring revision 2 (Campaign 1
    // finding I2): the closed eight-member descriptor projection, the
    // authority-dependent revocationKey, the lossless contact document,
    // and the record-level extension map — every value pinned to the
    // published Appendix B constants, so no adapter normalization or
    // cached value can survive this comparison.
    assert_eq!(
        result["record"],
        json!({
            "descriptor": {
                "descriptorVersion": "1",
                "rootKeySuite": "-19",
                "rootPublicKeyHex": fx_str("root_public_key"),
                "revocationCommitmentHex": fx_str("revocation_commitment"),
                "authorityDescriptorCborHex": fx_str("authority_descriptor_cbor"),
                "authorityDescriptorDigestHex": fx_str("descriptor_digest"),
                "multihashHex": fx_str("multihash_bytes"),
                "did": fx_str("followee_did"),
            },
            // Root record: label 5 is absent, so the member is null.
            "revocationKey": null,
            // Lossless contact presence: the B.4 contact carries labels
            // 0, 1, 3, and 4; avatar (2), migration (5), and contact
            // extensions (6) are absent wire labels and project null.
            "contact": {
                "displayName": "Alice Example",
                "summary": "Writer",
                "avatar": null,
                "alsoKnownAs": ["acct:alice@example.com"],
                "services": [{
                    "id": "feed",
                    "type": "Feed",
                    "endpoint": "https://alice.example/feed.xml",
                    "mediaType": "application/atom+xml",
                    "label": "Writing",
                    "language": null,
                    "rel": null
                }],
                "migration": null,
                "extensions": null
            },
            // Record label 8 is absent from B.4.
            "extensions": null,
        })
    );
    // The revision-2 deriveIdentity correspondence: the six shared member
    // names are equal member by member for the same identity.
    let derived = expect_accepted(
        "deriveIdentity",
        json!({
            "rootSeedHex": fx_str("root_seed"),
            "revocationSeedHex": fx_str("revocation_seed"),
        }),
    );
    for member in [
        "rootPublicKeyHex",
        "revocationCommitmentHex",
        "authorityDescriptorCborHex",
        "authorityDescriptorDigestHex",
        "multihashHex",
        "did",
    ] {
        assert_eq!(
            result["record"]["descriptor"][member], derived[member],
            "deriveIdentity correspondence for {member}"
        );
    }
}

#[test]
fn sec_b5_verify_record_projects_the_root_revoked_record() {
    let result = expect_accepted(
        "verifyRecord",
        json!({
            "targetDid": fx_str("followee_did"),
            "envelopeHex": fx_str("root_revoked_envelope"),
            "nowMs": "1785589201123",
        }),
    );
    assert_eq!(result["authority"], "rootRevoked");
    assert_eq!(
        result["record"]["descriptor"]["revocationCommitmentHex"],
        fx_str("revocation_commitment")
    );
    // RootRevoked: record.revocationKey is the exact three-member
    // projection of the revealed label-5 public-key object, matching the
    // published B.2/B.3 values and the deriveIdentity correspondence.
    assert_eq!(
        result["record"]["revocationKey"],
        json!({
            "suite": "-19",
            "publicKeyHex": fx_str("revocation_public_key"),
            "publicKeyCborHex": fx_str("revocation_public_key_cbor"),
        })
    );
}

#[test]
fn verify_record_classifies_rejections_and_bad_targets() {
    // B.8: valid attacker signature, substituted descriptor.
    expect_rejected(
        "verifyRecord",
        json!({
            "targetDid": fx_str("b8_target_did"),
            "envelopeHex": fx_str("b8_envelope"),
            "nowMs": "1785589200123",
        }),
        "identityBindingMismatch",
    );
    // Malformed targets are legitimate inputs, classified per section 3.1.
    expect_rejected(
        "verifyRecord",
        json!({
            "targetDid": "did:flw:zQ!!!",
            "envelopeHex": fx_str("root_record_envelope"),
            "nowMs": "1785589200123",
        }),
        "invalidDid",
    );
}

#[test]
fn verify_record_reports_premature_and_stale_under_the_supplied_clock() {
    // Premature: nowMs far before the B.4 timestamp minus the skew bound.
    let result = expect_accepted(
        "verifyRecord",
        json!({
            "targetDid": fx_str("followee_did"),
            "envelopeHex": fx_str("root_record_envelope"),
            "nowMs": "1000",
        }),
    );
    assert_eq!(result["premature"], true);
    assert_eq!(result["stale"], false);

    // Stale: author a bounded record, verify past its horizon.
    let authored = expect_accepted(
        "authorRecord",
        json!({
            "rootSeedHex": fx_str("root_seed"),
            "revocationSeedHex": fx_str("revocation_seed"),
            "authority": "root",
            "timestampMs": "1785589200123",
            "validUntilMs": "1785589300000",
            "contact": alice_contact(),
            "extensions": {},
            "signingSeed": "root",
        }),
    );
    let result = expect_accepted(
        "verifyRecord",
        json!({
            "targetDid": fx_str("followee_did"),
            "envelopeHex": authored["envelopeHex"],
            "nowMs": "1785589300001",
        }),
    );
    assert_eq!(result["validUntilMs"], "1785589300000");
    assert_eq!(result["stale"], true);
    assert_eq!(result["premature"], false);
}

#[test]
fn verify_record_round_trips_typed_extensions() {
    // Author a record with a nested typed extension tree and confirm the
    // projection reproduces it exactly, entries in deterministic key order.
    let extensions = json!({
        "https://example.com/ext": {
            "type": "map",
            "entries": [
                {"key": {"type": "text", "value": "b"}, "value": {"type": "bytes", "hex": "0102"}},
                {"key": {"type": "uint", "value": "7"}, "value": {"type": "bool", "value": true}},
                {"key": {"type": "nint", "value": "-2"}, "value": {"type": "null"}}
            ]
        },
        "https://example.com/list": {
            "type": "array",
            "items": [
                {"type": "uint", "value": "18446744073709551615"},
                {"type": "nint", "value": "-18446744073709551616"},
                {"type": "text", "value": "x"}
            ]
        }
    });
    let authored = expect_accepted(
        "authorRecord",
        json!({
            "rootSeedHex": fx_str("root_seed"),
            "revocationSeedHex": fx_str("revocation_seed"),
            "authority": "root",
            "timestampMs": "1785589200123",
            "validUntilMs": null,
            "contact": alice_contact(),
            "extensions": extensions,
            "signingSeed": "root",
        }),
    );
    let result = expect_accepted(
        "verifyRecord",
        json!({
            "targetDid": fx_str("followee_did"),
            "envelopeHex": authored["envelopeHex"],
            "nowMs": "1785589200123",
        }),
    );
    // Deterministic CBOR key order sorts uint 7 before nint -2 before
    // text "b".
    assert_eq!(
        result["record"]["extensions"],
        json!({
            "https://example.com/ext": {
                "type": "map",
                "entries": [
                    {"key": {"type": "uint", "value": "7"}, "value": {"type": "bool", "value": true}},
                    {"key": {"type": "nint", "value": "-2"}, "value": {"type": "null"}},
                    {"key": {"type": "text", "value": "b"}, "value": {"type": "bytes", "hex": "0102"}}
                ]
            },
            "https://example.com/list": {
                "type": "array",
                "items": [
                    {"type": "uint", "value": "18446744073709551615"},
                    {"type": "nint", "value": "-18446744073709551616"},
                    {"type": "text", "value": "x"}
                ]
            }
        })
    );
}

// ---------------------------------------------------------------------------
// strictEd25519, nextTimestamp, validateCbor
// ---------------------------------------------------------------------------

#[test]
fn sec_3_3_strict_ed25519_classifies_lengths_and_mutations() {
    let valid = expect_accepted(
        "strictEd25519",
        json!({
            "publicKeyHex": fx_str("root_public_key"),
            "messageHex": fx_str("root_sig_structure"),
            "signatureHex": fx_str("root_signature"),
        }),
    );
    assert_eq!(valid["valid"], true);

    // One flipped signature bit.
    let mut mutated = fx_bytes("root_signature");
    mutated[0] ^= 0x01;
    let flipped = expect_accepted(
        "strictEd25519",
        json!({
            "publicKeyHex": fx_str("root_public_key"),
            "messageHex": fx_str("root_sig_structure"),
            "signatureHex": hex::encode(&mutated),
        }),
    );
    assert_eq!(flipped["valid"], false);

    // Unconstrained lengths are classified by the strict verifier
    // (section 3.3 rules 1 and 2): valid=false, not an input error.
    for (key, sig) in [
        (&fx_str("root_public_key")[..62], fx_str("root_signature")),
        (
            fx_str("root_public_key").as_str(),
            fx_str("root_signature")[..126].to_owned(),
        ),
    ] {
        let result = expect_accepted(
            "strictEd25519",
            json!({
                "publicKeyHex": key,
                "messageHex": fx_str("root_sig_structure"),
                "signatureHex": sig,
            }),
        );
        assert_eq!(result["valid"], false, "wrong length is a false result");
    }

    // The Appendix B.4 S + L scalar (independently recomputed by the
    // Milestone 1 conformance suite) fails strict verification.
    let s_plus_l = "4db146d7bc6ca7690bac44b0c6ef38bcdd685ff157fdcca15da6b64662a26f94aa69aeecb156fa78fa072ff9a4e54a9e67103f9346dbef51c053cac381a50214";
    let result = expect_accepted(
        "strictEd25519",
        json!({
            "publicKeyHex": fx_str("root_public_key"),
            "messageHex": fx_str("root_sig_structure"),
            "signatureHex": s_plus_l,
        }),
    );
    assert_eq!(result["valid"], false, "S >= L is rejected");
}

#[test]
fn sec_5_3_next_timestamp_follows_the_signer_rule() {
    let result = expect_accepted(
        "nextTimestamp",
        json!({"nowMs": "1000", "previousTimestampMs": null}),
    );
    assert_eq!(result["timestampMs"], "1000");
    assert_eq!(result["error"], Value::Null);

    let result = expect_accepted(
        "nextTimestamp",
        json!({"nowMs": "1000", "previousTimestampMs": "2000"}),
    );
    assert_eq!(result["timestampMs"], "2001");

    let result = expect_accepted(
        "nextTimestamp",
        json!({"nowMs": "1000", "previousTimestampMs": "18446744073709551615"}),
    );
    assert_eq!(result["timestampMs"], Value::Null);
    assert_eq!(result["error"], "overflow");
}

#[test]
fn sec_6_1_validate_cbor_keeps_the_layer_boundary() {
    // The B.12 simple values pass structural validation (v0.8.1 boundary).
    for hex in ["f0", "f820"] {
        let result = expect_accepted(
            "validateCbor",
            json!({"cborHex": hex, "maxDepth": "8", "maxMembers": "256"}),
        );
        assert_eq!(result["valid"], true, "{hex}");
    }
    // Duplicate keys are basic invalidity.
    expect_rejected(
        "validateCbor",
        json!({"cborHex": "a20000000001", "maxDepth": "8", "maxMembers": "256"}),
        "invalidCbor",
    );
    // Non-minimal integers violate the deterministic profile.
    expect_rejected(
        "validateCbor",
        json!({"cborHex": "1801", "maxDepth": "8", "maxMembers": "256"}),
        "nonDeterministicCbor",
    );
    // Limit violations are schema classifications.
    expect_rejected(
        "validateCbor",
        json!({"cborHex": "8181818100", "maxDepth": "2", "maxMembers": "256"}),
        "schemaViolation",
    );
    // Out-of-domain limits are input errors, not protocol results.
    expect_input_error(
        "validateCbor",
        json!({"cborHex": "00", "maxDepth": "9", "maxMembers": "256"}),
    );
    expect_input_error(
        "validateCbor",
        json!({"cborHex": "00", "maxDepth": "8", "maxMembers": "257"}),
    );
}

// ---------------------------------------------------------------------------
// receivePublishResponse: the complete v0.9.2 status-dependent union
// ---------------------------------------------------------------------------

/// Deterministic publish-response bytes `{0: 1, 1: status, ? 2: code}`.
fn publish_response_hex(status: u8, code: Option<u64>) -> String {
    let mut bytes: Vec<u8> = Vec::new();
    bytes.push(if code.is_some() { 0xA3 } else { 0xA2 });
    bytes.extend_from_slice(&[0x00, 0x01, 0x01, status]);
    if let Some(code) = code {
        bytes.push(0x02);
        match code {
            0..=23 => bytes.push(code as u8),
            24..=255 => bytes.extend_from_slice(&[0x18, code as u8]),
            _ => {
                bytes.push(0x1B);
                bytes.extend_from_slice(&code.to_be_bytes());
            }
        }
    }
    hex::encode(bytes)
}

fn receive(hex: &str) -> Value {
    call("receivePublishResponse", json!({"responseHex": hex}))
}

#[test]
fn sec_12_5_receive_publish_response_accepts_every_conforming_combination() {
    // Status 0 bare.
    let response = receive(&publish_response_hex(0, None));
    assert_eq!(response["status"], "accepted", "{response}");
    assert_eq!(response["result"]["status"], "0");
    assert_eq!(response["result"]["errorCode"], Value::Null);

    // Status 1 bare, and with each permitted diagnostic.
    let response = receive(&publish_response_hex(1, None));
    assert_eq!(response["result"]["status"], "1");
    assert_eq!(response["result"]["errorCode"], Value::Null);
    for code in [12u64, 13] {
        let response = receive(&publish_response_hex(1, Some(code)));
        assert_eq!(response["status"], "accepted", "status 1 code {code}");
        assert_eq!(response["result"]["errorCode"], code.to_string());
    }

    // Status 2 with every registered rejection code.
    for code in (0u64..=19).filter(|c| *c != 12 && *c != 13) {
        let response = receive(&publish_response_hex(2, Some(code)));
        assert_eq!(response["status"], "accepted", "status 2 code {code}");
        assert_eq!(response["result"]["status"], "2");
        assert_eq!(response["result"]["errorCode"], code.to_string());
    }
}

#[test]
fn sec_12_5_receive_publish_response_rejects_every_invalid_combination() {
    // Status 0 with any code.
    for code in [0u64, 12, 13, 19] {
        let response = receive(&publish_response_hex(0, Some(code)));
        assert_eq!(response["status"], "rejected", "status 0 code {code}");
        assert_eq!(response["error"], "schemaViolation");
    }
    // Status 1 with every registered code other than 12/13.
    for code in (0u64..=19).filter(|c| *c != 12 && *c != 13) {
        let response = receive(&publish_response_hex(1, Some(code)));
        assert_eq!(response["status"], "rejected", "status 1 code {code}");
        assert_eq!(response["error"], "schemaViolation");
    }
    // Status 2 without a code, or with a no-change reason.
    let response = receive(&publish_response_hex(2, None));
    assert_eq!(response["status"], "rejected");
    assert_eq!(response["error"], "schemaViolation");
    for code in [12u64, 13] {
        let response = receive(&publish_response_hex(2, Some(code)));
        assert_eq!(response["status"], "rejected", "status 2 code {code}");
        assert_eq!(response["error"], "schemaViolation");
    }
    // Unregistered codes reject on every status.
    for status in [1u8, 2] {
        for code in [20u64, 255, u64::MAX] {
            let response = receive(&publish_response_hex(status, Some(code)));
            assert_eq!(
                response["status"], "rejected",
                "status {status} unregistered code {code}"
            );
            assert_eq!(response["error"], "schemaViolation");
        }
    }
    // A status outside 0..=2.
    let response = receive(&publish_response_hex(3, None));
    assert_eq!(response["status"], "rejected");
    assert_eq!(response["error"], "schemaViolation");
}

#[test]
fn sec_12_5_receive_publish_response_keeps_deeper_cbor_classifications() {
    // Truncated: not well-formed.
    let response = receive("a2000101");
    assert_eq!(response["status"], "rejected");
    assert_eq!(response["error"], "invalidCbor");
    // Non-minimal status encoding: deterministic-profile fault.
    let response = receive("a20001011800");
    assert_eq!(response["status"], "rejected");
    assert_eq!(response["error"], "nonDeterministicCbor");
    // Duplicate keys: basic invalidity.
    let response = receive("a3000101010101");
    assert_eq!(response["status"], "rejected");
    assert_eq!(response["error"], "invalidCbor");
}

// ---------------------------------------------------------------------------
// selectCurrent
// ---------------------------------------------------------------------------

#[test]
fn sec_8_select_current_is_permutation_independent_with_mixed_identities() {
    let candidates = [
        fx_str("root_record_envelope"),
        fx_str("bob_envelope"),
        fx_str("root_revoked_envelope"),
    ];
    let permutations: [[usize; 3]; 6] = [
        [0, 1, 2],
        [0, 2, 1],
        [1, 0, 2],
        [1, 2, 0],
        [2, 0, 1],
        [2, 1, 0],
    ];
    for permutation in permutations {
        let ordered: Vec<&str> = permutation
            .iter()
            .map(|i| candidates[*i].as_str())
            .collect();
        let result = expect_accepted(
            "selectCurrent",
            json!({
                "targetDid": fx_str("followee_did"),
                "candidateEnvelopesHex": ordered,
                "nowMs": "1785589201123",
                "stickyAuthority": "unknown",
            }),
        );
        assert_eq!(
            result["winnerRecordBodyDigestHex"],
            fx_str("root_revoked_body_digest"),
            "RootRevoked wins in every permutation"
        );
        assert_eq!(result["authorityState"], "rootRevoked");
    }
}

#[test]
fn sec_8_2_select_current_applies_sticky_state_and_discards_invalid_candidates() {
    // Sticky RootRevoked excludes the only (Root) candidate.
    let result = expect_accepted(
        "selectCurrent",
        json!({
            "targetDid": fx_str("followee_did"),
            "candidateEnvelopesHex": [fx_str("root_record_envelope")],
            "nowMs": "1785589201123",
            "stickyAuthority": "rootRevoked",
        }),
    );
    assert_eq!(result["winnerRecordBodyDigestHex"], Value::Null);
    assert_eq!(result["authorityState"], "rootRevoked");

    // The B.8 substituted-descriptor candidate is discarded by complete
    // verification and supplies nothing.
    let result = expect_accepted(
        "selectCurrent",
        json!({
            "targetDid": fx_str("b8_target_did"),
            "candidateEnvelopesHex": [fx_str("b8_envelope")],
            "nowMs": "1785589201123",
            "stickyAuthority": "unknown",
        }),
    );
    assert_eq!(result["winnerRecordBodyDigestHex"], Value::Null);
    assert_eq!(result["authorityState"], "unknown");

    // A premature candidate is excluded under the supplied clock.
    let result = expect_accepted(
        "selectCurrent",
        json!({
            "targetDid": fx_str("followee_did"),
            "candidateEnvelopesHex": [fx_str("root_record_envelope")],
            "nowMs": "1000",
            "stickyAuthority": "unknown",
        }),
    );
    assert_eq!(result["winnerRecordBodyDigestHex"], Value::Null);
    assert_eq!(result["authorityState"], "unknown");
}

// ---------------------------------------------------------------------------
// Boundary and value-convention cases (mutation-sweep killers)
// ---------------------------------------------------------------------------

#[test]
fn interface_line_length_boundary_is_exact() {
    let cfg = config();
    let base = r#"{"interfaceProtocol":"1","caseId":"pad","operation":"hello","input":{}}"#;
    // Trailing insignificant whitespace pads a valid request to exactly the
    // 1 MiB line cap: still accepted.
    let exact = format!("{base}{}", " ".repeat(1024 * 1024 - base.len()));
    assert_eq!(exact.len(), 1024 * 1024);
    let parsed: Value =
        serde_json::from_str(&followee::interop::handle_line(&cfg, &exact)).expect("json");
    assert_eq!(
        parsed["status"], "accepted",
        "exactly 1 MiB is within the cap"
    );
    // One byte past the cap is an input-contract error.
    let over = format!("{exact} ");
    let parsed: Value =
        serde_json::from_str(&followee::interop::handle_line(&cfg, &over)).expect("json");
    assert_eq!(parsed["status"], "error", "1 MiB + 1 exceeds the cap");
}

#[test]
fn interface_serve_lines_handles_an_unterminated_final_line() {
    let cfg = config();
    // A final request without a trailing newline — including one padded to
    // exactly the 1 MiB cap — is still processed normally.
    let base = r#"{"interfaceProtocol":"1","caseId":"tail","operation":"hello","input":{}}"#;
    for input in [
        base.to_owned(),
        format!("{base}{}", " ".repeat(1024 * 1024 - base.len())),
    ] {
        let mut reader = std::io::BufReader::new(input.as_bytes());
        let mut out = Vec::new();
        followee::interop::serve_lines(&cfg, &mut reader, &mut out).expect("io");
        let text = String::from_utf8(out).expect("utf8");
        let lines: Vec<Value> = text
            .lines()
            .map(|line| serde_json::from_str(line).expect("json"))
            .collect();
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0]["status"], "accepted", "len {}", input.len());
        assert_eq!(lines[0]["caseId"], "tail");
    }
}

#[test]
fn interface_decimal_string_convention_boundaries() {
    // Canonical decimal strings only: no sign, no leading zeros, no
    // non-digits, no empty string; "0" itself is canonical.
    for bad in ["+5", "01", "1a", "", " 1"] {
        expect_input_error(
            "nextTimestamp",
            json!({"nowMs": bad, "previousTimestampMs": null}),
        );
    }
    let result = expect_accepted(
        "nextTimestamp",
        json!({"nowMs": "0", "previousTimestampMs": null}),
    );
    assert_eq!(result["timestampMs"], "0");
}

#[test]
fn interface_nint_convention_boundaries() {
    let author_with_nint = |value: &str| {
        json!({
            "rootSeedHex": fx_str("root_seed"),
            "revocationSeedHex": fx_str("revocation_seed"),
            "authority": "root",
            "timestampMs": "1785589200123",
            "validUntilMs": null,
            "contact": alice_contact(),
            "extensions": {"https://example.com/n": {"type": "nint", "value": value}},
            "signingSeed": "root",
        })
    };
    // Canonical negative decimal strings only.
    for bad in ["-01", "-+5", "-", "5", "-18446744073709551617"] {
        expect_input_error("authorRecord", author_with_nint(bad));
    }
    // The most negative permitted value is exactly −2^64.
    let result = expect_accepted("authorRecord", author_with_nint("-18446744073709551616"));
    assert!(result["envelopeHex"].is_string());
}

#[test]
fn select_current_accepts_every_sticky_authority_form() {
    for (sticky, state) in [
        ("unknown", "root"),
        ("root", "root"),
        ("rootRevoked", "rootRevoked"),
    ] {
        let result = expect_accepted(
            "selectCurrent",
            json!({
                "targetDid": fx_str("followee_did"),
                "candidateEnvelopesHex": [fx_str("root_record_envelope")],
                "nowMs": "1785589201123",
                "stickyAuthority": sticky,
            }),
        );
        // Under sticky rootRevoked the Root candidate is excluded; under
        // unknown and root it wins.
        if sticky == "rootRevoked" {
            assert_eq!(result["winnerRecordBodyDigestHex"], Value::Null);
        } else {
            assert_eq!(
                result["winnerRecordBodyDigestHex"],
                fx_str("root_body_digest")
            );
        }
        assert_eq!(result["authorityState"], state, "sticky {sticky}");
    }
    expect_input_error(
        "selectCurrent",
        json!({
            "targetDid": fx_str("followee_did"),
            "candidateEnvelopesHex": [],
            "nowMs": "1785589201123",
            "stickyAuthority": "other",
        }),
    );
}

#[test]
fn contact_round_trip_preserves_every_member() {
    // Every contact member — including avatar — survives the author/verify
    // round trip exactly.
    let contact = json!({
        "displayName": "Alice Example",
        "summary": "Writer",
        "avatar": "https://alice.example/avatar.png",
        "alsoKnownAs": ["acct:alice@example.com"],
        "services": [{
            "id": "feed",
            "type": "Feed",
            "endpoint": "https://alice.example/feed.xml",
            "mediaType": "application/atom+xml",
            "label": "Writing",
            "language": "en-GB",
            "rel": "alternate"
        }],
        "migration": null,
        "extensions": {"https://example.com/c": {"type": "text", "value": "x"}}
    });
    let authored = expect_accepted(
        "authorRecord",
        json!({
            "rootSeedHex": fx_str("root_seed"),
            "revocationSeedHex": fx_str("revocation_seed"),
            "authority": "root",
            "timestampMs": "1785589200123",
            "validUntilMs": null,
            "contact": contact,
            "extensions": {},
            "signingSeed": "root",
        }),
    );
    let result = expect_accepted(
        "verifyRecord",
        json!({
            "targetDid": fx_str("followee_did"),
            "envelopeHex": authored["envelopeHex"],
            "nowMs": "1785589200123",
        }),
    );
    assert_eq!(result["record"]["contact"], contact);
}

// ---------------------------------------------------------------------------
// Revision 2: lossless presence, direct-wire present-empty fixtures, and
// the constructor canonicalization
// ---------------------------------------------------------------------------

/// Builds a validly signed Alice root envelope around a raw contact map and
/// optional raw record-extension bytes. The bodies are assembled with the
/// test suite's raw CBOR emitters — independent of the crate's writer and
/// of every neutral authoring vector — and signed with the published
/// Appendix B.2 root seed, so each fixture is a correctly signed direct
/// wire record that `authorRecord` cannot construct.
fn direct_wire_envelope(contact_raw: Vec<u8>, record_extensions_raw: Option<Vec<u8>>) -> String {
    let mut entries = vec![
        (r_uint(0), r_uint(1)),
        (r_uint(1), r_tstr(&fx_str("followee_did"))),
        (r_uint(2), r_uint(1_785_589_200_123)),
        (r_uint(3), r_uint(0)),
        (r_uint(4), fx_bytes("authority_descriptor_cbor")),
        (r_uint(7), contact_raw),
    ];
    if let Some(extensions) = record_extensions_raw {
        entries.push((r_uint(8), extensions));
    }
    let body = r_map(&entries);
    hex::encode(followee::record::seal_record_body(&body, &root_seed()))
}

fn verify_alice(envelope_hex: &str) -> Value {
    expect_accepted(
        "verifyRecord",
        json!({
            "targetDid": fx_str("followee_did"),
            "envelopeHex": envelope_hex,
            "nowMs": "1785589200123",
        }),
    )
}

#[test]
fn present_empty_collections_project_losslessly_from_direct_wire_fixtures() {
    // Present-empty labels 3, 4, and 6 in the contact, present-empty
    // record label 8, and present-empty texts at contact labels 0 and 1.
    let contact = r_map(&[
        (r_uint(0), r_tstr("")),
        (r_uint(1), r_tstr("")),
        (r_uint(3), r_array(&[])),
        (r_uint(4), r_array(&[])),
        (r_uint(6), r_map(&[])),
    ]);
    let envelope = direct_wire_envelope(contact, Some(r_map(&[])));
    let result = verify_alice(&envelope);
    assert_eq!(
        result["record"]["contact"],
        json!({
            "displayName": "",
            "summary": "",
            "avatar": null,
            "alsoKnownAs": [],
            "services": [],
            "migration": null,
            "extensions": {}
        }),
        "present-empty wire fields project as [] / {{}} / \"\", absent ones as null"
    );
    assert_eq!(result["record"]["extensions"], json!({}));
    assert_eq!(result["record"]["revocationKey"], Value::Null);

    // The documented normalization direction: feeding the faithfully
    // observed [] / {} values back through authorRecord is an omission
    // request, so the re-authored record omits those fields and the next
    // verification observes null — while "" remains present-empty text.
    let reauthored = expect_accepted(
        "authorRecord",
        json!({
            "rootSeedHex": fx_str("root_seed"),
            "revocationSeedHex": fx_str("revocation_seed"),
            "authority": "root",
            "timestampMs": "1785589200123",
            "validUntilMs": null,
            "contact": result["record"]["contact"],
            "extensions": result["record"]["extensions"],
            "signingSeed": "root",
        }),
    );
    let reverified = verify_alice(reauthored["envelopeHex"].as_str().expect("hex"));
    assert_eq!(
        reverified["record"]["contact"],
        json!({
            "displayName": "",
            "summary": "",
            "avatar": null,
            "alsoKnownAs": null,
            "services": null,
            "migration": null,
            "extensions": null
        })
    );
    assert_eq!(reverified["record"]["extensions"], Value::Null);
}

#[test]
fn entirely_empty_contact_document_projects_to_the_all_null_object() {
    // Specification section 7.1: an empty Contact Document is valid, and
    // record label 7 is mandatory; it projects to the all-null object.
    let envelope = direct_wire_envelope(r_map(&[]), None);
    let result = verify_alice(&envelope);
    assert_eq!(
        result["record"]["contact"],
        json!({
            "displayName": null,
            "summary": null,
            "avatar": null,
            "alsoKnownAs": null,
            "services": null,
            "migration": null,
            "extensions": null
        })
    );
    assert_eq!(result["record"]["extensions"], Value::Null);
}

#[test]
fn authored_records_are_a_stable_subset_under_reverification() {
    // Constructor-direction stability: null / [] / {} inputs request
    // omission, verification observes null, and re-authoring from that
    // null output reproduces the identical bytes.
    let input = json!({
        "rootSeedHex": fx_str("root_seed"),
        "revocationSeedHex": fx_str("revocation_seed"),
        "authority": "root",
        "timestampMs": "1785589200123",
        "validUntilMs": null,
        "contact": {
            "displayName": null,
            "summary": null,
            "avatar": null,
            "alsoKnownAs": [],
            "services": [],
            "migration": null,
            "extensions": {}
        },
        "extensions": {},
        "signingSeed": "root",
    });
    let authored = expect_accepted("authorRecord", input);
    let verified = verify_alice(authored["envelopeHex"].as_str().expect("hex"));
    for member in [
        "displayName",
        "summary",
        "avatar",
        "alsoKnownAs",
        "services",
        "migration",
        "extensions",
    ] {
        assert_eq!(
            verified["record"]["contact"][member],
            Value::Null,
            "omission-requested member {member} observes null"
        );
    }
    let reauthored = expect_accepted(
        "authorRecord",
        json!({
            "rootSeedHex": fx_str("root_seed"),
            "revocationSeedHex": fx_str("revocation_seed"),
            "authority": "root",
            "timestampMs": "1785589200123",
            "validUntilMs": null,
            "contact": verified["record"]["contact"],
            "extensions": {},
            "signingSeed": "root",
        }),
    );
    assert_eq!(
        reauthored["envelopeHex"], authored["envelopeHex"],
        "the authored subset is stable under re-verification and re-authoring"
    );
}

#[test]
fn present_empty_text_is_reachable_by_authoring_and_projected_exactly() {
    // "" is not one of the canonicalized omission forms: it requests a
    // present empty text wherever the grammar admits one (displayName,
    // summary, service label).
    let authored = expect_accepted(
        "authorRecord",
        json!({
            "rootSeedHex": fx_str("root_seed"),
            "revocationSeedHex": fx_str("revocation_seed"),
            "authority": "root",
            "timestampMs": "1785589200123",
            "validUntilMs": null,
            "contact": {
                "displayName": "",
                "summary": null,
                "avatar": null,
                "alsoKnownAs": null,
                "services": [{
                    "id": "feed",
                    "type": "Feed",
                    "endpoint": "https://alice.example/feed.xml",
                    "mediaType": null,
                    "label": "",
                    "language": null,
                    "rel": null
                }],
                "migration": null,
                "extensions": null
            },
            "extensions": {},
            "signingSeed": "root",
        }),
    );
    let result = verify_alice(authored["envelopeHex"].as_str().expect("hex"));
    assert_eq!(result["record"]["contact"]["displayName"], "");
    assert_eq!(result["record"]["contact"]["summary"], Value::Null);
    assert_eq!(result["record"]["contact"]["services"][0]["label"], "");
    assert_eq!(
        result["record"]["contact"]["services"][0]["mediaType"],
        Value::Null
    );
}

#[test]
fn migration_object_with_all_null_members_requests_omission() {
    // Revision 2 constructor canonicalization: an all-null migration
    // object is an empty map and requests omission, exactly like null.
    let author = |migration: Value| {
        expect_accepted(
            "authorRecord",
            json!({
                "rootSeedHex": fx_str("root_seed"),
                "revocationSeedHex": fx_str("revocation_seed"),
                "authority": "root",
                "timestampMs": "1785589200123",
                "validUntilMs": null,
                "contact": {
                    "displayName": "Alice Example",
                    "summary": null,
                    "avatar": null,
                    "alsoKnownAs": null,
                    "services": null,
                    "migration": migration,
                    "extensions": null
                },
                "extensions": {},
                "signingSeed": "root",
            }),
        )
    };
    let with_null = author(Value::Null);
    let with_empty_object = author(json!({"predecessor": null, "successor": null}));
    assert_eq!(
        with_null["envelopeHex"], with_empty_object["envelopeHex"],
        "both forms produce the identical omitted-label bytes"
    );
    let verified = verify_alice(with_empty_object["envelopeHex"].as_str().expect("hex"));
    assert_eq!(verified["record"]["contact"]["migration"], Value::Null);
}

#[test]
fn migration_object_with_one_member_is_authored_and_projected() {
    // A migration object with exactly one non-null member is a real
    // migration claim, not an omission request: label 5 is encoded and the
    // projection reproduces the single directional claim.
    let bob = fx_str("bob_did");
    let authored = expect_accepted(
        "authorRecord",
        json!({
            "rootSeedHex": fx_str("root_seed"),
            "revocationSeedHex": fx_str("revocation_seed"),
            "authority": "root",
            "timestampMs": "1785589200123",
            "validUntilMs": null,
            "contact": {
                "displayName": null,
                "summary": null,
                "avatar": null,
                "alsoKnownAs": null,
                "services": null,
                "migration": {"predecessor": null, "successor": bob},
                "extensions": null
            },
            "extensions": {},
            "signingSeed": "root",
        }),
    );
    let verified = verify_alice(authored["envelopeHex"].as_str().expect("hex"));
    assert_eq!(
        verified["record"]["contact"]["migration"],
        json!({"predecessor": null, "successor": bob}),
        "the single-member migration claim survives the round trip"
    );
}
