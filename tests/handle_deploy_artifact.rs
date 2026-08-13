//! Deployment-artifact parity (IMPLEMENTATION.md section 13 Milestone 5):
//! the shipped `demo/public-authority/` configuration — the artifact whose
//! only deployment delta is the domain, identities, and TLS termination —
//! loads through the same production loader, serves through the same
//! production authority, and yields the same JRD semantics the local
//! black-box tests pin, probed through the production WebFinger client
//! over real loopback sockets.
#![allow(clippy::arithmetic_side_effects)]

mod common;

use common::*;
use followee::clock::ManualClock;
use followee::relay::client::{BudgetMeter, HttpTransport, NetworkPolicy, OperationBudget};
use followee::webfinger::authority::AuthorityConfig;
use followee::webfinger::{Handle, WebFingerClient};
use std::path::Path;

fn artifact_dir() -> &'static Path {
    Path::new(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/demo/public-authority"
    ))
}

#[test]
fn deploy_artifact_example_config_loads_through_the_production_loader() {
    let config = AuthorityConfig::load(&artifact_dir().join("authority.example.json"))
        .expect("the shipped example configuration validates completely");
    assert_eq!(config.domain(), "your-domain.example");
    // alice + alias Alice + bob.
    assert_eq!(config.handle_count(), 3);
    // The shipped alice.cose (the exact Appendix B.4 envelope) verified
    // against Alice's DID at load; the alias shares it.
    assert_eq!(config.record_count(), 2);
}

/// The bootstrapped Railway public artifact: the exact domain, local,
/// DID, and signed record approved for the Milestone 5 public
/// demonstration. These constants are durable audit evidence — any
/// change to the deployed identity must change this test deliberately.
const RAILWAY_DOMAIN: &str = "handle-authority-production.up.railway.app";
const RAILWAY_LOCAL: &str = "demo";
const RAILWAY_DID: &str = "did:flw:zQmV2sbfh2M5kHBAa9G1svAdh54bZqGKLUE3YJpBHj8qb4R";
const RAILWAY_RECORD_FILE: &str = "demo.cose";
const RAILWAY_RECORD_BYTES: usize = 284;
const RAILWAY_RECORD_SHA256: &str =
    "9ece97525772992cdf049cb0387958e93daa4999913a9324ed91db78f513d927";

#[test]
fn deploy_artifact_railway_bootstrap_passes_the_production_deployment_gate() {
    // The Railway artifact is no longer a template: it carries the
    // bootstrapped public demonstration identity, and the production
    // predeployment gate must pass on exactly the checked-in bytes.
    // (Deployment and the live public probes have not yet occurred; this
    // pins the artifact those steps will publish.)
    let record =
        std::fs::read(artifact_dir().join("railway").join(RAILWAY_RECORD_FILE)).expect("readable");
    assert_eq!(record.len(), RAILWAY_RECORD_BYTES, "record size is pinned");
    assert_eq!(
        hex::encode(followee::crypto::sha256(&record)),
        RAILWAY_RECORD_SHA256,
        "record bytes are pinned by digest"
    );

    let config = AuthorityConfig::load(&artifact_dir().join("railway/authority.json"))
        .expect("the bootstrapped configuration validates completely");
    assert_eq!(config.domain(), RAILWAY_DOMAIN);
    assert_eq!(config.handle_count(), 1, "one local, no aliases");
    assert_eq!(config.record_count(), 1);

    let report = config.deployment_consistency();
    assert!(
        report.consistent,
        "the artifact is deployable as checked in"
    );
    assert_eq!(report.entries.len(), 1, "no extra mappings");
    let entry = &report.entries[0];
    assert_eq!(entry.local, RAILWAY_LOCAL);
    assert_eq!(entry.did, RAILWAY_DID);
    assert!(entry.has_record);
    assert!(entry.record_verified, "production verification succeeded");
    let resource = format!("acct:{RAILWAY_LOCAL}@{RAILWAY_DOMAIN}");
    assert_eq!(entry.resource, resource);
    assert_eq!(
        entry.claimed.as_deref(),
        Some(resource.as_str()),
        "the signed alsoKnownAs claims the exact deployed handle"
    );
}

#[test]
fn deploy_artifact_serves_the_same_jrd_semantics_as_the_tested_authority() {
    // Serve the artifact's own files (config + record) over a real socket.
    let config_text =
        std::fs::read_to_string(artifact_dir().join("authority.example.json")).expect("readable");
    let record = std::fs::read(artifact_dir().join("alice.cose")).expect("readable");
    let (addr, authority) = start_authority(&config_text, &[("alice.cose", record.clone())]);
    let endpoint = format!("http://{addr}/");

    let transport = HttpTransport;
    let clock = ManualClock::new(RELAY_NOW_MS);
    let client = WebFingerClient::new(&transport, NetworkPolicy::Development, &clock);
    let mut meter = BudgetMeter::new(OperationBudget {
        deadline_ms: None,
        max_response_bytes: 1024 * 1024,
        max_requests: 16,
    });

    // The production client discovers the mapped DID with the exact
    // canonical subject — the same requirements the public HTTPS probe
    // will assert after deployment.
    let handle = Handle::parse("alice@your-domain.example").expect("parses");
    let discovery = client
        .lookup(&handle, Some(&endpoint), &mut meter)
        .expect("discovers");
    assert_eq!(discovery.did, alice_did());
    assert_eq!(discovery.resource, "acct:alice@your-domain.example");
    assert_eq!(discovery.record_links.len(), 1);

    // The bootstrap record served by the artifact is byte-for-byte the
    // shipped Appendix B.4 envelope, and it verifies locally.
    let outcome = client.bootstrap(
        &discovery,
        RELAY_NOW_MS,
        followee::ordering::AuthorityState::Unknown,
        &mut meter,
    );
    let winner = outcome.winner.expect("bootstrap winner");
    assert_eq!(winner.record.envelope_bytes(), &record[..]);
    assert_eq!(record, fx_bytes("root_record_envelope"));

    // Bob has no record link; his mapping is DID-only.
    let bob = Handle::parse("bob@your-domain.example").expect("parses");
    let bob_discovery = client
        .lookup(&bob, Some(&endpoint), &mut meter)
        .expect("discovers");
    assert_eq!(bob_discovery.did, bob_did());
    assert!(bob_discovery.record_links.is_empty());

    // The artifact keeps the case-variant guarantee of the tested
    // authority: the listed alias resolves to the same DID, unlisted
    // variants do not resolve.
    let alias = Handle::parse("Alice@your-domain.example").expect("parses");
    assert_eq!(
        client
            .lookup(&alias, Some(&endpoint), &mut meter)
            .expect("alias discovers")
            .did,
        alice_did()
    );
    let variant = Handle::parse("ALICE@your-domain.example").expect("parses");
    assert!(
        client
            .lookup(&variant, Some(&endpoint), &mut meter)
            .is_err()
    );

    // Determinism: reloading the artifact configuration yields the same
    // document semantics (base URI factored out).
    let reloaded = AuthorityConfig::load(&artifact_dir().join("authority.example.json"))
        .expect("reload validates");
    let again = followee::webfinger::authority::HandleAuthority::new(
        reloaded,
        "https://your-domain.example/".to_owned(),
    )
    .expect("authority");
    assert!(
        !again.development_mode(),
        "an HTTPS base is conforming mode"
    );
    let deployed_document = again
        .jrd_for_resource("acct:alice@your-domain.example")
        .expect("mapping present");
    let local_document = authority
        .jrd_for_resource("acct:alice@your-domain.example")
        .expect("mapping present")
        .replace(&endpoint, "https://your-domain.example/");
    assert_eq!(
        deployed_document, local_document,
        "the deployed authority serves the same JRD semantics as the \
         locally tested one; only the base URI differs"
    );
}
