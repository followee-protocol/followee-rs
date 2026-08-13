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

#[test]
fn deploy_artifact_template_is_honestly_not_deployable_as_is() {
    // The checked-in railway configuration is an example/template: its
    // record is the Appendix B.4 envelope claiming acct:alice@example.com,
    // which cannot claim a provider-assigned domain. The predeployment
    // consistency gate must say so; final acceptance requires the
    // two-phase bootstrap with a freshly signed record.
    let config = AuthorityConfig::load(&artifact_dir().join("railway/authority.json"))
        .expect("the template validates structurally");
    let report = config.deployment_consistency();
    assert!(
        !report.consistent,
        "the template must not silently pass the deployment gate"
    );
    assert!(
        report
            .entries
            .iter()
            .filter(|e| e.has_record)
            .all(|e| e.record_verified && e.claimed.is_none()),
        "records verify but claim a different (example.com) handle"
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
