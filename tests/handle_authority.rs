//! Demonstration handle authority (specification sections 10.1–10.3;
//! IMPLEMENTATION.md section 13 Milestone 5): configuration validation
//! (including the ASCII-case-variant rule), untrusted query parsing, and
//! a real-socket black-box flow through the production WebFinger client
//! and production `HttpTransport` over actual loopback HTTP bytes.
#![allow(clippy::arithmetic_side_effects)]

mod common;

use common::*;
use followee::clock::ManualClock;
use followee::relay::client::{
    BudgetMeter, DestinationRule, HttpTransport, Method, NetworkPolicy, OperationBudget, Transport,
    TransportRequest,
};
use followee::webfinger::authority::{
    AuthorityConfig, ConfigError, QueryError, parse_resource_query,
};
use followee::webfinger::{Handle, WebFingerClient, WebFingerError};

fn no_records(_: &str) -> Result<Vec<u8>, ConfigError> {
    Err(ConfigError::Schema("no records in this test".to_owned()))
}

fn config_json(handles: &str) -> String {
    format!(r#"{{"version":1,"domain":"example.com","handles":[{handles}]}}"#)
}

fn alice_entry(local: &str) -> String {
    format!(r#"{{"local":"{local}","did":"{}"}}"#, alice_did().as_str())
}

fn bob_entry(local: &str) -> String {
    format!(r#"{{"local":"{local}","did":"{}"}}"#, bob_did().as_str())
}

fn meter() -> BudgetMeter {
    BudgetMeter::new(OperationBudget {
        deadline_ms: None,
        max_response_bytes: 1024 * 1024,
        max_requests: 16,
    })
}

// ---------------------------------------------------------------------------
// Configuration validation.
// ---------------------------------------------------------------------------

#[test]
fn sec_10_1_case_variants_mapping_to_different_dids_are_rejected_at_load() {
    let json = config_json(&format!("{},{}", alice_entry("alice"), bob_entry("Alice")));
    let error = AuthorityConfig::from_json(json.as_bytes(), no_records).unwrap_err();
    assert!(
        matches!(error, ConfigError::CaseVariantCollision(a, b)
            if (a == "Alice" && b == "alice") || (a == "alice" && b == "Alice")),
        "case variants can never be assigned to different DIDs"
    );
}

#[test]
fn sec_10_1_case_variants_as_aliases_of_one_did_are_accepted() {
    // As separate entries with the same DID …
    let json = config_json(&format!(
        "{},{}",
        alice_entry("alice"),
        alice_entry("Alice")
    ));
    let config = AuthorityConfig::from_json(json.as_bytes(), no_records).expect("loads");
    assert_eq!(config.handle_count(), 2);
    // … and as explicit aliases.
    let json = config_json(&format!(
        r#"{{"local":"alice","did":"{}","aliases":["Alice","ALICE"]}}"#,
        alice_did().as_str()
    ));
    let config = AuthorityConfig::from_json(json.as_bytes(), no_records).expect("loads");
    assert_eq!(config.handle_count(), 3);
}

#[test]
fn config_rejects_duplicate_locals_and_schema_faults() {
    // Exact duplicate local, even with the same DID.
    let json = config_json(&format!(
        "{},{}",
        alice_entry("alice"),
        alice_entry("alice")
    ));
    assert!(matches!(
        AuthorityConfig::from_json(json.as_bytes(), no_records).unwrap_err(),
        ConfigError::DuplicateLocal(local) if local == "alice"
    ));
    // Duplicate through an alias.
    let json = config_json(&format!(
        r#"{{"local":"alice","did":"{did}","aliases":["alice"]}}"#,
        did = alice_did().as_str()
    ));
    assert!(matches!(
        AuthorityConfig::from_json(json.as_bytes(), no_records).unwrap_err(),
        ConfigError::DuplicateLocal(_)
    ));
    // Invalid local grammar.
    let json = config_json(&format!(
        r#"{{"local":"bad local","did":"{}"}}"#,
        alice_did().as_str()
    ));
    assert!(matches!(
        AuthorityConfig::from_json(json.as_bytes(), no_records).unwrap_err(),
        ConfigError::Handle(_)
    ));
    // Malformed DID.
    let json = config_json(r#"{"local":"alice","did":"did:flw:nope"}"#);
    assert!(matches!(
        AuthorityConfig::from_json(json.as_bytes(), no_records).unwrap_err(),
        ConfigError::Schema(_)
    ));
    // Non-canonical (uppercase) domain.
    let json = format!(
        r#"{{"version":1,"domain":"EXAMPLE.com","handles":[{}]}}"#,
        alice_entry("alice")
    );
    assert!(matches!(
        AuthorityConfig::from_json(json.as_bytes(), no_records).unwrap_err(),
        ConfigError::Schema(_)
    ));
    // Unknown top-level and entry fields, wrong version.
    for json in [
        r#"{"version":1,"domain":"example.com","handles":[],"extra":1}"#.to_owned(),
        config_json(&format!(
            r#"{{"local":"alice","did":"{}","surprise":true}}"#,
            alice_did().as_str()
        )),
        r#"{"version":2,"domain":"example.com","handles":[]}"#.to_owned(),
    ] {
        assert!(matches!(
            AuthorityConfig::from_json(json.as_bytes(), no_records).unwrap_err(),
            ConfigError::Schema(_)
        ));
    }
    // Duplicate JSON member names are a parse fault, never collapsed.
    let json = r#"{"version":1,"version":1,"domain":"example.com","handles":[]}"#;
    assert!(matches!(
        AuthorityConfig::from_json(json.as_bytes(), no_records).unwrap_err(),
        ConfigError::Json(_)
    ));
}

#[test]
fn config_verifies_bootstrap_records_against_their_entry_did_at_load() {
    // Bob's valid record under Alice's DID fails identity binding at load.
    let json = config_json(&format!(
        r#"{{"local":"alice","did":"{}","record":"r.cose"}}"#,
        alice_did().as_str()
    ));
    let bob_record = bob_record_with_contact(RELAY_NOW_MS, None, contact_claiming(&[]));
    let error =
        AuthorityConfig::from_json(json.as_bytes(), |_| Ok(bob_record.clone())).unwrap_err();
    assert!(matches!(
        error,
        ConfigError::Record {
            error: followee::error::VerifyError::IdentityBindingMismatch,
            ..
        }
    ));
    // The exact verifying record loads.
    let alice_record = alice_record_with_contact(RELAY_NOW_MS, None, contact_claiming(&[]));
    let config =
        AuthorityConfig::from_json(json.as_bytes(), |_| Ok(alice_record.clone())).expect("loads");
    assert_eq!(config.record_count(), 1);
}

#[test]
fn config_enforces_the_handle_count_bound_exactly() {
    let at_limit: Vec<String> = (0..64).map(|i| alice_entry(&format!("user{i}"))).collect();
    let json = config_json(&at_limit.join(","));
    assert_eq!(
        AuthorityConfig::from_json(json.as_bytes(), no_records)
            .expect("64 locals load")
            .handle_count(),
        64
    );
    let over: Vec<String> = (0..65).map(|i| alice_entry(&format!("user{i}"))).collect();
    let json = config_json(&over.join(","));
    assert!(matches!(
        AuthorityConfig::from_json(json.as_bytes(), no_records).unwrap_err(),
        ConfigError::Schema(_)
    ));
}

// ---------------------------------------------------------------------------
// Untrusted query parsing.
// ---------------------------------------------------------------------------

#[test]
fn rfc_7033_resource_query_parsing_is_strict() {
    assert_eq!(
        parse_resource_query("resource=acct%3Aalice%40example.com").expect("parses"),
        "acct:alice@example.com"
    );
    // Unknown parameters are ignored; '+' stays literal.
    assert_eq!(
        parse_resource_query("rel=x&resource=a%2Bb&other=y").expect("parses"),
        "a+b"
    );
    assert_eq!(
        parse_resource_query("").unwrap_err(),
        QueryError::MissingResource
    );
    assert_eq!(
        parse_resource_query("rel=x").unwrap_err(),
        QueryError::MissingResource
    );
    assert_eq!(
        parse_resource_query("resource=a&resource=b").unwrap_err(),
        QueryError::DuplicateResource
    );
    for bad in ["resource=%zz", "resource=%4", "resource=%ff"] {
        assert_eq!(
            parse_resource_query(bad).unwrap_err(),
            QueryError::BadEncoding,
            "{bad:?}"
        );
    }
}

#[test]
fn rfc_7033_percent_decoding_accepts_both_hex_cases() {
    assert_eq!(
        parse_resource_query("resource=acct%3aalice%40example.com").expect("parses"),
        "acct:alice@example.com"
    );
    assert_eq!(
        parse_resource_query("resource=%2F%2f").expect("parses"),
        "//"
    );
}

#[test]
fn config_file_size_boundary_is_exact() {
    use followee::webfinger::authority::MAX_CONFIG_BYTES;
    // The bound is an absolute protocol-side constant, not whatever the
    // expression happens to evaluate to.
    assert_eq!(MAX_CONFIG_BYTES, 262_144);
    let dir = tempfile::tempdir().expect("tempdir");
    let base = config_json(&alice_entry("alice"));
    // Trailing whitespace is valid JSON padding, so the boundary is
    // reachable with a completely valid configuration.
    let pad_to = |len: usize| {
        let mut text = base.clone();
        text.push_str(&" ".repeat(len - base.len()));
        text
    };
    let at_limit = dir.path().join("at.json");
    std::fs::write(&at_limit, pad_to(MAX_CONFIG_BYTES)).expect("written");
    assert!(
        AuthorityConfig::load(&at_limit).is_ok(),
        "exactly {MAX_CONFIG_BYTES} bytes load"
    );
    let over = dir.path().join("over.json");
    std::fs::write(&over, pad_to(MAX_CONFIG_BYTES + 1)).expect("written");
    assert!(
        matches!(
            AuthorityConfig::load(&over).unwrap_err(),
            ConfigError::TooLarge
        ),
        "one byte past the bound is rejected before parsing"
    );
}

#[test]
fn sec_15_1_record_file_at_exactly_the_envelope_cap_loads() {
    use followee::limits::MAX_RECORD_BYTES;
    // Build a valid record of exactly 16 KiB by adjusting the padding
    // until the envelope length lands on the cap.
    let mut pad = 15 * 1024;
    let (did, envelope) = loop {
        let (did, envelope) = synthetic_identity_record(41, pad);
        match envelope.len().cmp(&MAX_RECORD_BYTES) {
            std::cmp::Ordering::Equal => break (did, envelope),
            std::cmp::Ordering::Less => pad += MAX_RECORD_BYTES - envelope.len(),
            std::cmp::Ordering::Greater => pad -= envelope.len() - MAX_RECORD_BYTES,
        }
    };
    assert_eq!(envelope.len(), MAX_RECORD_BYTES);
    let json = config_json(&format!(
        r#"{{"local":"big","did":"{did}","record":"big.cose"}}"#
    ));
    let config =
        AuthorityConfig::from_json(json.as_bytes(), |_| Ok(envelope.clone())).expect("loads");
    assert_eq!(config.record_count(), 1, "a maximal valid record is served");

    // The same maximal record must also load through the file path
    // (AuthorityConfig::load), whose size pre-check runs before the
    // verifier: an exactly-16-KiB record file is valid and served.
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("big.cose"), &envelope).expect("record written");
    let config_path = dir.path().join("authority.json");
    std::fs::write(&config_path, &json).expect("config written");
    let loaded = AuthorityConfig::load(&config_path).expect("maximal record file loads");
    assert_eq!(loaded.record_count(), 1);
}

// ---------------------------------------------------------------------------
// Real-socket black-box flow through the production client.
// ---------------------------------------------------------------------------

fn demo_config() -> String {
    format!(
        r#"{{"version":1,"domain":"example.com","handles":[
            {{"local":"alice","did":"{alice}","aliases":["Alice"],"record":"alice.cose"}},
            {{"local":"bob","did":"{bob}"}}
        ]}}"#,
        alice = alice_did().as_str(),
        bob = bob_did().as_str()
    )
}

#[test]
fn sec_10_2_real_socket_discovery_and_bootstrap_through_the_production_client() {
    let record = alice_record_with_contact(
        RELAY_NOW_MS,
        None,
        contact_claiming(&["acct:alice@example.com"]),
    );
    let (addr, _authority) = start_authority(&demo_config(), &[("alice.cose", record.clone())]);
    let endpoint = format!("http://{addr}/");
    let transport = HttpTransport;
    let clock = ManualClock::new(RELAY_NOW_MS);
    let client = WebFingerClient::new(&transport, NetworkPolicy::Development, &clock);
    let mut meter = meter();

    // Discovery: exact subject, one Followee link, canonical DID.
    let handle = Handle::parse("alice@example.com").expect("parses");
    let discovery = client
        .lookup(&handle, Some(&endpoint), &mut meter)
        .expect("discovers");
    assert_eq!(discovery.did, alice_did());
    assert_eq!(discovery.resource, "acct:alice@example.com");
    assert_eq!(discovery.record_links.len(), 1);

    // Bootstrap: the exact served bytes verify and win.
    let outcome = client.bootstrap(
        &discovery,
        RELAY_NOW_MS,
        followee::ordering::AuthorityState::Unknown,
        &mut meter,
    );
    let winner = outcome.winner.expect("bootstrap winner");
    assert_eq!(winner.record.envelope_bytes(), &record[..]);

    // Inverse verification binds both directions over real sockets.
    let verified_record = followee::verify::verify_record_for_target(alice_did().as_str(), &record)
        .expect("verifies");
    let verification = client.verify_handle(&handle, &verified_record, Some(&endpoint), &mut meter);
    assert!(verification.verified);

    // The alias maps to the same DID with its own exact subject echo.
    let alias = Handle::parse("Alice@example.com").expect("parses");
    let alias_discovery = client
        .lookup(&alias, Some(&endpoint), &mut meter)
        .expect("alias discovers");
    assert_eq!(alias_discovery.did, alice_did());
    assert_eq!(alias_discovery.resource, "acct:Alice@example.com");

    // An unlisted ASCII-case variant does not resolve.
    let variant = Handle::parse("aLiCe@example.com").expect("parses");
    assert_eq!(
        client
            .lookup(&variant, Some(&endpoint), &mut meter)
            .unwrap_err(),
        WebFingerError::HandleNotFound
    );

    // An unknown local does not resolve.
    let unknown = Handle::parse("nobody@example.com").expect("parses");
    assert_eq!(
        client
            .lookup(&unknown, Some(&endpoint), &mut meter)
            .unwrap_err(),
        WebFingerError::HandleNotFound
    );

    // A wrong-domain resource does not resolve here either.
    let wrong_domain = Handle::parse("alice@other.example").expect("parses");
    assert_eq!(
        client
            .lookup(&wrong_domain, Some(&endpoint), &mut meter)
            .unwrap_err(),
        WebFingerError::HandleNotFound
    );
}

#[test]
fn rfc_7033_malformed_queries_receive_http_400_over_real_sockets() {
    let (addr, _authority) = start_authority(
        &demo_config(),
        &[("alice.cose", {
            alice_record_with_contact(RELAY_NOW_MS, None, contact_claiming(&[]))
        })],
    );
    let transport = HttpTransport;
    for url in [
        format!("http://{addr}/.well-known/webfinger"),
        format!("http://{addr}/.well-known/webfinger?rel=x"),
        format!("http://{addr}/.well-known/webfinger?resource=a&resource=b"),
    ] {
        let response = transport
            .execute(&TransportRequest {
                method: Method::Get,
                url: &url,
                accept: Some("application/jrd+json"),
                content_type: None,
                body: &[],
                max_response_bytes: 4096,
                destination: DestinationRule::LoopbackOnly,
                timeout_ms: 5_000,
            })
            .expect("request completes");
        assert_eq!(response.status, 400, "{url}");
    }
    // A malformed percent-escape is not even a valid URI, so the strict
    // production transport refuses to send it; exercise the server's own
    // rejection with raw HTTP bytes.
    use std::io::{Read, Write};
    let mut stream = std::net::TcpStream::connect(addr).expect("connect");
    stream
        .write_all(
            format!(
                "GET /.well-known/webfinger?resource=%zz HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n"
            )
            .as_bytes(),
        )
        .expect("request sent");
    let mut raw = String::new();
    stream.read_to_string(&mut raw).expect("response read");
    assert!(
        raw.starts_with("HTTP/1.1 400"),
        "malformed escape is 400: {raw:.60}"
    );
}

#[test]
fn authority_restart_from_the_same_configuration_is_deterministic() {
    let record = alice_record_with_contact(RELAY_NOW_MS, None, contact_claiming(&[]));
    let (addr_a, authority_a) = start_authority(&demo_config(), &[("alice.cose", record.clone())]);
    let (addr_b, authority_b) = start_authority(&demo_config(), &[("alice.cose", record)]);
    // The served JRD semantics are identical up to the advertised base
    // URI (which carries the bound port); with the base factored out, the
    // documents are byte-identical.
    let a = authority_a
        .jrd_for_resource("acct:alice@example.com")
        .expect("mapping present")
        .replace(&format!("http://{addr_a}/"), "BASE/");
    let b = authority_b
        .jrd_for_resource("acct:alice@example.com")
        .expect("mapping present")
        .replace(&format!("http://{addr_b}/"), "BASE/");
    assert_eq!(a, b, "restart serves byte-identical semantics");
    // And a mapping without a record link is fully byte-identical.
    assert_eq!(
        authority_a.jrd_for_resource("acct:bob@example.com"),
        authority_b.jrd_for_resource("acct:bob@example.com"),
    );
}

// ---------------------------------------------------------------------------
// Predeployment consistency (bootstrap-record handle claims).
// ---------------------------------------------------------------------------

#[test]
fn deployment_consistency_requires_the_exact_handle_claim_per_record_local() {
    // A record claiming the exact served handle is consistent.
    let json = config_json(&format!(
        r#"{{"local":"alice","did":"{}","record":"r.cose"}}"#,
        alice_did().as_str()
    ));
    let claiming = alice_record_with_contact(
        RELAY_NOW_MS,
        None,
        contact_claiming(&["acct:alice@example.com"]),
    );
    let config =
        AuthorityConfig::from_json(json.as_bytes(), |_| Ok(claiming.clone())).expect("loads");
    let report = config.deployment_consistency();
    assert!(report.consistent);
    assert_eq!(report.entries.len(), 1);
    assert_eq!(
        report.entries[0].claimed.as_deref(),
        Some("acct:alice@example.com")
    );

    // The same record under a different domain is a claim mismatch: the
    // signed alsoKnownAs does not follow the configuration.
    let other_domain = format!(
        r#"{{"version":1,"domain":"other.example","handles":[{{"local":"alice","did":"{}","record":"r.cose"}}]}}"#,
        alice_did().as_str()
    );
    let config = AuthorityConfig::from_json(other_domain.as_bytes(), |_| Ok(claiming.clone()))
        .expect("loads");
    let report = config.deployment_consistency();
    assert!(!report.consistent);
    assert!(report.entries[0].record_verified);
    assert_eq!(report.entries[0].claimed, None);

    // Local case matters: a record claiming acct:Alice@… does not make
    // the local "alice" deployable.
    let case_claim = alice_record_with_contact(
        RELAY_NOW_MS,
        None,
        contact_claiming(&["acct:Alice@example.com"]),
    );
    let config =
        AuthorityConfig::from_json(json.as_bytes(), |_| Ok(case_claim.clone())).expect("loads");
    assert!(!config.deployment_consistency().consistent);
}

#[test]
fn deployment_consistency_covers_aliases_and_ignores_record_less_locals() {
    // An alias serves the same record: it must be claimed too.
    let json = config_json(&format!(
        r#"{{"local":"alice","did":"{did}","aliases":["Alice"],"record":"r.cose"}},{}"#,
        bob_entry("bob"),
        did = alice_did().as_str()
    ));
    let primary_only = alice_record_with_contact(
        RELAY_NOW_MS,
        None,
        contact_claiming(&["acct:alice@example.com"]),
    );
    let config =
        AuthorityConfig::from_json(json.as_bytes(), |_| Ok(primary_only.clone())).expect("loads");
    let report = config.deployment_consistency();
    assert!(!report.consistent, "the unclaimed alias blocks deployment");
    let alias = report
        .entries
        .iter()
        .find(|e| e.local == "Alice")
        .expect("alias entry");
    assert!(!alias.ok);
    // Bob has no record: a DID-only mapping is always consistent.
    let bob = report
        .entries
        .iter()
        .find(|e| e.local == "bob")
        .expect("bob entry");
    assert!(bob.ok && !bob.has_record);

    // Claiming both handles makes the same configuration deployable.
    let both = alice_record_with_contact(
        RELAY_NOW_MS,
        None,
        contact_claiming(&["acct:alice@example.com", "acct:Alice@example.com"]),
    );
    let config = AuthorityConfig::from_json(json.as_bytes(), |_| Ok(both.clone())).expect("loads");
    assert!(config.deployment_consistency().consistent);
}
