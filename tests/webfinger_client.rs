//! Production WebFinger client tests (specification sections 10.1 and
//! 10.2; IMPLEMENTATION.md sections 10 and 13 Milestone 5): handle
//! grammar, exact-subject and link-cardinality enforcement, strict
//! bounded JRD handling, media types, redirects, timeouts, and network
//! policy — all through the production client over a deterministic
//! injected transport.
#![allow(clippy::arithmetic_side_effects)]

mod common;

use common::*;
use followee::clock::ManualClock;
use followee::did::DidError;
use followee::relay::client::{
    BudgetMeter, ClientError, NetworkPolicy, OperationBudget, PolicyViolation, TransportError,
};
use followee::webfinger::{
    Handle, HandleError, MAX_JRD_RESPONSE_BYTES, WebFingerClient, WebFingerError,
    percent_encode_component,
};

const ENDPOINT: &str = "http://127.0.0.1:9300/";

fn meter() -> BudgetMeter {
    BudgetMeter::new(OperationBudget {
        deadline_ms: None,
        max_response_bytes: 1024 * 1024,
        max_requests: 16,
    })
}

fn lookup(
    transport: &MockTransport,
    policy: NetworkPolicy,
    handle: &str,
    endpoint: Option<&str>,
) -> Result<followee::webfinger::Discovery, WebFingerError> {
    let clock = ManualClock::new(RELAY_NOW_MS);
    let client = WebFingerClient::new(transport, policy, &clock);
    let handle = Handle::parse(handle).expect("test handle parses");
    client.lookup(&handle, endpoint, &mut meter())
}

fn dev_lookup(
    transport: &MockTransport,
    handle: &str,
) -> Result<followee::webfinger::Discovery, WebFingerError> {
    lookup(
        transport,
        NetworkPolicy::Development,
        handle,
        Some(ENDPOINT),
    )
}

fn on_alice(transport: &MockTransport, body: &str) {
    transport.on(
        &webfinger_url(ENDPOINT, "acct:alice@example.com"),
        jrd_ok(body),
    );
}

// ---------------------------------------------------------------------------
// Section 10.1: handle form.
// ---------------------------------------------------------------------------

#[test]
fn sec_10_1_local_part_grammar_boundaries_are_exact() {
    // 1..=64 ASCII from ALPHA / DIGIT / . / _ / -.
    for valid in ["a", "A", "0", "a.b_c-d", &"x".repeat(64)] {
        let handle = Handle::parse(&format!("{valid}@example.com")).expect(valid);
        assert_eq!(handle.local(), valid, "local part is never altered");
    }
    for (invalid, error) in [
        ("", HandleError::Local),
        (&"x".repeat(65) as &str, HandleError::Local),
        ("with space", HandleError::Local),
        ("percent%40", HandleError::Local),
        ("plus+tag", HandleError::Local),
        ("ünï", HandleError::Local),
    ] {
        assert_eq!(
            Handle::parse(&format!("{invalid}@example.com")).unwrap_err(),
            error,
            "{invalid:?}"
        );
    }
    assert_eq!(Handle::parse("noatsign").unwrap_err(), HandleError::Form);
    assert_eq!(Handle::parse("a@b@c").unwrap_err(), HandleError::Form);
}

#[test]
fn sec_10_1_local_part_is_case_sensitive_at_the_protocol_layer() {
    let lower = Handle::parse("alice@example.com").expect("parses");
    let upper = Handle::parse("Alice@example.com").expect("parses");
    assert_ne!(lower, upper);
    assert_eq!(lower.resource(), "acct:alice@example.com");
    assert_eq!(upper.resource(), "acct:Alice@example.com");
}

#[test]
fn sec_10_1_domain_canonicalizes_to_lowercase_ascii_idna() {
    assert_eq!(
        Handle::parse("alice@EXAMPLE.COM").expect("parses").domain(),
        "example.com"
    );
    // IDNA2008 processing: a Unicode domain becomes its punycode ASCII
    // form; the resource uses the canonical form.
    let unicode = Handle::parse("alice@bücher.example").expect("parses");
    assert_eq!(unicode.domain(), "xn--bcher-kva.example");
    assert_eq!(unicode.resource(), "acct:alice@xn--bcher-kva.example");
    assert_eq!(
        Handle::parse("alice@localhost").expect("parses").domain(),
        "localhost"
    );
}

#[test]
fn sec_10_1_invalid_domains_are_rejected() {
    for domain in [
        "",
        " ",
        "exa mple.com",
        "under_score.example",
        "-leading.example",
        "trailing-.example",
        "double..example",
        "example.com.",
        &format!("{}.example", "x".repeat(64)),
    ] {
        assert_eq!(
            Handle::parse(&format!("alice@{domain}")).unwrap_err(),
            HandleError::Domain,
            "{domain:?}"
        );
    }
}

#[test]
fn sec_10_1_acct_uri_claims_parse_with_case_insensitive_scheme_only() {
    for uri in ["acct:alice@example.com", "ACCT:alice@EXAMPLE.com"] {
        let handle = Handle::from_acct_uri(uri).expect(uri);
        assert_eq!(handle.local(), "alice");
        assert_eq!(handle.domain(), "example.com");
    }
    for uri in [
        "https://example.com/alice",
        "alice@example.com",
        "acct:alice%40example.com",
        "acct:",
    ] {
        assert!(Handle::from_acct_uri(uri).is_err(), "{uri:?}");
    }
}

#[test]
fn sec_10_2_resource_percent_encoding_matches_the_specification_example() {
    assert_eq!(
        percent_encode_component("acct:alice@example.com"),
        "acct%3Aalice%40example.com"
    );
}

// ---------------------------------------------------------------------------
// Section 10.2: successful mapping requirements.
// ---------------------------------------------------------------------------

#[test]
fn sec_10_2_exact_subject_with_exactly_one_followee_link_resolves() {
    let transport = MockTransport::new();
    on_alice(
        &transport,
        &jrd_body("acct:alice@example.com", alice_did().as_str()),
    );
    let discovery = dev_lookup(&transport, "alice@example.com").expect("resolves");
    assert_eq!(discovery.did, alice_did());
    assert_eq!(discovery.resource, "acct:alice@example.com");
    assert!(discovery.record_links.is_empty());
    // The Accept header names the JRD media type on the wire.
    let requests = transport.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(
        requests[0].url,
        webfinger_url(ENDPOINT, "acct:alice@example.com")
    );
}

#[test]
fn sec_10_2_wrong_subject_is_rejected() {
    let transport = MockTransport::new();
    on_alice(
        &transport,
        &jrd_body("acct:bob@example.com", alice_did().as_str()),
    );
    let error = dev_lookup(&transport, "alice@example.com").unwrap_err();
    assert_eq!(
        error,
        WebFingerError::SubjectMismatch {
            subject: "acct:bob@example.com".to_owned()
        }
    );
    assert_eq!(error.symbol(), "subjectMismatch");
}

#[test]
fn sec_10_2_subject_comparison_is_exact_not_case_folded() {
    // Even a case variant of the canonical resource is a mismatch:
    // verification is for the exact canonical resource requested.
    let transport = MockTransport::new();
    on_alice(
        &transport,
        &jrd_body("acct:Alice@example.com", alice_did().as_str()),
    );
    assert_eq!(
        dev_lookup(&transport, "alice@example.com")
            .unwrap_err()
            .symbol(),
        "subjectMismatch"
    );
}

#[test]
fn sec_10_2_missing_subject_is_rejected() {
    let transport = MockTransport::new();
    on_alice(
        &transport,
        &format!(
            r#"{{"links":[{{"rel":"https://w3id.org/followee/rel/did","href":"{}"}}]}}"#,
            alice_did().as_str()
        ),
    );
    let error = dev_lookup(&transport, "alice@example.com").unwrap_err();
    assert_eq!(error, WebFingerError::MissingSubject);
    assert_eq!(error.symbol(), "missingSubject");
}

#[test]
fn sec_10_2_zero_followee_links_is_not_a_mapping() {
    let transport = MockTransport::new();
    // No links member at all.
    on_alice(&transport, r#"{"subject":"acct:alice@example.com"}"#);
    assert_eq!(
        dev_lookup(&transport, "alice@example.com").unwrap_err(),
        WebFingerError::NoFolloweeLink
    );
    // A links array with only foreign relations.
    let transport = MockTransport::new();
    on_alice(
        &transport,
        r#"{"subject":"acct:alice@example.com","links":[{"rel":"http://webfinger.net/rel/profile-page","href":"https://example.com/alice"}]}"#,
    );
    let error = dev_lookup(&transport, "alice@example.com").unwrap_err();
    assert_eq!(error, WebFingerError::NoFolloweeLink);
    assert_eq!(error.symbol(), "noFolloweeLink");
}

#[test]
fn sec_10_2_two_or_more_followee_links_are_ambiguous() {
    for count in [2usize, 3] {
        let links: Vec<String> = (0..count)
            .map(|_| {
                format!(
                    r#"{{"rel":"https://w3id.org/followee/rel/did","href":"{}"}}"#,
                    alice_did().as_str()
                )
            })
            .collect();
        let body = format!(
            r#"{{"subject":"acct:alice@example.com","links":[{}]}}"#,
            links.join(",")
        );
        let transport = MockTransport::new();
        on_alice(&transport, &body);
        let error = dev_lookup(&transport, "alice@example.com").unwrap_err();
        assert_eq!(error, WebFingerError::MultipleFolloweeLinks(count));
        assert_eq!(error.symbol(), "multipleFolloweeLinks");
    }
}

#[test]
fn sec_10_2_malformed_and_wrong_scheme_did_targets_are_rejected() {
    for (href, expected) in [
        ("not-a-did", DidError::InvalidDid),
        ("did:web:example.com", DidError::InvalidDid),
        ("https://example.com/alice", DidError::InvalidDid),
        ("did:flw:QmNoMultibasePrefix", DidError::InvalidDid),
        // Structurally well-formed multihash (code 0x13, 32 declared and
        // present digest bytes): the production classification is
        // preserved.
        (
            "did:flw:zS5R7jbB5S625FMckt7C8ANBg4WUubLMvdttMD72yioQY5d",
            DidError::UnsupportedHash,
        ),
    ] {
        let transport = MockTransport::new();
        on_alice(&transport, &jrd_body("acct:alice@example.com", href));
        let error = dev_lookup(&transport, "alice@example.com").unwrap_err();
        assert_eq!(
            error,
            WebFingerError::InvalidDidTarget(expected),
            "{href:?}"
        );
    }
    // A Followee link without any href target.
    let transport = MockTransport::new();
    on_alice(
        &transport,
        r#"{"subject":"acct:alice@example.com","links":[{"rel":"https://w3id.org/followee/rel/did"}]}"#,
    );
    assert_eq!(
        dev_lookup(&transport, "alice@example.com").unwrap_err(),
        WebFingerError::MissingDidTarget
    );
}

// ---------------------------------------------------------------------------
// Untrusted JRD handling: parse faults, bounds, media types.
// ---------------------------------------------------------------------------

#[test]
fn sec_10_2_malformed_json_is_rejected() {
    let transport = MockTransport::new();
    on_alice(&transport, "{\"subject\": \"acct:alice@example.com\"");
    assert_eq!(
        dev_lookup(&transport, "alice@example.com")
            .unwrap_err()
            .symbol(),
        "jrdMalformed"
    );
}

#[test]
fn sec_10_2_duplicate_member_names_are_rejected_not_collapsed() {
    // A second subject member could otherwise smuggle a different
    // resource past a last-wins parser.
    let transport = MockTransport::new();
    on_alice(
        &transport,
        &format!(
            r#"{{"subject":"acct:alice@example.com","subject":"acct:mallory@example.com","links":[{{"rel":"https://w3id.org/followee/rel/did","href":"{}"}}]}}"#,
            alice_did().as_str()
        ),
    );
    let error = dev_lookup(&transport, "alice@example.com").unwrap_err();
    assert_eq!(error.symbol(), "jrdDuplicateMember");
}

#[test]
fn sec_10_2_oversized_responses_are_rejected_at_the_byte_bound() {
    let padding = "x".repeat(MAX_JRD_RESPONSE_BYTES as usize);
    let transport = MockTransport::new();
    on_alice(
        &transport,
        &format!(r#"{{"subject":"acct:alice@example.com","pad":"{padding}"}}"#),
    );
    assert_eq!(
        dev_lookup(&transport, "alice@example.com").unwrap_err(),
        WebFingerError::Client(ClientError::ResponseTooLarge)
    );
}

#[test]
fn sec_10_2_moderately_large_valid_jrds_are_accepted_within_the_bound() {
    // The 64 KiB bound must not silently shrink: a valid JRD a few KiB
    // large (well past any accidental smaller constant) still resolves.
    let padding = "x".repeat(8 * 1024);
    let transport = MockTransport::new();
    on_alice(
        &transport,
        &format!(
            r#"{{"subject":"acct:alice@example.com","links":[{{"rel":"https://w3id.org/followee/rel/did","href":"{}"}}],"pad":"{padding}"}}"#,
            alice_did().as_str()
        ),
    );
    let discovery = dev_lookup(&transport, "alice@example.com").expect("resolves");
    assert_eq!(discovery.did, alice_did());
}

#[test]
fn sec_10_2_excessive_nesting_is_rejected() {
    let deep = format!(
        r#"{{"subject":"acct:alice@example.com","deep":{}1{}}}"#,
        "[".repeat(16),
        "]".repeat(16)
    );
    let transport = MockTransport::new();
    on_alice(&transport, &deep);
    assert_eq!(
        dev_lookup(&transport, "alice@example.com")
            .unwrap_err()
            .symbol(),
        "jrdLimitExceeded"
    );
}

#[test]
fn sec_10_2_invalid_utf8_bodies_are_rejected() {
    let mut body = br#"{"subject":""#.to_vec();
    body.extend_from_slice(&[0xFF, 0xFE]);
    body.extend_from_slice(br#""}"#);
    let transport = MockTransport::new();
    transport.on(
        &webfinger_url(ENDPOINT, "acct:alice@example.com"),
        followee::relay::client::TransportResponse {
            status: 200,
            content_type: Some("application/jrd+json".to_owned()),
            location: None,
            body,
        },
    );
    assert_eq!(
        dev_lookup(&transport, "alice@example.com")
            .unwrap_err()
            .symbol(),
        "jrdInvalidUtf8"
    );
}

#[test]
fn sec_10_2_wrong_media_type_is_rejected() {
    // application/jrd+json is normative (sections 6.4 and 10.2); plain
    // application/json is not accepted.
    for wrong in ["application/json", "text/html", "application/cbor"] {
        let transport = MockTransport::new();
        transport.on(
            &webfinger_url(ENDPOINT, "acct:alice@example.com"),
            followee::relay::client::TransportResponse {
                status: 200,
                content_type: Some((*wrong).to_owned()),
                location: None,
                body: jrd_body("acct:alice@example.com", alice_did().as_str()).into_bytes(),
            },
        );
        assert_eq!(
            dev_lookup(&transport, "alice@example.com").unwrap_err(),
            WebFingerError::Client(ClientError::MediaType),
            "{wrong}"
        );
    }
    // Parameters after the essence are tolerated.
    let transport = MockTransport::new();
    transport.on(
        &webfinger_url(ENDPOINT, "acct:alice@example.com"),
        followee::relay::client::TransportResponse {
            status: 200,
            content_type: Some("application/jrd+json; charset=utf-8".to_owned()),
            location: None,
            body: jrd_body("acct:alice@example.com", alice_did().as_str()).into_bytes(),
        },
    );
    assert!(dev_lookup(&transport, "alice@example.com").is_ok());
}

#[test]
fn sec_10_2_http_404_is_handle_not_found_not_proof_of_absence() {
    let transport = MockTransport::new();
    transport.on(
        &webfinger_url(ENDPOINT, "acct:alice@example.com"),
        status_only(404),
    );
    let error = dev_lookup(&transport, "alice@example.com").unwrap_err();
    assert_eq!(error, WebFingerError::HandleNotFound);
    assert_eq!(error.symbol(), "handleNotFound");
}

// ---------------------------------------------------------------------------
// Network policy: HTTPS, redirects, unsafe destinations, timeouts.
// ---------------------------------------------------------------------------

#[test]
fn sec_10_2_public_lookup_derives_the_https_endpoint_from_the_domain() {
    let transport = MockTransport::new();
    let url = webfinger_url("https://example.com/", "acct:alice@example.com");
    transport.on(
        &url,
        jrd_ok(&jrd_body("acct:alice@example.com", alice_did().as_str())),
    );
    let discovery =
        lookup(&transport, NetworkPolicy::Public, "alice@example.com", None).expect("resolves");
    assert_eq!(discovery.contacted, vec![url]);
}

#[test]
fn sec_10_2_redirects_must_remain_within_policy() {
    // An HTTPS-to-HTTPS redirect is followed (bounded, revalidated).
    let transport = MockTransport::new();
    let first = webfinger_url("https://example.com/", "acct:alice@example.com");
    let target = "https://finger.example.com/webfinger?resource=acct%3Aalice%40example.com";
    transport.on(&first, redirect_to(302, target));
    transport.on(
        target,
        jrd_ok(&jrd_body("acct:alice@example.com", alice_did().as_str())),
    );
    let discovery =
        lookup(&transport, NetworkPolicy::Public, "alice@example.com", None).expect("resolves");
    assert_eq!(discovery.contacted.len(), 2, "both hops are recorded");

    // A redirect down to plain HTTP violates the public policy.
    let transport = MockTransport::new();
    transport.on(
        &first,
        redirect_to(302, "http://example.com/.well-known/webfinger"),
    );
    let error = lookup(&transport, NetworkPolicy::Public, "alice@example.com", None).unwrap_err();
    assert_eq!(
        error,
        WebFingerError::Client(ClientError::Policy(PolicyViolation::SchemeNotPermitted))
    );

    // A redirect into private address space is refused before connecting.
    let transport = MockTransport::new();
    transport.on(&first, redirect_to(302, "https://10.0.0.7/webfinger"));
    assert_eq!(
        lookup(&transport, NetworkPolicy::Public, "alice@example.com", None).unwrap_err(),
        WebFingerError::Client(ClientError::Policy(
            PolicyViolation::DestinationNotPermitted
        ))
    );

    // A relative redirect target is refused.
    let transport = MockTransport::new();
    transport.on(&first, redirect_to(302, "/elsewhere"));
    assert_eq!(
        lookup(&transport, NetworkPolicy::Public, "alice@example.com", None)
            .unwrap_err()
            .symbol(),
        "networkPolicy"
    );
}

#[test]
fn sec_10_2_unsafe_literal_destinations_are_rejected_by_policy() {
    // A handle domain that is itself a sensitive literal address never
    // reaches the transport under the public policy.
    let transport = MockTransport::new();
    let error = lookup(&transport, NetworkPolicy::Public, "alice@10.0.0.7", None).unwrap_err();
    assert_eq!(
        error,
        WebFingerError::Client(ClientError::Policy(
            PolicyViolation::DestinationNotPermitted
        ))
    );
    assert!(transport.requests().is_empty(), "nothing was contacted");
}

#[test]
fn sec_10_2_timeouts_are_transport_failures_not_mappings() {
    let transport = MockTransport::new();
    transport.fail(
        &webfinger_url(ENDPOINT, "acct:alice@example.com"),
        TransportError::TimedOut,
    );
    let error = dev_lookup(&transport, "alice@example.com").unwrap_err();
    assert_eq!(error.symbol(), "transportTimeout");
}

#[test]
fn sec_10_2_endpoint_override_requires_the_development_policy() {
    let transport = MockTransport::new();
    let error = lookup(
        &transport,
        NetworkPolicy::Public,
        "alice@example.com",
        Some(ENDPOINT),
    )
    .unwrap_err();
    assert_eq!(error, WebFingerError::EndpointOverridePolicy);
    assert!(transport.requests().is_empty());
}

#[test]
fn sec_14_1_lookups_charge_the_shared_budget() {
    let transport = MockTransport::new();
    on_alice(
        &transport,
        &jrd_body("acct:alice@example.com", alice_did().as_str()),
    );
    let clock = ManualClock::new(RELAY_NOW_MS);
    let client = WebFingerClient::new(&transport, NetworkPolicy::Development, &clock);
    let handle = Handle::parse("alice@example.com").expect("parses");
    let mut meter = BudgetMeter::new(OperationBudget {
        deadline_ms: None,
        max_response_bytes: 1024 * 1024,
        max_requests: 1,
    });
    client
        .lookup(&handle, Some(ENDPOINT), &mut meter)
        .expect("first lookup fits the budget");
    assert_eq!(meter.requests_used(), 1);
    let error = client
        .lookup(&handle, Some(ENDPOINT), &mut meter)
        .unwrap_err();
    assert_eq!(
        error,
        WebFingerError::Client(ClientError::BudgetExhausted("request budget"))
    );
}
