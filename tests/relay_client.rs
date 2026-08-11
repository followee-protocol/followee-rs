//! Strict production relay-client tests (specification sections 12.1, 12.3,
//! 12.6, 14.1, 15.4; Appendix B.11.2/B.11.3/B.11.4): exact request bytes,
//! deterministic-CBOR-first response validation, status-dependent field
//! rules, cardinality, positional candidate isolation, HTTP status and
//! media-type handling, redirect policy, and shared budget accounting —
//! all through the production [`RelayClient`] with injected deterministic
//! transports and clocks.
#![allow(clippy::arithmetic_side_effects)]

mod common;

use common::*;
use followee::clock::ManualClock;
use followee::error::VerifyError;
use followee::relay::client::{
    BudgetMeter, ClientError, Method, NetworkPolicy, OperationBudget, PolicyViolation,
    ReceivedResult, RelayClient, TransportError, TransportResponse,
};
use followee::relay::wire::ReceivedChangesResponse;
use followee::verify::verify_record_for_target;

const BASE: &str = "http://127.0.0.1:9001/";

fn meter() -> BudgetMeter {
    BudgetMeter::new(OperationBudget {
        deadline_ms: None,
        max_response_bytes: 8 * 1024 * 1024,
        max_requests: 64,
    })
}

fn dev_client<'a>(transport: &'a MockTransport, clock: &'a ManualClock) -> RelayClient<'a> {
    RelayClient::new(transport, NetworkPolicy::Development, clock)
}

fn b11_field(case: &str, field: &str) -> Vec<u8> {
    fx_bytes_at("b11", &format!("{case}/{field}"))
}

/// Rebuilds the B.11.3 response bytes (fixtures publish length and digest;
/// the body embeds the B.8 and B.9 envelopes).
fn b11_3_response() -> Vec<u8> {
    let response = resolve_response_with(
        &b11_generation(),
        &[
            rr_full(&fx_bytes("b8_envelope")),
            rr_full(&fx_bytes("bob_envelope")),
        ],
    );
    assert_eq!(response.len(), 743, "B.11.3 stated response length");
    assert_eq!(
        hex::encode(followee::crypto::sha256(&response)),
        "62246877adbd56be2996ea37d05475d88c0e7932ff9b042f8ddbb9a809f8f4ca",
        "B.11.3 stated response digest"
    );
    response
}

// ---------------------------------------------------------------------------
// Exact paths, methods, media types, and request bytes.
// ---------------------------------------------------------------------------

#[test]
fn sec_12_1_operations_use_exact_paths_methods_and_media_types() {
    let transport = MockTransport::new();
    let clock = ManualClock::new(RELAY_NOW_MS);
    let client = dev_client(&transport, &clock);
    let generation = b11_generation();
    transport.on(
        "http://127.0.0.1:9001/v1/info",
        cbor_ok(info_response(&[0xAA; 16], &[0xC0; 16], &generation)),
    );
    transport.on(
        "http://127.0.0.1:9001/v1/directory",
        cbor_ok(directory_response_with(&generation, &[])),
    );
    transport.on(
        "http://127.0.0.1:9001/v1/resolve",
        cbor_ok(resolve_response_with(&generation, &[rr_absent()])),
    );
    transport.on(
        "http://127.0.0.1:9001/v1/publish",
        cbor_ok(r_map(&[(r_uint(0), r_uint(1)), (r_uint(1), r_uint(0))])),
    );
    transport.on(
        "http://127.0.0.1:9001/v1/changes",
        cbor_ok(changes_success_with(&generation, &[], b"c1", false)),
    );

    let mut m = meter();
    client.info(BASE, &mut m).expect("info");
    client.directory(BASE, &mut m).expect("directory");
    client
        .resolve(BASE, &[alice_did().as_str()], &mut m)
        .expect("resolve");
    client
        .publish(BASE, &fx_bytes("root_record_envelope"), &mut m)
        .expect("publish");
    client
        .changes(BASE, None, 16, 1024 * 1024, &mut m)
        .expect("changes");

    let requests = transport.requests();
    let summary: Vec<(Method, &str, Option<&'static str>)> = requests
        .iter()
        .map(|r| (r.method, r.url.as_str(), r.content_type))
        .collect();
    assert_eq!(
        summary,
        vec![
            (Method::Get, "http://127.0.0.1:9001/v1/info", None),
            (Method::Get, "http://127.0.0.1:9001/v1/directory", None),
            (
                Method::Post,
                "http://127.0.0.1:9001/v1/resolve",
                Some("application/cbor")
            ),
            (
                Method::Post,
                "http://127.0.0.1:9001/v1/publish",
                Some("application/cose")
            ),
            (
                Method::Post,
                "http://127.0.0.1:9001/v1/changes",
                Some("application/cbor")
            ),
        ]
    );
    // The publish body is the exact untouched record bytes.
    assert_eq!(requests[3].body, fx_bytes("root_record_envelope"));
}

#[test]
fn sec_b11_3_client_emits_the_exact_published_resolve_request_bytes() {
    let transport = MockTransport::new();
    let clock = ManualClock::new(RELAY_NOW_MS);
    let client = dev_client(&transport, &clock);
    transport.on(
        "http://127.0.0.1:9001/v1/resolve",
        cbor_ok(b11_3_response()),
    );
    let mut m = meter();
    client
        .resolve(BASE, &[alice_did().as_str(), bob_did().as_str()], &mut m)
        .expect("accepted wrapper");
    assert_eq!(
        transport.requests()[0].body,
        b11_field("b11_3", "request_bytes"),
        "exact published B.11.3 request bytes"
    );
}

// ---------------------------------------------------------------------------
// B.11.2: invalid outer response rejected at the wrapper layer.
// ---------------------------------------------------------------------------

#[test]
fn sec_b11_2_non_deterministic_outer_response_is_rejected_not_absent() {
    let transport = MockTransport::new();
    let clock = ManualClock::new(RELAY_NOW_MS);
    let client = dev_client(&transport, &clock);
    transport.on(
        "http://127.0.0.1:9001/v1/resolve",
        cbor_ok(b11_field("b11_2", "response_bytes")),
    );
    let mut m = meter();
    let error = client
        .resolve(BASE, &[alice_did().as_str()], &mut m)
        .expect_err("wrapper rejected");
    assert_eq!(
        error,
        ClientError::OuterResponse(VerifyError::NonDeterministicCbor),
        "exact nonDeterministicCbor classification, never an Absent result"
    );
    // The attempt still consumed the ordinary budgets.
    assert_eq!(m.requests_used(), 1);
    assert!(m.bytes_used() > 0);
}

// ---------------------------------------------------------------------------
// B.11.3: positional candidate isolation after wrapper acceptance.
// ---------------------------------------------------------------------------

#[test]
fn sec_b11_3_wrapper_accepts_and_only_the_invalid_candidate_is_discarded() {
    let transport = MockTransport::new();
    let clock = ManualClock::new(RELAY_NOW_MS);
    let client = dev_client(&transport, &clock);
    transport.on(
        "http://127.0.0.1:9001/v1/resolve",
        cbor_ok(b11_3_response()),
    );
    let mut m = meter();
    let outcome = client
        .resolve(BASE, &[alice_did().as_str(), bob_did().as_str()], &mut m)
        .expect("the wrapper is accepted; opaque candidates cannot invalidate it");
    let results = outcome.value.results;
    assert_eq!(results.len(), 2, "positional alignment preserved");

    // Index 0: the B.8 candidate fails local verification for Alice's DID
    // with the exact binding error; only this candidate is discarded.
    let ReceivedResult::Full(alice_bytes) = &results[0] else {
        panic!("index 0 is a Full candidate");
    };
    assert_eq!(alice_bytes, &fx_bytes("b8_envelope"));
    assert_eq!(
        verify_record_for_target(alice_did().as_str(), alice_bytes).unwrap_err(),
        VerifyError::IdentityBindingMismatch,
    );

    // Index 1: Bob's candidate remains at its original index and verifies.
    let ReceivedResult::Full(bob_bytes) = &results[1] else {
        panic!("index 1 is a Full candidate, not shifted");
    };
    let bob = verify_record_for_target(bob_did().as_str(), bob_bytes).expect("Bob verifies");
    assert_eq!(bob.envelope_bytes(), fx_bytes("bob_envelope").as_slice());
}

// ---------------------------------------------------------------------------
// B.11.4: cardinality.
// ---------------------------------------------------------------------------

#[test]
fn sec_b11_4_result_count_mismatch_rejects_the_complete_response() {
    let transport = MockTransport::new();
    let clock = ManualClock::new(RELAY_NOW_MS);
    let client = dev_client(&transport, &clock);
    // Two results for three requested DIDs, both independently valid.
    transport.on(
        "http://127.0.0.1:9001/v1/resolve",
        cbor_ok(resolve_response_with(
            &b11_generation(),
            &[
                rr_full(&fx_bytes("root_record_envelope")),
                rr_full(&fx_bytes("bob_envelope")),
            ],
        )),
    );
    let mut m = meter();
    let alice = alice_did();
    let bob = bob_did();
    let error = client
        .resolve(
            BASE,
            &[alice.as_str(), alice.as_str(), bob.as_str()],
            &mut m,
        )
        .expect_err("count mismatch rejects the response");
    assert_eq!(
        error,
        ClientError::CardinalityMismatch {
            requested: 3,
            returned: 2
        },
        "no Absent inference for the omitted occurrence or tail"
    );
}

// ---------------------------------------------------------------------------
// Changes: status-dependent field rules and the item-limit gate.
// ---------------------------------------------------------------------------

fn changes_once(body: Vec<u8>, item_limit: u64) -> Result<ReceivedChangesResponse, ClientError> {
    let transport = MockTransport::new();
    let clock = ManualClock::new(RELAY_NOW_MS);
    let client = dev_client(&transport, &clock);
    transport.on("http://127.0.0.1:9001/v1/changes", cbor_ok(body));
    let mut m = meter();
    client
        .changes(BASE, None, item_limit, 4 * 1024 * 1024, &mut m)
        .map(|outcome| outcome.value)
}

#[test]
fn sec_12_6_exact_reset_required_response_is_accepted_and_extra_labels_reject() {
    assert_eq!(
        changes_once(changes_reset_body(), 16).expect("exact two-field reset"),
        ReceivedChangesResponse::ResetRequired
    );
    // Status 1 with any additional label is a schema violation.
    for extra in [
        (r_uint(2), r_array(&[])),
        (r_uint(3), r_bstr(b"c")),
        (r_uint(4), vec![0xf4]),
        (r_uint(5), r_bstr(&[0u8; 16])),
        (r_uint(6), r_uint(18)),
    ] {
        let body = r_map(&[(r_uint(0), r_uint(1)), (r_uint(1), r_uint(1)), extra]);
        assert_eq!(
            changes_once(body, 16).expect_err("forbidden label"),
            ClientError::OuterResponse(VerifyError::SchemaViolation)
        );
    }
}

#[test]
fn sec_12_6_success_and_error_status_field_rules_are_enforced() {
    let generation = b11_generation();
    // Success requires entries, nextCursor, hasMore, directoryGeneration.
    let complete = changes_success_with(&generation, &[], b"c1", false);
    assert!(matches!(
        changes_once(complete, 16).expect("complete success accepted"),
        ReceivedChangesResponse::Success { .. }
    ));
    // Each missing required success field rejects.
    let full_entries: Vec<(Vec<u8>, Vec<u8>)> = vec![
        (r_uint(0), r_uint(1)),
        (r_uint(1), r_uint(0)),
        (r_uint(2), r_array(&[])),
        (r_uint(3), r_bstr(b"c1")),
        (r_uint(4), vec![0xf4]),
        (r_uint(5), r_bstr(&generation)),
    ];
    for omit in 2..=5usize {
        let entries: Vec<(Vec<u8>, Vec<u8>)> = full_entries
            .iter()
            .enumerate()
            .filter(|(i, _)| *i != omit)
            .map(|(_, e)| e.clone())
            .collect();
        assert_eq!(
            changes_once(r_map(&entries), 16).expect_err("missing required field"),
            ClientError::OuterResponse(VerifyError::SchemaViolation),
            "omitted label {omit}"
        );
    }
    // Success with errorCode is forbidden.
    let mut with_error = full_entries.clone();
    with_error.push((r_uint(6), r_uint(19)));
    assert_eq!(
        changes_once(r_map(&with_error), 16).expect_err("errorCode on success"),
        ClientError::OuterResponse(VerifyError::SchemaViolation)
    );
    // Status 2 requires errorCode and forbids the success fields.
    assert_eq!(
        changes_once(changes_error_body(18), 16).expect("status-2 error accepted"),
        ReceivedChangesResponse::Error(18)
    );
    let status2_missing_code = r_map(&[(r_uint(0), r_uint(1)), (r_uint(1), r_uint(2))]);
    assert_eq!(
        changes_once(status2_missing_code, 16).expect_err("errorCode required"),
        ClientError::OuterResponse(VerifyError::SchemaViolation)
    );
    let status2_with_cursor = r_map(&[
        (r_uint(0), r_uint(1)),
        (r_uint(1), r_uint(2)),
        (r_uint(3), r_bstr(b"c1")),
        (r_uint(6), r_uint(18)),
    ]);
    assert_eq!(
        changes_once(status2_with_cursor, 16).expect_err("forbidden field on status 2"),
        ClientError::OuterResponse(VerifyError::SchemaViolation)
    );
}

#[test]
fn sec_12_6_over_item_limit_response_is_rejected_before_any_entry() {
    let generation = b11_generation();
    let entries: Vec<Vec<u8>> = (1..=3)
        .map(|i| ch_entry(alice_did().as_str(), rr_ref(0), i))
        .collect();
    let body = changes_success_with(&generation, &entries, b"c3", false);
    assert_eq!(
        changes_once(body, 2).expect_err("three entries for itemLimit 2"),
        ClientError::OuterResponse(VerifyError::SchemaViolation),
        "the complete response is rejected; its cursor is never surfaced"
    );
}

#[test]
fn sec_12_6_misordered_last_updated_rejects_the_complete_response() {
    let generation = b11_generation();
    for order in [[2u64, 1], [2, 2]] {
        let entries: Vec<Vec<u8>> = order
            .iter()
            .map(|i| ch_entry(alice_did().as_str(), rr_ref(0), *i))
            .collect();
        let body = changes_success_with(&generation, &entries, b"c", false);
        assert_eq!(
            changes_once(body, 16).expect_err("non-increasing lastUpdated"),
            ClientError::OuterResponse(VerifyError::SchemaViolation),
            "{order:?}"
        );
    }
}

#[test]
fn sec_12_6_over_byte_limit_changes_response_is_rejected() {
    let transport = MockTransport::new();
    let clock = ManualClock::new(RELAY_NOW_MS);
    let client = dev_client(&transport, &clock);
    let generation = b11_generation();
    let body = changes_success_with(&generation, &[], b"c1", false);
    let limit = (body.len() as u64) - 1;
    transport.on("http://127.0.0.1:9001/v1/changes", cbor_ok(body));
    let mut m = meter();
    let error = client
        .changes(BASE, None, 16, limit, &mut m)
        .expect_err("body exceeds requested byteLimit");
    assert_eq!(error, ClientError::ResponseTooLarge);
}

// ---------------------------------------------------------------------------
// HTTP status, media type, and budget handling.
// ---------------------------------------------------------------------------

#[test]
fn sec_15_4_non_200_statuses_are_transport_results_not_protocol_results() {
    for status in [400u16, 413, 415, 429, 500, 503] {
        let transport = MockTransport::new();
        let clock = ManualClock::new(RELAY_NOW_MS);
        let client = dev_client(&transport, &clock);
        transport.on(
            "http://127.0.0.1:9001/v1/resolve",
            TransportResponse {
                status,
                content_type: None,
                location: None,
                body: vec![0xA0; 8],
            },
        );
        let mut m = meter();
        let error = client
            .resolve(BASE, &[alice_did().as_str()], &mut m)
            .expect_err("non-200");
        assert_eq!(error, ClientError::HttpStatus { status });
    }
}

#[test]
fn sec_12_1_response_media_type_must_be_cbor() {
    for content_type in [None, Some("text/plain"), Some("application/cose")] {
        let transport = MockTransport::new();
        let clock = ManualClock::new(RELAY_NOW_MS);
        let client = dev_client(&transport, &clock);
        transport.on(
            "http://127.0.0.1:9001/v1/resolve",
            TransportResponse {
                status: 200,
                content_type: content_type.map(str::to_owned),
                location: None,
                body: resolve_response_with(&b11_generation(), &[rr_absent()]),
            },
        );
        let mut m = meter();
        let error = client
            .resolve(BASE, &[alice_did().as_str()], &mut m)
            .expect_err("wrong media type");
        assert_eq!(error, ClientError::MediaType, "{content_type:?}");
    }
    // Parameters and case are tolerated on the correct essence.
    let transport = MockTransport::new();
    let clock = ManualClock::new(RELAY_NOW_MS);
    let client = dev_client(&transport, &clock);
    transport.on(
        "http://127.0.0.1:9001/v1/resolve",
        TransportResponse {
            status: 200,
            content_type: Some("Application/CBOR; charset=binary".to_owned()),
            location: None,
            body: resolve_response_with(&b11_generation(), &[rr_absent()]),
        },
    );
    let mut m = meter();
    client
        .resolve(BASE, &[alice_did().as_str()], &mut m)
        .expect("essence matches");
}

#[test]
fn sec_14_1_budgets_are_charged_and_exhaust_without_reset() {
    let transport = MockTransport::new();
    let clock = ManualClock::new(RELAY_NOW_MS);
    let client = dev_client(&transport, &clock);
    let body = resolve_response_with(&b11_generation(), &[rr_absent()]);
    let body_len = body.len() as u64;
    for _ in 0..3 {
        transport.on("http://127.0.0.1:9001/v1/resolve", cbor_ok(body.clone()));
    }
    // Request budget: the third attempt is refused before any request.
    let mut m = BudgetMeter::new(OperationBudget {
        deadline_ms: None,
        max_response_bytes: 8 * body_len,
        max_requests: 2,
    });
    client
        .resolve(BASE, &[alice_did().as_str()], &mut m)
        .expect("first");
    client
        .resolve(BASE, &[alice_did().as_str()], &mut m)
        .expect("second");
    assert_eq!(
        client
            .resolve(BASE, &[alice_did().as_str()], &mut m)
            .expect_err("request budget"),
        ClientError::BudgetExhausted("request budget")
    );
    assert_eq!(transport.requests().len(), 2, "no request was attempted");
    assert_eq!(m.bytes_used(), 2 * body_len, "bytes charged per response");

    // Deadline: an expired injected-clock deadline refuses the request.
    let mut expired = BudgetMeter::new(OperationBudget {
        deadline_ms: Some(RELAY_NOW_MS),
        max_response_bytes: 8 * body_len,
        max_requests: 8,
    });
    assert_eq!(
        client
            .resolve(BASE, &[alice_did().as_str()], &mut expired)
            .expect_err("deadline"),
        ClientError::BudgetExhausted("deadline")
    );

    // Byte budget: charged even for a response that then exceeds it.
    let mut small = BudgetMeter::new(OperationBudget {
        deadline_ms: None,
        max_response_bytes: body_len - 1,
        max_requests: 8,
    });
    transport.on("http://127.0.0.1:9001/v1/resolve", cbor_ok(body));
    assert_eq!(
        client
            .resolve(BASE, &[alice_did().as_str()], &mut small)
            .expect_err("byte budget"),
        ClientError::BudgetExhausted("response-byte budget")
    );
}

#[test]
fn sec_14_1_transport_timeout_is_reported_distinctly() {
    let transport = MockTransport::new();
    let clock = ManualClock::new(RELAY_NOW_MS);
    let client = dev_client(&transport, &clock);
    transport.fail("http://127.0.0.1:9001/v1/resolve", TransportError::TimedOut);
    let mut m = meter();
    let error = client
        .resolve(BASE, &[alice_did().as_str()], &mut m)
        .expect_err("timeout");
    assert_eq!(error, ClientError::Transport(TransportError::TimedOut));
    assert_eq!(error.symbol(), "transportTimeout");
    assert_eq!(m.requests_used(), 1, "the attempt was charged");
}

// ---------------------------------------------------------------------------
// Redirect policy.
// ---------------------------------------------------------------------------

#[test]
fn sec_9_5_post_redirects_are_refused_and_get_redirects_are_policy_checked() {
    // POST: refused outright.
    let transport = MockTransport::new();
    let clock = ManualClock::new(RELAY_NOW_MS);
    let client = dev_client(&transport, &clock);
    transport.on(
        "http://127.0.0.1:9001/v1/resolve",
        TransportResponse {
            status: 307,
            content_type: None,
            location: Some("http://127.0.0.1:9002/v1/resolve".to_owned()),
            body: Vec::new(),
        },
    );
    let mut m = meter();
    assert!(matches!(
        client
            .resolve(BASE, &[alice_did().as_str()], &mut m)
            .expect_err("POST redirect"),
        ClientError::Policy(PolicyViolation::RedirectRefused(_))
    ));

    // GET: followed once when the absolute target passes policy.
    let transport = MockTransport::new();
    let client = dev_client(&transport, &clock);
    transport.on(
        "http://127.0.0.1:9001/v1/info",
        TransportResponse {
            status: 308,
            content_type: None,
            location: Some("http://127.0.0.1:9002/v1/info".to_owned()),
            body: Vec::new(),
        },
    );
    transport.on(
        "http://127.0.0.1:9002/v1/info",
        cbor_ok(info_response(&[0xAB; 16], &[0xC1; 16], &b11_generation())),
    );
    let mut m = meter();
    let outcome = client.info(BASE, &mut m).expect("redirect followed");
    assert_eq!(
        outcome.contacted,
        vec![
            "http://127.0.0.1:9001/v1/info".to_owned(),
            "http://127.0.0.1:9002/v1/info".to_owned()
        ],
        "every contacted URI is reported for budget accounting"
    );
    assert_eq!(m.requests_used(), 2, "the redirect hop was charged");

    // GET: a target that violates the policy is refused before any request.
    let transport = MockTransport::new();
    let client = dev_client(&transport, &clock);
    transport.on(
        "http://127.0.0.1:9001/v1/info",
        TransportResponse {
            status: 302,
            content_type: None,
            location: Some("http://10.0.0.7/v1/info".to_owned()),
            body: Vec::new(),
        },
    );
    let mut m = meter();
    assert_eq!(
        client.info(BASE, &mut m).expect_err("hostile redirect"),
        ClientError::Policy(PolicyViolation::DestinationNotPermitted)
    );
    assert_eq!(
        transport.requests().len(),
        1,
        "the target was never contacted"
    );

    // GET: a relative target is refused.
    let transport = MockTransport::new();
    let client = dev_client(&transport, &clock);
    transport.on(
        "http://127.0.0.1:9001/v1/info",
        TransportResponse {
            status: 302,
            content_type: None,
            location: Some("/elsewhere".to_owned()),
            body: Vec::new(),
        },
    );
    let mut m = meter();
    assert!(matches!(
        client.info(BASE, &mut m).expect_err("relative redirect"),
        ClientError::Policy(PolicyViolation::RedirectRefused(_))
    ));
}

#[test]
fn sec_9_5_public_policy_refuses_the_request_before_any_transport_call() {
    let transport = MockTransport::new();
    let clock = ManualClock::new(RELAY_NOW_MS);
    let client = RelayClient::new(&transport, NetworkPolicy::Public, &clock);
    let mut m = meter();
    assert_eq!(
        client
            .resolve("http://127.0.0.1:9001/", &[alice_did().as_str()], &mut m)
            .expect_err("plain HTTP under the public policy"),
        ClientError::Policy(PolicyViolation::SchemeNotPermitted)
    );
    assert_eq!(
        client
            .resolve("https://127.0.0.1/", &[alice_did().as_str()], &mut m)
            .expect_err("loopback under the public policy"),
        ClientError::Policy(PolicyViolation::DestinationNotPermitted)
    );
    assert!(
        transport.requests().is_empty(),
        "nothing reached the transport"
    );
}

#[test]
fn sec_15_2_client_refuses_to_emit_protocol_invalid_requests() {
    let transport = MockTransport::new();
    let clock = ManualClock::new(RELAY_NOW_MS);
    let client = dev_client(&transport, &clock);
    let mut m = meter();
    assert_eq!(
        client.resolve(BASE, &[], &mut m).expect_err("empty batch"),
        ClientError::RequestInvalid("resolve batch must contain 1..=256 DIDs")
    );
    let too_many: Vec<&str> = std::iter::repeat_n("did:flw:z", 257).collect();
    assert_eq!(
        client
            .resolve(BASE, &too_many, &mut m)
            .expect_err("over the 256 hard maximum"),
        ClientError::RequestInvalid("resolve batch must contain 1..=256 DIDs")
    );
    assert_eq!(
        client
            .changes(BASE, None, 0, 1024, &mut m)
            .expect_err("zero itemLimit"),
        ClientError::RequestInvalid("itemLimit must be 1..=1024")
    );
    assert_eq!(
        client
            .changes(BASE, None, 1025, 1024, &mut m)
            .expect_err("over itemLimit maximum"),
        ClientError::RequestInvalid("itemLimit must be 1..=1024")
    );
    assert_eq!(
        client
            .changes(BASE, None, 16, 0, &mut m)
            .expect_err("zero byteLimit"),
        ClientError::RequestInvalid("byteLimit must be 1..=4 MiB")
    );
    assert_eq!(
        client
            .changes(BASE, None, 16, 4 * 1024 * 1024 + 1, &mut m)
            .expect_err("over byteLimit maximum"),
        ClientError::RequestInvalid("byteLimit must be 1..=4 MiB")
    );
    assert_eq!(
        client
            .changes(BASE, Some(&[0u8; 129]), 16, 1024, &mut m)
            .expect_err("oversized cursor"),
        ClientError::RequestInvalid("cursor exceeds 128 bytes")
    );
    assert!(
        transport.requests().is_empty(),
        "no invalid request reached the transport"
    );
}

// ---------------------------------------------------------------------------
// Exact protocol boundaries in the response parsers (mutation follow-up).
// ---------------------------------------------------------------------------

fn info_body_with(base_uri: &str, versions: &[Vec<u8>], suites: &[Vec<u8>]) -> Vec<u8> {
    let limits = r_map(&[
        (r_uint(0), r_uint(16 * 1024)),
        (r_uint(1), r_uint(256)),
        (r_uint(2), r_uint(1024 * 1024)),
        (r_uint(3), r_uint(1024)),
        (r_uint(4), r_uint(4 * 1024 * 1024)),
    ]);
    r_map(&[
        (r_uint(0), r_uint(1)),
        (r_uint(1), r_bstr(&[0xAA; 16])),
        (r_uint(2), r_uint(7)),
        (r_uint(3), r_array(versions)),
        (r_uint(4), r_array(suites)),
        (r_uint(5), limits),
        (r_uint(6), r_bstr(&[0xC0; 16])),
        (r_uint(7), r_bstr(&b11_generation())),
        (r_uint(8), r_tstr(base_uri)),
    ])
}

fn info_once(body: Vec<u8>) -> Result<followee::relay::client::RelayInfo, ClientError> {
    let transport = MockTransport::new();
    let clock = ManualClock::new(RELAY_NOW_MS);
    let client = dev_client(&transport, &clock);
    transport.on("http://127.0.0.1:9001/v1/info", cbor_ok(body));
    let mut m = meter();
    client.info(BASE, &mut m).map(|o| o.value)
}

#[test]
fn sec_12_2_info_arrays_must_be_non_empty_and_typed() {
    // CDDL [1* uint] / [1* int]: empty arrays are schema violations.
    assert_eq!(
        info_once(info_body_with("http://127.0.0.1/", &[], &[r_nint_mag(18)]))
            .expect_err("empty versions"),
        ClientError::OuterResponse(VerifyError::SchemaViolation)
    );
    assert_eq!(
        info_once(info_body_with("http://127.0.0.1/", &[r_uint(1)], &[]))
            .expect_err("empty suites"),
        ClientError::OuterResponse(VerifyError::SchemaViolation)
    );
    // Suites may also advertise positive values alongside -19.
    let info = info_once(info_body_with(
        "http://127.0.0.1/",
        &[r_uint(1), r_uint(2)],
        &[r_uint(7), r_nint_mag(18)],
    ))
    .expect("mixed-sign suites accepted");
    assert_eq!(info.suites, vec![7, -19]);
    assert_eq!(info.protocol_versions, vec![1, 2]);
    // A text suite value is a schema violation.
    assert_eq!(
        info_once(info_body_with(
            "http://127.0.0.1/",
            &[r_uint(1)],
            &[r_tstr("ed25519")]
        ))
        .expect_err("typed suites"),
        ClientError::OuterResponse(VerifyError::SchemaViolation)
    );
}

#[test]
fn sec_12_2_info_limits_map_rejects_a_foreign_label_without_panicking() {
    let bad_limits = r_map(&[
        (r_uint(0), r_uint(16 * 1024)),
        (r_uint(1), r_uint(256)),
        (r_uint(2), r_uint(1024 * 1024)),
        (r_uint(3), r_uint(1024)),
        (r_uint(5), r_uint(4 * 1024 * 1024)),
    ]);
    let body = r_map(&[
        (r_uint(0), r_uint(1)),
        (r_uint(1), r_bstr(&[0xAA; 16])),
        (r_uint(2), r_uint(7)),
        (r_uint(3), r_array(&[r_uint(1)])),
        (r_uint(4), r_array(&[r_nint_mag(18)])),
        (r_uint(5), bad_limits),
        (r_uint(6), r_bstr(&[0xC0; 16])),
        (r_uint(7), r_bstr(&b11_generation())),
        (r_uint(8), r_tstr("http://127.0.0.1/")),
    ]);
    assert_eq!(
        info_once(body).expect_err("limits label 5 is foreign"),
        ClientError::OuterResponse(VerifyError::SchemaViolation)
    );
}

#[test]
fn sec_15_1_info_base_uri_length_boundary_is_exact() {
    let prefix = "http://127.0.0.1/";
    let at_limit = format!("{prefix}{}", "a".repeat(2048 - prefix.len()));
    info_once(info_body_with(&at_limit, &[r_uint(1)], &[r_nint_mag(18)]))
        .expect("2048-byte URI accepted");
    let over = format!("{at_limit}a");
    assert_eq!(
        info_once(info_body_with(&over, &[r_uint(1)], &[r_nint_mag(18)]))
            .expect_err("2049-byte URI"),
        ClientError::OuterResponse(VerifyError::SchemaViolation)
    );
}

#[test]
fn sec_15_2_resolve_result_count_boundary_is_exact() {
    let transport = MockTransport::new();
    let clock = ManualClock::new(RELAY_NOW_MS);
    let client = dev_client(&transport, &clock);
    let results: Vec<Vec<u8>> = (0..256).map(|_| rr_absent()).collect();
    transport.on(
        "http://127.0.0.1:9001/v1/resolve",
        cbor_ok(resolve_response_with(&b11_generation(), &results)),
    );
    let mut m = meter();
    let alice = alice_did();
    let dids: Vec<&str> = std::iter::repeat_n(alice.as_str(), 256).collect();
    let outcome = client
        .resolve(BASE, &dids, &mut m)
        .expect("exactly 256 results is the protocol hard maximum");
    assert_eq!(outcome.value.results.len(), 256);
    // 257 results violates the section 15.2 hard maximum outright.
    let results: Vec<Vec<u8>> = (0..257).map(|_| rr_absent()).collect();
    transport.on(
        "http://127.0.0.1:9001/v1/resolve",
        cbor_ok(resolve_response_with(&b11_generation(), &results)),
    );
    let error = client
        .resolve(BASE, &dids, &mut m)
        .expect_err("257 results");
    assert_eq!(
        error,
        ClientError::OuterResponse(VerifyError::SchemaViolation)
    );
}

#[test]
fn sec_15_2_directory_entry_count_and_uri_boundaries_are_exact() {
    let entries_at = |count: u32| -> Vec<u8> {
        let rows: Vec<Vec<u8>> = (0..count)
            .map(|i| {
                r_map(&[
                    (r_uint(0), r_uint(u64::from(i))),
                    (r_uint(1), r_bstr(&[0x22; 16])),
                    (r_uint(2), r_tstr("http://127.0.0.1:9002/")),
                    (r_uint(3), r_uint(3)),
                ])
            })
            .collect();
        r_map(&[
            (r_uint(0), r_uint(1)),
            (r_uint(1), r_bstr(&b11_generation())),
            (r_uint(2), r_array(&rows)),
        ])
    };
    let directory_once = |body: Vec<u8>| {
        let transport = MockTransport::new();
        let clock = ManualClock::new(RELAY_NOW_MS);
        let client = dev_client(&transport, &clock);
        transport.on("http://127.0.0.1:9001/v1/directory", cbor_ok(body));
        let mut m = BudgetMeter::new(OperationBudget {
            deadline_ms: None,
            max_response_bytes: 8 * 1024 * 1024,
            max_requests: 8,
        });
        client.directory(BASE, &mut m).map(|o| o.value)
    };
    let accepted = directory_once(entries_at(4096)).expect("4096 entries is the cap");
    assert_eq!(accepted.entries.len(), 4096);
    assert_eq!(
        directory_once(entries_at(4097)).expect_err("4097 entries"),
        ClientError::OuterResponse(VerifyError::SchemaViolation)
    );

    // Endpoint URI boundary inside a directory entry.
    let with_uri = |uri: &str| -> Vec<u8> {
        r_map(&[
            (r_uint(0), r_uint(1)),
            (r_uint(1), r_bstr(&b11_generation())),
            (
                r_uint(2),
                r_array(&[r_map(&[
                    (r_uint(0), r_uint(0)),
                    (r_uint(1), r_bstr(&[0x22; 16])),
                    (r_uint(2), r_tstr(uri)),
                    (r_uint(3), r_uint(3)),
                ])]),
            ),
        ])
    };
    let prefix = "http://127.0.0.1/";
    let at_limit = format!("{prefix}{}", "a".repeat(2048 - prefix.len()));
    directory_once(with_uri(&at_limit)).expect("2048-byte endpoint accepted");
    assert_eq!(
        directory_once(with_uri(&format!("{at_limit}a"))).expect_err("2049-byte endpoint"),
        ClientError::OuterResponse(VerifyError::SchemaViolation)
    );
}

#[test]
fn sec_15_2_changes_item_count_and_cursor_boundaries_are_exact() {
    let generation = b11_generation();
    // Exactly 1024 entries — the protocol hard maximum — is accepted when
    // the request permitted it.
    let entries: Vec<Vec<u8>> = (1..=1024)
        .map(|i| ch_entry(alice_did().as_str(), rr_ref(0), i))
        .collect();
    let body = changes_success_with(&generation, &entries, b"c", false);
    let value = changes_once(body, 1024).expect("1024 entries at itemLimit 1024");
    let ReceivedChangesResponse::Success { entries, .. } = value else {
        panic!("success expected");
    };
    assert_eq!(entries.len(), 1024);

    // A 128-byte cursor is exactly the cap; 129 bytes rejects.
    let body = changes_success_with(&generation, &[], &[0x41; 128], false);
    changes_once(body, 16).expect("128-byte cursor accepted");
    let body = changes_success_with(&generation, &[], &[0x41; 129], false);
    assert_eq!(
        changes_once(body, 16).expect_err("129-byte cursor"),
        ClientError::OuterResponse(VerifyError::SchemaViolation)
    );
}

#[test]
fn sec_12_6_change_entry_arity_must_be_exactly_three() {
    let generation = b11_generation();
    let two = r_array(&[r_tstr(alice_did().as_str()), rr_ref(0)]);
    let four = r_array(&[
        r_tstr(alice_did().as_str()),
        rr_ref(0),
        r_uint(1),
        r_uint(2),
    ]);
    for entry in [two, four] {
        let body = changes_success_with(&generation, &[entry], b"c", false);
        assert_eq!(
            changes_once(body, 16).expect_err("entry arity"),
            ClientError::OuterResponse(VerifyError::SchemaViolation)
        );
    }
}

#[test]
fn sec_12_6_status_two_forbids_each_success_field_individually() {
    for extra in [
        (r_uint(2), r_array(&[])),
        (r_uint(3), r_bstr(b"c")),
        (r_uint(4), vec![0xf4]),
        (r_uint(5), r_bstr(&[0u8; 16])),
    ] {
        let body = r_map(&[
            (r_uint(0), r_uint(1)),
            (r_uint(1), r_uint(2)),
            extra.clone(),
            (r_uint(6), r_uint(18)),
        ]);
        assert_eq!(
            changes_once(body, 16).expect_err("forbidden field on status 2"),
            ClientError::OuterResponse(VerifyError::SchemaViolation),
            "label {:?}",
            extra.0
        );
    }
}

#[test]
fn sec_12_1_response_exactly_at_the_size_bound_is_accepted() {
    // The changes byte-limit boundary is inclusive: a response of exactly
    // byteLimit bytes is accepted; one byte more is rejected (tested in
    // sec_12_6_over_byte_limit_changes_response_is_rejected).
    let transport = MockTransport::new();
    let clock = ManualClock::new(RELAY_NOW_MS);
    let client = dev_client(&transport, &clock);
    let body = changes_success_with(&b11_generation(), &[], b"c1", false);
    let limit = body.len() as u64;
    transport.on("http://127.0.0.1:9001/v1/changes", cbor_ok(body));
    let mut m = meter();
    client
        .changes(BASE, None, 16, limit, &mut m)
        .expect("exactly at the bound");
}

#[test]
fn sec_12_6_change_entry_must_be_an_array() {
    // A non-array change entry (a bare uint whose value happens to be 3)
    // rejects at the entry head, independent of the arity rule.
    let generation = b11_generation();
    let body = changes_success_with(&generation, &[r_uint(3)], b"c", false);
    assert_eq!(
        changes_once(body, 16).expect_err("non-array entry"),
        ClientError::OuterResponse(VerifyError::SchemaViolation)
    );
}

#[test]
fn sec_15_2_request_cursor_exactly_at_the_cap_is_sent() {
    let transport = MockTransport::new();
    let clock = ManualClock::new(RELAY_NOW_MS);
    let client = dev_client(&transport, &clock);
    transport.on(
        "http://127.0.0.1:9001/v1/changes",
        cbor_ok(changes_success_with(&b11_generation(), &[], b"next", false)),
    );
    let cursor = [0x41u8; 128];
    let mut m = meter();
    client
        .changes(BASE, Some(&cursor), 16, 1024 * 1024, &mut m)
        .expect("a 128-byte cursor is within the section 15.2 cap");
    assert_eq!(transport.requests().len(), 1, "the request was sent");
}
