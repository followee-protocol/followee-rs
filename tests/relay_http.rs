//! Black-box HTTP/CBOR relay tests over real sockets (specification
//! sections 12, 15.4, 20.2; IMPLEMENTATION.md sections 11.6 and 13).
//!
//! Each test starts a real server instance on a loopback ephemeral port —
//! memory-backed or SQLite-backed with an isolated temporary database — and
//! speaks raw HTTP/1.1 over a `TcpStream`, so the exact request bytes,
//! status lines, headers, and body bytes are all under test control.
#![allow(clippy::arithmetic_side_effects)]

mod common;

use common::*;
use followee::relay::http::serve;
use followee::store::MemoryStore;
use followee::store::sqlite::SqliteStore;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};

// ---------------------------------------------------------------------------
// Server harness and raw HTTP client.
// ---------------------------------------------------------------------------

fn start_server(t: &TestRelay) -> SocketAddr {
    let relay = std::sync::Arc::clone(&t.relay);
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio runtime");
        rt.block_on(async move {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind loopback");
            tx.send(listener.local_addr().expect("local addr"))
                .expect("send addr");
            serve(relay, listener).await.expect("serve");
        });
    });
    rx.recv().expect("server address")
}

struct HttpResponse {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl HttpResponse {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// Sends one raw HTTP/1.1 request and reads the complete response.
fn request(
    addr: SocketAddr,
    method: &str,
    path: &str,
    content_type: Option<&str>,
    body: &[u8],
) -> HttpResponse {
    let mut stream = TcpStream::connect(addr).expect("connect");
    let mut head = format!("{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\n");
    if let Some(ct) = content_type {
        head.push_str(&format!("Content-Type: {ct}\r\n"));
    }
    head.push_str(&format!(
        "Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    ));
    stream.write_all(head.as_bytes()).expect("write head");
    stream.write_all(body).expect("write body");
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).expect("read response");

    let header_end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("complete header block");
    let head_text = std::str::from_utf8(&raw[..header_end]).expect("ASCII headers");
    let mut lines = head_text.split("\r\n");
    let status_line = lines.next().expect("status line");
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .expect("status code")
        .parse()
        .expect("numeric status");
    let headers = lines
        .filter_map(|line| {
            line.split_once(':')
                .map(|(k, v)| (k.trim().to_owned(), v.trim().to_owned()))
        })
        .collect();
    let body = raw[header_end + 4..].to_vec();
    HttpResponse {
        status,
        headers,
        body,
    }
}

fn get(addr: SocketAddr, path: &str) -> HttpResponse {
    request(addr, "GET", path, None, &[])
}

fn post_cbor(addr: SocketAddr, path: &str, body: &[u8]) -> HttpResponse {
    request(addr, "POST", path, Some("application/cbor"), body)
}

fn publish_record(addr: SocketAddr, record: &[u8]) -> HttpResponse {
    request(
        addr,
        "POST",
        "/v1/publish",
        Some("application/cose"),
        record,
    )
}

/// Runs `case` against a memory-backed and a SQLite-backed server: the HTTP
/// surface must be indistinguishable across storage backends.
fn with_both_backends(case: impl Fn(SocketAddr)) {
    let memory = memory_relay();
    case(start_server(&memory));

    let dir = tempfile::tempdir().expect("temp dir");
    let store = SqliteStore::open(&dir.path().join("relay.db"), test_identity()).expect("sqlite");
    let sqlite = relay_over(Box::new(store));
    case(start_server(&sqlite));
}

fn seed_alice_and_bob(addr: SocketAddr) {
    for record in [fx_bytes("root_record_envelope"), fx_bytes("bob_envelope")] {
        let response = publish_record(addr, &record);
        assert_eq!(response.status, 200);
        assert_eq!(publish_outcome(&response.body).0, 0, "seed admitted");
    }
}

// ---------------------------------------------------------------------------
// Appendix B.11 wrapper vectors through the real HTTP surface.
// ---------------------------------------------------------------------------

#[test]
fn sec_b11_1_invalid_outer_request_is_http_400_without_per_item_results() {
    with_both_backends(|addr| {
        seed_alice_and_bob(addr);
        let response = post_cbor(
            addr,
            "/v1/resolve",
            &fx_bytes_at("b11", "b11_1/request_bytes"),
        );
        assert_eq!(response.status, 400, "outer CBOR fault");
        assert!(
            response.body.is_empty(),
            "no normative per-item CBOR body accompanies the 400"
        );
    });
}

#[test]
fn sec_b11_4_duplicate_dids_preserve_cardinality_byte_for_byte() {
    with_both_backends(|addr| {
        seed_alice_and_bob(addr);
        let response = post_cbor(
            addr,
            "/v1/resolve",
            &fx_bytes_at("b11", "b11_4/request_bytes"),
        );
        assert_eq!(response.status, 200);
        assert_eq!(response.body.len(), 1106, "published response length");
        assert_eq!(
            followee::crypto::sha256(&response.body).as_slice(),
            fx_bytes_at("b11", "b11_4/response_sha256").as_slice(),
            "exact published B.11.4 response bytes"
        );
    });
}

#[test]
fn sec_b11_6_malformed_did_inside_valid_batch_is_aligned_error_byte_for_byte() {
    with_both_backends(|addr| {
        seed_alice_and_bob(addr);
        let response = post_cbor(
            addr,
            "/v1/resolve",
            &fx_bytes_at("b11", "b11_6/request_bytes"),
        );
        assert_eq!(response.status, 200, "malformed middle DID is not HTTP 400");
        assert_eq!(response.body.len(), 748, "published response length");
        assert_eq!(
            followee::crypto::sha256(&response.body).as_slice(),
            fx_bytes_at("b11", "b11_6/response_sha256").as_slice(),
            "exact published B.11.6 response bytes"
        );
        // Structural double-check: exactly [Full, Error(invalidDid), Full].
        let value = decode_value(&response.body);
        let results = value.get(2).expect("results").as_array().to_vec();
        assert_eq!(results.len(), 3);
        assert_eq!(results[0].get(0).expect("kind").as_uint(), 0);
        assert_eq!(results[1].get(0).expect("kind").as_uint(), 3);
        assert_eq!(results[1].get(2).expect("code").as_uint(), 0);
        assert_eq!(results[2].get(0).expect("kind").as_uint(), 0);
    });
}

// ---------------------------------------------------------------------------
// Section 12.2: relay information.
// ---------------------------------------------------------------------------

#[test]
fn sec_12_2_info_reports_identity_capabilities_versions_and_limits() {
    with_both_backends(|addr| {
        let response = get(addr, "/v1/info");
        assert_eq!(response.status, 200);
        assert_eq!(response.header("content-type"), Some("application/cbor"));
        assert_eq!(
            response.header("access-control-allow-origin"),
            Some("*"),
            "public read operations carry CORS"
        );
        let info = decode_value(&response.body);
        assert_eq!(info.get(0).expect("version").as_uint(), 1);
        assert_eq!(info.get(1).expect("relay id").as_bytes().len(), 16);
        assert_eq!(
            info.get(2).expect("capabilities").as_uint(),
            0x07,
            "Relay Resolver + synchronization + ingress"
        );
        assert_eq!(
            info.get(3).expect("versions").as_array(),
            &[TestValue::Uint(1)]
        );
        assert_eq!(
            info.get(4).expect("suites").as_array(),
            &[TestValue::Nint(18)],
            "suite -19 encodes as negative magnitude 18"
        );
        let limits = info.get(5).expect("limits");
        assert_eq!(limits.get(0).expect("record bytes").as_uint(), 16 * 1024);
        assert_eq!(limits.get(1).expect("batch").as_uint(), 256);
        assert_eq!(limits.get(2).expect("resolve bytes").as_uint(), 1 << 20);
        assert_eq!(limits.get(3).expect("changes items").as_uint(), 1024);
        assert_eq!(limits.get(4).expect("changes bytes").as_uint(), 4 << 20);
        assert_eq!(info.get(6).expect("cursor generation").as_bytes().len(), 16);
        assert_eq!(
            info.get(7).expect("directory generation").as_bytes(),
            b11_generation().as_slice()
        );
        assert_eq!(
            info.get(8),
            Some(&TestValue::Text("http://127.0.0.1/".to_owned()))
        );
    });
}

#[test]
fn sec_12_4_directory_serves_generation_and_entries() {
    with_both_backends(|addr| {
        let response = get(addr, "/v1/directory");
        assert_eq!(response.status, 200);
        let directory = decode_value(&response.body);
        assert_eq!(directory.get(0).expect("version").as_uint(), 1);
        assert_eq!(
            directory.get(1).expect("generation").as_bytes(),
            b11_generation().as_slice()
        );
        assert_eq!(directory.get(2).expect("entries").as_array().len(), 0);
    });

    // Seeded directory entries round-trip with their generation.
    let t = memory_relay();
    t.relay
        .with_store(|s| {
            s.set_directory(
                vec![followee::store::DirectoryEntry {
                    index: 0,
                    relay_id: [0x11; 16],
                    endpoint: "https://relay.example/followee/".to_owned(),
                    capabilities: 0x03,
                }],
                [0x42; 16],
            )
        })
        .expect("seed directory");
    let addr = start_server(&t);
    let response = get(addr, "/v1/directory");
    let directory = decode_value(&response.body);
    assert_eq!(
        directory.get(1).expect("generation").as_bytes(),
        &[0x42; 16]
    );
    let entries = directory.get(2).expect("entries").as_array().to_vec();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].get(0).expect("index").as_uint(), 0);
    assert_eq!(
        entries[0].get(2),
        Some(&TestValue::Text(
            "https://relay.example/followee/".to_owned()
        ))
    );
}

// ---------------------------------------------------------------------------
// Sections 12.1/15.4: media types, outer faults, and bounded input.
// ---------------------------------------------------------------------------

#[test]
fn sec_12_1_wrong_media_types_are_rejected_with_415() {
    with_both_backends(|addr| {
        let ok = resolve_request(&[&fx_str("followee_did")]);
        for wrong in [Some("application/json"), Some("text/plain"), None] {
            let response = request(addr, "POST", "/v1/resolve", wrong, &ok);
            assert_eq!(response.status, 415, "{wrong:?}");
        }
        // Publish requires application/cose, not application/cbor.
        let response = post_cbor(addr, "/v1/publish", &fx_bytes("root_record_envelope"));
        assert_eq!(response.status, 415);
        // Media types are ASCII case-insensitive and parameters are ignored.
        let response = request(
            addr,
            "POST",
            "/v1/resolve",
            Some("Application/CBOR; q=1"),
            &ok,
        );
        assert_eq!(response.status, 200);
    });
}

#[test]
fn sec_15_4_outer_request_faults_are_http_400() {
    with_both_backends(|addr| {
        let cases: Vec<Vec<u8>> = vec![
            // Not well-formed CBOR.
            vec![0xff],
            // Trailing bytes after a complete item.
            {
                let mut bytes = resolve_request(&[&fx_str("followee_did")]);
                bytes.push(0x00);
                bytes
            },
            // Non-minimal protocol version (deterministic-profile fault).
            r_map(&[
                (r_uint(0), vec![0x18, 0x01]),
                (r_uint(1), r_array(&[r_tstr(&fx_str("followee_did"))])),
            ]),
            // Unknown top-level integer label (section 12.1).
            r_map(&[
                (r_uint(0), r_uint(1)),
                (r_uint(1), r_array(&[r_tstr(&fx_str("followee_did"))])),
                (r_uint(9), r_uint(1)),
            ]),
            // Wrong protocol version.
            r_map(&[
                (r_uint(0), r_uint(2)),
                (r_uint(1), r_array(&[r_tstr(&fx_str("followee_did"))])),
            ]),
            // Empty DID array (CDDL requires one or more).
            r_map(&[(r_uint(0), r_uint(1)), (r_uint(1), r_array(&[]))]),
            // Non-text DID entry.
            r_map(&[(r_uint(0), r_uint(1)), (r_uint(1), r_array(&[r_uint(1)]))]),
        ];
        for bytes in cases {
            let response = post_cbor(addr, "/v1/resolve", &bytes);
            assert_eq!(response.status, 400, "{bytes:02x?}");
            assert!(response.body.is_empty());
        }
    });
}

#[test]
fn sec_12_6_changes_request_value_bounds_are_top_level_schema_faults() {
    with_both_backends(|addr| {
        let cases = [
            changes_request(None, 0, 1 << 20),                // itemLimit zero
            changes_request(None, 1025, 1 << 20),             // over hard maximum
            changes_request(None, 10, 0),                     // byteLimit zero
            changes_request(None, 10, (4 << 20) + 1),         // over hard maximum
            changes_request(Some(&[0x00; 129]), 10, 1 << 20), // cursor > 128
        ];
        for bytes in cases {
            let response = post_cbor(addr, "/v1/changes", &bytes);
            assert_eq!(response.status, 400, "{bytes:02x?}");
        }
        // Missing required label: no byteLimit.
        let missing = r_map(&[
            (r_uint(0), r_uint(1)),
            (r_uint(1), vec![0xf6]),
            (r_uint(2), r_uint(10)),
        ]);
        assert_eq!(post_cbor(addr, "/v1/changes", &missing).status, 400);
    });
}

#[test]
fn sec_15_4_oversized_entities_stop_with_413_before_protocol_parsing() {
    with_both_backends(|addr| {
        // Far above the publish read bound.
        let response = request(
            addr,
            "POST",
            "/v1/publish",
            Some("application/cose"),
            &vec![0u8; 128 * 1024],
        );
        assert_eq!(response.status, 413);
        // Just above the record cap but within the read bound: the protocol
        // classification recordTooLarge, not a transport error.
        let response = publish_record(addr, &vec![0u8; 16 * 1024 + 1]);
        assert_eq!(response.status, 200);
        assert_eq!(publish_outcome(&response.body), (2, Some(3)));
    });
}

// ---------------------------------------------------------------------------
// Publish and resolve through the wire.
// ---------------------------------------------------------------------------

#[test]
fn sec_12_5_publish_statuses_and_exact_byte_resolution() {
    with_both_backends(|addr| {
        // Admitted and current.
        let response = publish_record(addr, &fx_bytes("root_record_envelope"));
        assert_eq!(response.status, 200);
        assert_eq!(publish_outcome(&response.body), (0, None));
        // Duplicate: valid, no current-state change.
        let response = publish_record(addr, &fx_bytes("root_record_envelope"));
        assert_eq!(publish_outcome(&response.body), (1, None));
        // Invalid: rejected with the exact classification.
        let response = publish_record(addr, &fx_bytes("b8_envelope"));
        assert_eq!(publish_outcome(&response.body), (2, Some(7)));

        // Resolution returns the exact admitted bytes as an opaque Full.
        let response = post_cbor(
            addr,
            "/v1/resolve",
            &resolve_request(&[&fx_str("followee_did")]),
        );
        assert_eq!(response.status, 200);
        assert_eq!(
            response.header("access-control-allow-origin"),
            Some("*"),
            "resolve is a public read operation"
        );
        let value = decode_value(&response.body);
        let results = value.get(2).expect("results").as_array().to_vec();
        assert_eq!(
            results[0].get(1).expect("bytes").as_bytes(),
            fx_bytes("root_record_envelope").as_slice(),
            "exact-byte publication round-trip"
        );
    });
}

#[test]
fn sec_12_3_response_splitting_degrades_overflow_results_to_aligned_error_16() {
    // Enough near-cap records that the complete batch exceeds the advertised
    // 1 MiB resolve-response bound.
    let t = memory_relay();
    let addr = start_server(&t);
    let identities: Vec<(String, Vec<u8>)> = (0..72)
        .map(|i| synthetic_identity_record(i, 15_000))
        .collect();
    for (_, record) in &identities {
        let response = publish_record(addr, record);
        assert_eq!(publish_outcome(&response.body).0, 0, "seed admitted");
    }
    let dids: Vec<&str> = identities.iter().map(|(did, _)| did.as_str()).collect();
    let response = post_cbor(addr, "/v1/resolve", &resolve_request(&dids));
    assert_eq!(response.status, 200);
    assert!(
        response.body.len() <= (1 << 20) + 64,
        "response respects the advertised bound (wrapper overhead aside)"
    );
    let value = decode_value(&response.body);
    let results = value.get(2).expect("results").as_array().to_vec();
    assert_eq!(results.len(), dids.len(), "cardinality is never reduced");
    let mut fulls = 0;
    let mut errors = 0;
    for (index, result) in results.iter().enumerate() {
        match result.get(0).expect("kind").as_uint() {
            0 => {
                fulls += 1;
                assert_eq!(
                    result.get(1).expect("bytes").as_bytes(),
                    identities[index].1.as_slice(),
                    "aligned exact bytes at index {index}"
                );
            }
            3 => {
                errors += 1;
                assert_eq!(
                    result.get(2).expect("code").as_uint(),
                    16,
                    "overflow results are responseTooLarge, never Absent"
                );
            }
            other => panic!("unexpected result kind {other}"),
        }
    }
    assert!(fulls >= 60, "the bound admits most of the batch: {fulls}");
    assert!(errors >= 1, "at least one overflow result: {errors}");
}

// ---------------------------------------------------------------------------
// Changes through the wire, including the exact reset encoding.
// ---------------------------------------------------------------------------

#[test]
fn sec_12_6_changes_flow_and_exact_reset_bytes_over_http() {
    with_both_backends(|addr| {
        seed_alice_and_bob(addr);
        let response = post_cbor(addr, "/v1/changes", &changes_request(None, 10, 1 << 20));
        assert_eq!(response.status, 200);
        let value = decode_value(&response.body);
        assert_eq!(value.get(1).expect("status").as_uint(), 0);
        assert_eq!(value.get(2).expect("entries").as_array().len(), 2);

        // A foreign-generation cursor over HTTP: the exact two-field reset.
        let foreign = raw_cursor(&[0x11; 16], 1);
        let response = post_cbor(
            addr,
            "/v1/changes",
            &changes_request(Some(&foreign), 10, 1 << 20),
        );
        assert_eq!(response.status, 200, "ResetRequired is HTTP 200");
        assert_eq!(response.body, vec![0xa2, 0x00, 0x01, 0x01, 0x01]);

        // A malformed cursor: status 2 with invalidCursor.
        let response = post_cbor(
            addr,
            "/v1/changes",
            &changes_request(Some(&[0x01; 7]), 10, 1 << 20),
        );
        let value = decode_value(&response.body);
        assert_eq!(value.get(1).expect("status").as_uint(), 2);
        assert_eq!(value.get(6).expect("code").as_uint(), 18);
    });
}

// ---------------------------------------------------------------------------
// Exact limit boundaries (mutation-sweep killer cases).
// ---------------------------------------------------------------------------

#[test]
fn sec_15_2_resolve_batch_boundary_256_accepted_257_rejected() {
    let t = memory_relay();
    let addr = start_server(&t);
    let alice = fx_str("followee_did");
    // Duplicates are legitimate batch entries, so one DID fills the batch.
    let at_limit: Vec<&str> = std::iter::repeat_n(alice.as_str(), 256).collect();
    let response = post_cbor(addr, "/v1/resolve", &resolve_request(&at_limit));
    assert_eq!(response.status, 200, "256 DIDs are the hard maximum");
    let value = decode_value(&response.body);
    assert_eq!(value.get(2).expect("results").as_array().len(), 256);

    let over: Vec<&str> = std::iter::repeat_n(alice.as_str(), 257).collect();
    let response = post_cbor(addr, "/v1/resolve", &resolve_request(&over));
    assert_eq!(response.status, 400, "257 DIDs exceed the hard maximum");
}

#[test]
fn sec_12_6_changes_request_boundaries_are_exact() {
    let t = memory_relay();
    let addr = start_server(&t);
    // Maxima themselves are valid.
    for bytes in [
        changes_request(None, 1024, 1 << 20),
        changes_request(None, 10, 4 << 20),
        changes_request(Some(&[0x00; 128]), 10, 1 << 20),
    ] {
        let response = post_cbor(addr, "/v1/changes", &bytes);
        assert_eq!(response.status, 200, "{bytes:02x?}");
    }
    // A 128-byte cursor is schema-valid but not this relay's encoding:
    // protocol-level invalidCursor, never an outer fault.
    let response = post_cbor(
        addr,
        "/v1/changes",
        &changes_request(Some(&[0x00; 128]), 10, 1 << 20),
    );
    let value = decode_value(&response.body);
    assert_eq!(value.get(1).expect("status").as_uint(), 2);
    assert_eq!(value.get(6).expect("code").as_uint(), 18);
    // A 22-byte cursor must not alias the CBOR null head value.
    let response = post_cbor(
        addr,
        "/v1/changes",
        &changes_request(Some(&[0x00; 22]), 10, 1 << 20),
    );
    let value = decode_value(&response.body);
    assert_eq!(value.get(1).expect("status").as_uint(), 2);
    assert_eq!(value.get(6).expect("code").as_uint(), 18);

    // Wrong protocol version and a Boolean cursor are outer faults.
    let wrong_version = r_map(&[
        (r_uint(0), r_uint(2)),
        (r_uint(1), vec![0xf6]),
        (r_uint(2), r_uint(10)),
        (r_uint(3), r_uint(1 << 20)),
    ]);
    assert_eq!(post_cbor(addr, "/v1/changes", &wrong_version).status, 400);
    let bool_cursor = r_map(&[
        (r_uint(0), r_uint(1)),
        (r_uint(1), vec![0xf4]),
        (r_uint(2), r_uint(10)),
        (r_uint(3), r_uint(1 << 20)),
    ]);
    assert_eq!(post_cbor(addr, "/v1/changes", &bool_cursor).status, 400);
}

#[test]
fn sec_15_1_record_at_exactly_16_kib_is_admitted() {
    let t = memory_relay();
    let addr = start_server(&t);
    // Two-step sizing: pad an Alice record-level extension so the complete
    // envelope lands on exactly 16,384 bytes.
    let build = |pad: usize| {
        let mut body = b4_body();
        body.extensions.insert(
            "https://example.com/pad".to_owned(),
            followee::contact::ExtensionValue::Bytes(vec![0x41; pad]),
        );
        followee::record::sign_record(&body, &root_seed()).expect("signs")
    };
    let probe = build(64).len();
    let guess = 16 * 1024 - probe + 64 - 8;
    let measured = build(guess).len();
    let record = build(guess + (16 * 1024 - measured));
    assert_eq!(record.len(), 16 * 1024, "exactly at the envelope cap");
    let response = publish_record(addr, &record);
    assert_eq!(response.status, 200);
    assert_eq!(
        publish_outcome(&response.body),
        (0, None),
        "cap-size admitted"
    );
}

#[test]
fn sec_15_4_publish_read_bound_splits_transport_from_protocol_classification() {
    let t = memory_relay();
    let addr = start_server(&t);
    // Well inside the transport read bound but over the record cap: the
    // protocol recordTooLarge classification, not a transport error.
    let response = publish_record(addr, &vec![0u8; 32 * 1024]);
    assert_eq!(response.status, 200);
    assert_eq!(publish_outcome(&response.body), (2, Some(3)));
}

#[test]
fn sec_12_6_byte_budget_accounting_is_exact_across_the_array_head_boundary() {
    // Thirty small entries cross the 24-entry CBOR array-head width change,
    // pinning the response-size accounting to the byte.
    let t = memory_relay();
    for index in 0..30 {
        let (_, record) = synthetic_identity_record(index, 0);
        assert_eq!(
            publish_outcome(&t.relay.publish(&record).expect("publish")).0,
            0
        );
    }
    let full = t
        .relay
        .changes(&changes_request(None, 1024, 1 << 20))
        .expect("changes");
    assert_eq!(
        decode_value(&full)
            .get(2)
            .expect("entries")
            .as_array()
            .len(),
        30
    );
    let full_len = full.len() as u64;

    // byteLimit exactly the full response: everything fits, byte-for-byte.
    let exact = t
        .relay
        .changes(&changes_request(None, 1024, full_len))
        .expect("changes");
    assert_eq!(
        exact, full,
        "exact-fit budget returns the identical response"
    );

    // Any smaller budget: the response never exceeds it, and continuing
    // from its cursor still reaches all thirty entries.
    for delta in 1..=4 {
        let limit = full_len - delta;
        let response = t
            .relay
            .changes(&changes_request(None, 1024, limit))
            .expect("changes");
        assert!(
            (response.len() as u64) <= limit,
            "response ({}) exceeds byteLimit ({limit})",
            response.len()
        );
        let value = decode_value(&response);
        assert_eq!(value.get(1).expect("status").as_uint(), 0);
        let first_page = value.get(2).expect("entries").as_array().len();
        assert!(first_page < 30, "some entry was omitted under {limit}");
        let cursor = value.get(3).expect("nextCursor").as_bytes().to_vec();
        let rest = t
            .relay
            .changes(&changes_request(Some(&cursor), 1024, 1 << 20))
            .expect("changes");
        let second_page = decode_value(&rest)
            .get(2)
            .expect("entries")
            .as_array()
            .len();
        assert_eq!(first_page + second_page, 30, "no gap across the split");
    }
}

#[test]
fn relay_debug_and_mode_accessors_are_faithful() {
    use followee::relay::{Relay, RelayConfig};
    let t = memory_relay();
    assert!(t.relay.development_mode(), "test relays run in dev mode");
    assert!(format!("{:?}", t.relay).contains("Relay"));
    let conforming = Relay::new(
        Box::new(MemoryStore::new(test_identity())),
        Box::new(followee::clock::SystemClock),
        RelayConfig {
            base_uri: "https://relay.example/".to_owned(),
            development_mode: false,
        },
    )
    .expect("valid config");
    assert!(!conforming.development_mode());
    let store = SqliteStore::open_in_memory(test_identity()).expect("sqlite");
    assert!(format!("{store:?}").contains("SqliteStore"));
}

// ---------------------------------------------------------------------------
// Restart: identity, generations, entries, sticky state, and counter.
// ---------------------------------------------------------------------------

#[test]
fn sec_13_5_restart_preserves_identity_generation_and_sticky_state() {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("relay.db");

    let (info_before, revoked_cursor) = {
        let store = SqliteStore::open(&path, test_identity()).expect("create");
        let t = relay_over(Box::new(store));
        let addr = start_server(&t);
        seed_alice_and_bob(addr);
        // Alice revokes; the sticky transition must survive restart.
        let mut body = b5_body();
        body.timestamp_ms = B4_TIMESTAMP_MS + 7;
        let revoked = followee::record::sign_record(&body, &revocation_seed()).expect("signs");
        assert_eq!(publish_outcome(&publish_record(addr, &revoked).body).0, 0);
        let info = get(addr, "/v1/info").body;
        let changes = post_cbor(addr, "/v1/changes", &changes_request(None, 10, 1 << 20)).body;
        let cursor = decode_value(&changes)
            .get(3)
            .expect("nextCursor")
            .as_bytes()
            .to_vec();
        (info, cursor)
    };

    // Reopen: a different identity argument must be ignored in favour of the
    // persisted identity (restart never mints a new relay).
    let other_identity = followee::store::RelayIdentity {
        relay_id: [0x55; 16],
        cursor_generation: [0x66; 16],
        directory_generation: [0x77; 16],
    };
    let store = SqliteStore::open(&path, other_identity).expect("reopen");
    let t = relay_over(Box::new(store));
    let addr = start_server(&t);

    let info_after = get(addr, "/v1/info").body;
    assert_eq!(
        info_before, info_after,
        "identity and generations preserved"
    );

    // The pre-restart cursor still works: same generation, same positions.
    let response = post_cbor(
        addr,
        "/v1/changes",
        &changes_request(Some(&revoked_cursor), 10, 1 << 20),
    );
    let value = decode_value(&response.body);
    assert_eq!(value.get(1).expect("status").as_uint(), 0);
    assert_eq!(value.get(2).expect("entries").as_array().len(), 0);

    // Sticky revocation survived: a later Root record stays excluded.
    let mut body = b4_body();
    body.timestamp_ms = B4_TIMESTAMP_MS + 100;
    let root = followee::record::sign_record(&body, &root_seed()).expect("signs");
    let response = publish_record(addr, &root);
    assert_eq!(publish_outcome(&response.body), (2, Some(11)));

    // The update counter continues rather than restarting: Bob's next
    // update gets a fresh, higher number.
    let mut bob = b9_body();
    bob.timestamp_ms += 5;
    let bob_next = followee::record::sign_record(&bob, &bob_root_seed()).expect("signs");
    assert_eq!(publish_outcome(&publish_record(addr, &bob_next).body).0, 0);
    let changes = post_cbor(addr, "/v1/changes", &changes_request(None, 10, 1 << 20)).body;
    let entries = decode_value(&changes)
        .get(2)
        .expect("entries")
        .as_array()
        .to_vec();
    let numbers: Vec<u64> = entries.iter().map(|e| e.as_array()[2].as_uint()).collect();
    assert_eq!(numbers, vec![3, 4], "counter continued after restart");
}

// ---------------------------------------------------------------------------
// Development-mode binding guard.
// ---------------------------------------------------------------------------

#[test]
fn impl_9_5_development_mode_refuses_non_loopback_binding() {
    let t = memory_relay();
    let relay = std::sync::Arc::clone(&t.relay);
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    let error = rt.block_on(async move {
        let listener = tokio::net::TcpListener::bind("0.0.0.0:0")
            .await
            .expect("bind wildcard");
        serve(relay, listener).await.expect_err("must refuse")
    });
    assert!(error.to_string().contains("loopback"));
}

#[test]
fn impl_9_5_conforming_config_requires_https_or_explicit_dev_mode() {
    use followee::relay::{ConfigError, Relay, RelayConfig};
    let store = || Box::new(MemoryStore::new(test_identity()));
    let clock = || Box::new(followee::clock::SystemClock);
    assert!(matches!(
        Relay::new(
            store(),
            clock(),
            RelayConfig {
                base_uri: "http://relay.example/".to_owned(),
                development_mode: false,
            },
        ),
        Err(ConfigError::InsecureBaseUri)
    ));
    assert!(matches!(
        Relay::new(
            store(),
            clock(),
            RelayConfig {
                base_uri: "https://relay.example".to_owned(),
                development_mode: false,
            },
        ),
        Err(ConfigError::BaseUriMissingSlash)
    ));
    assert!(
        Relay::new(
            store(),
            clock(),
            RelayConfig {
                base_uri: "https://relay.example/".to_owned(),
                development_mode: false,
            },
        )
        .is_ok()
    );
}
