//! Production client against a real relay server over real loopback
//! sockets: the production `HttpTransport` (reqwest/rustls), the production
//! axum relay, and the production wrapper validation, exercising actual
//! HTTP bytes end to end (IMPLEMENTATION.md section 11.6).
#![allow(clippy::arithmetic_side_effects)]

mod common;

use common::*;
use followee::relay::client::{
    BudgetMeter, HttpTransport, NetworkPolicy, OperationBudget, ReceivedResult, RelayClient,
};
use followee::relay::http::serve;
use followee::relay::wire::ReceivedChangesResponse;
use std::net::SocketAddr;

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

#[test]
fn sec_12_1_full_round_trip_over_real_http() {
    let t = memory_relay();
    let addr = start_server(&t);
    let base = format!("http://{addr}/");
    let transport = HttpTransport;
    let client = RelayClient::new(&transport, NetworkPolicy::Development, &*t.clock);
    let mut meter = BudgetMeter::new(OperationBudget {
        deadline_ms: None,
        max_response_bytes: 8 * 1024 * 1024,
        max_requests: 32,
    });

    // Info and directory.
    let info = client.info(&base, &mut meter).expect("info").value;
    assert_eq!(info.relay_id, [0xAA; 16]);
    assert!(info.protocol_versions.contains(&1));
    assert!(info.suites.contains(&-19));
    let directory = client
        .directory(&base, &mut meter)
        .expect("directory")
        .value;
    assert_eq!(directory.directory_generation, b11_generation());

    // Publish Alice's exact B.4 record, then a duplicate.
    let outcome = client
        .publish(&base, &fx_bytes("root_record_envelope"), &mut meter)
        .expect("publish");
    assert_eq!(outcome.value.status, 0, "admitted and current");
    let duplicate = client
        .publish(&base, &fx_bytes("root_record_envelope"), &mut meter)
        .expect("publish duplicate");
    assert_eq!(duplicate.value.status, 1, "valid, no current-state change");

    // Resolve returns the exact admitted bytes as an opaque candidate.
    let resolved = client
        .resolve(
            &base,
            &[alice_did().as_str(), bob_did().as_str()],
            &mut meter,
        )
        .expect("resolve")
        .value;
    assert_eq!(resolved.results.len(), 2);
    assert_eq!(
        resolved.results[0],
        ReceivedResult::Full(fx_bytes("root_record_envelope")),
        "exact admitted envelope bytes"
    );
    assert_eq!(
        resolved.results[1],
        ReceivedResult::Absent,
        "Bob absent here"
    );

    // Changes: one coalesced current tuple and a usable next cursor.
    let changes = client
        .changes(&base, None, 16, 1024 * 1024, &mut meter)
        .expect("changes")
        .value;
    let ReceivedChangesResponse::Success {
        entries,
        next_cursor,
        has_more,
        ..
    } = changes
    else {
        panic!("success expected");
    };
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].did, alice_did().as_str());
    assert!(!has_more);

    // The returned cursor round-trips: no further entries after it.
    let follow_up = client
        .changes(&base, Some(&next_cursor), 16, 1024 * 1024, &mut meter)
        .expect("changes after cursor")
        .value;
    let ReceivedChangesResponse::Success { entries, .. } = follow_up else {
        panic!("success expected");
    };
    assert!(entries.is_empty(), "cursor consumed the range exactly");
}
