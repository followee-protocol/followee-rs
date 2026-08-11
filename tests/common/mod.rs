//! Shared helpers for the conformance suites.
//!
//! The raw CBOR emitters here are deliberately independent of the crate's
//! writer so fixture mutations are not produced by the code under test.
#![allow(dead_code, clippy::arithmetic_side_effects)]

use followee::contact::{ContactDocument, ServiceEntry};
use followee::did::FolloweeDid;
use followee::record::{Authority, AuthorityDescriptor, RecordBody};

pub fn fixtures() -> serde_json::Value {
    serde_json::from_str(
        &std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/fixtures/specification/appendix_b.json"
        ))
        .expect("fixture file present"),
    )
    .expect("fixture JSON parses")
}

pub fn fx_str(name: &str) -> String {
    fixtures()[name]
        .as_str()
        .unwrap_or_else(|| panic!("fixture field {name} present"))
        .to_owned()
}

pub fn fx_bytes(name: &str) -> Vec<u8> {
    hex::decode(fx_str(name)).unwrap_or_else(|_| panic!("fixture field {name} is valid hex"))
}

pub fn fx32(name: &str) -> [u8; 32] {
    fx_bytes(name)
        .try_into()
        .unwrap_or_else(|_| panic!("fixture field {name} is 32 bytes"))
}

pub fn alice_did() -> FolloweeDid {
    FolloweeDid::parse(&fx_str("followee_did")).expect("Appendix B DID parses")
}

pub fn attacker_did() -> FolloweeDid {
    FolloweeDid::parse(&fx_str("attacker_did")).expect("attacker DID parses")
}

/// The Appendix B.4 timestamp.
pub const B4_TIMESTAMP_MS: u64 = 1_785_589_200_123;
/// The Appendix B.5 timestamp.
pub const B5_TIMESTAMP_MS: u64 = 1_785_589_201_123;

pub fn alice_contact() -> ContactDocument {
    ContactDocument {
        display_name: Some("Alice Example".to_owned()),
        summary: Some("Writer".to_owned()),
        also_known_as: vec!["acct:alice@example.com".to_owned()],
        services: vec![ServiceEntry {
            id: "feed".to_owned(),
            service_type: "Feed".to_owned(),
            endpoint: "https://alice.example/feed.xml".to_owned(),
            media_type: Some("application/atom+xml".to_owned()),
            label: Some("Writing".to_owned()),
            language: None,
            rel: None,
        }],
        ..ContactDocument::default()
    }
}

pub fn alice_descriptor() -> AuthorityDescriptor {
    AuthorityDescriptor {
        root_key: fx32("root_public_key"),
        revocation_commitment: fx32("revocation_commitment"),
    }
}

/// The Appendix B.4 record body from structured input (section 20.4:
/// identical structured input must produce byte-identical bodies).
pub fn b4_body() -> RecordBody {
    RecordBody {
        id: alice_did(),
        timestamp_ms: B4_TIMESTAMP_MS,
        authority: Authority::Root,
        descriptor: alice_descriptor(),
        revocation_key: None,
        valid_until_ms: None,
        contact: alice_contact(),
        extensions: Default::default(),
    }
}

/// The Appendix B.5 root-revoked record body.
pub fn b5_body() -> RecordBody {
    RecordBody {
        revocation_key: Some(fx32("revocation_public_key")),
        authority: Authority::RootRevoked,
        timestamp_ms: B5_TIMESTAMP_MS,
        ..b4_body()
    }
}

/// The Appendix B.9 Bob timestamp.
pub const B9_TIMESTAMP_MS: u64 = 1_785_589_201_123;

pub fn bob_did() -> FolloweeDid {
    FolloweeDid::parse(&fx_str("bob_did")).expect("Bob DID parses")
}

pub fn bob_contact() -> ContactDocument {
    ContactDocument {
        display_name: Some("Bob Example".to_owned()),
        summary: Some("Reader".to_owned()),
        also_known_as: vec!["acct:bob@example.net".to_owned()],
        services: vec![ServiceEntry {
            id: "feed".to_owned(),
            service_type: "Feed".to_owned(),
            endpoint: "https://bob.example/feed.xml".to_owned(),
            media_type: Some("application/atom+xml".to_owned()),
            label: Some("Reading".to_owned()),
            language: None,
            rel: None,
        }],
        ..ContactDocument::default()
    }
}

pub fn bob_descriptor() -> AuthorityDescriptor {
    AuthorityDescriptor {
        root_key: fx32("bob_root_public_key"),
        revocation_commitment: fx32("bob_revocation_commitment"),
    }
}

/// The Appendix B.9 Bob record body from structured input.
pub fn b9_body() -> RecordBody {
    RecordBody {
        id: bob_did(),
        timestamp_ms: B9_TIMESTAMP_MS,
        authority: Authority::Root,
        descriptor: bob_descriptor(),
        revocation_key: None,
        valid_until_ms: None,
        contact: bob_contact(),
        extensions: Default::default(),
    }
}

pub fn root_seed() -> [u8; 32] {
    fx32("root_seed")
}

pub fn bob_root_seed() -> [u8; 32] {
    fx32("bob_root_seed")
}

pub fn bob_revocation_seed() -> [u8; 32] {
    fx32("bob_revocation_seed")
}

pub fn revocation_seed() -> [u8; 32] {
    fx32("revocation_seed")
}

pub fn attacker_root_seed() -> [u8; 32] {
    fx32("attacker_root_seed")
}

pub fn attacker_revocation_seed() -> [u8; 32] {
    fx32("attacker_revocation_seed")
}

// ---------------------------------------------------------------------------
// Test-side raw CBOR emitters, independent of the crate writer.
// ---------------------------------------------------------------------------

pub fn r_head(major: u8, arg: u64) -> Vec<u8> {
    let ib = major << 5;
    if arg < 24 {
        vec![ib | arg as u8]
    } else if arg < 0x100 {
        vec![ib | 24, arg as u8]
    } else if arg < 0x1_0000 {
        let mut v = vec![ib | 25];
        v.extend((arg as u16).to_be_bytes());
        v
    } else if arg < 0x1_0000_0000 {
        let mut v = vec![ib | 26];
        v.extend((arg as u32).to_be_bytes());
        v
    } else {
        let mut v = vec![ib | 27];
        v.extend(arg.to_be_bytes());
        v
    }
}

pub fn r_uint(v: u64) -> Vec<u8> {
    r_head(0, v)
}

/// Encodes the negative integer `-(1 + magnitude)`.
pub fn r_nint_mag(magnitude: u64) -> Vec<u8> {
    r_head(1, magnitude)
}

pub fn r_bstr(bytes: &[u8]) -> Vec<u8> {
    let mut v = r_head(2, bytes.len() as u64);
    v.extend_from_slice(bytes);
    v
}

pub fn r_tstr(s: &str) -> Vec<u8> {
    let mut v = r_head(3, s.len() as u64);
    v.extend_from_slice(s.as_bytes());
    v
}

pub fn r_array(items: &[Vec<u8>]) -> Vec<u8> {
    let mut v = r_head(4, items.len() as u64);
    for item in items {
        v.extend_from_slice(item);
    }
    v
}

/// Emits a map with entries in the given order (no sorting: callers control
/// order deliberately, including wrong orders for negative cases).
pub fn r_map(entries: &[(Vec<u8>, Vec<u8>)]) -> Vec<u8> {
    let mut v = r_head(5, entries.len() as u64);
    for (k, val) in entries {
        v.extend_from_slice(k);
        v.extend_from_slice(val);
    }
    v
}

pub fn r_tag(v: u64) -> Vec<u8> {
    r_head(6, v)
}

/// The raw entry list of the Appendix B.4 body, in deterministic order, for
/// surgical mutation. Reconstructing from parts (rather than slicing the spec
/// hex) keeps each mutation explicit.
pub fn b4_raw_entries() -> Vec<(Vec<u8>, Vec<u8>)> {
    vec![
        (r_uint(0), r_uint(1)),
        (r_uint(1), r_tstr(&fx_str("followee_did"))),
        (r_uint(2), r_uint(B4_TIMESTAMP_MS)),
        (r_uint(3), r_uint(0)),
        (r_uint(4), fx_bytes("authority_descriptor_cbor")),
        (r_uint(7), alice_contact_raw()),
    ]
}

/// The raw entry list of the Appendix B.5 body, in deterministic order.
pub fn b5_raw_entries() -> Vec<(Vec<u8>, Vec<u8>)> {
    vec![
        (r_uint(0), r_uint(1)),
        (r_uint(1), r_tstr(&fx_str("followee_did"))),
        (r_uint(2), r_uint(B5_TIMESTAMP_MS)),
        (r_uint(3), r_uint(1)),
        (r_uint(4), fx_bytes("authority_descriptor_cbor")),
        (r_uint(5), fx_bytes("revocation_public_key_cbor")),
        (r_uint(7), alice_contact_raw()),
    ]
}

/// Alice's contact document, raw-encoded independently of the crate.
pub fn alice_contact_raw() -> Vec<u8> {
    let service = r_map(&[
        (r_uint(0), r_tstr("feed")),
        (r_uint(1), r_tstr("Feed")),
        (r_uint(2), r_tstr("https://alice.example/feed.xml")),
        (r_uint(3), r_tstr("application/atom+xml")),
        (r_uint(4), r_tstr("Writing")),
    ]);
    r_map(&[
        (r_uint(0), r_tstr("Alice Example")),
        (r_uint(1), r_tstr("Writer")),
        (r_uint(3), r_array(&[r_tstr("acct:alice@example.com")])),
        (r_uint(4), r_array(&[service])),
    ])
}

/// Counts one CBOR item's aggregate members — every map entry plus every
/// array element, recursively — per the specification section 15.1 counting
/// rule. Deliberately test-side and independent of the crate validator, so
/// derivations from this counter are not produced by the code under test.
/// Panics on input the r_* emitters cannot produce.
pub fn count_members(bytes: &[u8]) -> u32 {
    fn item(b: &[u8], pos: &mut usize, members: &mut u32) {
        let ib = b[*pos];
        *pos += 1;
        let (major, ai) = (ib >> 5, ib & 0x1f);
        let arg: u64 = match ai {
            0..=23 => u64::from(ai),
            24 => {
                let v = u64::from(b[*pos]);
                *pos += 1;
                v
            }
            25 => {
                let v = u64::from(u16::from_be_bytes([b[*pos], b[*pos + 1]]));
                *pos += 2;
                v
            }
            26 => {
                let v = u64::from(u32::from_be_bytes(b[*pos..*pos + 4].try_into().unwrap()));
                *pos += 4;
                v
            }
            27 => {
                let v = u64::from_be_bytes(b[*pos..*pos + 8].try_into().unwrap());
                *pos += 8;
                v
            }
            _ => panic!("unsupported additional information {ai}"),
        };
        match major {
            0 | 1 | 7 => {}
            2 | 3 => *pos += arg as usize,
            4 => {
                for _ in 0..arg {
                    *members += 1;
                    item(b, pos, members);
                }
            }
            5 => {
                for _ in 0..arg {
                    *members += 1;
                    item(b, pos, members);
                    item(b, pos, members);
                }
            }
            6 => item(b, pos, members),
            _ => panic!("unsupported major {major}"),
        }
    }
    let mut pos = 0;
    let mut members = 0;
    item(bytes, &mut pos, &mut members);
    assert_eq!(pos, bytes.len(), "exactly one complete item");
    members
}

/// Builds one Appendix B.10/B.12 raw record body: the B.4 body with its map
/// head changed from `a6` to `a7` and record label `8` plus one extension
/// entry appended. The appended bytes are reconstructed from parts (label,
/// extension-map head, key, value) rather than sliced from spec hex.
pub fn extension_raw_body(key: &str, extension_value_bytes: &[u8]) -> Vec<u8> {
    let mut body = r_map(&b4_raw_entries());
    assert_eq!(body[0], 0xa6, "B.4 body head");
    body[0] = 0xa7;
    body.extend(r_uint(8));
    // Extension map: one entry keyed by the published URI; the value bytes
    // are supplied raw because they are deliberately outside what the
    // crate's authoring path can produce (invalid CBOR content for B.10,
    // schema-disallowed simple values for B.12).
    body.extend(r_head(5, 1));
    body.extend(r_tstr(key));
    body.extend_from_slice(extension_value_bytes);
    body
}

/// The Appendix B.10 construction over the published B.10 extension key.
pub fn b10_raw_body(extension_value_bytes: &[u8]) -> Vec<u8> {
    extension_raw_body(&fx_str("b10_extension_key"), extension_value_bytes)
}

/// The Appendix B.12 construction over the published B.12 extension key.
pub fn b12_raw_body(extension_value_bytes: &[u8]) -> Vec<u8> {
    extension_raw_body(&fx_str("b12_extension_key"), extension_value_bytes)
}

/// Assembles a complete tagged envelope from raw parts with an arbitrary
/// protected header, signing the corresponding `Sig_structure` with `seed`.
/// Used for fault-isolated negative fixtures that must be validly signed.
pub fn seal_with_protected(protected: &[u8], payload: &[u8], seed: &[u8; 32]) -> Vec<u8> {
    let sig_structure = r_array(&[
        r_tstr("Signature1"),
        r_bstr(protected),
        r_bstr(b"Followee/IdentityRecord/v1"),
        r_bstr(payload),
    ]);
    let signature = followee::crypto::ed25519_sign(seed, &sig_structure);
    let mut envelope = r_tag(18);
    envelope.extend(r_head(4, 4));
    envelope.extend(r_bstr(protected));
    envelope.extend(r_head(5, 0));
    envelope.extend(r_bstr(payload));
    envelope.extend(r_bstr(&signature));
    envelope
}

/// Standard protected header bytes `{1: -19}`.
pub fn protected_ed25519() -> Vec<u8> {
    vec![0xa1, 0x01, 0x32]
}

// ---------------------------------------------------------------------------
// Test-side CBOR decoder, independent of the crate reader, for inspecting
// relay responses. Panics on input the deterministic writer cannot produce.
// ---------------------------------------------------------------------------

/// A decoded CBOR value for test assertions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TestValue {
    Uint(u64),
    Nint(u64),
    Bytes(Vec<u8>),
    Text(String),
    Bool(bool),
    Null,
    Array(Vec<TestValue>),
    /// Map entries in received order.
    Map(Vec<(TestValue, TestValue)>),
}

impl TestValue {
    /// Looks up an unsigned-integer map label.
    pub fn get(&self, wanted: u64) -> Option<&TestValue> {
        match self {
            TestValue::Map(entries) => entries.iter().find_map(|(k, v)| {
                (matches!(k, TestValue::Uint(label) if *label == wanted)).then_some(v)
            }),
            _ => None,
        }
    }

    pub fn as_uint(&self) -> u64 {
        match self {
            TestValue::Uint(v) => *v,
            other => panic!("expected uint, got {other:?}"),
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        match self {
            TestValue::Bytes(v) => v,
            other => panic!("expected bytes, got {other:?}"),
        }
    }

    pub fn as_array(&self) -> &[TestValue] {
        match self {
            TestValue::Array(v) => v,
            other => panic!("expected array, got {other:?}"),
        }
    }

    /// The map's unsigned-integer labels in received order.
    pub fn labels(&self) -> Vec<u64> {
        match self {
            TestValue::Map(entries) => entries
                .iter()
                .map(|(k, _)| match k {
                    TestValue::Uint(v) => *v,
                    other => panic!("expected uint label, got {other:?}"),
                })
                .collect(),
            other => panic!("expected map, got {other:?}"),
        }
    }
}

/// Decodes exactly one CBOR item, panicking on trailing bytes.
pub fn decode_value(bytes: &[u8]) -> TestValue {
    let mut pos = 0;
    let value = decode_at(bytes, &mut pos);
    assert_eq!(pos, bytes.len(), "exactly one complete item");
    value
}

fn decode_at(b: &[u8], pos: &mut usize) -> TestValue {
    let ib = b[*pos];
    *pos += 1;
    let (major, ai) = (ib >> 5, ib & 0x1f);
    let arg: u64 = match ai {
        0..=23 => u64::from(ai),
        24 => {
            let v = u64::from(b[*pos]);
            *pos += 1;
            v
        }
        25 => {
            let v = u64::from(u16::from_be_bytes([b[*pos], b[*pos + 1]]));
            *pos += 2;
            v
        }
        26 => {
            let v = u64::from(u32::from_be_bytes(b[*pos..*pos + 4].try_into().unwrap()));
            *pos += 4;
            v
        }
        27 => {
            let v = u64::from_be_bytes(b[*pos..*pos + 8].try_into().unwrap());
            *pos += 8;
            v
        }
        other => panic!("unsupported additional information {other}"),
    };
    match major {
        0 => TestValue::Uint(arg),
        1 => TestValue::Nint(arg),
        2 => {
            let v = b[*pos..*pos + arg as usize].to_vec();
            *pos += arg as usize;
            TestValue::Bytes(v)
        }
        3 => {
            let v = std::str::from_utf8(&b[*pos..*pos + arg as usize])
                .expect("valid UTF-8")
                .to_owned();
            *pos += arg as usize;
            TestValue::Text(v)
        }
        4 => TestValue::Array((0..arg).map(|_| decode_at(b, pos)).collect()),
        5 => TestValue::Map(
            (0..arg)
                .map(|_| (decode_at(b, pos), decode_at(b, pos)))
                .collect(),
        ),
        7 => match arg {
            20 => TestValue::Bool(false),
            21 => TestValue::Bool(true),
            22 => TestValue::Null,
            other => panic!("unsupported simple value {other}"),
        },
        other => panic!("unsupported major {other}"),
    }
}

// ---------------------------------------------------------------------------
// Relay test builders and request encoders.
// ---------------------------------------------------------------------------

use followee::clock::ManualClock;
use followee::relay::{Relay, RelayConfig};
use followee::store::{MemoryStore, RelayIdentity, RelayStore};
use std::sync::Arc;

/// The Appendix B.11 directory generation.
pub fn b11_generation() -> [u8; 16] {
    fx_bytes_at("b11", "directory_generation")
        .try_into()
        .expect("16 bytes")
}

pub fn fx_bytes_at(section: &str, name: &str) -> Vec<u8> {
    let mut value = fixtures()[section].clone();
    for part in name.split('/') {
        value = value[part].clone();
    }
    hex::decode(
        value
            .as_str()
            .unwrap_or_else(|| panic!("fixture field {section}.{name} present")),
    )
    .expect("valid hex")
}

/// A deterministic relay identity whose directory generation is the exact
/// Appendix B.11 value, so wrapper bytes reproduce byte-for-byte.
pub fn test_identity() -> RelayIdentity {
    RelayIdentity {
        relay_id: [0xAA; 16],
        cursor_generation: [0xC0; 16],
        directory_generation: b11_generation(),
    }
}

/// A clock at which both the B.4/B.6 Alice records and the B.9 Bob record
/// are admissible and non-premature.
pub const RELAY_NOW_MS: u64 = 1_785_589_201_123;

pub struct TestRelay {
    pub relay: Arc<Relay>,
    pub clock: Arc<ManualClock>,
}

/// Builds a development-mode relay over the given store with a manual clock.
pub fn relay_over(store: Box<dyn RelayStore>) -> TestRelay {
    let clock = Arc::new(ManualClock::new(RELAY_NOW_MS));
    let relay = Relay::new(
        store,
        Box::new(SharedClock(Arc::clone(&clock))),
        RelayConfig {
            base_uri: "http://127.0.0.1/".to_owned(),
            development_mode: true,
        },
    )
    .expect("valid test configuration");
    TestRelay {
        relay: Arc::new(relay),
        clock,
    }
}

/// Builds a memory-backed test relay.
pub fn memory_relay() -> TestRelay {
    relay_over(Box::new(MemoryStore::new(test_identity())))
}

/// Clock adapter sharing one `ManualClock` between test and relay.
pub struct SharedClock(pub Arc<ManualClock>);

impl followee::clock::Clock for SharedClock {
    fn now_ms(&self) -> Result<u64, followee::clock::ClockError> {
        self.0.now_ms()
    }
}

/// Encodes a deterministic `v1/resolve` request for the given DID strings.
pub fn resolve_request(dids: &[&str]) -> Vec<u8> {
    let items: Vec<Vec<u8>> = dids.iter().map(|d| r_tstr(d)).collect();
    r_map(&[(r_uint(0), r_uint(1)), (r_uint(1), r_array(&items))])
}

/// Encodes a deterministic `v1/changes` request.
pub fn changes_request(cursor: Option<&[u8]>, item_limit: u64, byte_limit: u64) -> Vec<u8> {
    let cursor_value = match cursor {
        Some(bytes) => r_bstr(bytes),
        None => vec![0xf6],
    };
    r_map(&[
        (r_uint(0), r_uint(1)),
        (r_uint(1), cursor_value),
        (r_uint(2), r_uint(item_limit)),
        (r_uint(3), r_uint(byte_limit)),
    ])
}

/// Builds a fresh valid identity whose record carries `pad` extension bytes.
/// The derived seeds are test material distinct from every published
/// Appendix B seed.
pub fn synthetic_identity_record(index: u64, pad: usize) -> (String, Vec<u8>) {
    use followee::record::{
        Authority, AuthorityDescriptor, RecordBody, revocation_commitment, sign_record,
    };
    let mut root = [0u8; 32];
    root[..8].copy_from_slice(&index.to_be_bytes());
    root[31] = 0x51;
    let mut revocation = [0u8; 32];
    revocation[..8].copy_from_slice(&index.to_be_bytes());
    revocation[31] = 0x52;
    let descriptor = AuthorityDescriptor {
        root_key: followee::crypto::ed25519_public_key(&root),
        revocation_commitment: revocation_commitment(&followee::crypto::ed25519_public_key(
            &revocation,
        )),
    };
    let did = descriptor.did();
    let mut extensions = followee::contact::ExtensionMap::new();
    if pad > 0 {
        extensions.insert(
            "https://example.com/pad".to_owned(),
            followee::contact::ExtensionValue::Bytes(vec![0x41; pad]),
        );
    }
    let body = RecordBody {
        id: did.clone(),
        timestamp_ms: B4_TIMESTAMP_MS,
        authority: Authority::Root,
        descriptor,
        revocation_key: None,
        valid_until_ms: None,
        contact: followee::contact::ContactDocument::default(),
        extensions,
    };
    (
        did.as_str().to_owned(),
        sign_record(&body, &root).expect("signs"),
    )
}

/// Builds a structurally valid cursor for an arbitrary generation, mirroring
/// the relay-local encoding (16 generation bytes, 8-byte big-endian
/// position) from the test side.
pub fn raw_cursor(generation: &[u8; 16], position: u64) -> Vec<u8> {
    let mut bytes = generation.to_vec();
    bytes.extend_from_slice(&position.to_be_bytes());
    bytes
}

/// Decodes a publish response into `(status, Option<errorCode>)`.
pub fn publish_outcome(response: &[u8]) -> (u64, Option<u64>) {
    let value = decode_value(response);
    assert_eq!(value.get(0).expect("version").as_uint(), 1);
    let status = value.get(1).expect("status").as_uint();
    let code = value.get(2).map(TestValue::as_uint);
    (status, code)
}

/// Seals a body with the standard profile using the test-side assembler.
pub fn seal(payload: &[u8], seed: &[u8; 32]) -> Vec<u8> {
    seal_with_protected(&protected_ed25519(), payload, seed)
}

// ---------------------------------------------------------------------------
// Milestone 4: deterministic mock transport and client-side builders.
// ---------------------------------------------------------------------------

use followee::relay::client::{
    Method, Transport, TransportError, TransportRequest, TransportResponse,
};
use std::cell::RefCell;
use std::collections::HashMap;

/// One request recorded by [`MockTransport`].
#[derive(Debug, Clone)]
pub struct RecordedRequest {
    pub method: Method,
    pub url: String,
    pub content_type: Option<&'static str>,
    pub body: Vec<u8>,
}

/// Deterministic injected transport: responses are queued per exact URL and
/// consumed in order; every request is recorded. No network, no sleeping.
#[derive(Default)]
pub struct MockTransport {
    routes: RefCell<HashMap<String, std::collections::VecDeque<TransportResponse>>>,
    errors: RefCell<HashMap<String, TransportError>>,
    pub log: RefCell<Vec<RecordedRequest>>,
}

impl MockTransport {
    pub fn new() -> Self {
        Self::default()
    }

    /// Queues a response for the exact URL.
    pub fn on(&self, url: &str, response: TransportResponse) {
        self.routes
            .borrow_mut()
            .entry(url.to_owned())
            .or_default()
            .push_back(response);
    }

    /// Makes the exact URL fail with a transport error.
    pub fn fail(&self, url: &str, error: TransportError) {
        self.errors.borrow_mut().insert(url.to_owned(), error);
    }

    pub fn requests(&self) -> Vec<RecordedRequest> {
        self.log.borrow().clone()
    }
}

impl Transport for MockTransport {
    fn execute(&self, request: &TransportRequest<'_>) -> Result<TransportResponse, TransportError> {
        self.log.borrow_mut().push(RecordedRequest {
            method: request.method,
            url: request.url.to_owned(),
            content_type: request.content_type,
            body: request.body.to_vec(),
        });
        if let Some(error) = self.errors.borrow().get(request.url) {
            return Err(error.clone());
        }
        self.routes
            .borrow_mut()
            .get_mut(request.url)
            .and_then(std::collections::VecDeque::pop_front)
            .ok_or_else(|| TransportError::Io(format!("no mock response for {}", request.url)))
    }
}

/// A 200 `application/cbor` transport response.
pub fn cbor_ok(body: Vec<u8>) -> TransportResponse {
    TransportResponse {
        status: 200,
        content_type: Some("application/cbor".to_owned()),
        location: None,
        body,
    }
}

/// Builds a conforming `v1/info` response body for a mock peer.
pub fn info_response(relay_id: &[u8; 16], cursor_gen: &[u8; 16], dir_gen: &[u8; 16]) -> Vec<u8> {
    let limits = r_map(&[
        (r_uint(0), r_uint(16 * 1024)),
        (r_uint(1), r_uint(256)),
        (r_uint(2), r_uint(1024 * 1024)),
        (r_uint(3), r_uint(1024)),
        (r_uint(4), r_uint(4 * 1024 * 1024)),
    ]);
    r_map(&[
        (r_uint(0), r_uint(1)),
        (r_uint(1), r_bstr(relay_id)),
        (r_uint(2), r_uint(0x01 | 0x02 | 0x04)),
        (r_uint(3), r_array(&[r_uint(1)])),
        (r_uint(4), r_array(&[r_nint_mag(18)])),
        (r_uint(5), limits),
        (r_uint(6), r_bstr(cursor_gen)),
        (r_uint(7), r_bstr(dir_gen)),
        (r_uint(8), r_tstr("http://127.0.0.1/")),
    ])
}

/// Builds a `v1/resolve` response wrapper from encoded results under the
/// given directory generation.
pub fn resolve_response_with(generation: &[u8; 16], results: &[Vec<u8>]) -> Vec<u8> {
    r_map(&[
        (r_uint(0), r_uint(1)),
        (r_uint(1), r_bstr(generation)),
        (r_uint(2), r_array(results)),
    ])
}

pub fn rr_full(envelope: &[u8]) -> Vec<u8> {
    r_map(&[(r_uint(0), r_uint(0)), (r_uint(1), r_bstr(envelope))])
}

pub fn rr_ref(index: u32) -> Vec<u8> {
    r_map(&[
        (r_uint(0), r_uint(1)),
        (r_uint(1), r_uint(u64::from(index))),
    ])
}

pub fn rr_absent() -> Vec<u8> {
    r_map(&[(r_uint(0), r_uint(2))])
}

pub fn rr_error(code: u64) -> Vec<u8> {
    r_map(&[(r_uint(0), r_uint(3)), (r_uint(2), r_uint(code))])
}

/// Builds a `v1/directory` response body.
pub fn directory_response_with(
    generation: &[u8; 16],
    entries: &[(u32, [u8; 16], &str)],
) -> Vec<u8> {
    let rows: Vec<Vec<u8>> = entries
        .iter()
        .map(|(index, relay_id, endpoint)| {
            r_map(&[
                (r_uint(0), r_uint(u64::from(*index))),
                (r_uint(1), r_bstr(relay_id)),
                (r_uint(2), r_tstr(endpoint)),
                (r_uint(3), r_uint(0x01 | 0x02)),
            ])
        })
        .collect();
    r_map(&[
        (r_uint(0), r_uint(1)),
        (r_uint(1), r_bstr(generation)),
        (r_uint(2), r_array(&rows)),
    ])
}

/// Builds one `v1/changes` change entry.
pub fn ch_entry(did: &str, payload: Vec<u8>, last_updated: u64) -> Vec<u8> {
    r_array(&[r_tstr(did), payload, r_uint(last_updated)])
}

/// Builds a `v1/changes` success response body.
pub fn changes_success_with(
    generation: &[u8; 16],
    entries: &[Vec<u8>],
    next_cursor: &[u8],
    has_more: bool,
) -> Vec<u8> {
    r_map(&[
        (r_uint(0), r_uint(1)),
        (r_uint(1), r_uint(0)),
        (r_uint(2), r_array(entries)),
        (r_uint(3), r_bstr(next_cursor)),
        (r_uint(4), vec![if has_more { 0xf5 } else { 0xf4 }]),
        (r_uint(5), r_bstr(generation)),
    ])
}

/// The exact two-field ResetRequired response body.
pub fn changes_reset_body() -> Vec<u8> {
    r_map(&[(r_uint(0), r_uint(1)), (r_uint(1), r_uint(1))])
}

/// A `v1/changes` status-2 error response body.
pub fn changes_error_body(code: u64) -> Vec<u8> {
    r_map(&[
        (r_uint(0), r_uint(1)),
        (r_uint(1), r_uint(2)),
        (r_uint(6), r_uint(code)),
    ])
}

/// Signs a fresh synthetic Root record with an explicit timestamp and
/// display name, returning `(did, envelope, root_seed)`. Distinct from
/// every published Appendix B seed.
pub fn synthetic_record_at(
    index: u64,
    timestamp_ms: u64,
    display_name: &str,
) -> (String, Vec<u8>, [u8; 32]) {
    use followee::record::{
        Authority, AuthorityDescriptor, RecordBody, revocation_commitment, sign_record,
    };
    let mut root = [0u8; 32];
    root[..8].copy_from_slice(&index.to_be_bytes());
    root[31] = 0x61;
    let mut revocation = [0u8; 32];
    revocation[..8].copy_from_slice(&index.to_be_bytes());
    revocation[31] = 0x62;
    let descriptor = AuthorityDescriptor {
        root_key: followee::crypto::ed25519_public_key(&root),
        revocation_commitment: revocation_commitment(&followee::crypto::ed25519_public_key(
            &revocation,
        )),
    };
    let did = descriptor.did();
    let contact = followee::contact::ContactDocument {
        display_name: Some(display_name.to_owned()),
        ..Default::default()
    };
    let body = RecordBody {
        id: did.clone(),
        timestamp_ms,
        authority: Authority::Root,
        descriptor,
        revocation_key: None,
        valid_until_ms: None,
        contact,
        extensions: Default::default(),
    };
    (
        did.as_str().to_owned(),
        sign_record(&body, &root).expect("signs"),
        root,
    )
}
