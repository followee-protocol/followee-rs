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

pub fn root_seed() -> [u8; 32] {
    fx32("root_seed")
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

/// Seals a body with the standard profile using the test-side assembler.
pub fn seal(payload: &[u8], seed: &[u8; 32]) -> Vec<u8> {
    seal_with_protected(&protected_ed25519(), payload, seed)
}
