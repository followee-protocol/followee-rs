//! Property tests: canonical-encoding determinism, decode/encode stability
//! through the complete sign-and-verify path, and candidate-selection
//! independence from arrival order (IMPLEMENTATION.md section 11.3).
#![allow(clippy::arithmetic_side_effects)]

mod common;

use common::*;
use followee::contact::{ContactDocument, ServiceEntry};
use followee::ordering::{AuthorityState, select_current};
use followee::record::{Authority, RecordBody, sign_record};
use followee::verify::{VerifiedRecord, verify_record};
use proptest::prelude::*;
use std::sync::OnceLock;

fn contact_strategy() -> impl Strategy<Value = ContactDocument> {
    let text = || proptest::string::string_regex("[a-zA-Z0-9 ._-]{0,64}").expect("regex");
    let uri = || {
        proptest::string::string_regex("https://[a-z0-9.]{1,32}/[a-zA-Z0-9/._-]{0,64}")
            .expect("regex")
    };
    (
        proptest::option::of(text()),
        proptest::option::of(text()),
        proptest::option::of(uri()),
        proptest::collection::vec(uri(), 0..4),
        proptest::collection::vec((0u32..1000, uri()), 0..4),
    )
        .prop_map(|(display_name, summary, avatar, also_known_as, services)| {
            let services = services
                .into_iter()
                .enumerate()
                .map(|(i, (n, endpoint))| ServiceEntry {
                    id: format!("s{i}-{n}"),
                    service_type: "Website".to_owned(),
                    endpoint,
                    media_type: None,
                    label: None,
                    language: None,
                    rel: None,
                })
                .collect();
            ContactDocument {
                display_name,
                summary,
                avatar,
                also_known_as,
                services,
                migration: None,
                extensions: Default::default(),
            }
        })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// Identical structured input yields identical bytes; the complete
    /// sign → verify path round-trips the body losslessly; and the body
    /// digest is stable.
    #[test]
    fn sec_7_2_encode_verify_round_trip(contact in contact_strategy(), ts in 1_600_000_000_000u64..2_000_000_000_000, horizon in proptest::option::of(0u64..10_000_000)) {
        let body = RecordBody {
            timestamp_ms: ts,
            valid_until_ms: horizon.map(|h| ts + h),
            contact,
            ..b4_body()
        };
        let bytes_a = body.encode().expect("encodes");
        let bytes_b = body.encode().expect("encodes");
        prop_assert_eq!(&bytes_a, &bytes_b, "deterministic encoding");

        let envelope = sign_record(&body, &root_seed()).expect("signs");
        let verified = verify_record(&alice_did(), &envelope).expect("verifies");
        prop_assert_eq!(verified.body(), &body, "lossless round trip");
        prop_assert_eq!(verified.payload_bytes(), bytes_a.as_slice(), "wire bytes preserved");
    }
}

/// Concrete full-feature round trip: migration plus every extension value
/// type and key kind must survive encode → sign → verify → compare losslessly.
#[test]
fn sec_7_4_and_5_6_full_feature_round_trip() {
    use followee::contact::{ExtensionKey, ExtensionValue, Migration};
    use followee::did::FolloweeDid;

    let mut extensions = followee::contact::ExtensionMap::new();
    extensions.insert(
        "https://example.com/ext/v1".to_owned(),
        ExtensionValue::Map(vec![
            (ExtensionKey::Unsigned(1), ExtensionValue::Bool(true)),
            (ExtensionKey::Negative(0), ExtensionValue::Null),
            (
                ExtensionKey::Text("k".to_owned()),
                ExtensionValue::Array(vec![
                    ExtensionValue::Unsigned(u64::MAX),
                    ExtensionValue::Negative(u64::MAX),
                    ExtensionValue::Bytes(vec![1, 2, 3]),
                    ExtensionValue::Text("v".to_owned()),
                    ExtensionValue::Bool(false),
                ]),
            ),
        ]),
    );
    let mut body = b4_body();
    body.contact.services.push(followee::contact::ServiceEntry {
        id: "full".to_owned(),
        service_type: "https://example.com/types/custom".to_owned(),
        endpoint: "https://example.com/profile".to_owned(),
        media_type: Some("text/html".to_owned()),
        label: Some("Profil".to_owned()),
        language: Some("de-DE".to_owned()),
        rel: Some("alternate".to_owned()),
    });
    body.contact.migration = Some(Migration {
        predecessor: Some(FolloweeDid::parse(&fx_str("attacker_did")).expect("parses")),
        successor: None,
    });
    body.contact.extensions = extensions.clone();
    body.extensions = extensions;

    let envelope = sign_record(&body, &root_seed()).expect("signs");
    let verified = verify_record(&alice_did(), &envelope).expect("verifies");
    assert_eq!(
        verified.body(),
        &body,
        "migration and extensions round-trip"
    );

    // Determinism: encoding the same body again reproduces identical bytes.
    assert_eq!(
        body.encode().expect("encodes"),
        verified.payload_bytes(),
        "wire bytes stable"
    );
}

fn attacker_records() -> Vec<VerifiedRecord> {
    // The published B.8.1 attacker seeds control a legitimate DID of their
    // own; its records make the mixed-identity pool.
    use followee::record::AuthorityDescriptor;
    let descriptor = AuthorityDescriptor {
        root_key: fx32("attacker_root_public_key"),
        revocation_commitment: fx32("attacker_revocation_commitment"),
    };
    let attacker = descriptor.did();
    [1_100u64, 2_000, 9_000]
        .into_iter()
        .map(|ts| {
            let body = followee::record::RecordBody {
                id: attacker.clone(),
                timestamp_ms: 1_785_589_200_000 + ts,
                authority: Authority::Root,
                descriptor: descriptor.clone(),
                revocation_key: None,
                valid_until_ms: None,
                contact: Default::default(),
                extensions: Default::default(),
            };
            let envelope = sign_record(&body, &fx32("attacker_root_seed")).expect("signs");
            verify_record(&attacker, &envelope).expect("verifies")
        })
        .collect()
}

fn pool() -> &'static Vec<VerifiedRecord> {
    static POOL: OnceLock<Vec<VerifiedRecord>> = OnceLock::new();
    POOL.get_or_init(|| {
        let mut records = Vec::new();
        for (i, ts) in [1_000u64, 2_000, 2_000, 3_000, 5_000].iter().enumerate() {
            let mut body = b4_body();
            body.timestamp_ms = 1_785_589_200_000 + ts;
            body.contact.display_name = Some(format!("Variant {i}"));
            let envelope = sign_record(&body, &root_seed()).expect("signs");
            records.push(verify_record(&alice_did(), &envelope).expect("verifies"));
        }
        for ts in [1_500u64, 4_000] {
            let mut body = b4_body();
            body.timestamp_ms = 1_785_589_200_000 + ts;
            body.authority = Authority::RootRevoked;
            body.revocation_key = Some(fx32("revocation_public_key"));
            let envelope = sign_record(&body, &revocation_seed()).expect("signs");
            records.push(verify_record(&alice_did(), &envelope).expect("verifies"));
        }
        records.extend(attacker_records());
        records
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    /// The selected winner and resulting authority state are independent of
    /// candidate arrival order, for every subset and permutation.
    #[test]
    fn sec_8_3_selection_is_order_independent(indices in proptest::collection::vec(0usize..10, 0..12)) {
        // The pool mixes valid records for two identities (Alice and the
        // B.8.1 attacker DID); selection is per explicit target, so the
        // winner and state must be permutation-independent for each target
        // and must never come from the other identity.
        let now = 1_785_589_300_000u64;
        let candidates: Vec<VerifiedRecord> =
            indices.iter().map(|&i| pool()[i].clone()).collect();
        let mut reversed = candidates.clone();
        reversed.reverse();

        let attacker = attacker_records()[0].body().id.clone();
        for target in [alice_did(), attacker] {
            for sticky in [AuthorityState::Unknown, AuthorityState::RootRevoked] {
                let a = select_current(&target, &candidates, now, sticky);
                let b = select_current(&target, &reversed, now, sticky);
                prop_assert_eq!(
                    a.winner.map(followee::verify::VerifiedRecord::body_digest),
                    b.winner.map(followee::verify::VerifiedRecord::body_digest),
                    "same winner under reversal"
                );
                prop_assert_eq!(a.authority_state, b.authority_state);

                // The winner always belongs to the requested identity.
                if let Some(winner) = a.winner {
                    prop_assert_eq!(&winner.body().id, &target);
                }

                // Monotone sticky revocation: with sticky RootRevoked, no
                // Root winner may ever be produced.
                if sticky == AuthorityState::RootRevoked
                    && let Some(winner) = a.winner {
                        prop_assert_eq!(winner.authority(), Authority::RootRevoked);
                    }
            }
        }
    }
}
