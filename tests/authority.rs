//! Provisional authority-precedence, future-bound, staleness, and sticky
//! state tests required by IMPLEMENTATION.md section 11.1 beyond Appendix B.
//! Expected results are derived from specification sections 5.4, 5.5, 8.2 and
//! 8.5 prose; fixture status: implementation (not specification bytes).
#![allow(clippy::arithmetic_side_effects)]

mod common;

use common::*;
use followee::ordering::{AuthorityState, select_current};
use followee::record::{Authority, RecordBody, sign_record};
use followee::timestamp::{Freshness, freshness};
use followee::verify::{VerifiedRecord, verify_record};

fn make_root(timestamp_ms: u64, valid_until_ms: Option<u64>) -> VerifiedRecord {
    let body = RecordBody {
        timestamp_ms,
        valid_until_ms,
        ..b4_body()
    };
    let envelope = sign_record(&body, &root_seed()).expect("signs");
    verify_record(&alice_did(), &envelope).expect("verifies")
}

fn make_revoked(timestamp_ms: u64, valid_until_ms: Option<u64>) -> VerifiedRecord {
    let body = RecordBody {
        timestamp_ms,
        valid_until_ms,
        authority: Authority::RootRevoked,
        revocation_key: Some(fx32("revocation_public_key")),
        ..b4_body()
    };
    let envelope = sign_record(&body, &revocation_seed()).expect("signs");
    verify_record(&alice_did(), &envelope).expect("verifies")
}

const NOW: u64 = 1_785_589_300_000;

#[test]
fn sec_8_2_root_revoked_outranks_root_with_later_timestamp() {
    let late_root = make_root(NOW - 1_000, None);
    let early_revoked = make_revoked(NOW - 50_000, None);
    for candidates in [
        vec![late_root.clone(), early_revoked.clone()],
        vec![early_revoked.clone(), late_root.clone()],
    ] {
        let selection = select_current(&alice_did(), &candidates, NOW, AuthorityState::Unknown);
        assert_eq!(
            selection.winner.expect("winner").authority(),
            Authority::RootRevoked,
            "absolute precedence regardless of timestamps and order"
        );
        assert_eq!(selection.authority_state, AuthorityState::RootRevoked);
    }
}

#[test]
fn sec_8_2_every_root_record_is_excluded_after_sticky_revocation() {
    let roots = vec![make_root(NOW - 10_000, None), make_root(NOW - 1_000, None)];
    let selection = select_current(&alice_did(), &roots, NOW, AuthorityState::RootRevoked);
    assert!(
        selection.winner.is_none(),
        "no Root record may be selected while sticky RootRevoked is retained"
    );
    assert_eq!(selection.authority_state, AuthorityState::RootRevoked);
}

#[test]
fn sec_8_2_no_last_good_root_fallback() {
    // Even the Root record that predates compromise is ineligible: the only
    // candidate set that can produce a winner under RootRevoked is the
    // RootRevoked class itself.
    let pre_compromise = make_root(NOW - 500_000, None);
    let bad_current = make_root(NOW - 10_000, None);
    let revoked = make_revoked(NOW - 5_000, None);
    let candidates = [pre_compromise, bad_current, revoked.clone()];
    let selection = select_current(&alice_did(), &candidates, NOW, AuthorityState::Unknown);
    assert_eq!(
        selection.winner.expect("winner").body_digest(),
        revoked.body_digest(),
        "the RootRevoked record itself is the complete replacement state"
    );
}

#[test]
fn sec_8_2_stale_root_revoked_still_activates_transition() {
    // validUntil == timestamp, and NOW is far past it: stale but decisive.
    let ts = NOW - 100_000;
    let stale_revoked = make_revoked(ts, Some(ts));
    assert_eq!(
        freshness(stale_revoked.body().valid_until_ms, NOW),
        Freshness::Stale
    );
    let later_root = make_root(NOW - 1_000, None);
    let candidates = [later_root, stale_revoked.clone()];
    let selection = select_current(&alice_did(), &candidates, NOW, AuthorityState::Unknown);
    assert_eq!(
        selection.winner.expect("winner").body_digest(),
        stale_revoked.body_digest(),
        "validUntil governs contact freshness, not authority expiry"
    );
    assert_eq!(selection.authority_state, AuthorityState::RootRevoked);
}

#[test]
fn sec_8_5_discarded_sticky_state_is_a_fresh_observer() {
    // While sticky state is retained, Root loses; after the caller discards
    // it (models dropping the entry), the same candidates elect Root again.
    let root = make_root(NOW - 1_000, None);
    let retained = select_current(
        &alice_did(),
        std::slice::from_ref(&root),
        NOW,
        AuthorityState::RootRevoked,
    );
    assert!(
        retained.winner.is_none(),
        "retained sticky state excludes Root"
    );

    let fresh = select_current(
        &alice_did(),
        std::slice::from_ref(&root),
        NOW,
        AuthorityState::Unknown,
    );
    assert!(
        fresh.winner.is_some(),
        "a fresh observer with no sticky state can be shown withheld Root state"
    );
}

#[test]
fn sec_5_4_premature_candidates_are_excluded_at_the_exact_boundary() {
    let at_bound = make_root(NOW + 300_000, None);
    let beyond = make_root(NOW + 300_001, None);

    let selection = select_current(
        &alice_did(),
        std::slice::from_ref(&at_bound),
        NOW,
        AuthorityState::Unknown,
    );
    assert!(
        selection.winner.is_some(),
        "exactly at now + skew is admissible"
    );

    let selection = select_current(
        &alice_did(),
        std::slice::from_ref(&beyond),
        NOW,
        AuthorityState::Unknown,
    );
    assert!(
        selection.winner.is_none(),
        "one past the bound is premature"
    );

    // A premature RootRevoked record must not activate the transition yet.
    let premature_revoked = make_revoked(NOW + 300_001, None);
    let root = make_root(NOW - 1_000, None);
    let candidates = [root, premature_revoked];
    let selection = select_current(&alice_did(), &candidates, NOW, AuthorityState::Unknown);
    assert_eq!(
        selection.winner.expect("winner").authority(),
        Authority::Root,
        "a premature RootRevoked record is not currently admissible"
    );
    assert_eq!(selection.authority_state, AuthorityState::Root);
}

#[test]
fn sec_8_3_later_timestamp_wins_within_root_revoked_state() {
    let older = make_revoked(NOW - 20_000, None);
    let newer = make_revoked(NOW - 10_000, None);
    let candidates = [older, newer.clone()];
    let selection = select_current(&alice_did(), &candidates, NOW, AuthorityState::RootRevoked);
    assert_eq!(
        selection.winner.expect("winner").body_digest(),
        newer.body_digest()
    );
}

#[test]
fn duplicate_candidates_select_the_same_record() {
    let record = make_root(NOW - 1_000, None);
    let candidates = [record.clone(), record.clone(), record.clone()];
    let selection = select_current(&alice_did(), &candidates, NOW, AuthorityState::Unknown);
    assert_eq!(
        selection.winner.expect("winner").body_digest(),
        record.body_digest()
    );
}

#[test]
fn sign_record_refuses_incoherent_authority_and_key_presence() {
    // Root body carrying a revocation key must be refused at signing, not
    // silently encoded (RecordBody::validate is load-bearing for authoring).
    let body = RecordBody {
        revocation_key: Some(fx32("revocation_public_key")),
        ..b4_body()
    };
    assert!(matches!(
        sign_record(&body, &root_seed()),
        Err(followee::record::SignError::InvalidBody(_))
    ));

    // RootRevoked body without the revealed key is equally refused.
    let body = RecordBody {
        authority: Authority::RootRevoked,
        revocation_key: None,
        ..b4_body()
    };
    assert!(matches!(
        sign_record(&body, &revocation_seed()),
        Err(followee::record::SignError::InvalidBody(_))
    ));
}

#[test]
fn authoring_accepts_at_limit_sizes_and_rejects_just_over() {
    use followee::contact::ExtensionValue;

    // Contact document at exactly 12 KiB through the authoring path.
    let sized_body = |pad: usize| {
        let mut body = b4_body();
        body.contact.extensions.insert(
            "https://example.com/pad".to_owned(),
            ExtensionValue::Bytes(vec![0x41; pad]),
        );
        body
    };
    let probe = sized_body(0)
        .contact
        .encode(Some(b4_body().id.as_str()))
        .expect("encodes")
        .len();
    let body = sized_body(12 * 1024 - probe - 2);
    assert_eq!(
        body.contact
            .encode(Some(body.id.as_str()))
            .expect("encodes")
            .len(),
        12 * 1024
    );
    assert!(
        sign_record(&body, &root_seed()).is_ok(),
        "contact at cap signs"
    );
    let over = sized_body(12 * 1024 - probe - 1);
    assert!(
        sign_record(&over, &root_seed()).is_err(),
        "one byte over is refused"
    );

    // Envelope near 16 KiB through the authoring path, using record-level
    // extensions so the contact cap is not the operative limit.
    let sized_record = |pad: usize| {
        let mut body = b4_body();
        body.extensions.insert(
            "https://example.com/pad".to_owned(),
            ExtensionValue::Bytes(vec![0x41; pad]),
        );
        body
    };
    let probe = sign_record(&sized_record(0), &root_seed())
        .expect("signs")
        .len();
    let guess = 16 * 1024 - probe - 8;
    let measured = sign_record(&sized_record(guess), &root_seed())
        .expect("signs")
        .len();
    let body = sized_record(guess + (16 * 1024 - measured));
    let envelope = sign_record(&body, &root_seed()).expect("at-cap envelope signs");
    assert_eq!(envelope.len(), 16 * 1024, "exactly at the envelope cap");
    let over = sized_record(16 * 1024 - probe + 8);
    assert!(matches!(
        sign_record(&over, &root_seed()),
        Err(followee::record::SignError::RecordTooLarge)
    ));
}
