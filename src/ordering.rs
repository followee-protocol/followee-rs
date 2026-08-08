//! Deterministic candidate ordering, authority precedence, and sticky
//! root-revocation state (specification sections 8.2–8.3).

use crate::record::Authority;
use crate::timestamp::{TimeStatus, time_status};
use crate::verify::VerifiedRecord;
use std::cmp::Ordering;

/// Locally known authority state for one DID (specification section 11.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AuthorityState {
    /// Nothing verified locally yet.
    #[default]
    Unknown,
    /// Only Root records verified so far.
    Root,
    /// A RootRevoked record was verified; the state is sticky while retained.
    RootRevoked,
}

/// Compares two same-authority ordering keys — `(timestamp_ms, body digest)`
/// — under specification section 8.3: the greater timestamp wins; at an
/// equal timestamp the lexicographically lower 32-byte body digest wins.
/// `Ordering::Greater` means `a` wins. `Ordering::Equal` means the keys are
/// duplicates by body digest. This is the single section 8.3 comparison;
/// the relay's stored-metadata comparison and record selection both
/// delegate to it.
#[must_use]
pub fn compare_ordering_keys(
    a_timestamp_ms: u64,
    a_digest: &[u8; 32],
    b_timestamp_ms: u64,
    b_digest: &[u8; 32],
) -> Ordering {
    match a_timestamp_ms.cmp(&b_timestamp_ms) {
        // Lower digest wins, so reverse the byte comparison.
        Ordering::Equal => b_digest.cmp(a_digest),
        other => other,
    }
}

/// Compares two records within the same authority state: the greater
/// admissible timestamp wins; at an equal timestamp the lexicographically
/// lower 32-byte body digest wins. `Ordering::Greater` means `a` wins.
/// `Ordering::Equal` means the records are duplicates by body digest.
#[must_use]
pub fn compare_precedence(a: &VerifiedRecord, b: &VerifiedRecord) -> Ordering {
    compare_ordering_keys(
        a.timestamp_ms(),
        a.body_digest(),
        b.timestamp_ms(),
        b.body_digest(),
    )
}

/// The result of a selection pass.
#[derive(Debug)]
pub struct Selection<'a> {
    /// The winning admissible record, if any candidate survived.
    pub winner: Option<&'a VerifiedRecord>,
    /// The updated local authority state, including sticky revocation.
    pub authority_state: AuthorityState,
}

/// Selects the winning admissible record for `target` from verified
/// candidates, applying premature exclusion, absolute RootRevoked precedence,
/// sticky state, and deterministic ordering. The result is independent of
/// candidate order.
///
/// Selection is defined per identity, so the subject is an explicit
/// parameter: candidates verified for a different DID are ignored, and a
/// mixed-identity input cannot change the selected subject.
///
/// `sticky` is the caller's retained authority state for `target`; a
/// returned `RootRevoked` state must be persisted by the caller to remain
/// sticky.
#[must_use]
pub fn select_current<'a>(
    target: &crate::did::FolloweeDid,
    candidates: &'a [VerifiedRecord],
    now_ms: u64,
    sticky: AuthorityState,
) -> Selection<'a> {
    let admissible = || {
        candidates.iter().filter(|c| {
            c.body().id == *target
                && time_status(c.timestamp_ms(), now_ms) == TimeStatus::Admissible
        })
    };

    // A stale RootRevoked record still activates the transition; staleness is
    // deliberately not consulted here (specification section 8.2).
    let revoked_seen = admissible().any(|c| c.authority() == Authority::RootRevoked);
    let state_revoked = sticky == AuthorityState::RootRevoked || revoked_seen;

    if state_revoked {
        let winner = admissible()
            .filter(|c| c.authority() == Authority::RootRevoked)
            .max_by(|a, b| compare_precedence(a, b));
        return Selection {
            winner,
            authority_state: AuthorityState::RootRevoked,
        };
    }

    let winner = admissible()
        .filter(|c| c.authority() == Authority::Root)
        .max_by(|a, b| compare_precedence(a, b));
    let authority_state = if winner.is_some() {
        AuthorityState::Root
    } else {
        sticky
    };
    Selection {
        winner,
        authority_state,
    }
}
