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

/// Compares two records within the same authority state: the greater
/// admissible timestamp wins; at an equal timestamp the lexicographically
/// lower 32-byte body digest wins. `Ordering::Greater` means `a` wins.
/// `Ordering::Equal` means the records are duplicates by body digest.
#[must_use]
pub fn compare_precedence(a: &VerifiedRecord, b: &VerifiedRecord) -> Ordering {
    match a.timestamp_ms().cmp(&b.timestamp_ms()) {
        Ordering::Equal => {
            // Lower digest wins, so reverse the byte comparison.
            b.body_digest().cmp(a.body_digest())
        }
        other => other,
    }
}

/// The result of a selection pass.
#[derive(Debug)]
pub struct Selection<'a> {
    /// The winning admissible record, if any candidate survived.
    pub winner: Option<&'a VerifiedRecord>,
    /// The updated local authority state, including sticky revocation.
    pub authority_state: AuthorityState,
}

/// Selects the winning admissible record from verified candidates for one
/// DID, applying premature exclusion, absolute RootRevoked precedence, sticky
/// state, and deterministic ordering. The result is independent of candidate
/// order.
///
/// `sticky` is the caller's retained authority state; a returned
/// `RootRevoked` state must be persisted by the caller to remain sticky.
///
/// Records whose DID differs from the first candidate's DID are ignored:
/// selection is defined per identity.
#[must_use]
pub fn select_current<'a>(
    candidates: &'a [VerifiedRecord],
    now_ms: u64,
    sticky: AuthorityState,
) -> Selection<'a> {
    let subject = candidates.first().map(|c| c.body().id.clone());
    let admissible = || {
        candidates.iter().filter(|c| {
            Some(&c.body().id) == subject.as_ref()
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
