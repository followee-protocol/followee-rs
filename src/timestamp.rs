//! Timestamp ordering rules: signer algorithm, future bound, and freshness
//! (specification sections 5.3–5.5).

/// The v1 future-skew bound in milliseconds (specification section 5.4).
pub const MAX_FUTURE_SKEW_MS: u64 = 300_000;

/// Recipient-side time admission classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeStatus {
    /// The timestamp is within the recipient's future bound.
    Admissible,
    /// The timestamp exceeds `now + MAX_FUTURE_SKEW_MS`; the record is not
    /// currently admissible but is not cryptographically invalid.
    Premature,
}

/// Classifies a record timestamp against the recipient's clock using
/// overflow-safe comparison (specification section 5.4).
#[must_use]
pub fn time_status(record_timestamp_ms: u64, now_ms: u64) -> TimeStatus {
    match now_ms.checked_add(MAX_FUTURE_SKEW_MS) {
        Some(bound) if record_timestamp_ms > bound => TimeStatus::Premature,
        // A recipient clock so late that the bound overflows u64 admits
        // every representable timestamp.
        _ => TimeStatus::Admissible,
    }
}

/// Freshness of an admissible record (specification section 5.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Freshness {
    /// No `validUntil_ms`, or it has not passed.
    Fresh,
    /// `validUntil_ms` has passed. Staleness affects freshness and
    /// presentation, not signature authenticity or revocation activation.
    Stale,
}

/// Classifies freshness against the recipient's clock.
#[must_use]
pub fn freshness(valid_until_ms: Option<u64>, now_ms: u64) -> Freshness {
    match valid_until_ms {
        Some(valid_until) if now_ms > valid_until => Freshness::Stale,
        _ => Freshness::Fresh,
    }
}

/// Signer timestamp-selection failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TimestampError {
    /// `previous + 1` would overflow. A previously admitted timestamp cannot
    /// legitimately be near `u64::MAX` because it would have violated the
    /// future bound, so this indicates corrupt input.
    #[error("timestamp increment would overflow")]
    Overflow,
}

/// Computes the signer's next record timestamp: `max(now, previous + 1)` with
/// checked arithmetic (specification section 5.3). `previous` is the greatest
/// non-premature timestamp known to the signer, or `None` for a first record.
///
/// # Errors
///
/// Returns [`TimestampError::Overflow`] when `previous + 1` is not
/// representable.
pub fn next_timestamp(now_ms: u64, previous: Option<u64>) -> Result<u64, TimestampError> {
    match previous {
        None => Ok(now_ms),
        Some(prev) => {
            let bumped = prev.checked_add(1).ok_or(TimestampError::Overflow)?;
            Ok(now_ms.max(bumped))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sec_5_4_future_boundary_is_exact() {
        let now = 1_785_589_200_000;
        let bound = now + MAX_FUTURE_SKEW_MS;
        assert_eq!(time_status(bound - 1, now), TimeStatus::Admissible);
        assert_eq!(time_status(bound, now), TimeStatus::Admissible);
        assert_eq!(time_status(bound + 1, now), TimeStatus::Premature);
    }

    #[test]
    fn sec_5_4_comparison_is_overflow_safe() {
        // A recipient clock near u64::MAX must not wrap the bound.
        assert_eq!(time_status(u64::MAX, u64::MAX), TimeStatus::Admissible);
        assert_eq!(time_status(0, u64::MAX - 1), TimeStatus::Admissible);
        // u64::MAX as a record timestamp against a sane clock is premature.
        assert_eq!(
            time_status(u64::MAX, 1_785_589_200_000),
            TimeStatus::Premature
        );
    }

    #[test]
    fn sec_5_5_freshness_boundary() {
        assert_eq!(freshness(None, u64::MAX), Freshness::Fresh);
        assert_eq!(freshness(Some(100), 100), Freshness::Fresh);
        assert_eq!(freshness(Some(100), 101), Freshness::Stale);
    }

    #[test]
    fn sec_5_3_signer_timestamp_rule() {
        assert_eq!(next_timestamp(1_000, None), Ok(1_000));
        assert_eq!(next_timestamp(1_000, Some(500)), Ok(1_000));
        assert_eq!(next_timestamp(1_000, Some(1_000)), Ok(1_001));
        assert_eq!(next_timestamp(1_000, Some(2_000)), Ok(2_001));
        assert_eq!(
            next_timestamp(1_000, Some(u64::MAX)),
            Err(TimestampError::Overflow)
        );
    }
}
