//! Injected time source.
//!
//! Protocol code never reads the operating-system clock directly. Everything
//! that needs the current time — signer timestamp selection, the
//! `MAX_FUTURE_SKEW_MS` admission bound, staleness classification, relay
//! serve-time rechecks — receives a [`Clock`] so tests can drive time
//! deterministically instead of sleeping (IMPLEMENTATION.md sections 7.3
//! and 11.6).

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// Milliseconds since the Unix epoch, the protocol's `timestamp_ms` scale
/// (specification section 5.3).
pub type UnixMillis = u64;

/// Failure to read a usable current time.
///
/// A clock failure means the caller cannot make time-admission decisions; it
/// must propagate the error rather than substitute a guessed time.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum ClockError {
    /// The operating-system clock reports a time before the Unix epoch.
    #[error("system time is before the Unix epoch")]
    BeforeUnixEpoch,
    /// The operating-system clock reports a time whose millisecond value does
    /// not fit in `u64`.
    #[error("system time in milliseconds exceeds the representable u64 range")]
    BeyondRepresentableRange,
}

/// A source of the current Unix time in milliseconds.
pub trait Clock {
    /// Returns the current Unix time in milliseconds.
    ///
    /// # Errors
    ///
    /// Returns a [`ClockError`] when the underlying source cannot produce a
    /// representable non-negative Unix time.
    fn now_ms(&self) -> Result<UnixMillis, ClockError>;
}

/// Production clock backed by the operating-system real-time clock.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_ms(&self) -> Result<UnixMillis, ClockError> {
        let elapsed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ClockError::BeforeUnixEpoch)?;
        u64::try_from(elapsed.as_millis()).map_err(|_| ClockError::BeyondRepresentableRange)
    }
}

/// Deterministic clock for tests and tools.
///
/// Time changes only through [`set`](ManualClock::set) and
/// [`advance`](ManualClock::advance); it never follows the operating system.
/// Not intended for production use.
#[derive(Debug, Default)]
pub struct ManualClock {
    now_ms: AtomicU64,
}

impl ManualClock {
    /// Creates a clock reading `now_ms` milliseconds since the Unix epoch.
    #[must_use]
    pub fn new(now_ms: UnixMillis) -> Self {
        Self {
            now_ms: AtomicU64::new(now_ms),
        }
    }

    /// Sets the current time.
    pub fn set(&self, now_ms: UnixMillis) {
        self.now_ms.store(now_ms, Ordering::SeqCst);
    }

    /// Advances the current time by `delta_ms`.
    ///
    /// # Panics
    ///
    /// Panics if the advance would overflow `u64`; test clocks fail loudly
    /// instead of wrapping.
    pub fn advance(&self, delta_ms: u64) {
        self.now_ms
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |now| {
                now.checked_add(delta_ms)
            })
            .expect("ManualClock::advance overflowed u64 milliseconds");
    }
}

impl Clock for ManualClock {
    fn now_ms(&self) -> Result<UnixMillis, ClockError> {
        Ok(self.now_ms.load(Ordering::SeqCst))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // 2020-01-01T00:00:00Z; a sanity floor for the host clock.
    const MS_2020_01_01: u64 = 1_577_836_800_000;

    #[test]
    fn system_clock_reports_plausible_current_time() {
        let now = SystemClock.now_ms().expect("host clock should be readable");
        assert!(now >= MS_2020_01_01, "host clock reports {now} ms");
    }

    #[test]
    fn manual_clock_is_deterministic() {
        let clock = ManualClock::new(1_000);
        assert_eq!(clock.now_ms(), Ok(1_000));
        assert_eq!(clock.now_ms(), Ok(1_000));

        clock.advance(234);
        assert_eq!(clock.now_ms(), Ok(1_234));

        clock.set(500);
        assert_eq!(clock.now_ms(), Ok(500));
    }

    #[test]
    #[should_panic(expected = "overflowed")]
    fn manual_clock_advance_refuses_to_wrap() {
        let clock = ManualClock::new(u64::MAX);
        clock.advance(1);
    }
}
