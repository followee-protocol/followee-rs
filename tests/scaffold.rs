//! Black-box checks that the Milestone 0 public surface is usable by an
//! external caller: the injected environment abstractions can be named,
//! stored behind trait objects, and driven deterministically.

use followee::clock::{Clock, ManualClock, SystemClock};
use followee::random::{DeterministicRandom, OsRandom, RandomSource};

#[test]
fn clock_trait_objects_are_usable() {
    let manual = ManualClock::new(1_785_589_200_123);
    let clocks: [&dyn Clock; 2] = [&SystemClock, &manual];
    for clock in clocks {
        clock.now_ms().expect("scaffold clocks should read");
    }
    assert_eq!(manual.now_ms(), Ok(1_785_589_200_123));
}

#[test]
fn fuzzing_entry_point_matches_validator_behaviour() {
    assert!(followee::fuzzing::validate_cbor(&[0x00]));
    assert!(!followee::fuzzing::validate_cbor(&[0xff]));
    assert!(!followee::fuzzing::validate_cbor(&[]));
}

#[test]
fn random_trait_objects_are_usable() {
    let deterministic = DeterministicRandom::from_seed(0);
    let sources: [&dyn RandomSource; 2] = [&OsRandom, &deterministic];
    for source in sources {
        let mut buf = [0u8; 32];
        source.fill(&mut buf).expect("scaffold sources should fill");
    }
}
