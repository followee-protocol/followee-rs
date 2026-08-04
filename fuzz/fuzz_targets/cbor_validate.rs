//! Fuzz target: the strict deterministic CBOR validator must never panic,
//! hang, read out of bounds, or allocate unboundedly for arbitrary bytes.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = followee::fuzzing::validate_cbor(data);
});
