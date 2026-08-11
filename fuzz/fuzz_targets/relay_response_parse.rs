//! Fuzz target: client-side relay API CBOR response parsing (specification
//! section 12; Milestone 4) must never panic, hang, read out of bounds, or
//! allocate unboundedly for arbitrary bytes, and must keep carried byte
//! strings opaque.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    followee::fuzzing::parse_relay_response(data);
});
