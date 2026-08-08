//! Fuzz target: relay API CBOR request parsing (specification section 12)
//! must never panic, hang, read out of bounds, or allocate unboundedly for
//! arbitrary bytes.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    followee::fuzzing::parse_relay_request(data);
});
