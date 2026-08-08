//! Fuzz target: opaque cursor decoding (specification section 12.7) must
//! never panic or misbehave for arbitrary bytes.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    followee::fuzzing::decode_cursor(data);
});
