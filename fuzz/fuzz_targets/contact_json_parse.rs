//! Fuzz target: the friendly contact-JSON authoring parser
//! (IMPLEMENTATION.md section 7.5) must never panic, hang, or allocate
//! unboundedly for arbitrary input.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    followee::fuzzing::parse_contact_json(data);
});
