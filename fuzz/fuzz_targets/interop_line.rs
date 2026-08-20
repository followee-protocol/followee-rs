//! Fuzz target: the neutral interoperability interface line handler
//! (Milestone 6) must never panic, hang, or allocate unboundedly for an
//! arbitrary request line, and must answer every line with exactly one
//! well-formed response.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    followee::fuzzing::interop_handle_line(data);
});
