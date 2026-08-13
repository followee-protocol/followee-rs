//! Fuzzes the strict bounded JRD/JSON parser with arbitrary bytes: it must
//! never panic, hang, allocate unboundedly, or read past its input, and it
//! must reject rather than silently normalize malformed input.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = followee::webfinger::jrd::parse_json(
        data,
        followee::webfinger::MAX_JRD_DEPTH,
        followee::webfinger::MAX_JRD_MEMBERS,
    );
});
