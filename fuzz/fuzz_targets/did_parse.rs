//! Fuzz target: `did:flw` parsing must never panic, hang, or over-allocate
//! for arbitrary input (IMPLEMENTATION.md section 11.5).
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = followee::did::FolloweeDid::parse(s);
    }
});
