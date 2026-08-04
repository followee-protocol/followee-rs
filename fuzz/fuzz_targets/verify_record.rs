//! Fuzz target: complete envelope verification (COSE parsing, deterministic
//! CBOR validation, schema parsing, binding and signature checks) must never
//! panic or hang for arbitrary candidate bytes.
#![no_main]

use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

fn target() -> &'static followee::did::FolloweeDid {
    static TARGET: OnceLock<followee::did::FolloweeDid> = OnceLock::new();
    TARGET.get_or_init(|| {
        followee::did::FolloweeDid::parse(
            "did:flw:zQmPcGstBa7wW9hoYQbS6JZ4UxwZmoKr7YVf9y7qxiyD3Cm",
        )
        .expect("test vector DID parses")
    })
}

fuzz_target!(|data: &[u8]| {
    let _ = followee::verify::verify_record(target(), data);
});
