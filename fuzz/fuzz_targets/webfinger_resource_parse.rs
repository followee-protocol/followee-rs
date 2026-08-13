//! Fuzzes the handle authority's untrusted query-string parsing and the
//! handle grammar (section 10.1 local part plus IDNA domain processing):
//! no panic, no hang, no unbounded allocation for arbitrary input.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = followee::webfinger::authority::parse_resource_query(text);
        let _ = followee::webfinger::Handle::parse(text);
        let _ = followee::webfinger::Handle::from_acct_uri(text);
    }
});
