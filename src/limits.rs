//! Hard protocol limits from specification section 15.1.
//!
//! These are interoperability maxima, not tunable configuration. Operators may
//! impose stricter local quotas, but nothing in this crate may accept a value
//! beyond these bounds.

/// Maximum complete tagged COSE Identity Record, in bytes.
pub const MAX_RECORD_BYTES: usize = 16 * 1024;

/// Maximum encoded Contact Document within the record, in bytes.
pub const MAX_CONTACT_BYTES: usize = 12 * 1024;

/// Maximum record-body CBOR nesting depth.
pub const MAX_BODY_DEPTH: u32 = 8;

/// Maximum total record-body map and array members.
pub const MAX_BODY_MEMBERS: u32 = 256;

/// Maximum display name, in UTF-8 bytes.
pub const MAX_DISPLAY_NAME_BYTES: usize = 256;

/// Maximum summary, in UTF-8 bytes.
pub const MAX_SUMMARY_BYTES: usize = 2_048;

/// Maximum length of any URI, in UTF-8 bytes.
pub const MAX_URI_BYTES: usize = 2_048;

/// Maximum `alsoKnownAs` entries.
pub const MAX_ALSO_KNOWN_AS: usize = 32;

/// Maximum service entries.
pub const MAX_SERVICES: usize = 64;

/// Maximum service identifier, label, media type, or relation token, in bytes.
pub const MAX_SERVICE_TOKEN_BYTES: usize = 256;

/// Maximum BCP 47 language tag, in ASCII bytes.
pub const MAX_LANGUAGE_BYTES: usize = 64;

/// Maximum extension key, in UTF-8 bytes.
pub const MAX_EXTENSION_KEY_BYTES: usize = 256;
