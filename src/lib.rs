#![forbid(unsafe_code)]

//! Non-normative Rust implementation of the Followee DID method and relay
//! protocol.
//!
//! **Status: Milestone 1 (protocol core) in progress.** This crate implements
//! the Followee v1 identifier, deterministic CBOR, COSE, strict Ed25519
//! verification, record schemas, signing, and ordering rules. No relay,
//! resolver, HTTP, or storage code exists yet.
//!
//! The normative authority for protocol behaviour is the pinned Followee
//! specification in the `followee-protocol/followee` repository, not this
//! crate. Where this code and the specification disagree, the specification
//! governs. Specification ambiguities are recorded in `SPEC-QUESTIONS.md`
//! rather than silently resolved here.
//!
//! Do not use `did:flw` for production identities. The DID method is not
//! registered and this implementation has not passed conformance or
//! interoperability testing.

mod cbor;
pub mod clock;
pub mod contact;
mod cose;
pub mod crypto;
pub mod did;
pub mod error;
pub mod limits;
pub mod ordering;
pub mod random;
pub mod record;
pub mod timestamp;
pub mod verify;

pub use cose::sig_structure;

/// Validates that `bytes` is exactly one deterministic-profile CBOR item
/// (specification section 6.1) within the requested nesting-depth and
/// total-member limits, with no trailing bytes.
///
/// This is structural validation only: it checks the deterministic encoding
/// profile (definite lengths, minimal encodings, bytewise map-key ordering,
/// no duplicates, no tags, floats, `undefined`, or reserved simples, valid
/// UTF-8) under explicit limits. It performs **no** Followee record-schema
/// check; use [`verify::verify_record`] for complete Identity Record
/// verification.
///
/// Classification follows the section 15.3 vocabulary: malformed, truncated,
/// or unsupported structure is [`error::VerifyError::InvalidCbor`];
/// non-minimal or indefinite encodings and duplicate or misordered map keys
/// are [`error::VerifyError::NonDeterministicCbor`]; exceeding a requested
/// limit is [`error::VerifyError::SchemaViolation`].
///
/// Followee v1 defines no context requiring limits beyond
/// [`limits::MAX_BODY_DEPTH`] and [`limits::MAX_BODY_MEMBERS`]. Requested
/// limits above those maxima are rejected as
/// [`error::VerifyError::SchemaViolation`] before any parsing, which also
/// bounds the validator's recursion and work regardless of caller input.
///
/// # Errors
///
/// Returns the [`error::VerifyError`] classification described above.
pub fn validate_cbor(
    bytes: &[u8],
    max_depth: u32,
    max_members: u32,
) -> Result<(), error::VerifyError> {
    if max_depth > limits::MAX_BODY_DEPTH || max_members > limits::MAX_BODY_MEMBERS {
        return Err(error::VerifyError::SchemaViolation);
    }
    cbor::validate(bytes, max_depth, max_members).map_err(error::VerifyError::from)
}

/// Entry points for fuzz targets only. Not part of the public API surface;
/// stability is not guaranteed.
#[doc(hidden)]
pub mod fuzzing {
    use crate::limits::{MAX_BODY_DEPTH, MAX_BODY_MEMBERS};

    /// Runs the strict deterministic CBOR validator over arbitrary bytes,
    /// routed through the public wrapper so one structural gate exists.
    pub fn validate_cbor(bytes: &[u8]) -> bool {
        crate::validate_cbor(bytes, MAX_BODY_DEPTH, MAX_BODY_MEMBERS).is_ok()
    }
}
