#![forbid(unsafe_code)]

//! Non-normative Rust implementation of the Followee DID method and relay
//! protocol.
//!
//! **Status: Milestone 3 (single relay) in progress.** This crate implements
//! the Followee v1 identifier, deterministic CBOR, COSE, strict Ed25519
//! verification, record schemas, signing, and ordering rules, plus the
//! single-relay protocol core: the [`store`] contract with memory and SQLite
//! backends, and the [`relay`] admission, resolve, changes, and HTTP/CBOR
//! surfaces. No resolver, synchronization-receiver, WebFinger, or CLI code
//! exists yet.
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
pub mod relay;
pub mod store;
pub mod timestamp;
pub mod verify;

pub use cose::sig_structure;

/// Validates that `bytes` is exactly one deterministic-profile CBOR item
/// (specification section 6.1) within the requested nesting-depth and
/// total-member limits, with no trailing bytes.
///
/// This is structural validation only: it checks well-formedness, RFC 8949
/// basic validity, and the deterministic encoding profile (definite lengths,
/// minimal encodings, bytewise map-key ordering, no tags, floats,
/// `undefined`, or reserved simples) under explicit limits. It performs
/// **no** Followee record-schema check; use [`verify::verify_record`] for
/// complete Identity Record verification.
///
/// Classification follows the section 6.1 layers and section 15.3
/// vocabulary: input that is not well-formed, or is well-formed but not
/// basically valid — duplicate map keys under generic-data-model key
/// equivalence, or invalid RFC 3629 UTF-8 — is
/// [`error::VerifyError::InvalidCbor`]; basically valid input with
/// non-minimal or indefinite encodings, misordered map keys, or
/// profile-forbidden items (tags, floats, `undefined`) is
/// [`error::VerifyError::NonDeterministicCbor`];
/// exceeding a requested limit is [`error::VerifyError::SchemaViolation`].
/// CBOR simple values other than `false`, `true`, `null`, and `undefined`
/// pass this structural validation in their shortest encodings
/// (specification v0.8.1 section 6.1.2): no v1 schema admits them, but that
/// is a section 6.1.3 schema classification produced by record verification,
/// not by this gate. Validation recurses through arrays and maps and stops
/// at byte-string boundaries; byte-string contents are opaque and never
/// reinterpreted as CBOR.
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

    /// Parses arbitrary bytes as each relay API request wrapper
    /// (specification section 12): must never panic, hang, or allocate
    /// unboundedly.
    pub fn parse_relay_request(bytes: &[u8]) {
        let _ = crate::relay::wire::parse_resolve_request(bytes);
        let _ = crate::relay::wire::parse_changes_request(bytes);
    }

    /// Decodes arbitrary bytes as an opaque changes cursor against a fixed
    /// generation.
    pub fn decode_cursor(bytes: &[u8]) {
        let _ = crate::relay::cursor::decode(bytes, &[0u8; 16]);
    }
}
