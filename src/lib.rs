#![forbid(unsafe_code)]

//! Non-normative Rust implementation of the Followee DID method and relay
//! protocol.
//!
//! **Status: Milestone 6 (external interoperability) in progress as the
//! maintained v0.9.2 Rust participant — not an independent implementation
//! and not yet interoperable.** This crate implements the Followee v1
//! identifier,
//! deterministic CBOR, COSE, strict Ed25519 verification, record schemas,
//! signing, and ordering rules; the [`cli`] module backing the `followee`
//! binary (identity creation, record signing and revocation, verification,
//! inspection, deterministic selection, JSON authoring, safe local
//! test-key storage, the network commands, and the handle commands); the
//! single-relay protocol core (the [`store`] contract with memory and
//! SQLite backends and the [`relay`] admission, resolve, changes, and
//! HTTP/CBOR surfaces); the strict bounded relay client
//! ([`relay::client`]); the current-state synchronization receiver with
//! persisted peer cursors ([`relay::sync`]); the multi-relay [`resolver`]
//! with shared traversal budgets and the three migration presentation
//! states; and WebFinger handle discovery, inverse verification, bootstrap,
//! and the minimal demonstration handle authority ([`webfinger`]); and
//! the neutral interoperability interface engine ([`interop`]) serving
//! every v0.9.2 INTERFACE.md operation through the production entry
//! points, behind `followee interop`.
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
pub mod cli;
pub mod clock;
pub mod contact;
mod cose;
pub mod crypto;
pub mod did;
pub mod error;
pub mod interop;
pub mod limits;
pub mod ordering;
pub mod random;
pub mod record;
pub mod relay;
pub mod resolver;
pub mod store;
pub mod timestamp;
pub mod verify;
pub mod webfinger;

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

    /// Parses arbitrary bytes as authoring-format contact JSON
    /// (IMPLEMENTATION.md section 7.5): must never panic, hang, or allocate
    /// unboundedly.
    pub fn parse_contact_json(bytes: &[u8]) {
        if let Ok(text) = std::str::from_utf8(bytes) {
            let _ = crate::cli::json::contact_from_json(text);
        }
    }

    /// Parses arbitrary bytes as each relay API request wrapper
    /// (specification section 12): must never panic, hang, or allocate
    /// unboundedly.
    pub fn parse_relay_request(bytes: &[u8]) {
        let _ = crate::relay::wire::parse_resolve_request(bytes);
        let _ = crate::relay::wire::parse_changes_request(bytes);
    }

    /// Parses arbitrary bytes as each client-side relay API response
    /// wrapper (specification section 12; Milestone 4): must never panic,
    /// hang, or allocate unboundedly, and byte strings must stay opaque.
    pub fn parse_relay_response(bytes: &[u8]) {
        let _ = crate::relay::wire::parse_info_response(bytes);
        let _ = crate::relay::wire::parse_resolve_response(bytes);
        let _ = crate::relay::wire::parse_directory_response(bytes);
        let _ = crate::relay::wire::parse_publish_response(bytes);
        let _ = crate::relay::wire::parse_changes_response(bytes, 1024);
    }

    /// Decodes arbitrary bytes as an opaque changes cursor against a fixed
    /// generation.
    pub fn decode_cursor(bytes: &[u8]) {
        let _ = crate::relay::cursor::decode(bytes, &[0u8; 16]);
    }

    /// Handles arbitrary bytes as one neutral interoperability interface
    /// request line (Milestone 6): must never panic, hang, or allocate
    /// unboundedly, and must produce exactly one response line.
    pub fn interop_handle_line(bytes: &[u8]) {
        if let Ok(text) = std::str::from_utf8(bytes) {
            let config = crate::interop::InteropConfig {
                implementation_commit: "fuzz".to_owned(),
            };
            let _ = crate::interop::handle_line(&config, text);
        }
    }
}
