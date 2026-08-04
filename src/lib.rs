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

/// Entry points for fuzz targets only. Not part of the public API surface;
/// stability is not guaranteed.
#[doc(hidden)]
pub mod fuzzing {
    use crate::limits::{MAX_BODY_DEPTH, MAX_BODY_MEMBERS};

    /// Runs the strict deterministic CBOR validator over arbitrary bytes.
    pub fn validate_cbor(bytes: &[u8]) -> bool {
        crate::cbor::validate(bytes, MAX_BODY_DEPTH, MAX_BODY_MEMBERS).is_ok()
    }
}
