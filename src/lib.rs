#![forbid(unsafe_code)]

//! Non-normative Rust implementation of the Followee DID method and relay
//! protocol.
//!
//! **Status: Milestone 0 scaffold.** No protocol behaviour — no DID handling,
//! CBOR, COSE, cryptography, verification, ordering, relay or resolver code —
//! is implemented yet. The only public modules are the injected [`clock`] and
//! [`random`] environment abstractions required before protocol work begins
//! (IMPLEMENTATION.md section 7.3).
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

pub mod clock;
pub mod random;
