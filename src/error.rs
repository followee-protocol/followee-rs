//! Verification error vocabulary (specification section 15.3).

use crate::cbor::CborError;
use crate::did::DidError;

/// Symbolic verification error, mirroring the specification's classification.
///
/// `IdentityBindingMismatch` is the section 8.1 steps 7/9 error for any
/// failure of the identity-binding invariant
/// `body id = target = DID(authorityDescriptor)` (wire code `7`; named
/// `descriptorMismatch` before the specification v0.4 amendment).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum VerifyError {
    /// Envelope exceeds the 16 KiB hard cap.
    #[error("record exceeds the 16 KiB envelope limit")]
    RecordTooLarge,
    /// Input is not well-formed CBOR, or is well-formed but not basically
    /// valid under RFC 8949 (section 6.1.1), including invalid UTF-8 text
    /// strings and duplicate map keys.
    #[error("input is not well-formed or basically valid CBOR")]
    InvalidCbor,
    /// Basically valid CBOR that violates the section 6.1.2 deterministic or
    /// restricted Followee profile.
    #[error("encoding violates the deterministic CBOR profile")]
    NonDeterministicCbor,
    /// Parsed object violates its v1 schema or limits, including use of a
    /// well-formed, basically valid, deterministically encoded data-item
    /// type that the applicable schema does not admit (section 15.3 code 6,
    /// v0.8.1 wording).
    #[error("record violates the v1 schema or its limits")]
    SchemaViolation,
    /// DID syntax, multibase encoding, or multihash structure is malformed.
    #[error("DID syntax, multibase encoding, or multihash structure is malformed")]
    InvalidDid,
    /// A structurally well-formed multihash names an unsupported hash profile.
    #[error("hash profile is not supported by this version")]
    UnsupportedHash,
    /// Signature suite is not supported.
    #[error("signature suite is not supported")]
    UnsupportedSuite,
    /// Body `id`, target DID, and Authority Descriptor do not bind to the
    /// same identifier (section 8.1 steps 7 and 9).
    #[error("body id, target DID, and Authority Descriptor do not bind to the same identifier")]
    IdentityBindingMismatch,
    /// Revealed revocation key does not match the descriptor commitment or
    /// key profile.
    #[error("revealed revocation key does not match the descriptor commitment")]
    InvalidRevocationKey,
    /// COSE or Ed25519 verification fails.
    #[error("signature verification failed")]
    InvalidSignature,
}

impl VerifyError {
    /// The specification's symbolic error name.
    #[must_use]
    pub fn symbol(&self) -> &'static str {
        match self {
            VerifyError::RecordTooLarge => "recordTooLarge",
            VerifyError::InvalidCbor => "invalidCbor",
            VerifyError::NonDeterministicCbor => "nonDeterministicCbor",
            VerifyError::SchemaViolation => "schemaViolation",
            VerifyError::InvalidDid => "invalidDid",
            VerifyError::UnsupportedHash => "unsupportedHash",
            VerifyError::UnsupportedSuite => "unsupportedSuite",
            VerifyError::IdentityBindingMismatch => "identityBindingMismatch",
            VerifyError::InvalidRevocationKey => "invalidRevocationKey",
            VerifyError::InvalidSignature => "invalidSignature",
        }
    }

    /// The section 15.3 numeric wire error code.
    #[must_use]
    pub fn wire_code(&self) -> u64 {
        match self {
            VerifyError::InvalidDid => 0,
            VerifyError::UnsupportedHash => 1,
            VerifyError::UnsupportedSuite => 2,
            VerifyError::RecordTooLarge => 3,
            VerifyError::InvalidCbor => 4,
            VerifyError::NonDeterministicCbor => 5,
            VerifyError::SchemaViolation => 6,
            VerifyError::IdentityBindingMismatch => 7,
            VerifyError::InvalidRevocationKey => 8,
            VerifyError::InvalidSignature => 9,
        }
    }
}

/// The symbolic name for any section 15.3 wire error code, or `None` for a
/// code outside the v1 table. Used to render received per-DID and publish
/// error codes; never to reinterpret them.
#[must_use]
pub fn wire_error_symbol(code: u64) -> Option<&'static str> {
    Some(match code {
        0 => "invalidDid",
        1 => "unsupportedHash",
        2 => "unsupportedSuite",
        3 => "recordTooLarge",
        4 => "invalidCbor",
        5 => "nonDeterministicCbor",
        6 => "schemaViolation",
        7 => "identityBindingMismatch",
        8 => "invalidRevocationKey",
        9 => "invalidSignature",
        10 => "premature",
        11 => "rootRevoked",
        12 => "losingRecord",
        13 => "duplicate",
        14 => "policyRejected",
        15 => "rateLimited",
        16 => "responseTooLarge",
        17 => "temporarilyUnavailable",
        18 => "invalidCursor",
        19 => "internalError",
        _ => return None,
    })
}

impl From<CborError> for VerifyError {
    fn from(e: CborError) -> Self {
        match e {
            CborError::Invalid => VerifyError::InvalidCbor,
            CborError::NonDeterministic => VerifyError::NonDeterministicCbor,
            CborError::LimitExceeded => VerifyError::SchemaViolation,
        }
    }
}

impl From<DidError> for VerifyError {
    fn from(e: DidError) -> Self {
        match e {
            DidError::InvalidDid => VerifyError::InvalidDid,
            DidError::UnsupportedHash => VerifyError::UnsupportedHash,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sec_15_3_wire_error_symbol_table_is_exhaustive_and_exact() {
        let table: [(u64, &str); 20] = [
            (0, "invalidDid"),
            (1, "unsupportedHash"),
            (2, "unsupportedSuite"),
            (3, "recordTooLarge"),
            (4, "invalidCbor"),
            (5, "nonDeterministicCbor"),
            (6, "schemaViolation"),
            (7, "identityBindingMismatch"),
            (8, "invalidRevocationKey"),
            (9, "invalidSignature"),
            (10, "premature"),
            (11, "rootRevoked"),
            (12, "losingRecord"),
            (13, "duplicate"),
            (14, "policyRejected"),
            (15, "rateLimited"),
            (16, "responseTooLarge"),
            (17, "temporarilyUnavailable"),
            (18, "invalidCursor"),
            (19, "internalError"),
        ];
        for (code, symbol) in table {
            assert_eq!(wire_error_symbol(code), Some(symbol), "code {code}");
        }
        assert_eq!(wire_error_symbol(20), None, "codes outside the v1 table");
        assert_eq!(wire_error_symbol(u64::MAX), None);
    }

    #[test]
    fn sec_15_3_symbols_and_wire_codes_are_exhaustive_and_exact() {
        let table: [(VerifyError, &str, u64); 10] = [
            (VerifyError::InvalidDid, "invalidDid", 0),
            (VerifyError::UnsupportedHash, "unsupportedHash", 1),
            (VerifyError::UnsupportedSuite, "unsupportedSuite", 2),
            (VerifyError::RecordTooLarge, "recordTooLarge", 3),
            (VerifyError::InvalidCbor, "invalidCbor", 4),
            (VerifyError::NonDeterministicCbor, "nonDeterministicCbor", 5),
            (VerifyError::SchemaViolation, "schemaViolation", 6),
            // Renamed from descriptorMismatch by the v0.4 amendment; code 7
            // is unchanged.
            (
                VerifyError::IdentityBindingMismatch,
                "identityBindingMismatch",
                7,
            ),
            (VerifyError::InvalidRevocationKey, "invalidRevocationKey", 8),
            (VerifyError::InvalidSignature, "invalidSignature", 9),
        ];
        for (error, symbol, code) in table {
            assert_eq!(error.symbol(), symbol);
            assert_eq!(error.wire_code(), code);
        }
    }
}
