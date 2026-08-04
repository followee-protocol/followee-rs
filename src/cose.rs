//! Exact COSE Sign1 profile for Identity Records (specification section 6.2).
//!
//! The profile is byte-precise: tag 18, protected header exactly `a10132`,
//! empty unprotected map, attached payload, 64-byte signature, no trailing
//! bytes. This module is implemented directly over the strict CBOR codec
//! rather than a general COSE library (IMPLEMENTATION.md section 6.1).

use crate::cbor::{
    self, MAJOR_ARRAY, MAJOR_BSTR, MAJOR_MAP, MAJOR_NINT, MAJOR_SIMPLE, MAJOR_TAG, MAJOR_UINT,
    Reader, SIMPLE_NULL,
};
use crate::crypto::RECORD_AAD;
use crate::error::VerifyError;
use std::ops::Range;

/// The exact protected-header bytes: the deterministic encoding of `{1: -19}`.
pub const PROTECTED_HEADER: [u8; 3] = [0xa1, 0x01, 0x32];

const COSE_SIGN1_TAG: u64 = 18;

/// Extracted envelope parts. The payload range points into the original
/// received bytes, which remain the bytes verified.
pub(crate) struct EnvelopeParts {
    pub payload: Range<usize>,
    pub signature: [u8; 64],
}

/// Parses one complete tagged COSE Sign1 Identity Record envelope.
pub(crate) fn parse_envelope(bytes: &[u8]) -> Result<EnvelopeParts, VerifyError> {
    let mut r = Reader::new(bytes);

    let tag = r.read_head().map_err(VerifyError::from)?;
    if tag.major != MAJOR_TAG {
        // Parseable CBOR that is not tagged: the required tag 18 is missing.
        return Err(VerifyError::SchemaViolation);
    }
    if tag.arg != COSE_SIGN1_TAG {
        return Err(VerifyError::SchemaViolation);
    }

    let array = r.read_head().map_err(VerifyError::from)?;
    if array.major != MAJOR_ARRAY || array.arg != 4 {
        return Err(VerifyError::SchemaViolation);
    }

    // Protected header byte string.
    let protected_head = r.read_head().map_err(VerifyError::from)?;
    if protected_head.major != MAJOR_BSTR {
        return Err(VerifyError::SchemaViolation);
    }
    let protected = r
        .read_bytes_body(protected_head.arg)
        .map_err(VerifyError::from)?;
    if protected != PROTECTED_HEADER {
        return Err(classify_protected(protected));
    }

    // Unprotected header map: must be exactly the empty map.
    let unprotected = r.read_head().map_err(VerifyError::from)?;
    if unprotected.major != MAJOR_MAP || unprotected.arg != 0 {
        return Err(VerifyError::SchemaViolation);
    }

    // Attached payload byte string. A null payload is the detached form.
    let payload_head = r.read_head().map_err(VerifyError::from)?;
    if payload_head.major == MAJOR_SIMPLE && payload_head.arg == SIMPLE_NULL {
        return Err(VerifyError::SchemaViolation);
    }
    if payload_head.major != MAJOR_BSTR {
        return Err(VerifyError::SchemaViolation);
    }
    let payload_start = r.position();
    let payload = r
        .read_bytes_body(payload_head.arg)
        .map_err(VerifyError::from)?;
    let payload_range = payload_start
        ..payload_start
            .checked_add(payload.len())
            .ok_or(VerifyError::InvalidCbor)?;

    // 64-byte signature.
    let sig_head = r.read_head().map_err(VerifyError::from)?;
    if sig_head.major != MAJOR_BSTR {
        return Err(VerifyError::SchemaViolation);
    }
    let sig = r.read_bytes_body(sig_head.arg).map_err(VerifyError::from)?;
    let signature: [u8; 64] = sig.try_into().map_err(|_| VerifyError::SchemaViolation)?;

    if !r.is_at_end() {
        // No trailing bytes are permitted after the tagged COSE object.
        return Err(VerifyError::SchemaViolation);
    }

    Ok(EnvelopeParts {
        payload: payload_range,
        signature,
    })
}

/// Distinguishes an unsupported-but-well-formed algorithm header from a
/// malformed protected header.
fn classify_protected(protected: &[u8]) -> VerifyError {
    let mut r = Reader::new(protected);
    let Ok(head) = r.read_head() else {
        return VerifyError::SchemaViolation;
    };
    if head.major != MAJOR_MAP || head.arg != 1 {
        return VerifyError::SchemaViolation;
    }
    let Ok(key) = r.read_head() else {
        return VerifyError::SchemaViolation;
    };
    if key.major != MAJOR_UINT || key.arg != 1 {
        return VerifyError::SchemaViolation;
    }
    let Ok(value) = r.read_head() else {
        return VerifyError::SchemaViolation;
    };
    if !r.is_at_end() {
        return VerifyError::SchemaViolation;
    }
    match value.major {
        // A well-formed `{1: <other integer>}` names another signature
        // suite: unsupported, not malformed. The deprecated polymorphic
        // EdDSA value -8 lands here.
        MAJOR_UINT | MAJOR_NINT => VerifyError::UnsupportedSuite,
        _ => VerifyError::SchemaViolation,
    }
}

/// Builds the COSE `Sig_structure` bytes for a record-body payload
/// (specification section 6.2).
#[must_use]
pub fn sig_structure(payload: &[u8]) -> Vec<u8> {
    cbor::encode_with(|w| {
        w.array(4);
        w.tstr("Signature1");
        w.bstr(&PROTECTED_HEADER);
        w.bstr(RECORD_AAD);
        w.bstr(payload);
    })
}

/// Assembles a complete tagged envelope from payload bytes and a signature.
#[must_use]
pub(crate) fn assemble_envelope(payload: &[u8], signature: &[u8; 64]) -> Vec<u8> {
    cbor::encode_with(|w| {
        w.tag(COSE_SIGN1_TAG);
        w.array(4);
        w.bstr(&PROTECTED_HEADER);
        w.head(MAJOR_MAP, 0);
        w.bstr(payload);
        w.bstr(signature);
    })
}
