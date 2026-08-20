//! Full-record verification (specification section 8.1).

use crate::cbor;
use crate::cose;
use crate::crypto;
use crate::did::FolloweeDid;
use crate::error::VerifyError;
use crate::limits::{MAX_BODY_DEPTH, MAX_BODY_MEMBERS, MAX_RECORD_BYTES};
use crate::record::{Authority, RecordBody, parse_record_body};
use std::ops::Range;

/// Internal signature-verifier seam. Production code always uses
/// [`FolloweeStrictVerifier`]; a spy implementation exists only for the
/// wiring tests required by IMPLEMENTATION.md section 6.2.
pub(crate) trait SignatureVerifier {
    fn verify(&self, public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool;
}

/// The production verifier: delegates to the sole strict entry point.
pub(crate) struct FolloweeStrictVerifier;

impl SignatureVerifier for FolloweeStrictVerifier {
    fn verify(&self, public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
        crypto::verify_followee_ed25519(public_key, message, signature)
    }
}

/// A record that has passed the complete section 8.1 verification algorithm
/// against its target DID.
///
/// Values are only constructible through [`verify_record`]; there is no way
/// to fabricate one (IMPLEMENTATION.md section 7.1). Time admission and
/// freshness are recipient-side classifications applied separately.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedRecord {
    envelope: Vec<u8>,
    payload: Range<usize>,
    body: RecordBody,
    body_digest: [u8; 32],
    wire_presence: crate::record::WirePresence,
}

impl VerifiedRecord {
    /// The verified record body.
    #[must_use]
    pub fn body(&self) -> &RecordBody {
        &self.body
    }

    /// The locally computed SHA-256 body digest (specification section 6.3).
    #[must_use]
    pub fn body_digest(&self) -> &[u8; 32] {
        &self.body_digest
    }

    /// The exact received envelope bytes.
    #[must_use]
    pub fn envelope_bytes(&self) -> &[u8] {
        &self.envelope
    }

    /// The exact received record-body payload bytes.
    #[must_use]
    pub fn payload_bytes(&self) -> &[u8] {
        &self.envelope[self.payload.clone()]
    }

    /// The record's authority state.
    #[must_use]
    pub fn authority(&self) -> Authority {
        self.body.authority
    }

    /// The record's ordering timestamp.
    #[must_use]
    pub fn timestamp_ms(&self) -> u64 {
        self.body.timestamp_ms
    }

    /// Wire presence of the record's optional collection-valued fields, as
    /// observed by the production parser: absent and present-empty are
    /// distinct wire encodings (specification sections 5.2 and 7.1) that
    /// the typed body merges, so faithful projections consume this record
    /// of which encoding was received.
    #[must_use]
    pub fn wire_presence(&self) -> crate::record::WirePresence {
        self.wire_presence
    }
}

/// Verifies one complete candidate envelope against the expected target DID,
/// performing every specification section 8.1 check.
///
/// # Errors
///
/// Returns the [`VerifyError`] classifying the first failed check. For
/// single-fault inputs the classification is order-independent.
pub fn verify_record(
    target: &FolloweeDid,
    candidate: &[u8],
) -> Result<VerifiedRecord, VerifyError> {
    verify_record_with_verifier(target, candidate, &FolloweeStrictVerifier)
}

/// Verifies a candidate for a target given as text, performing section 8.1
/// step 6 (target parsing and classification) first.
///
/// # Errors
///
/// Returns `invalidDid`/`unsupportedHash` for a bad target, otherwise as
/// [`verify_record`].
pub fn verify_record_for_target(
    target: &str,
    candidate: &[u8],
) -> Result<VerifiedRecord, VerifyError> {
    let target = FolloweeDid::parse(target)?;
    verify_record(&target, candidate)
}

pub(crate) fn verify_record_with_verifier(
    target: &FolloweeDid,
    candidate: &[u8],
    verifier: &impl SignatureVerifier,
) -> Result<VerifiedRecord, VerifyError> {
    // Step 1: reject an oversized envelope before deep parsing.
    if candidate.len() > MAX_RECORD_BYTES {
        return Err(VerifyError::RecordTooLarge);
    }

    // Steps 2–3: exactly one tagged COSE Sign1 object with the exact
    // profile, applying the section 6.1 well-formedness, basic-validity, and
    // deterministic-profile classifications. The payload byte string is
    // opaque at this boundary (section 6.1.1).
    let parts = cose::parse_envelope(candidate)?;
    let payload = &candidate[parts.payload.clone()];

    // Step 4: the payload is one basically valid, deterministic record body
    // with no trailing bytes, within depth and member limits. Validation
    // recurses through unknown extension values (duplicate keys and invalid
    // UTF-8 anywhere in the body are `invalidCbor`).
    cbor::validate(payload, MAX_BODY_DEPTH, MAX_BODY_MEMBERS)?;

    // Steps 5, 10, 15, 16: exact v1 schema, including the authority-dependent
    // presence of `revocationKey`, complete Contact Document validation, and
    // the `validUntil_ms >= timestamp_ms` rule. (Reordering relative to the
    // signature check is permitted for cheap independent checks; single-fault
    // classifications are unaffected.)
    let parsed = parse_record_body(payload)?;

    // Step 7: the signed body must name the target DID byte for byte.
    if parsed.id_text != target.as_str() {
        return Err(VerifyError::IdentityBindingMismatch);
    }

    // Step 9: the carried Authority Descriptor must reproduce the target DID.
    let descriptor_bytes = &payload[parsed.descriptor_range.clone()];
    let derived = crypto::sha256_domain(crypto::DESCRIPTOR_HASH_PREFIX, descriptor_bytes);
    if derived != *target.digest() {
        return Err(VerifyError::IdentityBindingMismatch);
    }

    // Steps 11–12: select the applicable key; for RootRevoked, the revealed
    // key's canonical encoding must reproduce the descriptor commitment.
    let signing_key = match parsed.authority {
        Authority::Root => parsed.descriptor.root_key,
        Authority::RootRevoked => {
            let range = parsed
                .revocation_key_range
                .clone()
                .ok_or(VerifyError::SchemaViolation)?;
            let revealed_bytes = &payload[range];
            let commitment =
                crypto::sha256_domain(crypto::REVOCATION_COMMITMENT_PREFIX, revealed_bytes);
            if commitment != parsed.descriptor.revocation_commitment {
                return Err(VerifyError::InvalidRevocationKey);
            }
            parsed.revocation_key.ok_or(VerifyError::SchemaViolation)?
        }
    };

    // Step 13: the protected COSE algorithm equals the key suite. Both are
    // fixed to -19 by the envelope profile and public-key schema, so equality
    // holds by construction here.

    // Step 14: strict Ed25519 verification over the COSE Sig_structure.
    let message = cose::sig_structure(payload);
    if !verifier.verify(&signing_key, &message, &parts.signature) {
        return Err(VerifyError::InvalidSignature);
    }

    // Step 18: locally computed body digest.
    let body_digest = crypto::sha256(payload);

    Ok(VerifiedRecord {
        envelope: candidate.to_vec(),
        payload: parts.payload,
        body: RecordBody {
            id: target.clone(),
            timestamp_ms: parsed.timestamp_ms,
            authority: parsed.authority,
            descriptor: parsed.descriptor,
            revocation_key: parsed.revocation_key,
            valid_until_ms: parsed.valid_until_ms,
            contact: parsed.contact,
            extensions: parsed.extensions,
        },
        body_digest,
        wire_presence: parsed.presence,
    })
}

#[cfg(test)]
mod wiring_tests {
    //! IMPLEMENTATION.md section 6.2 wiring tests: the complete parsed
    //! positive envelopes delegate exactly once to the injected verifier with
    //! the exact authority-applicable public key, exact reconstructed COSE
    //! `Sig_structure` bytes, and exact received 64-byte signature.
    #![allow(clippy::arithmetic_side_effects)]

    use super::*;
    use std::cell::RefCell;

    type SpyCall = ([u8; 32], Vec<u8>, [u8; 64]);

    struct SpyVerifier {
        calls: RefCell<Vec<SpyCall>>,
    }

    impl SpyVerifier {
        fn new() -> Self {
            SpyVerifier {
                calls: RefCell::new(Vec::new()),
            }
        }
    }

    impl SignatureVerifier for SpyVerifier {
        fn verify(&self, public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
            self.calls
                .borrow_mut()
                .push((*public_key, message.to_vec(), *signature));
            true
        }
    }

    fn fixture(name: &str) -> Vec<u8> {
        let manifest: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/fixtures/specification/appendix_b.json"
            ))
            .expect("fixture file present"),
        )
        .expect("fixture JSON parses");
        let hex = manifest[name].as_str().expect("fixture field present");
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("valid hex"))
            .collect()
    }

    fn expected_message(envelope: &[u8]) -> Vec<u8> {
        // Reconstruct the Sig_structure independently of the parser: the
        // payload of both Appendix B envelopes starts after the fixed
        // 7-byte prefix d2 84 43 a1 01 32 a0 plus the payload bstr head,
        // and ends before the trailing 2-byte signature head + 64 bytes.
        let head_len = 7;
        let (payload_head_len, sig_trailer) = (3, 66);
        let payload = &envelope[head_len + payload_head_len..envelope.len() - sig_trailer];
        cose::sig_structure(payload)
    }

    #[test]
    fn sec_6_2_b4_root_wiring_delegates_once_with_root_key() {
        let envelope = fixture("root_record_envelope");
        let target = FolloweeDid::parse("did:flw:zQmPcGstBa7wW9hoYQbS6JZ4UxwZmoKr7YVf9y7qxiyD3Cm")
            .expect("target parses");
        let spy = SpyVerifier::new();
        verify_record_with_verifier(&target, &envelope, &spy).expect("spy accepts");
        let calls = spy.calls.borrow();
        assert_eq!(calls.len(), 1, "exactly one delegation");
        let (key, message, signature) = &calls[0];
        assert_eq!(
            key.as_slice(),
            fixture("root_public_key").as_slice(),
            "descriptor root public key"
        );
        assert_eq!(message, &expected_message(&envelope), "exact Sig_structure");
        assert_eq!(
            signature.as_slice(),
            &envelope[envelope.len() - 64..],
            "exact received signature"
        );
    }

    #[test]
    fn sec_6_2_b5_root_revoked_wiring_delegates_once_with_revealed_key() {
        let envelope = fixture("root_revoked_envelope");
        let target = FolloweeDid::parse("did:flw:zQmPcGstBa7wW9hoYQbS6JZ4UxwZmoKr7YVf9y7qxiyD3Cm")
            .expect("target parses");
        let spy = SpyVerifier::new();
        verify_record_with_verifier(&target, &envelope, &spy).expect("spy accepts");
        let calls = spy.calls.borrow();
        assert_eq!(calls.len(), 1, "exactly one delegation");
        let (key, message, signature) = &calls[0];
        assert_eq!(
            key.as_slice(),
            fixture("revocation_public_key").as_slice(),
            "label 5 revealed revocation public key"
        );
        assert_eq!(message, &expected_message(&envelope), "exact Sig_structure");
        assert_eq!(
            signature.as_slice(),
            &envelope[envelope.len() - 64..],
            "exact received signature"
        );
    }
}
