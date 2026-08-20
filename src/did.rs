//! `did:flw` identifier parsing and derivation (specification section 3.1
//! and 4.3).

use crate::crypto;
use crate::limits::MAX_URI_BYTES;
use std::fmt;
use std::str::FromStr;

/// The lowercase method prefix.
pub const DID_PREFIX: &str = "did:flw:";

const MULTIHASH_SHA2_256: u64 = 0x12;
const DIGEST_LENGTH: u64 = 0x20;

/// Rejection classification for a `did:flw` identifier, following the
/// syntax-versus-profile split fixed by specification v0.3 section 3.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DidError {
    /// Syntax, multibase encoding, or multihash structure is malformed.
    #[error("DID syntax, multibase encoding, or multihash structure is malformed")]
    InvalidDid,
    /// A structurally well-formed multihash names a hash code or digest
    /// length unsupported by Followee v1.
    #[error("structurally well-formed multihash names an unsupported hash code or digest length")]
    UnsupportedHash,
}

/// A canonical, fully validated Followee v1 DID.
///
/// Construction is only possible through strict parsing or derivation from an
/// Authority Descriptor, so possession of a value proves canonical form.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FolloweeDid {
    text: String,
    /// The exact validated 34-byte multihash the method-specific identifier
    /// decodes to: `0x12 || 0x20 || digest` (specification section 3.1).
    multihash: [u8; 34],
}

impl FolloweeDid {
    /// Parses and validates a canonical v1 Followee DID.
    ///
    /// # Errors
    ///
    /// Returns [`DidError::InvalidDid`] for malformed syntax or encoding and
    /// [`DidError::UnsupportedHash`] for a structurally well-formed multihash
    /// outside the v1 `(sha2-256, 32)` profile.
    pub fn parse(s: &str) -> Result<Self, DidError> {
        // Bound work before decoding; a valid v1 DID is 55 characters.
        if s.len() > MAX_URI_BYTES {
            return Err(DidError::InvalidDid);
        }
        let msi = s.strip_prefix(DID_PREFIX).ok_or(DidError::InvalidDid)?;
        let b58 = msi.strip_prefix('z').ok_or(DidError::InvalidDid)?;
        if b58.is_empty() {
            return Err(DidError::InvalidDid);
        }
        let bytes = bs58::decode(b58)
            .into_vec()
            .map_err(|_| DidError::InvalidDid)?;

        // Structurally well-formed multihash: minimal code varint, minimal
        // length varint, exactly that many digest bytes, no trailing bytes.
        let (code, after_code) = read_minimal_varint(&bytes).ok_or(DidError::InvalidDid)?;
        let (length, after_len) =
            read_minimal_varint(bytes.get(after_code..).ok_or(DidError::InvalidDid)?)
                .ok_or(DidError::InvalidDid)?;
        let digest_start = after_code
            .checked_add(after_len)
            .ok_or(DidError::InvalidDid)?;
        let digest = bytes.get(digest_start..).ok_or(DidError::InvalidDid)?;
        if u64::try_from(digest.len()).map_err(|_| DidError::InvalidDid)? != length {
            return Err(DidError::InvalidDid);
        }

        if code != MULTIHASH_SHA2_256 || length != DIGEST_LENGTH {
            return Err(DidError::UnsupportedHash);
        }
        // The validated decode is exactly the 34-byte v1 multihash; retain
        // those exact bytes (IMPLEMENTATION.md section 11.8 finding I1).
        let multihash: [u8; 34] = bytes.try_into().map_err(|_| DidError::InvalidDid)?;

        // base58btc is a bijection, so the retained text is canonical.
        Ok(FolloweeDid {
            text: s.to_owned(),
            multihash,
        })
    }

    /// Derives the DID committed to by deterministic Authority Descriptor
    /// bytes (specification section 4.3).
    #[must_use]
    pub fn from_descriptor_bytes(descriptor: &[u8]) -> Self {
        let digest = crypto::sha256_domain(crypto::DESCRIPTOR_HASH_PREFIX, descriptor);
        let mut multihash = [0u8; 34];
        multihash[0] = 0x12;
        multihash[1] = 0x20;
        multihash[2..].copy_from_slice(&digest);
        let text = format!("{DID_PREFIX}z{}", bs58::encode(multihash).into_string());
        FolloweeDid { text, multihash }
    }

    /// The canonical textual form.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// The committed 32-byte descriptor digest.
    #[must_use]
    pub fn digest(&self) -> &[u8; 32] {
        self.multihash[2..]
            .try_into()
            .expect("a validated v1 multihash carries exactly 32 digest bytes")
    }

    /// The exact already-validated 34-byte DID multihash:
    /// `0x12 || 0x20 || digest` (specification sections 3.1 and 4.3).
    ///
    /// This is the narrow production accessor required by the Campaign 1
    /// finding I1 (IMPLEMENTATION.md section 11.8): interoperability
    /// adapters take these bytes from the validated value rather than
    /// re-parsing the DID or reconstructing the multihash themselves. The
    /// bytes are retained from strict parsing, or assembled once during
    /// derivation, and are identical for both construction paths of one
    /// canonical DID.
    #[must_use]
    pub fn multihash_bytes(&self) -> &[u8; 34] {
        &self.multihash
    }
}

impl fmt::Display for FolloweeDid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text)
    }
}

impl FromStr for FolloweeDid {
    type Err = DidError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        FolloweeDid::parse(s)
    }
}

/// Reads one minimally encoded unsigned varint; returns the value and the
/// number of bytes consumed. Bounded at nine bytes (u63 range suffices for
/// every registered multicodec).
fn read_minimal_varint(bytes: &[u8]) -> Option<(u64, usize)> {
    let mut value: u64 = 0;
    let mut shift: u32 = 0;
    for (i, &b) in bytes.iter().enumerate() {
        if i >= 9 {
            return None;
        }
        let group = u64::from(b & 0x7f);
        value |= group.checked_shl(shift)?;
        if b & 0x80 == 0 {
            // Minimality: a multi-byte varint must not end in a zero group.
            if i > 0 && b == 0 {
                return None;
            }
            return Some((value, i.checked_add(1)?));
        }
        shift = shift.checked_add(7)?;
        if shift > 63 {
            return None;
        }
    }
    None
}

#[cfg(test)]
mod tests {
    #![allow(clippy::arithmetic_side_effects)]

    use super::*;

    // Appendix B.3 vector.
    const ALICE: &str = "did:flw:zQmPcGstBa7wW9hoYQbS6JZ4UxwZmoKr7YVf9y7qxiyD3Cm";

    #[test]
    fn parses_the_appendix_b_did() {
        let did = FolloweeDid::parse(ALICE).expect("canonical DID parses");
        assert_eq!(did.as_str(), ALICE);
        assert_eq!(
            hex_upper(did.digest()),
            "12DC4B843D10C5CA7313AA2452DB61D661AFBE3943B3FDBEA43405C7028D1EB2"
        );
    }

    fn hex_upper(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02X}")).collect()
    }

    #[test]
    fn sec_3_1_rejects_malformed_syntax_as_invalid_did() {
        for s in [
            "",
            "did:flw:",
            "did:flw:Qm00",              // missing multibase prefix
            "did:FLW:zQmPcGstBa7wW9hoY", // uppercase method
            "did:flw:z",                 // empty base58
            "did:flw:z0OIl",             // characters outside the alphabet
            "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
        ] {
            assert_eq!(FolloweeDid::parse(s), Err(DidError::InvalidDid), "{s}");
        }
    }

    #[test]
    fn sec_3_1_rejects_oversized_input_before_decoding() {
        let long = format!("did:flw:z{}", "2".repeat(4096));
        assert_eq!(FolloweeDid::parse(&long), Err(DidError::InvalidDid));
    }

    #[test]
    fn display_matches_canonical_text() {
        let did = FolloweeDid::parse(ALICE).expect("parses");
        assert_eq!(format!("{did}"), ALICE);
    }

    #[test]
    fn sec_3_1_identity_multihash_code_zero_is_unsupported_hash() {
        // Code 0x00 (identity) with matching declared length is a
        // structurally well-formed single-byte varint: profile rejection,
        // not syntax rejection.
        let mut mh = vec![0x00, 0x03];
        mh.extend_from_slice(b"abc");
        let text = format!("{DID_PREFIX}z{}", bs58::encode(mh).into_string());
        assert_eq!(FolloweeDid::parse(&text), Err(DidError::UnsupportedHash));
    }

    #[test]
    fn sec_3_1_non_minimal_multibyte_code_varint_is_invalid_did() {
        // Code 0x12 spread over a three-byte varint ending in a zero group:
        // a lenient parser would accept a second, non-canonical text form of
        // an existing DID.
        let mut mh = vec![0x92, 0x80, 0x00, 0x20];
        mh.extend_from_slice(&[0u8; 32]);
        let text = format!("{DID_PREFIX}z{}", bs58::encode(mh).into_string());
        assert_eq!(FolloweeDid::parse(&text), Err(DidError::InvalidDid));
    }

    #[test]
    fn round_trips_derivation_and_parsing() {
        let did = FolloweeDid::from_descriptor_bytes(b"example descriptor bytes");
        let reparsed = FolloweeDid::parse(did.as_str()).expect("derived DID parses");
        assert_eq!(did, reparsed);
    }

    #[test]
    fn sec_4_3_multihash_accessor_returns_the_exact_validated_bytes() {
        // Appendix B.3 publishes Alice's exact multihash bytes; the I1
        // accessor must return them unchanged from strict parsing.
        let did = FolloweeDid::parse(ALICE).expect("parses");
        assert_eq!(
            hex_upper(did.multihash_bytes()),
            "122012DC4B843D10C5CA7313AA2452DB61D661AFBE3943B3FDBEA43405C7028D1EB2"
        );
        assert_eq!(did.multihash_bytes()[0], 0x12, "sha2-256 code");
        assert_eq!(did.multihash_bytes()[1], 0x20, "32-byte digest length");
        assert_eq!(&did.multihash_bytes()[2..], did.digest().as_slice());
    }

    #[test]
    fn sec_4_3_multihash_bytes_agree_between_parsing_and_derivation() {
        let derived = FolloweeDid::from_descriptor_bytes(b"example descriptor bytes");
        let parsed = FolloweeDid::parse(derived.as_str()).expect("parses");
        assert_eq!(derived.multihash_bytes(), parsed.multihash_bytes());
    }

    #[test]
    fn minimal_varint_rules() {
        assert_eq!(read_minimal_varint(&[0x12]), Some((0x12, 1)));
        assert_eq!(read_minimal_varint(&[0x80, 0x01]), Some((128, 2)));
        assert_eq!(read_minimal_varint(&[0x92, 0x00]), None); // non-minimal
        assert_eq!(read_minimal_varint(&[0x80]), None); // truncated
        assert_eq!(read_minimal_varint(&[]), None);
    }
}
