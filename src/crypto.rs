//! Cryptographic primitives: SHA-256, Ed25519 signing, and the sole
//! Followee-strict Ed25519 verification entry point.
//!
//! [`verify_followee_ed25519`] is the only production signature-verification
//! routine in this crate (IMPLEMENTATION.md section 6.2). Record verification
//! reaches Ed25519 exclusively through it; direct calls to library
//! verification entry points are rejected mechanically by `clippy.toml`.

use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::IsIdentity;
use sha2::{Digest, Sha256, Sha512};

/// Domain-separation prefix for the Authority Descriptor digest
/// (specification section 3.4), including the terminal zero byte.
pub const DESCRIPTOR_HASH_PREFIX: &[u8] = b"Followee/AuthorityDescriptor/v1\0";

/// Domain-separation prefix for the revocation-key commitment (specification
/// section 3.4), including the terminal zero byte.
pub const REVOCATION_COMMITMENT_PREFIX: &[u8] = b"Followee/RevocationKey/v1\0";

/// COSE external additional authenticated data for Identity Records
/// (specification section 3.4). No terminal zero byte.
pub const RECORD_AAD: &[u8] = b"Followee/IdentityRecord/v1";

/// SHA-256 of `data`.
#[must_use]
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

/// SHA-256 over a domain-separation prefix followed by `data`.
#[must_use]
pub fn sha256_domain(prefix: &[u8], data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(prefix);
    h.update(data);
    h.finalize().into()
}

/// Derives the 32-byte Ed25519 public key for a 32-byte private seed.
#[must_use]
pub fn ed25519_public_key(seed: &[u8; 32]) -> [u8; 32] {
    ed25519_dalek::SigningKey::from_bytes(seed)
        .verifying_key()
        .to_bytes()
}

/// Signs `message` with pure Ed25519 (RFC 8032, deterministic) under `seed`.
///
/// Signing is used by authoring paths and fixture construction. It performs no
/// Followee schema validation; callers are responsible for signing only
/// deterministic, schema-valid material.
#[must_use]
pub fn ed25519_sign(seed: &[u8; 32], message: &[u8]) -> [u8; 64] {
    use ed25519_dalek::Signer;
    ed25519_dalek::SigningKey::from_bytes(seed)
        .sign(message)
        .to_bytes()
}

/// Decompresses a 32-byte point encoding, requiring canonical form.
///
/// Canonicality is proven by recompression: curve25519-dalek accepts
/// non-canonical field encodings (y ≥ p) during decompression, so the
/// round-trip comparison is what enforces specification section 3.3 rule 3.
fn decompress_canonical(bytes: &[u8; 32]) -> Option<EdwardsPoint> {
    let point = CompressedEdwardsY(*bytes).decompress()?;
    if point.compress().to_bytes() == *bytes {
        Some(point)
    } else {
        None
    }
}

/// The sole production Followee-strict Ed25519 verification entry point.
///
/// Enforces every specification section 3.3 requirement:
///
/// 1. the public key is exactly 32 bytes (by type);
/// 2. the signature is exactly 64 bytes (by type);
/// 3. the public key encoding and the signature's encoded `R` point are
///    canonical (proven by recompression);
/// 4. the scalar `S` is less than the Ed25519 group order `L`;
/// 5. the public key decodes to a non-identity point in the prime-order
///    subgroup;
/// 6. `R` decodes to a point in the prime-order subgroup; and
/// 7. the uncofactored verification equation `[S]B = R + [k]A` holds.
///
/// Verification operates on public data, so variable-time arithmetic is
/// acceptable and used.
#[must_use]
pub fn verify_followee_ed25519(
    public_key: &[u8; 32],
    message: &[u8],
    signature: &[u8; 64],
) -> bool {
    let r_bytes: [u8; 32] = match signature[..32].try_into() {
        Ok(b) => b,
        Err(_) => return false,
    };
    let s_bytes: [u8; 32] = match signature[32..].try_into() {
        Ok(b) => b,
        Err(_) => return false,
    };

    // Rule 4: S < L. `from_canonical_bytes` rejects any non-reduced scalar.
    let Some(s) = Option::<Scalar>::from(Scalar::from_canonical_bytes(s_bytes)) else {
        return false;
    };

    // Rules 3 and 6: canonical R in the prime-order subgroup.
    let Some(r_point) = decompress_canonical(&r_bytes) else {
        return false;
    };
    if !r_point.is_torsion_free() {
        return false;
    }

    // Rules 3 and 5: canonical, non-identity public key in the prime-order
    // subgroup. `is_torsion_free` alone admits the identity, which is in the
    // prime-order subgroup, so the identity is excluded explicitly.
    let Some(a_point) = decompress_canonical(public_key) else {
        return false;
    };
    if a_point.is_identity() || !a_point.is_torsion_free() {
        return false;
    }

    // k = SHA-512(R || A || M) reduced modulo L (RFC 8032, pure Ed25519).
    let mut h = Sha512::new();
    h.update(r_bytes);
    h.update(public_key);
    h.update(message);
    let wide: [u8; 64] = h.finalize().into();
    let k = Scalar::from_bytes_mod_order_wide(&wide);

    // Rule 7, rearranged: [S]B - [k]A == R, computed uncofactored.
    // Scalar negation is arithmetic modulo the group order L; it cannot
    // overflow or wrap in the integer sense the lint guards against.
    #[allow(clippy::arithmetic_side_effects)]
    let neg_k = -k;
    let check = EdwardsPoint::vartime_double_scalar_mul_basepoint(&neg_k, &a_point, &s);
    check == r_point
}

/// [`verify_followee_ed25519`] over unsized byte slices: the production
/// entry point for callers whose inputs arrive with unconstrained lengths,
/// such as the neutral `strictEd25519` interoperability operation.
///
/// Specification section 3.3 rules 1 and 2 (exact 32-byte public key, exact
/// 64-byte signature) are enforced here by classification: any other length
/// is an invalid signature input and verification fails. Every remaining
/// rule is enforced by the sole strict entry point this function delegates
/// to.
#[must_use]
pub fn verify_followee_ed25519_unsized(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> bool {
    let Ok(public_key) = <&[u8; 32]>::try_from(public_key) else {
        return false;
    };
    let Ok(signature) = <&[u8; 64]>::try_from(signature) else {
        return false;
    };
    verify_followee_ed25519(public_key, message, signature)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::arithmetic_side_effects)]

    use super::*;

    // RFC 8032 test vector 1 (empty message).
    const RFC8032_SEED_1: [u8; 32] = [
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c,
        0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae,
        0x7f, 0x60,
    ];

    #[test]
    fn signs_and_verifies_rfc8032_vector_1() {
        let public = ed25519_public_key(&RFC8032_SEED_1);
        assert_eq!(
            public,
            [
                0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64,
                0x07, 0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68,
                0xf7, 0x07, 0x51, 0x1a
            ]
        );
        let sig = ed25519_sign(&RFC8032_SEED_1, b"");
        assert!(verify_followee_ed25519(&public, b"", &sig));
        assert!(!verify_followee_ed25519(&public, b"x", &sig));
    }

    #[test]
    fn rejects_flipped_signature_bit() {
        let public = ed25519_public_key(&RFC8032_SEED_1);
        let mut sig = ed25519_sign(&RFC8032_SEED_1, b"followee");
        sig[0] ^= 0x01;
        assert!(!verify_followee_ed25519(&public, b"followee", &sig));
    }

    #[test]
    fn rejects_identity_public_key() {
        // The canonical encoding of the identity point (y = 1).
        let mut identity = [0u8; 32];
        identity[0] = 0x01;
        let sig = [0u8; 64];
        assert!(!verify_followee_ed25519(&identity, b"m", &sig));
    }

    #[test]
    fn rejects_identity_key_trivial_forgery() {
        // With A = identity, R = identity, S = 0 the verification equation
        // [S]B = R + [k]A holds trivially for EVERY message. The identity is
        // torsion-free, so only the explicit non-identity check (rule 5)
        // stops this universal forgery.
        let mut identity = [0u8; 32];
        identity[0] = 0x01;
        let mut sig = [0u8; 64];
        sig[..32].copy_from_slice(&identity); // R = identity, S = 0
        assert!(!verify_followee_ed25519(&identity, b"any message", &sig));
        assert!(!verify_followee_ed25519(&identity, b"another", &sig));
    }

    #[test]
    fn rejects_small_order_public_key() {
        // Canonical encoding of an order-8 torsion point.
        let public = curve25519_dalek::constants::EIGHT_TORSION[1]
            .compress()
            .to_bytes();
        let sig = ed25519_sign(&RFC8032_SEED_1, b"m");
        assert!(!verify_followee_ed25519(&public, b"m", &sig));
    }

    #[test]
    fn rejects_non_canonical_public_key_encoding() {
        // y = p is a non-canonical encoding of y = 0; more simply, take a
        // valid key and produce the non-canonical equivalent by adding p to
        // its y-coordinate where that stays under 2^255. Deterministic cheap
        // variant: 2^255 - 19 + 1 = encoding of y = 1 (identity) plus p.
        // p = 2^255 - 19, so y = 1 non-canonically encodes as p + 1.
        let mut non_canonical = [0xffu8; 32];
        non_canonical[0] = 0xee; // little-endian p + 1
        non_canonical[31] = 0x7f;
        let sig = [0u8; 64];
        assert!(!verify_followee_ed25519(&non_canonical, b"m", &sig));
    }
}
