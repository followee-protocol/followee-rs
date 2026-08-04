//! Identity Record data model: Authority Descriptors, record bodies, and
//! signing (specification sections 4 and 5).

use crate::cbor::{self, MAJOR_BSTR, MAJOR_MAP, MAJOR_NINT, MAJOR_TSTR, MAJOR_UINT, Reader};
use crate::contact::{self, ContactDocument, ExtensionMap};
use crate::cose;
use crate::crypto;
use crate::did::FolloweeDid;
use crate::error::VerifyError;
use crate::limits::{
    MAX_BODY_DEPTH, MAX_BODY_MEMBERS, MAX_CONTACT_BYTES, MAX_RECORD_BYTES, MAX_URI_BYTES,
};
use std::ops::Range;

/// The v1 record protocol version.
pub const PROTOCOL_VERSION: u64 = 1;

/// The v1 Authority Descriptor version.
pub const DESCRIPTOR_VERSION: u64 = 1;

/// The fully specified Ed25519 COSE algorithm value (RFC 9864).
pub const SUITE_ED25519: i64 = -19;

// -19 encodes as a negative integer with magnitude 18.
const SUITE_ED25519_MAGNITUDE: u64 = 18;

/// Record authority state (specification section 8.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Authority {
    /// Signed by the descriptor's root key (`authority = 0`).
    Root,
    /// Signed by the revealed precommitted revocation key (`authority = 1`).
    RootRevoked,
}

impl Authority {
    /// The signed integer encoding of the authority state.
    #[must_use]
    pub fn wire_value(&self) -> u64 {
        match self {
            Authority::Root => 0,
            Authority::RootRevoked => 1,
        }
    }
}

/// The immutable v1 Authority Descriptor (specification section 4.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityDescriptor {
    /// The 32-byte Ed25519 root public key.
    pub root_key: [u8; 32],
    /// The 32-byte commitment to the canonical revocation-key encoding.
    pub revocation_commitment: [u8; 32],
}

impl AuthorityDescriptor {
    /// Deterministic CBOR encoding of the descriptor.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let key = |label: u64| cbor::encode_with(|w| w.uint(label));
        let entries = vec![
            (key(0), cbor::encode_with(|w| w.uint(DESCRIPTOR_VERSION))),
            (key(1), encode_public_key(&self.root_key)),
            (
                key(2),
                cbor::encode_with(|w| w.bstr(&self.revocation_commitment)),
            ),
        ];
        cbor::encode_with(|w| w.map_entries(entries))
    }

    /// Derives the Followee DID committed to by this descriptor.
    #[must_use]
    pub fn did(&self) -> FolloweeDid {
        FolloweeDid::from_descriptor_bytes(&self.encode())
    }
}

/// Canonical v1 `public-key` encoding: `{0: -19, 1: key}`.
#[must_use]
pub fn encode_public_key(key: &[u8; 32]) -> Vec<u8> {
    let label = |v: u64| cbor::encode_with(|w| w.uint(v));
    let entries = vec![
        (label(0), cbor::encode_with(|w| w.int(SUITE_ED25519))),
        (label(1), cbor::encode_with(|w| w.bstr(key))),
    ];
    cbor::encode_with(|w| w.map_entries(entries))
}

/// The revocation-key commitment (specification section 4.2): SHA-256 over
/// the domain-separation prefix and the canonical public-key encoding.
#[must_use]
pub fn revocation_commitment(revocation_public_key: &[u8; 32]) -> [u8; 32] {
    crypto::sha256_domain(
        crypto::REVOCATION_COMMITMENT_PREFIX,
        &encode_public_key(revocation_public_key),
    )
}

/// A complete Identity Record body (specification section 5.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordBody {
    /// The canonical Followee DID being updated.
    pub id: FolloweeDid,
    /// Ordering value in Unix milliseconds; not evidence of creation time.
    pub timestamp_ms: u64,
    /// Authority state.
    pub authority: Authority,
    /// The complete immutable Authority Descriptor.
    pub descriptor: AuthorityDescriptor,
    /// The revealed revocation public key; present exactly when
    /// `authority` is [`Authority::RootRevoked`].
    pub revocation_key: Option<[u8; 32]>,
    /// Optional freshness horizon; must be ≥ `timestamp_ms` when present.
    pub valid_until_ms: Option<u64>,
    /// The complete current Contact Document.
    pub contact: ContactDocument,
    /// Namespaced record extensions.
    pub extensions: ExtensionMap,
}

impl RecordBody {
    /// Validates the body's own schema coherence (not the identity binding,
    /// which requires the target DID).
    ///
    /// # Errors
    ///
    /// Returns [`VerifyError::SchemaViolation`] on any constraint failure.
    pub fn validate(&self) -> Result<(), VerifyError> {
        match (self.authority, self.revocation_key.is_some()) {
            (Authority::Root, false) | (Authority::RootRevoked, true) => {}
            _ => return Err(VerifyError::SchemaViolation),
        }
        if let Some(valid_until) = self.valid_until_ms
            && valid_until < self.timestamp_ms
        {
            return Err(VerifyError::SchemaViolation);
        }
        self.contact.validate(Some(self.id.as_str()))?;
        Ok(())
    }

    /// Deterministic CBOR encoding of the complete record body, after
    /// validating schema coherence, aggregate limits, and the descriptor
    /// binding of `id`.
    ///
    /// # Errors
    ///
    /// Returns a [`VerifyError`] naming the violated rule.
    pub fn encode(&self) -> Result<Vec<u8>, VerifyError> {
        self.validate()?;
        if self.descriptor.did() != self.id {
            return Err(VerifyError::IdentityBindingMismatch);
        }
        let contact_bytes = self.contact.encode(Some(self.id.as_str()))?;
        if contact_bytes.len() > MAX_CONTACT_BYTES {
            return Err(VerifyError::SchemaViolation);
        }
        let key = |label: u64| cbor::encode_with(|w| w.uint(label));
        let mut entries = vec![
            (key(0), cbor::encode_with(|w| w.uint(PROTOCOL_VERSION))),
            (key(1), cbor::encode_with(|w| w.tstr(self.id.as_str()))),
            (key(2), cbor::encode_with(|w| w.uint(self.timestamp_ms))),
            (
                key(3),
                cbor::encode_with(|w| w.uint(self.authority.wire_value())),
            ),
            (key(4), self.descriptor.encode()),
            (key(7), contact_bytes),
        ];
        if let Some(rk) = &self.revocation_key {
            entries.push((key(5), encode_public_key(rk)));
        }
        if let Some(valid_until) = self.valid_until_ms {
            entries.push((key(6), cbor::encode_with(|w| w.uint(valid_until))));
        }
        if !self.extensions.is_empty() {
            entries.push((key(8), contact::encode_extension_map(&self.extensions)));
        }
        let bytes = cbor::encode_with(|w| w.map_entries(entries));
        // Aggregate depth and member limits apply to the produced encoding
        // exactly as they would on receipt.
        cbor::validate(&bytes, MAX_BODY_DEPTH, MAX_BODY_MEMBERS).map_err(VerifyError::from)?;
        Ok(bytes)
    }
}

/// Signing failure classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SignError {
    /// The body fails schema validation or aggregate limits.
    #[error("record body is not schema-valid: {0}")]
    InvalidBody(VerifyError),
    /// The seed's public key is not the key applicable to the authority state.
    #[error("signing key does not match the applicable authority key")]
    KeyMismatch,
    /// The complete envelope exceeds the 16 KiB record limit.
    #[error("complete record exceeds the 16 KiB envelope limit")]
    RecordTooLarge,
}

/// Creates a complete signed Identity Record from a schema-valid body and the
/// 32-byte private seed applicable to its authority state.
///
/// # Errors
///
/// Returns a [`SignError`] naming the failed precondition.
pub fn sign_record(body: &RecordBody, seed: &[u8; 32]) -> Result<Vec<u8>, SignError> {
    let body_bytes = body.encode().map_err(SignError::InvalidBody)?;
    let public = crypto::ed25519_public_key(seed);
    let applicable = match body.authority {
        Authority::Root => body.descriptor.root_key,
        Authority::RootRevoked => body.revocation_key.ok_or(SignError::KeyMismatch)?,
    };
    if public != applicable {
        return Err(SignError::KeyMismatch);
    }
    let envelope = seal_record_body(&body_bytes, seed);
    if envelope.len() > MAX_RECORD_BYTES {
        return Err(SignError::RecordTooLarge);
    }
    Ok(envelope)
}

/// Signs arbitrary record-body bytes and assembles the COSE envelope without
/// any validation.
///
/// This is a low-level building block for conformance-fixture construction
/// (re-signing deliberately mutated bodies per IMPLEMENTATION.md section
/// 11.1). Production authoring uses [`sign_record`].
#[must_use]
pub fn seal_record_body(body_bytes: &[u8], seed: &[u8; 32]) -> Vec<u8> {
    let signature = crypto::ed25519_sign(seed, &cose::sig_structure(body_bytes));
    cose::assemble_envelope(body_bytes, &signature)
}

/// A parsed, schema-valid record body plus the exact payload byte ranges
/// needed for descriptor binding and commitment checks.
pub(crate) struct ParsedBody {
    pub id_text: String,
    pub timestamp_ms: u64,
    pub authority: Authority,
    pub descriptor: AuthorityDescriptor,
    pub descriptor_range: Range<usize>,
    pub revocation_key: Option<[u8; 32]>,
    pub revocation_key_range: Option<Range<usize>>,
    pub valid_until_ms: Option<u64>,
    pub contact: ContactDocument,
    pub extensions: ExtensionMap,
}

/// Parses one record body from validated payload bytes, enforcing the exact
/// v1 schema (specification section 5.1).
pub(crate) fn parse_record_body(payload: &[u8]) -> Result<ParsedBody, VerifyError> {
    let mut r = Reader::new(payload);
    let head = r.read_head().map_err(VerifyError::from)?;
    if head.major != MAJOR_MAP {
        return Err(VerifyError::SchemaViolation);
    }

    let mut protocol_version = None;
    let mut id_text = None;
    let mut timestamp_ms = None;
    let mut authority = None;
    let mut descriptor = None;
    let mut descriptor_range = None;
    let mut revocation_key = None;
    let mut revocation_key_range = None;
    let mut valid_until_ms = None;
    let mut contact_range: Option<Range<usize>> = None;
    let mut extensions = ExtensionMap::new();

    for _ in 0..head.arg {
        let key = r.read_head().map_err(VerifyError::from)?;
        if key.major != MAJOR_UINT {
            return Err(VerifyError::SchemaViolation);
        }
        match key.arg {
            0 => protocol_version = Some(read_uint(&mut r)?),
            1 => {
                let text = read_tstr_bounded(&mut r, MAX_URI_BYTES)?;
                id_text = Some(text);
            }
            2 => timestamp_ms = Some(read_uint(&mut r)?),
            3 => {
                authority = Some(match read_uint(&mut r)? {
                    0 => Authority::Root,
                    1 => Authority::RootRevoked,
                    _ => return Err(VerifyError::SchemaViolation),
                });
            }
            4 => {
                let start = r.position();
                let parsed = parse_descriptor(&mut r)?;
                descriptor_range = Some(start..r.position());
                descriptor = Some(parsed);
            }
            5 => {
                let start = r.position();
                let parsed = parse_public_key(&mut r)?;
                revocation_key_range = Some(start..r.position());
                revocation_key = Some(parsed);
            }
            6 => valid_until_ms = Some(read_uint(&mut r)?),
            7 => {
                let start = r.position();
                r.skip_value().map_err(VerifyError::from)?;
                contact_range = Some(start..r.position());
            }
            8 => {
                let ext_start = r.position();
                r.skip_value().map_err(VerifyError::from)?;
                let slice = &payload[ext_start..r.position()];
                let mut er = Reader::new(slice);
                extensions = parse_record_extensions(&mut er)?;
            }
            _ => return Err(VerifyError::SchemaViolation),
        }
    }
    if !r.is_at_end() {
        return Err(VerifyError::InvalidCbor);
    }

    if protocol_version != Some(PROTOCOL_VERSION) {
        return Err(VerifyError::SchemaViolation);
    }
    let id_text = id_text.ok_or(VerifyError::SchemaViolation)?;
    let timestamp_ms = timestamp_ms.ok_or(VerifyError::SchemaViolation)?;
    let authority = authority.ok_or(VerifyError::SchemaViolation)?;
    let descriptor = descriptor.ok_or(VerifyError::SchemaViolation)?;
    let descriptor_range = descriptor_range.ok_or(VerifyError::SchemaViolation)?;
    let contact_range = contact_range.ok_or(VerifyError::SchemaViolation)?;

    // Label 5 presence must match the authority state exactly.
    match (authority, revocation_key.is_some()) {
        (Authority::Root, false) | (Authority::RootRevoked, true) => {}
        _ => return Err(VerifyError::SchemaViolation),
    }
    if let Some(valid_until) = valid_until_ms
        && valid_until < timestamp_ms
    {
        return Err(VerifyError::SchemaViolation);
    }

    let contact_slice = &payload[contact_range];
    if contact_slice.len() > MAX_CONTACT_BYTES {
        return Err(VerifyError::SchemaViolation);
    }
    let contact = contact::parse_contact(contact_slice, &id_text)?;

    Ok(ParsedBody {
        id_text,
        timestamp_ms,
        authority,
        descriptor,
        descriptor_range,
        revocation_key,
        revocation_key_range,
        valid_until_ms,
        contact,
        extensions,
    })
}

fn read_uint(r: &mut Reader<'_>) -> Result<u64, VerifyError> {
    let head = r.read_head().map_err(VerifyError::from)?;
    if head.major != MAJOR_UINT {
        return Err(VerifyError::SchemaViolation);
    }
    Ok(head.arg)
}

fn read_tstr_bounded(r: &mut Reader<'_>, max: usize) -> Result<String, VerifyError> {
    let head = r.read_head().map_err(VerifyError::from)?;
    if head.major != MAJOR_TSTR {
        return Err(VerifyError::SchemaViolation);
    }
    let text = r.read_text_body(head.arg).map_err(VerifyError::from)?;
    if text.len() > max {
        return Err(VerifyError::SchemaViolation);
    }
    Ok(text.to_owned())
}

fn parse_descriptor(r: &mut Reader<'_>) -> Result<AuthorityDescriptor, VerifyError> {
    let head = r.read_head().map_err(VerifyError::from)?;
    if head.major != MAJOR_MAP || head.arg != 3 {
        return Err(VerifyError::SchemaViolation);
    }
    let mut version = None;
    let mut root_key = None;
    let mut commitment = None;
    for _ in 0..head.arg {
        let key = r.read_head().map_err(VerifyError::from)?;
        if key.major != MAJOR_UINT {
            return Err(VerifyError::SchemaViolation);
        }
        match key.arg {
            0 => version = Some(read_uint(r)?),
            1 => root_key = Some(parse_public_key(r)?),
            2 => commitment = Some(read_bstr32(r)?),
            _ => return Err(VerifyError::SchemaViolation),
        }
    }
    if version != Some(DESCRIPTOR_VERSION) {
        return Err(VerifyError::SchemaViolation);
    }
    Ok(AuthorityDescriptor {
        root_key: root_key.ok_or(VerifyError::SchemaViolation)?,
        revocation_commitment: commitment.ok_or(VerifyError::SchemaViolation)?,
    })
}

fn parse_public_key(r: &mut Reader<'_>) -> Result<[u8; 32], VerifyError> {
    let head = r.read_head().map_err(VerifyError::from)?;
    if head.major != MAJOR_MAP || head.arg != 2 {
        return Err(VerifyError::SchemaViolation);
    }
    let mut suite_ok = false;
    let mut key_bytes = None;
    for _ in 0..head.arg {
        let key = r.read_head().map_err(VerifyError::from)?;
        if key.major != MAJOR_UINT {
            return Err(VerifyError::SchemaViolation);
        }
        match key.arg {
            0 => {
                let value = r.read_head().map_err(VerifyError::from)?;
                match (value.major, value.arg) {
                    (MAJOR_NINT, SUITE_ED25519_MAGNITUDE) => suite_ok = true,
                    // Another integer names a different suite: unsupported,
                    // not malformed (specification section 3.2).
                    (MAJOR_UINT | MAJOR_NINT, _) => {
                        return Err(VerifyError::UnsupportedSuite);
                    }
                    _ => return Err(VerifyError::SchemaViolation),
                }
            }
            1 => key_bytes = Some(read_bstr32(r)?),
            _ => return Err(VerifyError::SchemaViolation),
        }
    }
    if !suite_ok {
        return Err(VerifyError::SchemaViolation);
    }
    key_bytes.ok_or(VerifyError::SchemaViolation)
}

fn read_bstr32(r: &mut Reader<'_>) -> Result<[u8; 32], VerifyError> {
    let head = r.read_head().map_err(VerifyError::from)?;
    if head.major != MAJOR_BSTR {
        return Err(VerifyError::SchemaViolation);
    }
    let bytes = r.read_bytes_body(head.arg).map_err(VerifyError::from)?;
    bytes.try_into().map_err(|_| VerifyError::SchemaViolation)
}

fn parse_record_extensions(r: &mut Reader<'_>) -> Result<ExtensionMap, VerifyError> {
    // Record extensions share the contact extension-map schema and rules.
    let map = contact::parse_extension_map_checked(r)?;
    if !r.is_at_end() {
        return Err(VerifyError::InvalidCbor);
    }
    Ok(map)
}
