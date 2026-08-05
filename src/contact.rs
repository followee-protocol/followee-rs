//! Contact Document schema, parsing, validation, and deterministic encoding
//! (specification section 7).

use crate::cbor::{
    self, MAJOR_ARRAY, MAJOR_BSTR, MAJOR_MAP, MAJOR_NINT, MAJOR_SIMPLE, MAJOR_TSTR, MAJOR_UINT,
    Reader, SIMPLE_FALSE, SIMPLE_NULL, SIMPLE_TRUE,
};
use crate::did::FolloweeDid;
use crate::error::VerifyError;
use crate::limits::{
    MAX_ALSO_KNOWN_AS, MAX_DISPLAY_NAME_BYTES, MAX_EXTENSION_KEY_BYTES, MAX_LANGUAGE_BYTES,
    MAX_SERVICE_TOKEN_BYTES, MAX_SERVICES, MAX_SUMMARY_BYTES, MAX_URI_BYTES,
};
use std::collections::BTreeMap;

/// The initial case-sensitive service-type tokens (specification section 7.3).
pub const SERVICE_TYPE_TOKENS: [&str; 8] = [
    "Website",
    "Feed",
    "Profile",
    "ActivityPub",
    "Messaging",
    "Repository",
    "Payment",
    "Other",
];

/// A complete, schema-valid Contact Document. Every field is optional; an
/// empty document is valid.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ContactDocument {
    /// Human-readable name (≤ 256 UTF-8 bytes).
    pub display_name: Option<String>,
    /// Short public description (≤ 2,048 UTF-8 bytes).
    pub summary: Option<String>,
    /// URI of an avatar image (section 7.2 URI production).
    pub avatar: Option<String>,
    /// Claimed handles and alternate identifiers, as section 7.2 URIs.
    pub also_known_as: Vec<String>,
    /// Ordered public service endpoints; array order is presentation order.
    pub services: Vec<ServiceEntry>,
    /// Optional reciprocal migration claims.
    pub migration: Option<Migration>,
    /// Namespaced contact extensions keyed by section 7.2 URIs.
    pub extensions: ExtensionMap,
}

/// One service endpoint entry (specification section 7.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceEntry {
    /// Unique local token: 1–256 ASCII `unreserved` characters.
    pub id: String,
    /// Initial type token or section 7.2 URI.
    pub service_type: String,
    /// URI of the service (section 7.2 URI production).
    pub endpoint: String,
    /// Optional ASCII media type (≤ 256 bytes).
    pub media_type: Option<String>,
    /// Optional human-readable label (≤ 256 UTF-8 bytes).
    pub label: Option<String>,
    /// Optional BCP 47 language tag (≤ 64 ASCII bytes).
    pub language: Option<String>,
    /// Optional link-relation token or section 7.2 URI (≤ 256 bytes).
    pub rel: Option<String>,
}

/// Directional migration claims (specification section 7.4). At least one
/// field must be present, and each value must differ from the containing
/// record's DID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Migration {
    /// The one Followee DID from which this DID claims to continue.
    pub predecessor: Option<FolloweeDid>,
    /// The one Followee DID to which this DID invites followers to move.
    pub successor: Option<FolloweeDid>,
}

/// Extension map keyed by URI strings (section 7.2 URI production).
pub type ExtensionMap = BTreeMap<String, ExtensionValue>;

/// A restricted extension value (specification section 5.6 / Appendix A).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExtensionValue {
    /// Unsigned integer `0 ..= 2^64 - 1`.
    Unsigned(u64),
    /// Negative integer `-(1 + magnitude)`, covering `-2^64 ..= -1`.
    Negative(u64),
    /// Byte string.
    Bytes(Vec<u8>),
    /// Text string.
    Text(String),
    /// Boolean.
    Bool(bool),
    /// Null.
    Null,
    /// Array of extension values.
    Array(Vec<ExtensionValue>),
    /// Map with integer or text keys, in deterministic order.
    Map(Vec<(ExtensionKey, ExtensionValue)>),
}

/// A key permitted inside a nested extension map.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExtensionKey {
    /// Unsigned integer key.
    Unsigned(u64),
    /// Negative integer key `-(1 + magnitude)`.
    Negative(u64),
    /// Text key.
    Text(String),
}

/// Specification section 7.2 (v0.7): the RFC 3986 section 3 `URI`
/// production — scheme required, optional query and fragment permitted,
/// every `relative-ref` form rejected. Uppercase and lowercase `IPvFuture`
/// introducers are both accepted (ABNF string literals are case-insensitive).
/// No general URI canonicalization is performed.
fn is_uri(s: &str) -> bool {
    iri_string::types::UriStr::new(s).is_ok()
}

fn check_uri(s: &str, max_bytes: usize) -> Result<(), VerifyError> {
    if s.len() > max_bytes || !is_uri(s) {
        return Err(VerifyError::SchemaViolation);
    }
    Ok(())
}

fn is_unreserved_ascii(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~'))
}

/// RFC 6838 section 4.2 `restricted-name`: one ALPHA/DIGIT first character,
/// then at most 126 further characters from ALPHA / DIGIT /
/// `! # $ & - ^ _ . +`.
fn is_restricted_name(s: &str) -> bool {
    let bytes = s.as_bytes();
    let Some((&first, rest)) = bytes.split_first() else {
        return false;
    };
    first.is_ascii_alphanumeric()
        && rest.len() <= 126
        && rest.iter().all(|&b| {
            b.is_ascii_alphanumeric()
                || matches!(
                    b,
                    b'!' | b'#' | b'$' | b'&' | b'-' | b'^' | b'_' | b'.' | b'+'
                )
        })
}

/// `mediaType` (specification section 7.3, v0.6): exactly an RFC 6838
/// `type-name`, `/`, and `subtype-name`; no parameters.
fn is_media_type(s: &str) -> bool {
    match s.split_once('/') {
        Some((type_name, subtype_name)) => {
            is_restricted_name(type_name) && is_restricted_name(subtype_name)
        }
        None => false,
    }
}

/// The fixed RFC 5646 `grandfathered` productions, normatively included by
/// specification section 7.3 (v0.6). Matching is case-insensitive; callers
/// pass a lowercased tag.
const GRANDFATHERED_TAGS: [&str; 26] = [
    // irregular
    "en-gb-oed",
    "i-ami",
    "i-bnn",
    "i-default",
    "i-enochian",
    "i-hak",
    "i-klingon",
    "i-lux",
    "i-mingo",
    "i-navajo",
    "i-pwn",
    "i-tao",
    "i-tay",
    "i-tsu",
    "sgn-be-fr",
    "sgn-be-nl",
    "sgn-ch-de",
    // regular
    "art-lojban",
    "cel-gaulish",
    "no-bok",
    "no-nyn",
    "zh-guoyu",
    "zh-hakka",
    "zh-min",
    "zh-min-nan",
    "zh-xiang",
];

/// `language` (specification section 7.3, v0.6): well-formed RFC 5646
/// `Language-Tag` ABNF, including the fixed grandfathered productions.
/// Verification is case-insensitive; the exact signed text is retained by
/// the caller. No registry lookup or canonicalization is performed.
fn is_language_tag(s: &str) -> bool {
    if s.is_empty() || !s.is_ascii() {
        return false;
    }
    let lower = s.to_ascii_lowercase();
    if GRANDFATHERED_TAGS.contains(&lower.as_str()) {
        return true;
    }
    let parts: Vec<&str> = lower.split('-').collect();
    // Empty segments cover leading/trailing/double hyphens.
    if parts.iter().any(|p| p.is_empty()) {
        return false;
    }
    let alpha = |p: &str| p.bytes().all(|b| b.is_ascii_lowercase());
    let digit = |p: &str| p.bytes().all(|b| b.is_ascii_digit());
    let alnum = |p: &str| {
        p.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
    };

    // privateuse = "x" 1*("-" (1*8alphanum))
    if parts[0] == "x" {
        let rest = &parts[1..];
        return !rest.is_empty() && rest.iter().all(|p| p.len() <= 8 && alnum(p));
    }

    // langtag = language ["-" script] ["-" region] *variant *extension ["-" privateuse]
    let mut i = 1;
    match parts[0].len() {
        // language = 2*3ALPHA ["-" extlang]; extlang = up to three 3ALPHA.
        2 | 3 if alpha(parts[0]) => {
            let mut extlangs = 0u8;
            while i < parts.len() && extlangs < 3 && parts[i].len() == 3 && alpha(parts[i]) {
                i = i.saturating_add(1);
                extlangs = extlangs.saturating_add(1);
            }
        }
        4..=8 if alpha(parts[0]) => {}
        _ => return false,
    }
    // script = 4ALPHA
    if i < parts.len() && parts[i].len() == 4 && alpha(parts[i]) {
        i = i.saturating_add(1);
    }
    // region = 2ALPHA / 3DIGIT
    if i < parts.len()
        && ((parts[i].len() == 2 && alpha(parts[i])) || (parts[i].len() == 3 && digit(parts[i])))
    {
        i = i.saturating_add(1);
    }
    // variant = 5*8alphanum / DIGIT 3alphanum
    while i < parts.len() {
        let p = parts[i];
        let is_variant = (p.len() >= 5 && p.len() <= 8 && alnum(p))
            || (p.len() == 4 && p.as_bytes()[0].is_ascii_digit() && alnum(p));
        if !is_variant {
            break;
        }
        i = i.saturating_add(1);
    }
    // extension = singleton 1*("-" 2*8alphanum); singleton excludes "x".
    while i < parts.len() && parts[i].len() == 1 && parts[i] != "x" && alnum(parts[i]) {
        i = i.saturating_add(1);
        let mut ext_parts = 0u8;
        while i < parts.len() && parts[i].len() >= 2 && parts[i].len() <= 8 && alnum(parts[i]) {
            i = i.saturating_add(1);
            ext_parts = ext_parts.saturating_add(1);
        }
        if ext_parts == 0 {
            return false;
        }
    }
    // privateuse = "x" 1*("-" 1*8alphanum)
    if i < parts.len() && parts[i] == "x" {
        i = i.saturating_add(1);
        let mut private_parts = 0u8;
        while i < parts.len() && parts[i].len() <= 8 && alnum(parts[i]) {
            i = i.saturating_add(1);
            private_parts = private_parts.saturating_add(1);
        }
        if private_parts == 0 {
            return false;
        }
    }
    i == parts.len()
}

/// The token form of `rel` (specification section 7.3, v0.6): RFC 8288
/// `reg-rel-type` exactly — one lowercase ASCII letter, then zero or more
/// lowercase letters, digits, `.`, or `-`.
fn is_relation_token(s: &str) -> bool {
    let bytes = s.as_bytes();
    let Some((&first, rest)) = bytes.split_first() else {
        return false;
    };
    first.is_ascii_lowercase()
        && rest
            .iter()
            .all(|&b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'-'))
}

impl ContactDocument {
    /// Validates every schema constraint. `containing_did` is the canonical
    /// DID of the record carrying this document, used for the migration
    /// self-reference rule.
    ///
    /// # Errors
    ///
    /// Returns [`VerifyError::SchemaViolation`] on any constraint failure.
    pub fn validate(&self, containing_did: Option<&str>) -> Result<(), VerifyError> {
        if let Some(name) = &self.display_name
            && name.len() > MAX_DISPLAY_NAME_BYTES
        {
            return Err(VerifyError::SchemaViolation);
        }
        if let Some(summary) = &self.summary
            && summary.len() > MAX_SUMMARY_BYTES
        {
            return Err(VerifyError::SchemaViolation);
        }
        if let Some(avatar) = &self.avatar {
            check_uri(avatar, MAX_URI_BYTES)?;
        }
        if self.also_known_as.len() > MAX_ALSO_KNOWN_AS {
            return Err(VerifyError::SchemaViolation);
        }
        for aka in &self.also_known_as {
            check_uri(aka, MAX_URI_BYTES)?;
        }
        if self.services.len() > MAX_SERVICES {
            return Err(VerifyError::SchemaViolation);
        }
        let mut ids = std::collections::BTreeSet::new();
        for service in &self.services {
            service.validate()?;
            if !ids.insert(service.id.as_str()) {
                return Err(VerifyError::SchemaViolation);
            }
        }
        if let Some(migration) = &self.migration {
            migration.validate(containing_did)?;
        }
        validate_extension_map(&self.extensions)?;
        Ok(())
    }

    /// Encodes the document deterministically after validating it.
    ///
    /// # Errors
    ///
    /// Returns [`VerifyError::SchemaViolation`] when validation fails.
    pub fn encode(&self, containing_did: Option<&str>) -> Result<Vec<u8>, VerifyError> {
        self.validate(containing_did)?;
        let mut entries: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
        let key = |label: u64| cbor::encode_with(|w| w.uint(label));
        if let Some(v) = &self.display_name {
            entries.push((key(0), cbor::encode_with(|w| w.tstr(v))));
        }
        if let Some(v) = &self.summary {
            entries.push((key(1), cbor::encode_with(|w| w.tstr(v))));
        }
        if let Some(v) = &self.avatar {
            entries.push((key(2), cbor::encode_with(|w| w.tstr(v))));
        }
        if !self.also_known_as.is_empty() {
            entries.push((
                key(3),
                cbor::encode_with(|w| {
                    w.array(self.also_known_as.len() as u64);
                    for aka in &self.also_known_as {
                        w.tstr(aka);
                    }
                }),
            ));
        }
        if !self.services.is_empty() {
            entries.push((
                key(4),
                cbor::encode_with(|w| {
                    w.array(self.services.len() as u64);
                    for service in &self.services {
                        w.raw(&service.encode());
                    }
                }),
            ));
        }
        if let Some(migration) = &self.migration {
            entries.push((key(5), migration.encode()));
        }
        if !self.extensions.is_empty() {
            entries.push((key(6), encode_extension_map(&self.extensions)));
        }
        Ok(cbor::encode_with(|w| w.map_entries(entries)))
    }
}

impl ServiceEntry {
    fn validate(&self) -> Result<(), VerifyError> {
        if self.id.len() > MAX_SERVICE_TOKEN_BYTES || !is_unreserved_ascii(&self.id) {
            return Err(VerifyError::SchemaViolation);
        }
        let type_ok = SERVICE_TYPE_TOKENS.contains(&self.service_type.as_str())
            || (self.service_type.len() <= MAX_URI_BYTES && is_uri(&self.service_type));
        if !type_ok {
            return Err(VerifyError::SchemaViolation);
        }
        check_uri(&self.endpoint, MAX_URI_BYTES)?;
        if let Some(mt) = &self.media_type
            && (mt.len() > MAX_SERVICE_TOKEN_BYTES || !is_media_type(mt))
        {
            return Err(VerifyError::SchemaViolation);
        }
        if let Some(label) = &self.label
            && label.len() > MAX_SERVICE_TOKEN_BYTES
        {
            return Err(VerifyError::SchemaViolation);
        }
        if let Some(lang) = &self.language
            && (lang.len() > MAX_LANGUAGE_BYTES || !is_language_tag(lang))
        {
            return Err(VerifyError::SchemaViolation);
        }
        if let Some(rel) = &self.rel
            && (rel.len() > MAX_SERVICE_TOKEN_BYTES || !(is_relation_token(rel) || is_uri(rel)))
        {
            return Err(VerifyError::SchemaViolation);
        }
        Ok(())
    }

    fn encode(&self) -> Vec<u8> {
        let key = |label: u64| cbor::encode_with(|w| w.uint(label));
        let mut entries = vec![
            (key(0), cbor::encode_with(|w| w.tstr(&self.id))),
            (key(1), cbor::encode_with(|w| w.tstr(&self.service_type))),
            (key(2), cbor::encode_with(|w| w.tstr(&self.endpoint))),
        ];
        if let Some(v) = &self.media_type {
            entries.push((key(3), cbor::encode_with(|w| w.tstr(v))));
        }
        if let Some(v) = &self.label {
            entries.push((key(4), cbor::encode_with(|w| w.tstr(v))));
        }
        if let Some(v) = &self.language {
            entries.push((key(5), cbor::encode_with(|w| w.tstr(v))));
        }
        if let Some(v) = &self.rel {
            entries.push((key(6), cbor::encode_with(|w| w.tstr(v))));
        }
        cbor::encode_with(|w| w.map_entries(entries))
    }
}

impl Migration {
    fn validate(&self, containing_did: Option<&str>) -> Result<(), VerifyError> {
        if self.predecessor.is_none() && self.successor.is_none() {
            return Err(VerifyError::SchemaViolation);
        }
        for value in [&self.predecessor, &self.successor].into_iter().flatten() {
            if let Some(own) = containing_did
                && value.as_str() == own
            {
                return Err(VerifyError::SchemaViolation);
            }
        }
        Ok(())
    }

    fn encode(&self) -> Vec<u8> {
        let key = |label: u64| cbor::encode_with(|w| w.uint(label));
        let mut entries = Vec::new();
        if let Some(v) = &self.predecessor {
            entries.push((key(0), cbor::encode_with(|w| w.tstr(v.as_str()))));
        }
        if let Some(v) = &self.successor {
            entries.push((key(1), cbor::encode_with(|w| w.tstr(v.as_str()))));
        }
        cbor::encode_with(|w| w.map_entries(entries))
    }
}

/// Validates an extension map's key and value rules. This single function
/// serves both the contact-level (label 6) and record-level (label 8)
/// extension positions; there is deliberately no second implementation.
pub(crate) fn validate_extension_map(map: &ExtensionMap) -> Result<(), VerifyError> {
    for (uri, value) in map {
        if uri.len() > MAX_EXTENSION_KEY_BYTES || !is_uri(uri) {
            return Err(VerifyError::SchemaViolation);
        }
        validate_extension_value(value)?;
    }
    Ok(())
}

fn validate_extension_value(value: &ExtensionValue) -> Result<(), VerifyError> {
    match value {
        ExtensionValue::Unsigned(_)
        | ExtensionValue::Negative(_)
        | ExtensionValue::Bytes(_)
        | ExtensionValue::Text(_)
        | ExtensionValue::Bool(_)
        | ExtensionValue::Null => Ok(()),
        ExtensionValue::Array(items) => {
            for item in items {
                validate_extension_value(item)?;
            }
            Ok(())
        }
        ExtensionValue::Map(entries) => {
            let mut keys = std::collections::BTreeSet::new();
            for (k, v) in entries {
                if !keys.insert(encode_extension_key(k)) {
                    return Err(VerifyError::SchemaViolation);
                }
                validate_extension_value(v)?;
            }
            Ok(())
        }
    }
}

/// Encodes an extension map keyed by URI strings.
pub(crate) fn encode_extension_map(map: &ExtensionMap) -> Vec<u8> {
    let entries = map
        .iter()
        .map(|(k, v)| (cbor::encode_with(|w| w.tstr(k)), encode_extension_value(v)))
        .collect();
    cbor::encode_with(|w| w.map_entries(entries))
}

fn encode_extension_key(key: &ExtensionKey) -> Vec<u8> {
    cbor::encode_with(|w| match key {
        ExtensionKey::Unsigned(v) => w.uint(*v),
        ExtensionKey::Negative(m) => w.nint_from_magnitude(*m),
        ExtensionKey::Text(s) => w.tstr(s),
    })
}

fn encode_extension_value(value: &ExtensionValue) -> Vec<u8> {
    cbor::encode_with(|w| match value {
        ExtensionValue::Unsigned(v) => w.uint(*v),
        ExtensionValue::Negative(m) => w.nint_from_magnitude(*m),
        ExtensionValue::Bytes(b) => w.bstr(b),
        ExtensionValue::Text(s) => w.tstr(s),
        ExtensionValue::Bool(b) => w.bool(*b),
        ExtensionValue::Null => w.null(),
        ExtensionValue::Array(items) => {
            w.array(items.len() as u64);
            for item in items {
                w.raw(&encode_extension_value(item));
            }
        }
        ExtensionValue::Map(entries) => {
            let encoded = entries
                .iter()
                .map(|(k, v)| (encode_extension_key(k), encode_extension_value(v)))
                .collect();
            w.map_entries(encoded);
        }
    })
}

/// Parses and validates a Contact Document from its exact validated slice.
/// `containing_did` is the record's body `id` text.
pub(crate) fn parse_contact(
    slice: &[u8],
    containing_did: &str,
) -> Result<ContactDocument, VerifyError> {
    let mut r = Reader::new(slice);
    let head = r.read_head().map_err(VerifyError::from)?;
    if head.major != MAJOR_MAP {
        return Err(VerifyError::SchemaViolation);
    }
    let mut doc = ContactDocument::default();
    for _ in 0..head.arg {
        let key = r.read_head().map_err(VerifyError::from)?;
        if key.major != MAJOR_UINT {
            return Err(VerifyError::SchemaViolation);
        }
        match key.arg {
            0 => doc.display_name = Some(read_tstr(&mut r)?),
            1 => doc.summary = Some(read_tstr(&mut r)?),
            2 => doc.avatar = Some(read_tstr(&mut r)?),
            3 => {
                let len = read_array_len(&mut r)?;
                for _ in 0..len {
                    doc.also_known_as.push(read_tstr(&mut r)?);
                }
            }
            4 => {
                let len = read_array_len(&mut r)?;
                for _ in 0..len {
                    doc.services.push(parse_service(&mut r)?);
                }
            }
            5 => doc.migration = Some(parse_migration(&mut r)?),
            6 => doc.extensions = parse_extension_map(&mut r)?,
            // Unknown core labels are a schema violation: the normative CDDL
            // contact-document map is closed; extensions live under label 6.
            _ => return Err(VerifyError::SchemaViolation),
        }
    }
    if !r.is_at_end() {
        return Err(VerifyError::InvalidCbor);
    }
    doc.validate(Some(containing_did))?;
    Ok(doc)
}

fn read_tstr(r: &mut Reader<'_>) -> Result<String, VerifyError> {
    let head = r.read_head().map_err(VerifyError::from)?;
    if head.major != MAJOR_TSTR {
        return Err(VerifyError::SchemaViolation);
    }
    Ok(r.read_text_body(head.arg)
        .map_err(VerifyError::from)?
        .to_owned())
}

fn read_array_len(r: &mut Reader<'_>) -> Result<u64, VerifyError> {
    let head = r.read_head().map_err(VerifyError::from)?;
    if head.major != MAJOR_ARRAY {
        return Err(VerifyError::SchemaViolation);
    }
    Ok(head.arg)
}

fn parse_service(r: &mut Reader<'_>) -> Result<ServiceEntry, VerifyError> {
    let head = r.read_head().map_err(VerifyError::from)?;
    if head.major != MAJOR_MAP {
        return Err(VerifyError::SchemaViolation);
    }
    let mut id = None;
    let mut service_type = None;
    let mut endpoint = None;
    let mut media_type = None;
    let mut label = None;
    let mut language = None;
    let mut rel = None;
    for _ in 0..head.arg {
        let key = r.read_head().map_err(VerifyError::from)?;
        if key.major != MAJOR_UINT {
            return Err(VerifyError::SchemaViolation);
        }
        let value = read_tstr(r)?;
        match key.arg {
            0 => id = Some(value),
            1 => service_type = Some(value),
            2 => endpoint = Some(value),
            3 => media_type = Some(value),
            4 => label = Some(value),
            5 => language = Some(value),
            6 => rel = Some(value),
            _ => return Err(VerifyError::SchemaViolation),
        }
    }
    Ok(ServiceEntry {
        id: id.ok_or(VerifyError::SchemaViolation)?,
        service_type: service_type.ok_or(VerifyError::SchemaViolation)?,
        endpoint: endpoint.ok_or(VerifyError::SchemaViolation)?,
        media_type,
        label,
        language,
        rel,
    })
}

fn parse_migration(r: &mut Reader<'_>) -> Result<Migration, VerifyError> {
    let head = r.read_head().map_err(VerifyError::from)?;
    if head.major != MAJOR_MAP {
        return Err(VerifyError::SchemaViolation);
    }
    let mut predecessor = None;
    let mut successor = None;
    for _ in 0..head.arg {
        let key = r.read_head().map_err(VerifyError::from)?;
        if key.major != MAJOR_UINT {
            return Err(VerifyError::SchemaViolation);
        }
        let value = read_tstr(r)?;
        // A migration value that is not a canonical v1 Followee DID violates
        // the section 7.4 contact schema; the DID-level classification is not
        // surfaced for embedded contact fields.
        let did = FolloweeDid::parse(&value).map_err(|_| VerifyError::SchemaViolation)?;
        match key.arg {
            0 => predecessor = Some(did),
            1 => successor = Some(did),
            _ => return Err(VerifyError::SchemaViolation),
        }
    }
    Ok(Migration {
        predecessor,
        successor,
    })
}

/// Parses an extension map for the record-level `extensions` field, applying
/// the same key and value rules as contact extensions.
pub(crate) fn parse_extension_map_checked(r: &mut Reader<'_>) -> Result<ExtensionMap, VerifyError> {
    let map = parse_extension_map(r)?;
    validate_extension_map(&map)?;
    Ok(map)
}

fn parse_extension_map(r: &mut Reader<'_>) -> Result<ExtensionMap, VerifyError> {
    let head = r.read_head().map_err(VerifyError::from)?;
    if head.major != MAJOR_MAP {
        return Err(VerifyError::SchemaViolation);
    }
    let mut map = ExtensionMap::new();
    for _ in 0..head.arg {
        let key = read_tstr(r)?;
        let value = parse_extension_value(r)?;
        map.insert(key, value);
    }
    Ok(map)
}

fn parse_extension_value(r: &mut Reader<'_>) -> Result<ExtensionValue, VerifyError> {
    let head = r.read_head().map_err(VerifyError::from)?;
    match head.major {
        MAJOR_UINT => Ok(ExtensionValue::Unsigned(head.arg)),
        MAJOR_NINT => Ok(ExtensionValue::Negative(head.arg)),
        MAJOR_BSTR => Ok(ExtensionValue::Bytes(
            r.read_bytes_body(head.arg)
                .map_err(VerifyError::from)?
                .to_vec(),
        )),
        MAJOR_TSTR => Ok(ExtensionValue::Text(
            r.read_text_body(head.arg)
                .map_err(VerifyError::from)?
                .to_owned(),
        )),
        MAJOR_SIMPLE => match head.arg {
            SIMPLE_FALSE => Ok(ExtensionValue::Bool(false)),
            SIMPLE_TRUE => Ok(ExtensionValue::Bool(true)),
            SIMPLE_NULL => Ok(ExtensionValue::Null),
            _ => Err(VerifyError::SchemaViolation),
        },
        MAJOR_ARRAY => {
            let mut items = Vec::new();
            for _ in 0..head.arg {
                items.push(parse_extension_value(r)?);
            }
            Ok(ExtensionValue::Array(items))
        }
        MAJOR_MAP => {
            let mut entries = Vec::new();
            for _ in 0..head.arg {
                let key_head = r.read_head().map_err(VerifyError::from)?;
                let key = match key_head.major {
                    MAJOR_UINT => ExtensionKey::Unsigned(key_head.arg),
                    MAJOR_NINT => ExtensionKey::Negative(key_head.arg),
                    MAJOR_TSTR => ExtensionKey::Text(
                        r.read_text_body(key_head.arg)
                            .map_err(VerifyError::from)?
                            .to_owned(),
                    ),
                    _ => return Err(VerifyError::SchemaViolation),
                };
                entries.push((key, parse_extension_value(r)?));
            }
            Ok(ExtensionValue::Map(entries))
        }
        _ => Err(VerifyError::SchemaViolation),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sec_7_3_service_token_shape_helpers() {
        // Service id: ASCII unreserved only, non-empty.
        assert!(is_unreserved_ascii("feed-01.x_~"));
        assert!(!is_unreserved_ascii(""));
        assert!(!is_unreserved_ascii("has space"));
        assert!(!is_unreserved_ascii("słow"));
        assert!(!is_unreserved_ascii("a/b"));

        // sec_7_3_media_type_grammar: exactly RFC 6838 type "/" subtype,
        // both restricted-name, no parameters.
        assert!(is_media_type("application/atom+xml"));
        assert!(is_media_type("text/html"));
        assert!(is_media_type("A/B"));
        assert!(is_media_type("x-custom/v1.2+json"));
        assert!(is_media_type(&format!(
            "{}/{}",
            "a".repeat(127),
            "b".repeat(127)
        )));
        assert!(!is_media_type(""));
        assert!(!is_media_type("text"));
        assert!(!is_media_type("text/"));
        assert!(!is_media_type("/plain"));
        assert!(!is_media_type("text/plain; charset=utf-8"));
        assert!(!is_media_type("text plain"));
        assert!(!is_media_type("tëxt/plain"));
        assert!(!is_media_type("-text/plain"));
        assert!(!is_media_type("text/pl/ain"));
        assert!(!is_media_type(&format!("{}/{}", "a".repeat(128), "b")));

        // sec_7_3_language_tag_grammar: well-formed RFC 5646 Language-Tag,
        // grandfathered included, case-insensitive, no registry lookups.
        assert!(is_language_tag("en"));
        assert!(is_language_tag("en-US"));
        assert!(is_language_tag("EN-us"));
        assert!(is_language_tag("zh-Hant-CN"));
        assert!(is_language_tag("sl-rozaj-biske"));
        assert!(is_language_tag("de-DE-1996"));
        assert!(is_language_tag("en-a-bbb-x-a-cccc"));
        assert!(is_language_tag("x-priv-a1"));
        assert!(is_language_tag("i-klingon"));
        assert!(is_language_tag("en-GB-oed"));
        assert!(is_language_tag("zh-min-nan"));
        assert!(is_language_tag("ar-aao"));
        assert!(is_language_tag("abcd"));
        assert!(is_language_tag("abcdefgh"));
        assert!(is_language_tag("ab-abc-abc-abc"));
        assert!(!is_language_tag(""));
        assert!(!is_language_tag("a"));
        assert!(!is_language_tag("abcdefghi"));
        assert!(!is_language_tag("12"));
        assert!(!is_language_tag("1a"));
        assert!(!is_language_tag("ab-abc-abc-abc-abc"));
        assert!(!is_language_tag("en-12"));
        assert!(!is_language_tag("en-Latn-abc"));
        assert!(!is_language_tag("en-Latn-abcd"));
        assert!(!is_language_tag("x-abcdefghi"));
        assert!(!is_language_tag(&"a".repeat(64)));
        assert!(!is_language_tag("-en"));
        assert!(!is_language_tag("en-"));
        assert!(!is_language_tag("en--US"));
        assert!(!is_language_tag("en_US"));
        assert!(!is_language_tag("en-a"));
        assert!(!is_language_tag("x"));
        assert!(!is_language_tag("en-abcdefghi"));
        assert!(!is_language_tag("en-€"));

        // sec_7_3_relation_type_grammar: RFC 8288 reg-rel-type exactly.
        assert!(is_relation_token("alternate"));
        assert!(is_relation_token("describedby"));
        assert!(is_relation_token("a1.-"));
        assert!(!is_relation_token(""));
        assert!(!is_relation_token("Alternate"));
        assert!(!is_relation_token("x_custom"));
        assert!(!is_relation_token("1abc"));
        assert!(!is_relation_token("has space"));
        assert!(!is_relation_token("rel!"));
    }

    #[test]
    fn sec_7_3_helper_violations_reach_schema_validation() {
        let base = ServiceEntry {
            id: "ok".to_owned(),
            service_type: "Website".to_owned(),
            endpoint: "https://example.com/".to_owned(),
            media_type: None,
            label: None,
            language: None,
            rel: None,
        };
        let doc = |service: ServiceEntry| ContactDocument {
            services: vec![service],
            ..ContactDocument::default()
        };
        assert!(doc(base.clone()).validate(None).is_ok());
        for bad in [
            ServiceEntry {
                language: Some("en--US".to_owned()),
                ..base.clone()
            },
            ServiceEntry {
                rel: Some("bad rel".to_owned()),
                ..base.clone()
            },
            ServiceEntry {
                media_type: Some("text plain".to_owned()),
                ..base.clone()
            },
            ServiceEntry {
                id: "bad id".to_owned(),
                ..base.clone()
            },
        ] {
            assert_eq!(doc(bad).validate(None), Err(VerifyError::SchemaViolation));
        }
    }

    #[test]
    fn sec_15_1_per_field_byte_boundaries_are_exact() {
        let base = ServiceEntry {
            id: "ok".to_owned(),
            service_type: "Website".to_owned(),
            endpoint: "https://example.com/".to_owned(),
            media_type: None,
            label: None,
            language: None,
            rel: None,
        };
        // (mutator, at-limit value, over-limit value)
        type Set = fn(&mut ServiceEntry, String);
        let cases: [(Set, String, String); 5] = [
            (|s, v| s.id = v, "i".repeat(256), "i".repeat(257)),
            (|s, v| s.label = Some(v), "l".repeat(256), "l".repeat(257)),
            (
                // The grammar's maximum is 255 bytes (127 + "/" + 127),
                // inside the 256-byte cap; the over case breaks the cap.
                |s, v| s.media_type = Some(v),
                format!("{}/{}", "m".repeat(127), "m".repeat(127)),
                format!("{}/{}", "m".repeat(127), "m".repeat(129)),
            ),
            (
                // A well-formed RFC 5646 tag of exactly 64 bytes (language
                // plus variant subtags); one more subtag crosses the cap.
                |s, v| s.language = Some(v),
                format!("en{}-abcdefg", "-abcdefgh".repeat(6)),
                format!("en{}", "-abcdefgh".repeat(7)),
            ),
            (|s, v| s.rel = Some(v), "r".repeat(256), "r".repeat(257)),
        ];
        for (set, at_limit, over) in cases {
            let mut ok_entry = base.clone();
            set(&mut ok_entry, at_limit);
            assert!(ok_entry.validate().is_ok());
            let mut bad_entry = base.clone();
            set(&mut bad_entry, over);
            assert_eq!(bad_entry.validate(), Err(VerifyError::SchemaViolation));
        }

        // Display name and summary boundaries at the document level.
        let doc = ContactDocument {
            display_name: Some("d".repeat(256)),
            summary: Some("s".repeat(2048)),
            ..ContactDocument::default()
        };
        assert!(doc.validate(None).is_ok());
        let over = ContactDocument {
            summary: Some("s".repeat(2049)),
            ..ContactDocument::default()
        };
        assert_eq!(over.validate(None), Err(VerifyError::SchemaViolation));
    }

    #[test]
    fn sec_15_1_collection_count_boundaries_via_direct_validation() {
        // Direct document validation exercises the per-collection caps that
        // the aggregate member budget makes unreachable through a complete
        // record (64 minimal services alone cost 256 members).
        let service = |i: usize| ServiceEntry {
            id: format!("s{i}"),
            service_type: "Website".to_owned(),
            endpoint: "https://example.com/".to_owned(),
            media_type: None,
            label: None,
            language: None,
            rel: None,
        };
        let doc = |n: usize| ContactDocument {
            services: (0..n).map(service).collect(),
            ..ContactDocument::default()
        };
        assert!(doc(64).validate(None).is_ok());
        assert_eq!(doc(65).validate(None), Err(VerifyError::SchemaViolation));

        let aka = |n: usize| ContactDocument {
            also_known_as: (0..n).map(|i| format!("https://e.com/{i}")).collect(),
            ..ContactDocument::default()
        };
        assert!(aka(32).validate(None).is_ok());
        assert_eq!(aka(33).validate(None), Err(VerifyError::SchemaViolation));
    }

    #[test]
    fn sec_5_6_extension_key_rules() {
        // Key exactly at 256 bytes, absolute URI: valid.
        let key_at_limit = format!("https://e.com/{}", "k".repeat(256 - 14));
        assert_eq!(key_at_limit.len(), 256);
        let mut map = ExtensionMap::new();
        map.insert(key_at_limit, ExtensionValue::Unsigned(1));
        assert!(validate_extension_map(&map).is_ok());

        // Non-URI key: invalid.
        let mut bad = ExtensionMap::new();
        bad.insert("not a uri".to_owned(), ExtensionValue::Null);
        assert_eq!(
            validate_extension_map(&bad),
            Err(VerifyError::SchemaViolation)
        );

        // Duplicate keys in a nested extension map: invalid.
        let mut dup = ExtensionMap::new();
        dup.insert(
            "https://e.com/x".to_owned(),
            ExtensionValue::Map(vec![
                (ExtensionKey::Unsigned(1), ExtensionValue::Null),
                (ExtensionKey::Unsigned(1), ExtensionValue::Bool(true)),
            ]),
        );
        assert_eq!(
            validate_extension_map(&dup),
            Err(VerifyError::SchemaViolation)
        );

        // The duplicate check also applies inside arrays.
        let mut nested = ExtensionMap::new();
        nested.insert(
            "https://e.com/x".to_owned(),
            ExtensionValue::Array(vec![ExtensionValue::Map(vec![
                (ExtensionKey::Text("a".to_owned()), ExtensionValue::Null),
                (ExtensionKey::Text("a".to_owned()), ExtensionValue::Null),
            ])]),
        );
        assert_eq!(
            validate_extension_map(&nested),
            Err(VerifyError::SchemaViolation)
        );
    }

    #[test]
    fn sec_15_1_uri_byte_boundary_is_exact() {
        let at_limit = format!("https://e.com/{}", "p".repeat(2048 - 14));
        assert_eq!(at_limit.len(), 2048);
        assert_eq!(check_uri(&at_limit, MAX_URI_BYTES), Ok(()));
        let over = format!("https://e.com/{}", "p".repeat(2049 - 14));
        assert_eq!(
            check_uri(&over, MAX_URI_BYTES),
            Err(VerifyError::SchemaViolation)
        );
    }
}
