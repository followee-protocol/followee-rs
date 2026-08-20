//! Neutral interoperability interface operations (Milestone 6).
//!
//! Implements the mechanical operation surface defined by the v0.9.2
//! authoring subset's `INTERFACE.md`: newline-delimited JSON requests, one
//! response per line, with integers as canonical decimal strings and
//! binary values as lowercase hex. Every operation is served by the same
//! production entry points the implementation itself uses — derivation and
//! authoring ([`crate::record`], [`crate::crypto`]), complete record
//! verification ([`crate::verify::verify_record_for_target`]), strict
//! Ed25519 ([`crate::crypto::verify_followee_ed25519_unsized`]), signer
//! timestamps ([`crate::timestamp::next_timestamp`]), bounded
//! deterministic-CBOR validation ([`crate::validate_cbor`]),
//! publish-response wrapper acceptance
//! ([`crate::relay::wire::parse_publish_response`], the exact decoder
//! behind the production publishing client), and candidate selection
//! ([`crate::ordering::select_current`]) — never by comparison-only shims.
//!
//! Every protocol operation is deterministic: clocks arrive as explicit
//! `nowMs` inputs, no randomness or environment is consulted, and signing
//! is deterministic RFC 8032 Ed25519.
//!
//! # `verifyRecord` `record` projection (Campaign 1 finding I2)
//!
//! Authoring **revision 2** of the v0.9.2 `INTERFACE.md` defines the
//! accepted `verifyRecord` result exactly, and this module implements
//! that definition member for member:
//!
//! - `record` holds exactly `descriptor`, `revocationKey`, `contact`, and
//!   `extensions`;
//! - `record.descriptor` is the closed eight-member projection of the
//!   Authority Descriptor (`descriptorVersion`, `rootKeySuite`,
//!   `rootPublicKeyHex`, `revocationCommitmentHex`,
//!   `authorityDescriptorCborHex`, `authorityDescriptorDigestHex`,
//!   `multihashHex`, `did`) — descriptor content and total functions of
//!   the descriptor bytes only, satisfying the contract's coherence
//!   relationships by construction from the production values;
//! - `record.revocationKey` projects record-body label `5` as a separate
//!   authority-dependent member: JSON `null` exactly for `authority`
//!   `"root"`, and the three-member object (`suite`, `publicKeyHex`,
//!   `publicKeyCborHex`) exactly for `"rootRevoked"`;
//! - `record.contact` and the two distinct extension maps
//!   (`record.contact.extensions`, contact label `6`, and
//!   `record.extensions`, record label `8`) use **lossless** presence:
//!   `null` for an absent wire label; `[]`, `{}`, or `""` for a
//!   present-empty one, from the production parser's
//!   [`crate::record::WirePresence`] observation rather than adapter
//!   re-parsing.
//!
//! The `authorRecord` input direction applies the constructor
//! canonicalization instead: an omitted member, `null`, an empty array,
//! or an empty object requests omission of the optional wire field
//! (including a migration object whose members are all `null`), while an
//! empty string requests a present empty text where the grammar admits
//! one. The canonicalization never reaches inside a typed extension
//! value. Consequently `authorRecord` cannot construct present-empty
//! optional collections; those are covered by direct wire fixtures
//! through `verifyRecord`.
//!
//! No adapter re-parses the DID, reconstructs the multihash, or
//! normalizes protocol values: `deriveIdentity` and `record.descriptor`
//! take the multihash bytes from the validated production accessor
//! [`crate::did::FolloweeDid::multihash_bytes`] (Campaign 1 finding I1),
//! and every derived descriptor member comes from the production
//! derivation chain over the carried descriptor.

pub(crate) mod json;

use crate::contact::{
    ContactDocument, ExtensionKey, ExtensionMap, ExtensionValue, Migration, ServiceEntry,
};
use crate::error::VerifyError;
use crate::record::{Authority, AuthorityDescriptor, RecordBody, SignError};
use crate::timestamp::{Freshness, TimeStatus};
use crate::{cose, crypto, ordering, record, timestamp, verify};
use json::Json;
use std::collections::HashMap;

/// Maximum request or response line length in bytes (INTERFACE.md).
pub const MAX_LINE_BYTES: u64 = 1024 * 1024;

/// The interface protocol version this engine implements.
const INTERFACE_PROTOCOL: &str = "1";

/// The pinned specification revision commit (IMPLEMENTATION.md section 2).
const SPECIFICATION_COMMIT: &str = "f1d19fec0dba455d90d473bfad625d1c288e0c15";

/// This implementation's public repository.
const IMPLEMENTATION_REPOSITORY: &str = "https://github.com/followee-protocol/followee-rs";

/// The operations served, as reported by `hello`.
const OPERATIONS: [&str; 9] = [
    "hello",
    "deriveIdentity",
    "authorRecord",
    "verifyRecord",
    "strictEd25519",
    "nextTimestamp",
    "validateCbor",
    "receivePublishResponse",
    "selectCurrent",
];

/// Engine configuration: values reported by `hello` that the engine cannot
/// know itself.
#[derive(Debug, Clone)]
pub struct InteropConfig {
    /// Reported as `implementationCommit`. The engine cannot observe the
    /// enclosing source revision; the caller supplies it, and recorded
    /// frozen outputs identify their revision through the repository
    /// instead.
    pub implementation_commit: String,
}

/// An operation failure, preserving the interface's separation between
/// protocol rejections and infrastructure/input-contract errors.
enum OpFailure {
    /// `status: "error"` — an input-contract violation, never a protocol
    /// comparison result.
    Input(String),
    /// `status: "rejected"` — exactly one symbolic Followee classification.
    Protocol(&'static str),
}

fn input(message: impl Into<String>) -> OpFailure {
    OpFailure::Input(message.into())
}

/// Handles one request line, returning the complete response line (without
/// the trailing newline).
#[must_use]
pub fn handle_line(config: &InteropConfig, line: &str) -> String {
    if line.len() as u64 > MAX_LINE_BYTES {
        return render_error("", "request line exceeds 1 MiB");
    }
    let parsed = match json::parse(line) {
        Ok(value) => value,
        Err(e) => return render_error("", &format!("request is not contract JSON: {e}")),
    };
    let (case_id, outcome) = dispatch(config, &parsed);
    match outcome {
        Ok(result) => render(&case_id, "accepted", vec![("result", result)]),
        Err(OpFailure::Protocol(symbol)) => {
            render(&case_id, "rejected", vec![("error", Json::str(symbol))])
        }
        Err(OpFailure::Input(message)) => render_error(&case_id, &message),
    }
}

/// Serves the newline-delimited interface: one request per line on
/// `reader`, one response per line on `out`. Oversized lines and invalid
/// UTF-8 receive `status: "error"` responses; the loop continues until end
/// of input.
///
/// # Errors
///
/// Returns the underlying I/O error if reading or writing fails.
pub fn serve_lines(
    config: &InteropConfig,
    reader: &mut dyn std::io::BufRead,
    out: &mut dyn std::io::Write,
) -> std::io::Result<()> {
    loop {
        let mut buf: Vec<u8> = Vec::new();
        let n = {
            let mut limited = std::io::Read::take(&mut *reader, MAX_LINE_BYTES.saturating_add(2));
            std::io::BufRead::read_until(&mut limited, b'\n', &mut buf)?
        };
        if n == 0 {
            return Ok(());
        }
        let complete = buf.last() == Some(&b'\n');
        if complete {
            buf.pop();
        }
        if !complete && buf.len() as u64 > MAX_LINE_BYTES {
            // The line was truncated mid-stream: report it, then drain the
            // remainder of the oversized line so the next read starts at a
            // line boundary.
            writeln!(out, "{}", render_error("", "request line exceeds 1 MiB"))?;
            let mut discard: Vec<u8> = Vec::new();
            std::io::BufRead::read_until(reader, b'\n', &mut discard)?;
            continue;
        }
        let response = match String::from_utf8(buf) {
            Ok(line) => handle_line(config, &line),
            Err(_) => render_error("", "request line is not valid UTF-8"),
        };
        writeln!(out, "{response}")?;
    }
}

fn render(case_id: &str, status: &str, extra: Vec<(&str, Json)>) -> String {
    let mut members = vec![
        (
            "interfaceProtocol".to_owned(),
            Json::str(INTERFACE_PROTOCOL),
        ),
        ("caseId".to_owned(), Json::str(case_id)),
        ("status".to_owned(), Json::str(status)),
    ];
    for (name, value) in extra {
        members.push((name.to_owned(), value));
    }
    json::write(&Json::Object(members))
}

fn render_error(case_id: &str, message: &str) -> String {
    render(
        case_id,
        "error",
        vec![
            ("errorSymbol", Json::str("followee-rs.inputContract")),
            ("message", Json::str(message)),
        ],
    )
}

/// Parses the request envelope and dispatches the operation. The returned
/// `String` is the caseId to echo (empty when it could not be read).
fn dispatch(config: &InteropConfig, request: &Json) -> (String, Result<Json, OpFailure>) {
    let members = match request {
        Json::Object(members) => members,
        _ => {
            return (String::new(), Err(input("request must be one JSON object")));
        }
    };
    // Recover the caseId first so even envelope violations echo it.
    let case_id = members
        .iter()
        .find(|(name, _)| name == "caseId")
        .and_then(|(_, value)| match value {
            Json::Str(s) => Some(s.clone()),
            _ => None,
        })
        .unwrap_or_default();
    let outcome = (|| {
        let fields = take_fields(
            members,
            &["interfaceProtocol", "caseId", "operation", "input"],
            "request envelope",
        )?;
        let protocol = require_str(&fields, "interfaceProtocol")?;
        if protocol != INTERFACE_PROTOCOL {
            return Err(input("unsupported interfaceProtocol"));
        }
        require_str(&fields, "caseId")?;
        let operation = require_str(&fields, "operation")?;
        let input_members = match fields.get("input") {
            Some(Json::Object(members)) => members.as_slice(),
            Some(_) => return Err(input("input must be a JSON object")),
            None => return Err(input("missing member `input`")),
        };
        match operation {
            "hello" => op_hello(config, input_members),
            "deriveIdentity" => op_derive_identity(input_members),
            "authorRecord" => op_author_record(input_members),
            "verifyRecord" => op_verify_record(input_members),
            "strictEd25519" => op_strict_ed25519(input_members),
            "nextTimestamp" => op_next_timestamp(input_members),
            "validateCbor" => op_validate_cbor(input_members),
            "receivePublishResponse" => op_receive_publish_response(input_members),
            "selectCurrent" => op_select_current(input_members),
            other => Err(input(format!("unknown operation `{other}`"))),
        }
    })();
    (case_id, outcome)
}

// ---------------------------------------------------------------------------
// Field and value-convention helpers
// ---------------------------------------------------------------------------

/// Collects an object's members, rejecting any name outside `allowed`.
fn take_fields<'a>(
    members: &'a [(String, Json)],
    allowed: &[&str],
    what: &str,
) -> Result<HashMap<&'a str, &'a Json>, OpFailure> {
    let mut map = HashMap::new();
    for (name, value) in members {
        if !allowed.contains(&name.as_str()) {
            return Err(input(format!("unknown member `{name}` in {what}")));
        }
        map.insert(name.as_str(), value);
    }
    Ok(map)
}

fn require_str<'a>(fields: &HashMap<&str, &'a Json>, name: &str) -> Result<&'a str, OpFailure> {
    match fields.get(name) {
        Some(Json::Str(s)) => Ok(s),
        Some(_) => Err(input(format!("member `{name}` must be a string"))),
        None => Err(input(format!("missing member `{name}`"))),
    }
}

/// A string member that may be `null` or absent.
fn optional_str<'a>(
    fields: &HashMap<&str, &'a Json>,
    name: &str,
) -> Result<Option<&'a str>, OpFailure> {
    match fields.get(name) {
        Some(Json::Str(s)) => Ok(Some(s)),
        Some(Json::Null) | None => Ok(None),
        Some(_) => Err(input(format!("member `{name}` must be a string or null"))),
    }
}

/// Decodes a lowercase even-length hex string (the interface's binary-value
/// convention).
fn parse_hex(text: &str, what: &str) -> Result<Vec<u8>, OpFailure> {
    if text.len() % 2 != 0 {
        return Err(input(format!("{what} must be even-length hex")));
    }
    if !text
        .bytes()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(input(format!("{what} must be lowercase hex")));
    }
    hex::decode(text).map_err(|_| input(format!("{what} is not valid hex")))
}

fn parse_hex32(text: &str, what: &str) -> Result<[u8; 32], OpFailure> {
    parse_hex(text, what)?
        .try_into()
        .map_err(|_| input(format!("{what} must be exactly 32 bytes")))
}

/// Parses a canonical decimal `uint64` string: digits only, no leading
/// zeros, within range.
fn parse_dec_u64(text: &str, what: &str) -> Result<u64, OpFailure> {
    if text.is_empty()
        || !text.bytes().all(|b| b.is_ascii_digit())
        || (text.len() > 1 && text.starts_with('0'))
    {
        return Err(input(format!("{what} must be a canonical decimal string")));
    }
    text.parse::<u64>()
        .map_err(|_| input(format!("{what} exceeds uint64")))
}

fn dec(value: u64) -> Json {
    Json::Str(value.to_string())
}

fn hex_json(bytes: &[u8]) -> Json {
    Json::Str(hex::encode(bytes))
}

fn obj(members: Vec<(&str, Json)>) -> Json {
    Json::Object(
        members
            .into_iter()
            .map(|(name, value)| (name.to_owned(), value))
            .collect(),
    )
}

// ---------------------------------------------------------------------------
// Operations
// ---------------------------------------------------------------------------

fn op_hello(config: &InteropConfig, input_members: &[(String, Json)]) -> Result<Json, OpFailure> {
    take_fields(input_members, &[], "hello input")?;
    Ok(obj(vec![
        ("implementation", Json::str("followee-rs")),
        (
            "implementationRepository",
            Json::str(IMPLEMENTATION_REPOSITORY),
        ),
        (
            "implementationCommit",
            Json::str(config.implementation_commit.as_str()),
        ),
        ("specificationCommit", Json::str(SPECIFICATION_COMMIT)),
        (
            "interfaceProtocols",
            Json::Array(vec![Json::str(INTERFACE_PROTOCOL)]),
        ),
        (
            "operations",
            Json::Array(OPERATIONS.iter().map(|op| Json::str(*op)).collect()),
        ),
    ]))
}

/// The derivation chain both `deriveIdentity` and `authorRecord` share,
/// entirely through production components.
struct DerivedIdentity {
    root_public: [u8; 32],
    revocation_public: [u8; 32],
    descriptor: AuthorityDescriptor,
    did: crate::did::FolloweeDid,
}

fn derive_identity(root_seed: &[u8; 32], revocation_seed: &[u8; 32]) -> DerivedIdentity {
    let root_public = crypto::ed25519_public_key(root_seed);
    let revocation_public = crypto::ed25519_public_key(revocation_seed);
    let descriptor = AuthorityDescriptor {
        root_key: root_public,
        revocation_commitment: record::revocation_commitment(&revocation_public),
    };
    let did = descriptor.did();
    DerivedIdentity {
        root_public,
        revocation_public,
        descriptor,
        did,
    }
}

fn seeds_from(fields: &HashMap<&str, &Json>) -> Result<([u8; 32], [u8; 32]), OpFailure> {
    let root = parse_hex32(require_str(fields, "rootSeedHex")?, "rootSeedHex")?;
    let revocation = parse_hex32(
        require_str(fields, "revocationSeedHex")?,
        "revocationSeedHex",
    )?;
    Ok((root, revocation))
}

fn op_derive_identity(input_members: &[(String, Json)]) -> Result<Json, OpFailure> {
    let fields = take_fields(
        input_members,
        &["rootSeedHex", "revocationSeedHex"],
        "deriveIdentity input",
    )?;
    let (root_seed, revocation_seed) = seeds_from(&fields)?;
    let derived = derive_identity(&root_seed, &revocation_seed);
    Ok(obj(vec![
        ("rootPublicKeyHex", hex_json(&derived.root_public)),
        (
            "revocationPublicKeyHex",
            hex_json(&derived.revocation_public),
        ),
        (
            "revocationPublicKeyCborHex",
            hex_json(&record::encode_public_key(&derived.revocation_public)),
        ),
        (
            "revocationCommitmentHex",
            hex_json(&derived.descriptor.revocation_commitment),
        ),
        (
            "authorityDescriptorCborHex",
            hex_json(&derived.descriptor.encode()),
        ),
        (
            "authorityDescriptorDigestHex",
            hex_json(derived.did.digest().as_slice()),
        ),
        // Campaign 1 finding I1: the exact already-validated multihash
        // bytes come from the narrow production accessor.
        ("multihashHex", hex_json(derived.did.multihash_bytes())),
        ("did", Json::str(derived.did.as_str())),
    ]))
}

fn op_author_record(input_members: &[(String, Json)]) -> Result<Json, OpFailure> {
    let fields = take_fields(
        input_members,
        &[
            "rootSeedHex",
            "revocationSeedHex",
            "authority",
            "timestampMs",
            "validUntilMs",
            "contact",
            "extensions",
            "signingSeed",
        ],
        "authorRecord input",
    )?;
    let (root_seed, revocation_seed) = seeds_from(&fields)?;
    let authority = match require_str(&fields, "authority")? {
        "root" => Authority::Root,
        "rootRevoked" => Authority::RootRevoked,
        _ => return Err(input("authority must be \"root\" or \"rootRevoked\"")),
    };
    let signing_seed = match require_str(&fields, "signingSeed")? {
        "root" => &root_seed,
        "revocation" => &revocation_seed,
        _ => return Err(input("signingSeed must be \"root\" or \"revocation\"")),
    };
    // An incoherent authority/signingSeed pairing is an input-contract
    // violation, never silently re-keyed (INTERFACE.md).
    let coherent = matches!(
        (authority, require_str(&fields, "signingSeed")?),
        (Authority::Root, "root") | (Authority::RootRevoked, "revocation")
    );
    if !coherent {
        return Err(input("incoherent authority/signingSeed pairing"));
    }
    let timestamp_ms = parse_dec_u64(require_str(&fields, "timestampMs")?, "timestampMs")?;
    let valid_until_ms = optional_str(&fields, "validUntilMs")?
        .map(|text| parse_dec_u64(text, "validUntilMs"))
        .transpose()?;
    let contact = match fields.get("contact") {
        Some(Json::Object(members)) => contact_from_json(members)?,
        Some(_) => return Err(input("contact must be a JSON object")),
        None => return Err(input("missing member `contact`")),
    };
    let extensions = match fields.get("extensions") {
        Some(Json::Object(members)) => extension_map_from_json(members)?,
        Some(Json::Null) | None => ExtensionMap::new(),
        Some(_) => return Err(input("extensions must be a JSON object")),
    };

    let derived = derive_identity(&root_seed, &revocation_seed);
    let body = RecordBody {
        id: derived.did.clone(),
        timestamp_ms,
        authority,
        descriptor: derived.descriptor,
        revocation_key: match authority {
            Authority::Root => None,
            Authority::RootRevoked => Some(derived.revocation_public),
        },
        valid_until_ms,
        contact,
        extensions,
    };
    let envelope = record::sign_record(&body, signing_seed).map_err(|e| match e {
        SignError::InvalidBody(inner) => OpFailure::Protocol(inner.symbol()),
        // Coherence was checked above, so a mismatch cannot occur here;
        // classified defensively as an input violation.
        SignError::KeyMismatch => input("signing key does not match the authority key"),
        SignError::RecordTooLarge => OpFailure::Protocol("recordTooLarge"),
    })?;
    // Extract the exact payload and signature back out of the produced
    // envelope through the production COSE parser rather than re-deriving
    // them separately.
    let parts = cose::parse_envelope(&envelope)
        .map_err(|_| input("internal: produced envelope failed to re-parse"))?;
    let payload = envelope[parts.payload.clone()].to_vec();
    Ok(obj(vec![
        ("did", Json::str(derived.did.as_str())),
        ("recordBodyCborHex", hex_json(&payload)),
        ("recordBodyDigestHex", hex_json(&crypto::sha256(&payload))),
        ("sigStructureHex", hex_json(&cose::sig_structure(&payload))),
        ("signatureHex", hex_json(&parts.signature)),
        ("envelopeHex", hex_json(&envelope)),
    ]))
}

fn op_verify_record(input_members: &[(String, Json)]) -> Result<Json, OpFailure> {
    let fields = take_fields(
        input_members,
        &["targetDid", "envelopeHex", "nowMs"],
        "verifyRecord input",
    )?;
    // Malformed targets are legitimate protocol inputs here.
    let target = require_str(&fields, "targetDid")?;
    let envelope = parse_hex(require_str(&fields, "envelopeHex")?, "envelopeHex")?;
    let now_ms = parse_dec_u64(require_str(&fields, "nowMs")?, "nowMs")?;
    let verified = verify::verify_record_for_target(target, &envelope)
        .map_err(|e| OpFailure::Protocol(e.symbol()))?;
    let body = verified.body();
    let premature =
        timestamp::time_status(verified.timestamp_ms(), now_ms) == TimeStatus::Premature;
    let stale = timestamp::freshness(body.valid_until_ms, now_ms) == Freshness::Stale;
    Ok(obj(vec![
        ("envelopeHex", hex_json(verified.envelope_bytes())),
        ("recordBodyCborHex", hex_json(verified.payload_bytes())),
        ("recordBodyDigestHex", hex_json(verified.body_digest())),
        ("id", Json::str(body.id.as_str())),
        ("timestampMs", dec(verified.timestamp_ms())),
        (
            "authority",
            Json::str(match verified.authority() {
                Authority::Root => "root",
                Authority::RootRevoked => "rootRevoked",
            }),
        ),
        ("validUntilMs", body.valid_until_ms.map_or(Json::Null, dec)),
        ("premature", Json::Bool(premature)),
        ("stale", Json::Bool(stale)),
        (
            "record",
            obj(vec![
                ("descriptor", descriptor_to_json(&body.descriptor)),
                ("revocationKey", revocation_key_to_json(body)),
                (
                    "contact",
                    contact_to_json(&body.contact, verified.wire_presence().contact),
                ),
                (
                    "extensions",
                    if verified.wire_presence().record_extensions {
                        extension_map_to_json(&body.extensions)
                    } else {
                        Json::Null
                    },
                ),
            ]),
        ),
    ]))
}

fn op_strict_ed25519(input_members: &[(String, Json)]) -> Result<Json, OpFailure> {
    let fields = take_fields(
        input_members,
        &["publicKeyHex", "messageHex", "signatureHex"],
        "strictEd25519 input",
    )?;
    // Lengths are deliberately unconstrained: the production strict
    // verifier classifies them (section 3.3 rules 1 and 2).
    let public_key = parse_hex(require_str(&fields, "publicKeyHex")?, "publicKeyHex")?;
    let message = parse_hex(require_str(&fields, "messageHex")?, "messageHex")?;
    let signature = parse_hex(require_str(&fields, "signatureHex")?, "signatureHex")?;
    let valid = crypto::verify_followee_ed25519_unsized(&public_key, &message, &signature);
    Ok(obj(vec![("valid", Json::Bool(valid))]))
}

fn op_next_timestamp(input_members: &[(String, Json)]) -> Result<Json, OpFailure> {
    let fields = take_fields(
        input_members,
        &["nowMs", "previousTimestampMs"],
        "nextTimestamp input",
    )?;
    let now_ms = parse_dec_u64(require_str(&fields, "nowMs")?, "nowMs")?;
    let previous = optional_str(&fields, "previousTimestampMs")?
        .map(|text| parse_dec_u64(text, "previousTimestampMs"))
        .transpose()?;
    Ok(match timestamp::next_timestamp(now_ms, previous) {
        Ok(value) => obj(vec![("timestampMs", dec(value)), ("error", Json::Null)]),
        Err(_) => obj(vec![
            ("timestampMs", Json::Null),
            ("error", Json::str("overflow")),
        ]),
    })
}

fn op_validate_cbor(input_members: &[(String, Json)]) -> Result<Json, OpFailure> {
    let fields = take_fields(
        input_members,
        &["cborHex", "maxDepth", "maxMembers"],
        "validateCbor input",
    )?;
    let bytes = parse_hex(require_str(&fields, "cborHex")?, "cborHex")?;
    let max_depth = parse_dec_u64(require_str(&fields, "maxDepth")?, "maxDepth")?;
    let max_members = parse_dec_u64(require_str(&fields, "maxMembers")?, "maxMembers")?;
    // Out-of-domain limits are input errors, not protocol results.
    if max_depth > u64::from(crate::limits::MAX_BODY_DEPTH) {
        return Err(input("maxDepth must be within \"0\"..\"8\""));
    }
    if max_members > u64::from(crate::limits::MAX_BODY_MEMBERS) {
        return Err(input("maxMembers must be within \"0\"..\"256\""));
    }
    // The domain checks above bound both values, so the conversions hold.
    let depth =
        u32::try_from(max_depth).map_err(|_| input("maxDepth must be within \"0\"..\"8\""))?;
    let members = u32::try_from(max_members)
        .map_err(|_| input("maxMembers must be within \"0\"..\"256\""))?;
    match crate::validate_cbor(&bytes, depth, members) {
        Ok(()) => Ok(obj(vec![("valid", Json::Bool(true))])),
        Err(e) => Err(OpFailure::Protocol(e.symbol())),
    }
}

fn op_receive_publish_response(input_members: &[(String, Json)]) -> Result<Json, OpFailure> {
    let fields = take_fields(
        input_members,
        &["responseHex"],
        "receivePublishResponse input",
    )?;
    let bytes = parse_hex(require_str(&fields, "responseHex")?, "responseHex")?;
    // The exact production wrapper-acceptance path used by
    // `RelayClient::publish`, enforcing the specification v0.9.2
    // status-dependent field-presence rules.
    let response = crate::relay::wire::parse_publish_response(&bytes)
        .map_err(|e| OpFailure::Protocol(e.symbol()))?;
    Ok(obj(vec![
        ("status", dec(response.status)),
        ("errorCode", response.error_code.map_or(Json::Null, dec)),
    ]))
}

fn op_select_current(input_members: &[(String, Json)]) -> Result<Json, OpFailure> {
    let fields = take_fields(
        input_members,
        &[
            "targetDid",
            "candidateEnvelopesHex",
            "nowMs",
            "stickyAuthority",
        ],
        "selectCurrent input",
    )?;
    let target = crate::did::FolloweeDid::parse(require_str(&fields, "targetDid")?)
        .map_err(|e| OpFailure::Protocol(VerifyError::from(e).symbol()))?;
    let now_ms = parse_dec_u64(require_str(&fields, "nowMs")?, "nowMs")?;
    let sticky = match require_str(&fields, "stickyAuthority")? {
        "unknown" => ordering::AuthorityState::Unknown,
        "root" => ordering::AuthorityState::Root,
        "rootRevoked" => ordering::AuthorityState::RootRevoked,
        _ => {
            return Err(input(
                "stickyAuthority must be \"unknown\", \"root\", or \"rootRevoked\"",
            ));
        }
    };
    let candidates = match fields.get("candidateEnvelopesHex") {
        Some(Json::Array(items)) => items,
        Some(_) => return Err(input("candidateEnvelopesHex must be an array")),
        None => return Err(input("missing member `candidateEnvelopesHex`")),
    };
    // Every candidate is verified for the explicit target through complete
    // production record verification; the subject is never inferred from a
    // candidate. Candidates failing verification supply nothing.
    let mut verified = Vec::new();
    for (index, item) in candidates.iter().enumerate() {
        let Json::Str(text) = item else {
            return Err(input(format!(
                "candidateEnvelopesHex[{index}] must be a hex string"
            )));
        };
        let bytes = parse_hex(text, "candidateEnvelopesHex entry")?;
        if let Ok(candidate) = verify::verify_record(&target, &bytes) {
            verified.push(candidate);
        }
    }
    let selection = ordering::select_current(&target, &verified, now_ms, sticky);
    Ok(obj(vec![
        (
            "winnerRecordBodyDigestHex",
            selection
                .winner
                .map_or(Json::Null, |w| hex_json(w.body_digest())),
        ),
        (
            "authorityState",
            Json::str(match selection.authority_state {
                ordering::AuthorityState::Unknown => "unknown",
                ordering::AuthorityState::Root => "root",
                ordering::AuthorityState::RootRevoked => "rootRevoked",
            }),
        ),
    ]))
}

// ---------------------------------------------------------------------------
// Structured contact and typed extension conversions
// ---------------------------------------------------------------------------

fn contact_from_json(members: &[(String, Json)]) -> Result<ContactDocument, OpFailure> {
    let fields = take_fields(
        members,
        &[
            "displayName",
            "summary",
            "avatar",
            "alsoKnownAs",
            "services",
            "migration",
            "extensions",
        ],
        "contact",
    )?;
    let mut doc = ContactDocument {
        display_name: optional_str(&fields, "displayName")?.map(str::to_owned),
        summary: optional_str(&fields, "summary")?.map(str::to_owned),
        avatar: optional_str(&fields, "avatar")?.map(str::to_owned),
        ..ContactDocument::default()
    };
    match fields.get("alsoKnownAs") {
        Some(Json::Array(items)) => {
            for (index, item) in items.iter().enumerate() {
                let Json::Str(text) = item else {
                    return Err(input(format!("alsoKnownAs[{index}] must be a string")));
                };
                doc.also_known_as.push(text.clone());
            }
        }
        Some(Json::Null) | None => {}
        Some(_) => return Err(input("alsoKnownAs must be an array or null")),
    }
    match fields.get("services") {
        Some(Json::Array(items)) => {
            for item in items {
                let Json::Object(service_members) = item else {
                    return Err(input("each service must be a JSON object"));
                };
                doc.services.push(service_from_json(service_members)?);
            }
        }
        Some(Json::Null) | None => {}
        Some(_) => return Err(input("services must be an array or null")),
    }
    match fields.get("migration") {
        Some(Json::Object(migration_members)) => {
            let migration = migration_from_json(migration_members)?;
            // Constructor canonicalization (interface revision 2): a
            // migration object whose members are all null is an empty map
            // and requests omission of label 5, exactly like `null`.
            if migration.predecessor.is_some() || migration.successor.is_some() {
                doc.migration = Some(migration);
            }
        }
        Some(Json::Null) | None => {}
        Some(_) => return Err(input("migration must be an object or null")),
    }
    match fields.get("extensions") {
        Some(Json::Object(extension_members)) => {
            doc.extensions = extension_map_from_json(extension_members)?;
        }
        Some(Json::Null) | None => {}
        Some(_) => return Err(input("contact extensions must be an object or null")),
    }
    Ok(doc)
}

fn service_from_json(members: &[(String, Json)]) -> Result<ServiceEntry, OpFailure> {
    let fields = take_fields(
        members,
        &[
            "id",
            "type",
            "endpoint",
            "mediaType",
            "label",
            "language",
            "rel",
        ],
        "service",
    )?;
    Ok(ServiceEntry {
        id: require_str(&fields, "id")?.to_owned(),
        service_type: require_str(&fields, "type")?.to_owned(),
        endpoint: require_str(&fields, "endpoint")?.to_owned(),
        media_type: optional_str(&fields, "mediaType")?.map(str::to_owned),
        label: optional_str(&fields, "label")?.map(str::to_owned),
        language: optional_str(&fields, "language")?.map(str::to_owned),
        rel: optional_str(&fields, "rel")?.map(str::to_owned),
    })
}

fn migration_from_json(members: &[(String, Json)]) -> Result<Migration, OpFailure> {
    let fields = take_fields(members, &["predecessor", "successor"], "migration")?;
    // A migration value that is not a canonical v1 Followee DID violates
    // the section 7.4 contact schema — the same classification the
    // production record parser applies.
    let parse_did = |text: &str| {
        crate::did::FolloweeDid::parse(text)
            .map_err(|_| OpFailure::Protocol(VerifyError::SchemaViolation.symbol()))
    };
    Ok(Migration {
        predecessor: optional_str(&fields, "predecessor")?
            .map(parse_did)
            .transpose()?,
        successor: optional_str(&fields, "successor")?
            .map(parse_did)
            .transpose()?,
    })
}

fn extension_map_from_json(members: &[(String, Json)]) -> Result<ExtensionMap, OpFailure> {
    let mut map = ExtensionMap::new();
    for (uri, value) in members {
        map.insert(uri.clone(), typed_value_from_json(value)?);
    }
    Ok(map)
}

/// Converts one interface typed extension value into the production
/// [`ExtensionValue`]. Shape faults are input-contract violations; semantic
/// validity (URI keys, aggregate limits, duplicate nested keys) is decided
/// later by production validation.
fn typed_value_from_json(value: &Json) -> Result<ExtensionValue, OpFailure> {
    let Json::Object(members) = value else {
        return Err(input("typed extension value must be a JSON object"));
    };
    let fields = take_fields(
        members,
        &["type", "value", "hex", "items", "entries"],
        "typed extension value",
    )?;
    let type_name = require_str(&fields, "type")?;
    let only = |allowed: &[&str]| -> Result<(), OpFailure> {
        for name in ["value", "hex", "items", "entries"] {
            if fields.contains_key(name) && !allowed.contains(&name) {
                return Err(input(format!(
                    "member `{name}` is not permitted for type `{type_name}`"
                )));
            }
        }
        Ok(())
    };
    match type_name {
        "uint" => {
            only(&["value"])?;
            let text = require_str(&fields, "value")?;
            Ok(ExtensionValue::Unsigned(parse_dec_u64(text, "uint value")?))
        }
        "nint" => {
            only(&["value"])?;
            let text = require_str(&fields, "value")?;
            Ok(ExtensionValue::Negative(parse_nint_magnitude(text)?))
        }
        "text" => {
            only(&["value"])?;
            Ok(ExtensionValue::Text(
                require_str(&fields, "value")?.to_owned(),
            ))
        }
        "bytes" => {
            only(&["hex"])?;
            let text = require_str(&fields, "hex")?;
            Ok(ExtensionValue::Bytes(parse_hex(text, "bytes hex")?))
        }
        "bool" => {
            only(&["value"])?;
            match fields.get("value") {
                Some(Json::Bool(b)) => Ok(ExtensionValue::Bool(*b)),
                _ => Err(input("bool value must be a JSON boolean")),
            }
        }
        "null" => {
            only(&[])?;
            Ok(ExtensionValue::Null)
        }
        "array" => {
            only(&["items"])?;
            match fields.get("items") {
                Some(Json::Array(items)) => Ok(ExtensionValue::Array(
                    items
                        .iter()
                        .map(typed_value_from_json)
                        .collect::<Result<_, _>>()?,
                )),
                _ => Err(input("array items must be a JSON array")),
            }
        }
        "map" => {
            only(&["entries"])?;
            let Some(Json::Array(entries)) = fields.get("entries") else {
                return Err(input("map entries must be a JSON array"));
            };
            let mut converted = Vec::with_capacity(entries.len());
            for entry in entries {
                let Json::Object(entry_members) = entry else {
                    return Err(input("each map entry must be a JSON object"));
                };
                let entry_fields = take_fields(entry_members, &["key", "value"], "map entry")?;
                let key = match entry_fields.get("key") {
                    Some(key_json) => typed_key_from_json(key_json)?,
                    None => return Err(input("missing member `key` in map entry")),
                };
                let value = match entry_fields.get("value") {
                    Some(value_json) => typed_value_from_json(value_json)?,
                    None => return Err(input("missing member `value` in map entry")),
                };
                converted.push((key, value));
            }
            // Entries are converted in received order. The INTERFACE.md
            // requirement that entries encode in deterministic CBOR key
            // order regardless of their JSON order is discharged by the
            // production deterministic writer, which sorts every map by
            // encoded key; production validation rejects any duplicate key
            // before encoding.
            Ok(ExtensionValue::Map(converted))
        }
        other => Err(input(format!("unknown typed value type `{other}`"))),
    }
}

fn typed_key_from_json(value: &Json) -> Result<ExtensionKey, OpFailure> {
    // Map keys are restricted to uint, nint, and text (Appendix A
    // `extension-inner-key`).
    match typed_value_from_json(value)? {
        ExtensionValue::Unsigned(v) => Ok(ExtensionKey::Unsigned(v)),
        ExtensionValue::Negative(m) => Ok(ExtensionKey::Negative(m)),
        ExtensionValue::Text(s) => Ok(ExtensionKey::Text(s)),
        _ => Err(input("map keys are restricted to uint, nint, and text")),
    }
}

/// Parses a canonical negative decimal string `-1 ..= -(2^64)` into the
/// CBOR negative-integer magnitude `m` where the value is `-(1 + m)`.
fn parse_nint_magnitude(text: &str) -> Result<u64, OpFailure> {
    let digits = text
        .strip_prefix('-')
        .ok_or_else(|| input("nint value must be a negative decimal string"))?;
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) || digits.starts_with('0') {
        return Err(input(
            "nint value must be a canonical negative decimal string",
        ));
    }
    let magnitude: u128 = digits
        .parse()
        .map_err(|_| input("nint value is out of range"))?;
    // The canonical-form checks above exclude "0", so magnitude ≥ 1; the
    // most negative permitted value −2^64 has magnitude u64::MAX + 1, and
    // the conversion below rejects anything larger.
    u64::try_from(magnitude.saturating_sub(1)).map_err(|_| input("nint value is out of range"))
}

// ---------------------------------------------------------------------------
// Result projections (verifyRecord)
// ---------------------------------------------------------------------------

/// The closed eight-member `record.descriptor` projection of authoring
/// revision 2 (Campaign 1 finding I2): descriptor content plus total
/// functions of the descriptor bytes, produced by the production
/// derivation chain. Verification enforced the deterministic profile on
/// the carried descriptor, so the deterministic re-encoding below is
/// byte-identical to the descriptor bytes as carried in the verified
/// record, and the derived digest, multihash, and DID come from the same
/// production path `deriveIdentity` uses — the coherence relationships
/// hold by construction, never from cached or separately obtained values.
fn descriptor_to_json(descriptor: &AuthorityDescriptor) -> Json {
    let descriptor_cbor = descriptor.encode();
    let did = descriptor.did();
    obj(vec![
        ("descriptorVersion", dec(record::DESCRIPTOR_VERSION)),
        ("rootKeySuite", Json::str(record::SUITE_ED25519.to_string())),
        ("rootPublicKeyHex", hex_json(&descriptor.root_key)),
        (
            "revocationCommitmentHex",
            hex_json(&descriptor.revocation_commitment),
        ),
        ("authorityDescriptorCborHex", hex_json(&descriptor_cbor)),
        (
            "authorityDescriptorDigestHex",
            hex_json(did.digest().as_slice()),
        ),
        ("multihashHex", hex_json(did.multihash_bytes())),
        ("did", Json::str(did.as_str())),
    ])
}

/// The authority-dependent `record.revocationKey` projection of record-body
/// label `5`: JSON `null` exactly for a root record (Specification
/// Section 5.1 requires the label absent), the three-member `public-key`
/// projection exactly for a rootRevoked record.
fn revocation_key_to_json(body: &RecordBody) -> Json {
    match body.authority {
        Authority::Root => Json::Null,
        Authority::RootRevoked => {
            // Complete verification enforced the label-5 presence rule, and
            // `VerifiedRecord` values are unfabricable, so the key exists.
            let key = body
                .revocation_key
                .as_ref()
                .expect("a verified RootRevoked record carries label 5");
            obj(vec![
                ("suite", Json::str(record::SUITE_ED25519.to_string())),
                ("publicKeyHex", hex_json(key)),
                (
                    "publicKeyCborHex",
                    hex_json(&record::encode_public_key(key)),
                ),
            ])
        }
    }
}

/// The lossless `record.contact` projection: `null` for an absent wire
/// label, `[]`/`{}`/`""` for a present-empty one. Collection presence
/// comes from the production parser's wire observation; text presence is
/// carried by the typed model itself (`Some("")` is a present empty text).
fn contact_to_json(contact: &ContactDocument, presence: crate::contact::ContactPresence) -> Json {
    let opt = |value: &Option<String>| value.as_deref().map_or(Json::Null, Json::str);
    obj(vec![
        ("displayName", opt(&contact.display_name)),
        ("summary", opt(&contact.summary)),
        ("avatar", opt(&contact.avatar)),
        (
            "alsoKnownAs",
            if presence.also_known_as {
                Json::Array(
                    contact
                        .also_known_as
                        .iter()
                        .map(|uri| Json::str(uri.as_str()))
                        .collect(),
                )
            } else {
                Json::Null
            },
        ),
        (
            "services",
            if presence.services {
                Json::Array(
                    contact
                        .services
                        .iter()
                        .map(|service| {
                            obj(vec![
                                ("id", Json::str(service.id.as_str())),
                                ("type", Json::str(service.service_type.as_str())),
                                ("endpoint", Json::str(service.endpoint.as_str())),
                                ("mediaType", opt(&service.media_type)),
                                ("label", opt(&service.label)),
                                ("language", opt(&service.language)),
                                ("rel", opt(&service.rel)),
                            ])
                        })
                        .collect(),
                )
            } else {
                Json::Null
            },
        ),
        (
            "migration",
            contact.migration.as_ref().map_or(Json::Null, |migration| {
                let did = |value: &Option<crate::did::FolloweeDid>| {
                    value.as_ref().map_or(Json::Null, |d| Json::str(d.as_str()))
                };
                obj(vec![
                    ("predecessor", did(&migration.predecessor)),
                    ("successor", did(&migration.successor)),
                ])
            }),
        ),
        (
            "extensions",
            if presence.extensions {
                extension_map_to_json(&contact.extensions)
            } else {
                Json::Null
            },
        ),
    ])
}

fn extension_map_to_json(map: &ExtensionMap) -> Json {
    Json::Object(
        map.iter()
            .map(|(uri, value)| (uri.clone(), typed_value_to_json(value)))
            .collect(),
    )
}

fn typed_value_to_json(value: &ExtensionValue) -> Json {
    match value {
        ExtensionValue::Unsigned(v) => obj(vec![("type", Json::str("uint")), ("value", dec(*v))]),
        ExtensionValue::Negative(m) => obj(vec![
            ("type", Json::str("nint")),
            (
                "value",
                Json::Str(format!("-{}", u128::from(*m).saturating_add(1))),
            ),
        ]),
        ExtensionValue::Text(s) => obj(vec![
            ("type", Json::str("text")),
            ("value", Json::str(s.as_str())),
        ]),
        ExtensionValue::Bytes(b) => obj(vec![("type", Json::str("bytes")), ("hex", hex_json(b))]),
        ExtensionValue::Bool(b) => {
            obj(vec![("type", Json::str("bool")), ("value", Json::Bool(*b))])
        }
        ExtensionValue::Null => obj(vec![("type", Json::str("null"))]),
        ExtensionValue::Array(items) => obj(vec![
            ("type", Json::str("array")),
            (
                "items",
                Json::Array(items.iter().map(typed_value_to_json).collect()),
            ),
        ]),
        ExtensionValue::Map(entries) => obj(vec![
            ("type", Json::str("map")),
            (
                "entries",
                Json::Array(
                    entries
                        .iter()
                        .map(|(key, entry_value)| {
                            obj(vec![
                                ("key", typed_key_to_json(key)),
                                ("value", typed_value_to_json(entry_value)),
                            ])
                        })
                        .collect(),
                ),
            ),
        ]),
    }
}

fn typed_key_to_json(key: &ExtensionKey) -> Json {
    match key {
        ExtensionKey::Unsigned(v) => typed_value_to_json(&ExtensionValue::Unsigned(*v)),
        ExtensionKey::Negative(m) => typed_value_to_json(&ExtensionValue::Negative(*m)),
        ExtensionKey::Text(s) => typed_value_to_json(&ExtensionValue::Text(s.clone())),
    }
}
