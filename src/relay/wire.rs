//! Relay API CBOR message codec (specification section 12 and Appendix A).
//!
//! Requests are validated as complete deterministic items under the section
//! 15.2 relay-message limits before parsing, and the v1 parsers reject
//! unknown top-level integer labels rather than guessing their semantics
//! (section 12.1). Byte strings inside a wrapper — cursors and carried Full
//! candidates — stay opaque under the section 6.1.1 boundary rule; nothing
//! here re-interprets their contents. Responses are produced with the same
//! deterministic writer used by every other Followee structure.

use crate::cbor::{
    self, MAJOR_ARRAY, MAJOR_BSTR, MAJOR_MAP, MAJOR_SIMPLE, MAJOR_TSTR, MAJOR_UINT, Reader,
    SIMPLE_NULL,
};
use crate::store::{ChangeRow, DirectoryEntry, EntryPayload, RelayIdentity};

/// Relay API CBOR nesting-depth cap (specification section 15.2).
pub(crate) const RELAY_API_MAX_DEPTH: u32 = 8;

/// Protocol hard maximum resolve-request DID count (section 15.2).
pub(crate) const MAX_RESOLVE_DIDS: usize = 256;

/// Advertised maximum resolve-response bytes: the section 12.3 conforming
/// minimum bound.
pub(crate) const MAX_RESOLVE_RESPONSE_BYTES: usize = 1024 * 1024;

/// Protocol hard maximum `changes` item count (section 15.2).
pub(crate) const MAX_CHANGES_ITEMS: u64 = 1024;

/// Protocol hard maximum `changes` response bytes (section 15.2).
pub(crate) const MAX_CHANGES_BYTES: u64 = 4 * 1024 * 1024;

/// Maximum cursor length in bytes (section 15.2).
pub(crate) const MAX_CURSOR_BYTES: usize = 128;

/// Member budget for outer relay requests: a maximal resolve request holds
/// two map entries plus 256 array elements; nothing larger is a valid v1
/// request, so anything past this bound is rejected before allocation.
const RELAY_REQUEST_MAX_MEMBERS: u32 = 300;

/// An outer-request fault: the request failed section 6.1 well-formedness,
/// basic validity, deterministic-profile, or top-level schema validation and
/// protocol item processing did not begin. The transport layer answers HTTP
/// `400` with no per-item results (sections 12.1 and 15.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OuterRequestFault;

/// Parsed `v1/resolve` request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ResolveRequest {
    /// Requested DID strings, order and duplicates preserved exactly.
    pub dids: Vec<String>,
}

/// Parsed `v1/changes` request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ChangesRequest {
    /// The opaque cursor bytes, or `None` for a bounded initial enumeration.
    pub cursor: Option<Vec<u8>>,
    /// Maximum entries the caller will accept; validated `1..=1024`.
    pub item_limit: u64,
    /// Maximum response bytes the caller will accept; validated `1..=4 MiB`.
    pub byte_limit: u64,
}

fn validated_reader(bytes: &[u8]) -> Result<Reader<'_>, OuterRequestFault> {
    cbor::validate(bytes, RELAY_API_MAX_DEPTH, RELAY_REQUEST_MAX_MEMBERS)
        .map_err(|_| OuterRequestFault)?;
    Ok(Reader::new(bytes))
}

/// Parses a `v1/resolve` request (specification section 12.3).
pub(crate) fn parse_resolve_request(bytes: &[u8]) -> Result<ResolveRequest, OuterRequestFault> {
    let mut r = validated_reader(bytes)?;
    let head = r.read_head().map_err(|_| OuterRequestFault)?;
    if head.major != MAJOR_MAP {
        return Err(OuterRequestFault);
    }
    let mut version = None;
    let mut dids: Option<Vec<String>> = None;
    for _ in 0..head.arg {
        let key = r.read_head().map_err(|_| OuterRequestFault)?;
        if key.major != MAJOR_UINT {
            return Err(OuterRequestFault);
        }
        match key.arg {
            0 => {
                let value = r.read_head().map_err(|_| OuterRequestFault)?;
                if value.major != MAJOR_UINT || value.arg != 1 {
                    return Err(OuterRequestFault);
                }
                version = Some(());
            }
            1 => {
                let value = r.read_head().map_err(|_| OuterRequestFault)?;
                if value.major != MAJOR_ARRAY {
                    return Err(OuterRequestFault);
                }
                let count = usize::try_from(value.arg).map_err(|_| OuterRequestFault)?;
                if count == 0 || count > MAX_RESOLVE_DIDS {
                    return Err(OuterRequestFault);
                }
                let mut list = Vec::with_capacity(count);
                for _ in 0..count {
                    let item = r.read_head().map_err(|_| OuterRequestFault)?;
                    if item.major != MAJOR_TSTR {
                        return Err(OuterRequestFault);
                    }
                    // A syntactically malformed DID carried as valid UTF-8 is
                    // protocol-level input classified per DID, not an outer
                    // fault (section 15.4); only the string type is enforced
                    // here.
                    let text = r.read_text_body(item.arg).map_err(|_| OuterRequestFault)?;
                    list.push(text.to_owned());
                }
                dids = Some(list);
            }
            _ => return Err(OuterRequestFault),
        }
    }
    version.ok_or(OuterRequestFault)?;
    let dids = dids.ok_or(OuterRequestFault)?;
    Ok(ResolveRequest { dids })
}

/// Parses a `v1/changes` request, enforcing the section 12.6 value bounds as
/// top-level schema validation.
pub(crate) fn parse_changes_request(bytes: &[u8]) -> Result<ChangesRequest, OuterRequestFault> {
    let mut r = validated_reader(bytes)?;
    let head = r.read_head().map_err(|_| OuterRequestFault)?;
    if head.major != MAJOR_MAP {
        return Err(OuterRequestFault);
    }
    let mut version = None;
    let mut cursor: Option<Option<Vec<u8>>> = None;
    let mut item_limit = None;
    let mut byte_limit = None;
    for _ in 0..head.arg {
        let key = r.read_head().map_err(|_| OuterRequestFault)?;
        if key.major != MAJOR_UINT {
            return Err(OuterRequestFault);
        }
        match key.arg {
            0 => {
                let value = r.read_head().map_err(|_| OuterRequestFault)?;
                if value.major != MAJOR_UINT || value.arg != 1 {
                    return Err(OuterRequestFault);
                }
                version = Some(());
            }
            1 => {
                let value = r.read_head().map_err(|_| OuterRequestFault)?;
                if value.major == MAJOR_SIMPLE && value.arg == SIMPLE_NULL {
                    cursor = Some(None);
                } else if value.major == MAJOR_BSTR {
                    let raw = r
                        .read_bytes_body(value.arg)
                        .map_err(|_| OuterRequestFault)?;
                    if raw.len() > MAX_CURSOR_BYTES {
                        return Err(OuterRequestFault);
                    }
                    cursor = Some(Some(raw.to_vec()));
                } else {
                    return Err(OuterRequestFault);
                }
            }
            2 => {
                let value = r.read_head().map_err(|_| OuterRequestFault)?;
                if value.major != MAJOR_UINT || value.arg == 0 || value.arg > MAX_CHANGES_ITEMS {
                    return Err(OuterRequestFault);
                }
                item_limit = Some(value.arg);
            }
            3 => {
                let value = r.read_head().map_err(|_| OuterRequestFault)?;
                if value.major != MAJOR_UINT || value.arg == 0 || value.arg > MAX_CHANGES_BYTES {
                    return Err(OuterRequestFault);
                }
                byte_limit = Some(value.arg);
            }
            _ => return Err(OuterRequestFault),
        }
    }
    version.ok_or(OuterRequestFault)?;
    Ok(ChangesRequest {
        cursor: cursor.ok_or(OuterRequestFault)?,
        item_limit: item_limit.ok_or(OuterRequestFault)?,
        byte_limit: byte_limit.ok_or(OuterRequestFault)?,
    })
}

fn label(value: u64) -> Vec<u8> {
    cbor::encode_with(|w| w.uint(value))
}

/// Encodes the `v1/info` response (specification section 12.2).
pub(crate) fn encode_info(identity: &RelayIdentity, capabilities: u64, base_uri: &str) -> Vec<u8> {
    let limits = cbor::encode_with(|w| {
        w.map_entries(vec![
            (
                label(0),
                cbor::encode_with(|w| w.uint(crate::limits::MAX_RECORD_BYTES as u64)),
            ),
            (
                label(1),
                cbor::encode_with(|w| w.uint(MAX_RESOLVE_DIDS as u64)),
            ),
            (
                label(2),
                cbor::encode_with(|w| w.uint(MAX_RESOLVE_RESPONSE_BYTES as u64)),
            ),
            (label(3), cbor::encode_with(|w| w.uint(MAX_CHANGES_ITEMS))),
            (label(4), cbor::encode_with(|w| w.uint(MAX_CHANGES_BYTES))),
        ]);
    });
    cbor::encode_with(|w| {
        w.map_entries(vec![
            (label(0), cbor::encode_with(|w| w.uint(1))),
            (label(1), cbor::encode_with(|w| w.bstr(&identity.relay_id))),
            (label(2), cbor::encode_with(|w| w.uint(capabilities))),
            (
                label(3),
                cbor::encode_with(|w| {
                    w.array(1);
                    w.uint(1);
                }),
            ),
            (
                label(4),
                cbor::encode_with(|w| {
                    w.array(1);
                    w.int(crate::record::SUITE_ED25519);
                }),
            ),
            (label(5), limits),
            (
                label(6),
                cbor::encode_with(|w| w.bstr(&identity.cursor_generation)),
            ),
            (
                label(7),
                cbor::encode_with(|w| w.bstr(&identity.directory_generation)),
            ),
            (label(8), cbor::encode_with(|w| w.tstr(base_uri))),
        ]);
    })
}

/// One aligned per-DID resolve result (specification section 12.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ResolveResult {
    /// Complete envelope bytes as an untrusted candidate.
    Full(Vec<u8>),
    /// Relay index under the response's directory generation.
    Ref(u32),
    /// Local absence, not global non-existence.
    Absent,
    /// Per-DID error code from section 15.3.
    Error(u64),
}

/// Encodes one resolve result.
pub(crate) fn encode_resolve_result(result: &ResolveResult) -> Vec<u8> {
    match result {
        ResolveResult::Full(bytes) => cbor::encode_with(|w| {
            w.map_entries(vec![
                (label(0), cbor::encode_with(|w| w.uint(0))),
                (label(1), cbor::encode_with(|w| w.bstr(bytes))),
            ]);
        }),
        ResolveResult::Ref(index) => cbor::encode_with(|w| {
            w.map_entries(vec![
                (label(0), cbor::encode_with(|w| w.uint(1))),
                (label(1), cbor::encode_with(|w| w.uint(u64::from(*index)))),
            ]);
        }),
        ResolveResult::Absent => cbor::encode_with(|w| {
            w.map_entries(vec![(label(0), cbor::encode_with(|w| w.uint(2)))]);
        }),
        ResolveResult::Error(code) => cbor::encode_with(|w| {
            w.map_entries(vec![
                (label(0), cbor::encode_with(|w| w.uint(3))),
                (label(2), cbor::encode_with(|w| w.uint(*code))),
            ]);
        }),
    }
}

/// Encodes the `v1/resolve` response wrapper around pre-encoded results.
pub(crate) fn encode_resolve_response(
    directory_generation: &[u8; 16],
    encoded_results: &[Vec<u8>],
) -> Vec<u8> {
    let results = cbor::encode_with(|w| {
        w.array(encoded_results.len() as u64);
        for encoded in encoded_results {
            w.raw(encoded);
        }
    });
    cbor::encode_with(|w| {
        w.map_entries(vec![
            (label(0), cbor::encode_with(|w| w.uint(1))),
            (
                label(1),
                cbor::encode_with(|w| w.bstr(directory_generation)),
            ),
            (label(2), results),
        ]);
    })
}

/// Encodes the `v1/directory` response (specification section 12.4).
pub(crate) fn encode_directory(
    directory_generation: &[u8; 16],
    entries: &[DirectoryEntry],
) -> Vec<u8> {
    let list = cbor::encode_with(|w| {
        w.array(entries.len() as u64);
        for entry in entries {
            let encoded = cbor::encode_with(|w| {
                w.map_entries(vec![
                    (
                        label(0),
                        cbor::encode_with(|w| w.uint(u64::from(entry.index))),
                    ),
                    (label(1), cbor::encode_with(|w| w.bstr(&entry.relay_id))),
                    (label(2), cbor::encode_with(|w| w.tstr(&entry.endpoint))),
                    (label(3), cbor::encode_with(|w| w.uint(entry.capabilities))),
                ]);
            });
            w.raw(&encoded);
        }
    });
    cbor::encode_with(|w| {
        w.map_entries(vec![
            (label(0), cbor::encode_with(|w| w.uint(1))),
            (
                label(1),
                cbor::encode_with(|w| w.bstr(directory_generation)),
            ),
            (label(2), list),
        ]);
    })
}

/// Encodes the `v1/publish` response (specification section 12.5). The error
/// code accompanies only a rejection.
pub(crate) fn encode_publish_response(status: u64, error_code: Option<u64>) -> Vec<u8> {
    let mut entries = vec![
        (label(0), cbor::encode_with(|w| w.uint(1))),
        (label(1), cbor::encode_with(|w| w.uint(status))),
    ];
    if let Some(code) = error_code {
        entries.push((label(2), cbor::encode_with(|w| w.uint(code))));
    }
    cbor::encode_with(|w| w.map_entries(entries))
}

/// Encodes one `v1/changes` change entry.
pub(crate) fn encode_change_entry(row: &ChangeRow) -> Vec<u8> {
    let payload = match &row.payload {
        EntryPayload::Full(bytes) => cbor::encode_with(|w| {
            w.map_entries(vec![
                (label(0), cbor::encode_with(|w| w.uint(0))),
                (label(1), cbor::encode_with(|w| w.bstr(bytes))),
            ]);
        }),
        EntryPayload::Ref(index) => cbor::encode_with(|w| {
            w.map_entries(vec![
                (label(0), cbor::encode_with(|w| w.uint(1))),
                (label(1), cbor::encode_with(|w| w.uint(u64::from(*index)))),
            ]);
        }),
    };
    cbor::encode_with(|w| {
        w.array(3);
        w.tstr(&row.did);
        w.raw(&payload);
        w.uint(row.last_updated);
    })
}

/// Encodes a `v1/changes` success response: labels `0`–`5` with `errorCode`
/// absent (specification section 12.6).
pub(crate) fn encode_changes_success(
    encoded_entries: &[Vec<u8>],
    next_cursor: &[u8],
    has_more: bool,
    directory_generation: &[u8; 16],
) -> Vec<u8> {
    let entries = cbor::encode_with(|w| {
        w.array(encoded_entries.len() as u64);
        for encoded in encoded_entries {
            w.raw(encoded);
        }
    });
    cbor::encode_with(|w| {
        w.map_entries(vec![
            (label(0), cbor::encode_with(|w| w.uint(1))),
            (label(1), cbor::encode_with(|w| w.uint(0))),
            (label(2), entries),
            (label(3), cbor::encode_with(|w| w.bstr(next_cursor))),
            (label(4), cbor::encode_with(|w| w.bool(has_more))),
            (
                label(5),
                cbor::encode_with(|w| w.bstr(directory_generation)),
            ),
        ]);
    })
}

/// Encodes the exact two-field `ResetRequired` response: status `1` is the
/// sole v1 wire encoding, and every other label is forbidden (section 12.6).
pub(crate) fn encode_changes_reset() -> Vec<u8> {
    cbor::encode_with(|w| {
        w.map_entries(vec![
            (label(0), cbor::encode_with(|w| w.uint(1))),
            (label(1), cbor::encode_with(|w| w.uint(1))),
        ]);
    })
}

/// Encodes a `v1/changes` status-`2` error response: `errorCode` required,
/// entries, `nextCursor`, `hasMore`, and `directoryGeneration` forbidden.
pub(crate) fn encode_changes_error(error_code: u64) -> Vec<u8> {
    cbor::encode_with(|w| {
        w.map_entries(vec![
            (label(0), cbor::encode_with(|w| w.uint(1))),
            (label(1), cbor::encode_with(|w| w.uint(2))),
            (label(6), cbor::encode_with(|w| w.uint(error_code))),
        ]);
    })
}

// ---------------------------------------------------------------------------
// Client-side codec: request encoders and strict response parsers
// (specification sections 12.1–12.6; used only by the production relay
// client, the synchronization receiver, and the multi-relay resolver).
// ---------------------------------------------------------------------------

/// Encodes a deterministic `v1/resolve` request (specification section 12.3),
/// preserving order and duplicates exactly.
pub(crate) fn encode_resolve_request(dids: &[&str]) -> Vec<u8> {
    let list = cbor::encode_with(|w| {
        w.array(dids.len() as u64);
        for did in dids {
            w.tstr(did);
        }
    });
    cbor::encode_with(|w| {
        w.map_entries(vec![
            (label(0), cbor::encode_with(|w| w.uint(1))),
            (label(1), list),
        ]);
    })
}

/// Encodes a deterministic `v1/changes` request (specification section 12.6).
pub(crate) fn encode_changes_request(
    cursor: Option<&[u8]>,
    item_limit: u64,
    byte_limit: u64,
) -> Vec<u8> {
    let cursor_value = match cursor {
        Some(bytes) => cbor::encode_with(|w| w.bstr(bytes)),
        None => cbor::encode_with(|w| w.null()),
    };
    cbor::encode_with(|w| {
        w.map_entries(vec![
            (label(0), cbor::encode_with(|w| w.uint(1))),
            (label(1), cursor_value),
            (label(2), cbor::encode_with(|w| w.uint(item_limit))),
            (label(3), cbor::encode_with(|w| w.uint(byte_limit))),
        ]);
    })
}

/// Denial-of-service member caps for outer relay *responses*. Section 15.2
/// gives no member limit for relay messages, so these are implementation
/// bounds set above anything a section 15.2-conforming response can contain
/// (they are not schema limits; the exact schemas below still apply).
const INFO_RESPONSE_MAX_MEMBERS: u32 = 64;
const PUBLISH_RESPONSE_MAX_MEMBERS: u32 = 8;
const RESOLVE_RESPONSE_MAX_MEMBERS: u32 = 1_024;
const DIRECTORY_RESPONSE_MAX_MEMBERS: u32 = 24_576;
const CHANGES_RESPONSE_MAX_MEMBERS: u32 = 8_192;

/// Protocol hard maximum directory entries (section 15.2).
pub(crate) const MAX_DIRECTORY_ENTRIES: usize = 4_096;

use crate::error::VerifyError;

/// Validates an outer relay response as one complete deterministic CBOR item
/// (section 12.1: well-formedness, basic validity, and deterministic profile
/// apply to each outer response; byte strings within it stay opaque). The
/// returned classification is exact for the section 6.1 layers; every later
/// shape fault in the strict parsers is `schemaViolation`.
fn validated_response_reader(bytes: &[u8], max_members: u32) -> Result<Reader<'_>, VerifyError> {
    cbor::validate(bytes, RELAY_API_MAX_DEPTH, max_members).map_err(VerifyError::from)?;
    Ok(Reader::new(bytes))
}

/// Reads a map head, returning the entry count.
fn read_map_head(r: &mut Reader<'_>) -> Result<u64, VerifyError> {
    let head = r.read_head().map_err(|_| VerifyError::SchemaViolation)?;
    if head.major != MAJOR_MAP {
        return Err(VerifyError::SchemaViolation);
    }
    Ok(head.arg)
}

/// Reads one unsigned-integer map label.
fn read_label(r: &mut Reader<'_>) -> Result<u64, VerifyError> {
    let head = r.read_head().map_err(|_| VerifyError::SchemaViolation)?;
    if head.major != MAJOR_UINT {
        return Err(VerifyError::SchemaViolation);
    }
    Ok(head.arg)
}

fn read_uint(r: &mut Reader<'_>) -> Result<u64, VerifyError> {
    let head = r.read_head().map_err(|_| VerifyError::SchemaViolation)?;
    if head.major != MAJOR_UINT {
        return Err(VerifyError::SchemaViolation);
    }
    Ok(head.arg)
}

fn read_bool(r: &mut Reader<'_>) -> Result<bool, VerifyError> {
    let head = r.read_head().map_err(|_| VerifyError::SchemaViolation)?;
    if head.major != MAJOR_SIMPLE {
        return Err(VerifyError::SchemaViolation);
    }
    match head.arg {
        crate::cbor::SIMPLE_FALSE => Ok(false),
        crate::cbor::SIMPLE_TRUE => Ok(true),
        _ => Err(VerifyError::SchemaViolation),
    }
}

fn read_bstr<'a>(r: &mut Reader<'a>) -> Result<&'a [u8], VerifyError> {
    let head = r.read_head().map_err(|_| VerifyError::SchemaViolation)?;
    if head.major != MAJOR_BSTR {
        return Err(VerifyError::SchemaViolation);
    }
    r.read_bytes_body(head.arg)
        .map_err(|_| VerifyError::SchemaViolation)
}

fn read_bstr16(r: &mut Reader<'_>) -> Result<[u8; 16], VerifyError> {
    read_bstr(r)?
        .try_into()
        .map_err(|_| VerifyError::SchemaViolation)
}

fn read_tstr<'a>(r: &mut Reader<'a>) -> Result<&'a str, VerifyError> {
    let head = r.read_head().map_err(|_| VerifyError::SchemaViolation)?;
    if head.major != MAJOR_TSTR {
        return Err(VerifyError::SchemaViolation);
    }
    r.read_text_body(head.arg)
        .map_err(|_| VerifyError::SchemaViolation)
}

fn read_u32(r: &mut Reader<'_>) -> Result<u32, VerifyError> {
    u32::try_from(read_uint(r)?).map_err(|_| VerifyError::SchemaViolation)
}

/// Requires the version label `0` to carry protocol version `1`.
fn require_version_1(r: &mut Reader<'_>) -> Result<(), VerifyError> {
    if read_uint(r)? != 1 {
        return Err(VerifyError::SchemaViolation);
    }
    Ok(())
}

/// The advertised limits map (specification section 12.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelayLimits {
    /// Maximum complete Identity Record bytes.
    pub max_record_bytes: u64,
    /// Maximum resolve-request DID count.
    pub max_resolve_dids: u64,
    /// Maximum resolve-response bytes.
    pub max_resolve_response_bytes: u64,
    /// Maximum `changes` item count.
    pub max_changes_items: u64,
    /// Maximum `changes` response bytes.
    pub max_changes_bytes: u64,
}

/// A parsed `v1/info` response (specification section 12.2). Values are the
/// peer's claims; nothing here is verified identity content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayInfo {
    /// The peer's stable 16-byte relay instance identifier.
    pub relay_id: [u8; 16],
    /// Capability bit mask; unknown bits are ignored by callers.
    pub capabilities: u64,
    /// Advertised supported protocol versions.
    pub protocol_versions: Vec<u64>,
    /// Advertised supported signature suites.
    pub suites: Vec<i64>,
    /// Advertised limits.
    pub limits: RelayLimits,
    /// Current 16-byte cursor generation (opaque equality token).
    pub cursor_generation: [u8; 16],
    /// Current 16-byte directory generation (opaque equality token).
    pub directory_generation: [u8; 16],
    /// Advertised canonical base URI.
    pub base_uri: String,
}

/// Parses a `v1/info` response under the exact `relay-info` schema; unknown
/// core labels are a schema violation under protocol version 1
/// (section 12.1).
pub(crate) fn parse_info_response(bytes: &[u8]) -> Result<RelayInfo, VerifyError> {
    let mut r = validated_response_reader(bytes, INFO_RESPONSE_MAX_MEMBERS)?;
    let entries = read_map_head(&mut r)?;
    if entries != 9 {
        return Err(VerifyError::SchemaViolation);
    }
    let mut relay_id = None;
    let mut capabilities = None;
    let mut protocol_versions = None;
    let mut suites = None;
    let mut limits = None;
    let mut cursor_generation = None;
    let mut directory_generation = None;
    let mut base_uri = None;
    for _ in 0..entries {
        match read_label(&mut r)? {
            0 => require_version_1(&mut r)?,
            1 => relay_id = Some(read_bstr16(&mut r)?),
            2 => capabilities = Some(read_uint(&mut r)?),
            3 => {
                let head = r.read_head().map_err(|_| VerifyError::SchemaViolation)?;
                if head.major != MAJOR_ARRAY || head.arg == 0 {
                    return Err(VerifyError::SchemaViolation);
                }
                let mut versions = Vec::new();
                for _ in 0..head.arg {
                    versions.push(read_uint(&mut r)?);
                }
                protocol_versions = Some(versions);
            }
            4 => {
                let head = r.read_head().map_err(|_| VerifyError::SchemaViolation)?;
                if head.major != MAJOR_ARRAY || head.arg == 0 {
                    return Err(VerifyError::SchemaViolation);
                }
                let mut list = Vec::new();
                for _ in 0..head.arg {
                    let item = r.read_head().map_err(|_| VerifyError::SchemaViolation)?;
                    let value = match item.major {
                        MAJOR_UINT => {
                            i64::try_from(item.arg).map_err(|_| VerifyError::SchemaViolation)?
                        }
                        crate::cbor::MAJOR_NINT => i64::try_from(item.arg)
                            .ok()
                            .and_then(|magnitude| magnitude.checked_add(1))
                            .and_then(i64::checked_neg)
                            .ok_or(VerifyError::SchemaViolation)?,
                        _ => return Err(VerifyError::SchemaViolation),
                    };
                    list.push(value);
                }
                suites = Some(list);
            }
            5 => {
                let count = read_map_head(&mut r)?;
                if count != 5 {
                    return Err(VerifyError::SchemaViolation);
                }
                let mut values = [None; 5];
                for _ in 0..count {
                    let key = read_label(&mut r)?;
                    let slot = usize::try_from(key)
                        .ok()
                        .filter(|k| *k < 5)
                        .ok_or(VerifyError::SchemaViolation)?;
                    values[slot] = Some(read_uint(&mut r)?);
                }
                let field = |slot: usize| -> Result<u64, VerifyError> {
                    values[slot].ok_or(VerifyError::SchemaViolation)
                };
                limits = Some(RelayLimits {
                    max_record_bytes: field(0)?,
                    max_resolve_dids: field(1)?,
                    max_resolve_response_bytes: field(2)?,
                    max_changes_items: field(3)?,
                    max_changes_bytes: field(4)?,
                });
            }
            6 => cursor_generation = Some(read_bstr16(&mut r)?),
            7 => directory_generation = Some(read_bstr16(&mut r)?),
            8 => {
                let uri = read_tstr(&mut r)?;
                if uri.len() > crate::limits::MAX_URI_BYTES {
                    return Err(VerifyError::SchemaViolation);
                }
                base_uri = Some(uri.to_owned());
            }
            _ => return Err(VerifyError::SchemaViolation),
        }
    }
    // Section 12.2: a v1 implementation MUST include protocol version `1`
    // and signature suite `-19` in these arrays. An info response missing
    // either is non-conforming output; the strict client rejects it
    // completely rather than exposing partial peer metadata.
    let protocol_versions = protocol_versions.ok_or(VerifyError::SchemaViolation)?;
    if !protocol_versions.contains(&1) {
        return Err(VerifyError::SchemaViolation);
    }
    let suites = suites.ok_or(VerifyError::SchemaViolation)?;
    if !suites.contains(&crate::record::SUITE_ED25519) {
        return Err(VerifyError::SchemaViolation);
    }
    Ok(RelayInfo {
        relay_id: relay_id.ok_or(VerifyError::SchemaViolation)?,
        capabilities: capabilities.ok_or(VerifyError::SchemaViolation)?,
        protocol_versions,
        suites,
        limits: limits.ok_or(VerifyError::SchemaViolation)?,
        cursor_generation: cursor_generation.ok_or(VerifyError::SchemaViolation)?,
        directory_generation: directory_generation.ok_or(VerifyError::SchemaViolation)?,
        base_uri: base_uri.ok_or(VerifyError::SchemaViolation)?,
    })
}

/// A received per-DID resolve result: untrusted protocol data. Full bytes
/// are opaque candidates awaiting section 8.1 verification; a Ref is a
/// routing hint under the response's directory generation only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReceivedResult {
    /// Opaque candidate envelope bytes.
    Full(Vec<u8>),
    /// Relay index in the response's directory generation.
    Ref(u32),
    /// Local absence at that relay, never global non-existence.
    Absent,
    /// Per-DID section 15.3 error code: diagnostic from that relay only.
    Error(u64),
}

/// A parsed `v1/resolve` response wrapper (specification section 12.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceivedResolveResponse {
    /// The response's 16-byte directory generation.
    pub directory_generation: [u8; 16],
    /// Aligned per-DID results, order preserved exactly.
    pub results: Vec<ReceivedResult>,
}

/// Parses one resolve result with its exact status-dependent label set.
fn parse_received_result(r: &mut Reader<'_>) -> Result<ReceivedResult, VerifyError> {
    let entries = read_map_head(r)?;
    let mut kind = None;
    let mut full: Option<Vec<u8>> = None;
    let mut index = None;
    let mut code = None;
    for _ in 0..entries {
        match read_label(r)? {
            0 => kind = Some(read_uint(r)?),
            1 => {
                // Either opaque Full bytes or a Ref index; disambiguated by
                // the result kind below. The byte string stays opaque
                // (section 6.1.1); a candidate exceeding the record cap is
                // rejected later by verification, not by the wrapper.
                let head = r.read_head().map_err(|_| VerifyError::SchemaViolation)?;
                match head.major {
                    MAJOR_BSTR => {
                        full = Some(
                            r.read_bytes_body(head.arg)
                                .map_err(|_| VerifyError::SchemaViolation)?
                                .to_vec(),
                        );
                    }
                    MAJOR_UINT => {
                        index = Some(
                            u32::try_from(head.arg).map_err(|_| VerifyError::SchemaViolation)?,
                        );
                    }
                    _ => return Err(VerifyError::SchemaViolation),
                }
            }
            2 => code = Some(read_uint(r)?),
            _ => return Err(VerifyError::SchemaViolation),
        }
    }
    match (kind, full, index, code) {
        (Some(0), Some(bytes), None, None) => Ok(ReceivedResult::Full(bytes)),
        (Some(1), None, Some(idx), None) => Ok(ReceivedResult::Ref(idx)),
        (Some(2), None, None, None) => Ok(ReceivedResult::Absent),
        (Some(3), None, None, Some(error)) => Ok(ReceivedResult::Error(error)),
        _ => Err(VerifyError::SchemaViolation),
    }
}

/// Parses a `v1/resolve` response wrapper. Cardinality against the request
/// is enforced by the caller, which knows the request it sent.
pub(crate) fn parse_resolve_response(bytes: &[u8]) -> Result<ReceivedResolveResponse, VerifyError> {
    let mut r = validated_response_reader(bytes, RESOLVE_RESPONSE_MAX_MEMBERS)?;
    let entries = read_map_head(&mut r)?;
    if entries != 3 {
        return Err(VerifyError::SchemaViolation);
    }
    let mut directory_generation = None;
    let mut results = None;
    for _ in 0..entries {
        match read_label(&mut r)? {
            0 => require_version_1(&mut r)?,
            1 => directory_generation = Some(read_bstr16(&mut r)?),
            2 => {
                let head = r.read_head().map_err(|_| VerifyError::SchemaViolation)?;
                if head.major != MAJOR_ARRAY {
                    return Err(VerifyError::SchemaViolation);
                }
                let count = usize::try_from(head.arg).map_err(|_| VerifyError::SchemaViolation)?;
                if count > MAX_RESOLVE_DIDS {
                    return Err(VerifyError::SchemaViolation);
                }
                let mut list = Vec::with_capacity(count);
                for _ in 0..count {
                    list.push(parse_received_result(&mut r)?);
                }
                results = Some(list);
            }
            _ => return Err(VerifyError::SchemaViolation),
        }
    }
    Ok(ReceivedResolveResponse {
        directory_generation: directory_generation.ok_or(VerifyError::SchemaViolation)?,
        results: results.ok_or(VerifyError::SchemaViolation)?,
    })
}

/// A parsed `v1/directory` response (specification section 12.4). Entries
/// are unverified routing hints subject to network policy before use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceivedDirectory {
    /// The publishing relay's 16-byte directory generation.
    pub directory_generation: [u8; 16],
    /// Directory rows in received order.
    pub entries: Vec<DirectoryEntry>,
}

/// Parses a `v1/directory` response under the exact schema and the section
/// 15.2 entry cap.
pub(crate) fn parse_directory_response(bytes: &[u8]) -> Result<ReceivedDirectory, VerifyError> {
    let mut r = validated_response_reader(bytes, DIRECTORY_RESPONSE_MAX_MEMBERS)?;
    let entries = read_map_head(&mut r)?;
    if entries != 3 {
        return Err(VerifyError::SchemaViolation);
    }
    let mut directory_generation = None;
    let mut rows = None;
    for _ in 0..entries {
        match read_label(&mut r)? {
            0 => require_version_1(&mut r)?,
            1 => directory_generation = Some(read_bstr16(&mut r)?),
            2 => {
                let head = r.read_head().map_err(|_| VerifyError::SchemaViolation)?;
                if head.major != MAJOR_ARRAY {
                    return Err(VerifyError::SchemaViolation);
                }
                let count = usize::try_from(head.arg).map_err(|_| VerifyError::SchemaViolation)?;
                if count > MAX_DIRECTORY_ENTRIES {
                    return Err(VerifyError::SchemaViolation);
                }
                let mut list = Vec::with_capacity(count);
                let mut seen_indices = std::collections::HashSet::with_capacity(count);
                for _ in 0..count {
                    let members = read_map_head(&mut r)?;
                    if members != 4 {
                        return Err(VerifyError::SchemaViolation);
                    }
                    let mut index = None;
                    let mut relay_id = None;
                    let mut endpoint = None;
                    let mut capabilities = None;
                    for _ in 0..members {
                        match read_label(&mut r)? {
                            0 => index = Some(read_u32(&mut r)?),
                            1 => relay_id = Some(read_bstr16(&mut r)?),
                            2 => {
                                let uri = read_tstr(&mut r)?;
                                if uri.len() > crate::limits::MAX_URI_BYTES {
                                    return Err(VerifyError::SchemaViolation);
                                }
                                endpoint = Some(uri.to_owned());
                            }
                            3 => capabilities = Some(read_uint(&mut r)?),
                            _ => return Err(VerifyError::SchemaViolation),
                        }
                    }
                    let index = index.ok_or(VerifyError::SchemaViolation)?;
                    // Section 11.4: an index is meaningful only as one
                    // mapping within the response's directory generation and
                    // must not be reused. A response assigning the same
                    // index twice is non-conforming output whose Ref
                    // resolution would be ambiguous; the strict client
                    // rejects the complete response.
                    if !seen_indices.insert(index) {
                        return Err(VerifyError::SchemaViolation);
                    }
                    list.push(DirectoryEntry {
                        index,
                        relay_id: relay_id.ok_or(VerifyError::SchemaViolation)?,
                        endpoint: endpoint.ok_or(VerifyError::SchemaViolation)?,
                        capabilities: capabilities.ok_or(VerifyError::SchemaViolation)?,
                    });
                }
                rows = Some(list);
            }
            _ => return Err(VerifyError::SchemaViolation),
        }
    }
    Ok(ReceivedDirectory {
        directory_generation: directory_generation.ok_or(VerifyError::SchemaViolation)?,
        entries: rows.ok_or(VerifyError::SchemaViolation)?,
    })
}

/// A parsed, v0.9.2-conforming `v1/publish` response (specification
/// section 12.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReceivedPublishResponse {
    /// Status: `0` admitted and current, `1` valid but no change, `2`
    /// rejected. "Admitted" is current at that relay only.
    pub status: u64,
    /// The section 15.3 error code, already validated against the v0.9.2
    /// status-dependent rules: absent on status `0`; absent or exactly the
    /// `losingRecord`/`duplicate` diagnostic on status `1`; a registered
    /// rejection code other than those two on status `2`.
    pub error_code: Option<u64>,
}

/// Parses a `v1/publish` response, enforcing the specification v0.9.2
/// status-dependent union of section 12.5 in addition to the section 6.1
/// layers and the Appendix A CDDL shape.
///
/// This is the one production wrapper-acceptance path for publish
/// responses: [`super::client::RelayClient::publish`] and the neutral
/// `receivePublishResponse` interoperability operation both decode through
/// it. Status `0` forbids `errorCode`; status `1` permits it only as the
/// `losingRecord` (12) or `duplicate` (13) diagnostic; status `2` requires
/// a registered section 15.3 code other than those two. Every other
/// combination — including any code outside the section 15.3 registry —
/// fails the applicable v1 schema and the complete response is rejected
/// without extracting a status (section 12.5: "MUST NOT extract a status
/// from it"). Deeper CBOR faults retain their exact section 6.1
/// classification (`invalidCbor` / `nonDeterministicCbor`).
///
/// # Errors
///
/// Returns the [`VerifyError`] classification for the rejected response.
pub fn parse_publish_response(bytes: &[u8]) -> Result<ReceivedPublishResponse, VerifyError> {
    let mut r = validated_response_reader(bytes, PUBLISH_RESPONSE_MAX_MEMBERS)?;
    let entries = read_map_head(&mut r)?;
    if !(2..=3).contains(&entries) {
        return Err(VerifyError::SchemaViolation);
    }
    let mut status = None;
    let mut error_code = None;
    for _ in 0..entries {
        match read_label(&mut r)? {
            0 => require_version_1(&mut r)?,
            1 => {
                let value = read_uint(&mut r)?;
                if value > 2 {
                    return Err(VerifyError::SchemaViolation);
                }
                status = Some(value);
            }
            2 => error_code = Some(read_uint(&mut r)?),
            _ => return Err(VerifyError::SchemaViolation),
        }
    }
    let status = status.ok_or(VerifyError::SchemaViolation)?;
    use super::wire_code::{DUPLICATE, LOSING_RECORD};
    match (status, error_code) {
        // Status 0: errorCode forbidden.
        (0, None) => {}
        // Status 1: no code, or exactly the accurate no-change diagnostic.
        // (Accuracy is the emitting relay's obligation; a receiver can only
        // enforce the permitted code set.)
        (1, None) | (1, Some(LOSING_RECORD | DUPLICATE)) => {}
        // Status 2: a registered section 15.3 rejection code is required,
        // and the two no-change reasons never mark a rejection.
        (2, Some(code))
            if code != LOSING_RECORD
                && code != DUPLICATE
                && crate::error::wire_error_symbol(code).is_some() => {}
        _ => return Err(VerifyError::SchemaViolation),
    }
    Ok(ReceivedPublishResponse { status, error_code })
}

/// One received `v1/changes` entry: untrusted protocol data. The DID is a
/// routing label; Full bytes are opaque candidates and the sender's
/// `lastUpdated` is never a receiver update number.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceivedChangeEntry {
    /// The entry's DID string as received (validated only as text here).
    pub did: String,
    /// Opaque Full candidate bytes or a Ref routing hint.
    pub payload: ReceivedChangePayload,
    /// The sender's relay-local `lastUpdated` value.
    pub last_updated: u64,
}

/// The payload of a received change entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReceivedChangePayload {
    /// Opaque candidate envelope bytes.
    Full(Vec<u8>),
    /// Relay index in the response's directory generation.
    Ref(u32),
}

/// A parsed `v1/changes` response with the exact status-dependent required
/// and forbidden fields (specification section 12.6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReceivedChangesResponse {
    /// Status `0`: entries, `nextCursor`, `hasMore`, and
    /// `directoryGeneration` present; `errorCode` absent.
    Success {
        /// Received entries in received order.
        entries: Vec<ReceivedChangeEntry>,
        /// The exact opaque next cursor to store and use.
        next_cursor: Vec<u8>,
        /// Whether further entries were known when assembled.
        has_more: bool,
        /// The response's directory generation.
        directory_generation: [u8; 16],
    },
    /// Status `1`: the exact two-field ResetRequired response.
    ResetRequired,
    /// Status `2`: another error identified by its section 15.3 code.
    Error(u64),
}

/// Parses a `v1/changes` response, enforcing every status-dependent required
/// and forbidden field combination. `item_limit` is the limit the caller
/// requested: a success response with more entries is rejected completely,
/// before any entry is interpreted (section 12.6; Appendix B.11.7).
pub(crate) fn parse_changes_response(
    bytes: &[u8],
    item_limit: u64,
) -> Result<ReceivedChangesResponse, VerifyError> {
    let mut r = validated_response_reader(bytes, CHANGES_RESPONSE_MAX_MEMBERS)?;
    let entry_count = read_map_head(&mut r)?;
    let mut status = None;
    let mut entries: Option<Vec<ReceivedChangeEntry>> = None;
    let mut next_cursor: Option<Vec<u8>> = None;
    let mut has_more = None;
    let mut directory_generation = None;
    let mut error_code = None;
    for _ in 0..entry_count {
        match read_label(&mut r)? {
            0 => require_version_1(&mut r)?,
            1 => {
                let value = read_uint(&mut r)?;
                if value > 2 {
                    return Err(VerifyError::SchemaViolation);
                }
                status = Some(value);
            }
            2 => {
                let head = r.read_head().map_err(|_| VerifyError::SchemaViolation)?;
                if head.major != MAJOR_ARRAY {
                    return Err(VerifyError::SchemaViolation);
                }
                let count = usize::try_from(head.arg).map_err(|_| VerifyError::SchemaViolation)?;
                // The item-limit check happens against the complete parsed
                // response below; the protocol hard maximum bounds work here.
                if count as u64 > MAX_CHANGES_ITEMS {
                    return Err(VerifyError::SchemaViolation);
                }
                let mut list = Vec::with_capacity(count);
                for _ in 0..count {
                    let entry_head = r.read_head().map_err(|_| VerifyError::SchemaViolation)?;
                    if entry_head.major != MAJOR_ARRAY {
                        return Err(VerifyError::SchemaViolation);
                    }
                    if entry_head.arg != 3 {
                        return Err(VerifyError::SchemaViolation);
                    }
                    let did = read_tstr(&mut r)?.to_owned();
                    let members = read_map_head(&mut r)?;
                    if members != 2 {
                        return Err(VerifyError::SchemaViolation);
                    }
                    let mut kind = None;
                    let mut full = None;
                    let mut index = None;
                    for _ in 0..members {
                        match read_label(&mut r)? {
                            0 => kind = Some(read_uint(&mut r)?),
                            1 => {
                                let value_head =
                                    r.read_head().map_err(|_| VerifyError::SchemaViolation)?;
                                match value_head.major {
                                    MAJOR_BSTR => {
                                        full = Some(
                                            r.read_bytes_body(value_head.arg)
                                                .map_err(|_| VerifyError::SchemaViolation)?
                                                .to_vec(),
                                        );
                                    }
                                    MAJOR_UINT => {
                                        index = Some(
                                            u32::try_from(value_head.arg)
                                                .map_err(|_| VerifyError::SchemaViolation)?,
                                        );
                                    }
                                    _ => return Err(VerifyError::SchemaViolation),
                                }
                            }
                            _ => return Err(VerifyError::SchemaViolation),
                        }
                    }
                    let payload = match (kind, full, index) {
                        (Some(0), Some(bytes), None) => ReceivedChangePayload::Full(bytes),
                        (Some(1), None, Some(idx)) => ReceivedChangePayload::Ref(idx),
                        _ => return Err(VerifyError::SchemaViolation),
                    };
                    let last_updated = read_uint(&mut r)?;
                    list.push(ReceivedChangeEntry {
                        did,
                        payload,
                        last_updated,
                    });
                }
                entries = Some(list);
            }
            3 => {
                let cursor = read_bstr(&mut r)?;
                if cursor.len() > MAX_CURSOR_BYTES {
                    return Err(VerifyError::SchemaViolation);
                }
                next_cursor = Some(cursor.to_vec());
            }
            4 => has_more = Some(read_bool(&mut r)?),
            5 => directory_generation = Some(read_bstr16(&mut r)?),
            6 => error_code = Some(read_uint(&mut r)?),
            _ => return Err(VerifyError::SchemaViolation),
        }
    }
    match status.ok_or(VerifyError::SchemaViolation)? {
        0 => {
            if error_code.is_some() {
                return Err(VerifyError::SchemaViolation);
            }
            let entries = entries.ok_or(VerifyError::SchemaViolation)?;
            // Complete rejection before any entry is interpreted: the
            // caller never sees entries from an over-limit response and its
            // nextCursor is never returned (Appendix B.11.7).
            if entries.len() as u64 > item_limit {
                return Err(VerifyError::SchemaViolation);
            }
            // Entries are ordered by strictly increasing lastUpdated
            // (section 12.6; update numbers are unique per relay). A
            // misordered response is rejected completely (SQ-18).
            let ordered = entries
                .windows(2)
                .all(|pair| pair[0].last_updated < pair[1].last_updated);
            if !ordered {
                return Err(VerifyError::SchemaViolation);
            }
            Ok(ReceivedChangesResponse::Success {
                entries,
                next_cursor: next_cursor.ok_or(VerifyError::SchemaViolation)?,
                has_more: has_more.ok_or(VerifyError::SchemaViolation)?,
                directory_generation: directory_generation.ok_or(VerifyError::SchemaViolation)?,
            })
        }
        1 => {
            // The exact two-field response is the sole ResetRequired wire
            // encoding: every other label is forbidden.
            if entries.is_some()
                || next_cursor.is_some()
                || has_more.is_some()
                || directory_generation.is_some()
                || error_code.is_some()
            {
                return Err(VerifyError::SchemaViolation);
            }
            Ok(ReceivedChangesResponse::ResetRequired)
        }
        _ => {
            if entries.is_some()
                || next_cursor.is_some()
                || has_more.is_some()
                || directory_generation.is_some()
            {
                return Err(VerifyError::SchemaViolation);
            }
            Ok(ReceivedChangesResponse::Error(
                error_code.ok_or(VerifyError::SchemaViolation)?,
            ))
        }
    }
}
