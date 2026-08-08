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
