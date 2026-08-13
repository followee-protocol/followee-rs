//! Minimal demonstration handle authority (specification sections 10.1
//! and 10.2; IMPLEMENTATION.md sections 8 and 10).
//!
//! This is the process behind `followee handle serve`: it answers
//! `GET /.well-known/webfinger` with `application/jrd+json` documents for
//! an operator-reviewed, deterministic configuration, and optionally
//! serves one complete Identity Record per handle as the section 10.3
//! bootstrap endpoint. The same implementation is exercised by the local
//! black-box tests and shipped as the public deployment artifact behind
//! provider HTTPS termination (`demo/public-authority/`).
//!
//! Design constraints:
//!
//! - the configuration is a bounded, reviewable JSON file parsed by the
//!   crate's strict duplicate-rejecting JSON parser and validated
//!   completely at load; the server holds no mutable state, so restarts
//!   are deterministic;
//! - ASCII-case variants of one local part can never be assigned to
//!   different Followee DIDs: the loader rejects any configuration in
//!   which two locals that differ only by ASCII case map to different
//!   DIDs. Variants of one DID are explicit aliases; lookup remains
//!   exact-match, and every successful response names the exact canonical
//!   `acct:` resource requested (section 10.1);
//! - bootstrap record files are verified against their entry's DID
//!   through the production verifier at load — the authority never serves
//!   bytes it could not verify (clients still verify locally; there is no
//!   transmitted validity assertion);
//! - nothing in the configuration or its responses is secret.

use super::jrd::{self, JrdFault, JsonValue};
use super::{HandleError, canonical_domain, local_part_valid};
use crate::did::FolloweeDid;
use crate::error::VerifyError;
use crate::limits::MAX_RECORD_BYTES;
use axum::Router;
use axum::extract::{Path as AxumPath, RawQuery, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;

/// Bound on the configuration file, in bytes: far above any reviewable
/// demonstration configuration while refusing unbounded reads.
pub const MAX_CONFIG_BYTES: usize = 256 * 1024;
/// Bound on configuration JSON nesting.
pub const MAX_CONFIG_DEPTH: u32 = 8;
/// Bound on total configuration JSON members and elements.
pub const MAX_CONFIG_MEMBERS: u32 = 1024;
/// Bound on configured handles, aliases included: a demonstration
/// authority is deliberately small.
pub const MAX_CONFIG_HANDLES: usize = 64;

/// Configuration rejection. The loader fails completely on the first
/// fault: a partially loaded authority is never served.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// The file could not be read.
    #[error("configuration {path}: {source}")]
    Io {
        /// The path involved.
        path: String,
        /// The operating-system error.
        source: std::io::Error,
    },
    /// The file exceeds [`MAX_CONFIG_BYTES`].
    #[error("configuration exceeds the {MAX_CONFIG_BYTES}-byte bound")]
    TooLarge,
    /// The file is not strict, duplicate-free, bounded JSON.
    #[error("configuration JSON: {0}")]
    Json(#[from] JrdFault),
    /// The JSON parsed but violates the configuration schema.
    #[error("configuration schema: {0}")]
    Schema(String),
    /// A local part or the domain violates section 10.1.
    #[error("configuration handle: {0}")]
    Handle(#[from] HandleError),
    /// Two identical locals are configured.
    #[error("local {0:?} is configured more than once")]
    DuplicateLocal(String),
    /// Two locals differing only by ASCII case map to different DIDs
    /// (specification section 10.1: variants are rejected or aliased to
    /// one DID, never assigned independently).
    #[error("locals {0:?} and {1:?} differ only by ASCII case but map to different DIDs")]
    CaseVariantCollision(String, String),
    /// A bootstrap record file failed production verification against its
    /// entry's DID.
    #[error("record file {path} does not verify for its DID: {error}")]
    Record {
        /// The record file path.
        path: String,
        /// The production classification.
        error: VerifyError,
    },
}

/// One resolvable local: the mapped DID and the optional bootstrap record.
#[derive(Debug, Clone)]
struct Mapping {
    did: FolloweeDid,
    record: Option<Arc<Vec<u8>>>,
}

/// A validated, immutable authority configuration.
#[derive(Debug, Clone)]
pub struct AuthorityConfig {
    domain: String,
    /// Exact-match lookup table: every configured local and alias.
    mappings: BTreeMap<String, Mapping>,
}

fn schema_err<T>(message: impl Into<String>) -> Result<T, ConfigError> {
    Err(ConfigError::Schema(message.into()))
}

fn member_str<'v>(value: &'v JsonValue, name: &str) -> Option<&'v str> {
    value.member(name).and_then(JsonValue::as_str)
}

impl AuthorityConfig {
    /// Loads and completely validates a configuration file. Record files
    /// are resolved relative to the configuration file's directory and
    /// verified against their entry's DID through the production verifier.
    ///
    /// # Errors
    ///
    /// Returns the first [`ConfigError`].
    pub fn load(path: &Path) -> Result<AuthorityConfig, ConfigError> {
        let io = |source| ConfigError::Io {
            path: path.display().to_string(),
            source,
        };
        let metadata = std::fs::metadata(path).map_err(io)?;
        if metadata.len() > MAX_CONFIG_BYTES as u64 {
            return Err(ConfigError::TooLarge);
        }
        let bytes = std::fs::read(path).map_err(io)?;
        if bytes.len() > MAX_CONFIG_BYTES {
            return Err(ConfigError::TooLarge);
        }
        let base_dir = path.parent().unwrap_or(Path::new("."));
        Self::from_json(&bytes, |record_path| {
            let resolved = base_dir.join(record_path);
            let record_io = |source| ConfigError::Io {
                path: resolved.display().to_string(),
                source,
            };
            let record = std::fs::read(&resolved).map_err(record_io)?;
            if record.len() > MAX_RECORD_BYTES {
                return Err(ConfigError::Record {
                    path: resolved.display().to_string(),
                    error: VerifyError::RecordTooLarge,
                });
            }
            Ok(record)
        })
    }

    /// Parses and validates configuration JSON, loading each referenced
    /// record file through `read_record`.
    ///
    /// # Errors
    ///
    /// Returns the first [`ConfigError`].
    pub fn from_json(
        bytes: &[u8],
        mut read_record: impl FnMut(&str) -> Result<Vec<u8>, ConfigError>,
    ) -> Result<AuthorityConfig, ConfigError> {
        let document = jrd::parse_json(bytes, MAX_CONFIG_DEPTH, MAX_CONFIG_MEMBERS)?;
        let JsonValue::Object(members) = &document else {
            return schema_err("the configuration must be a JSON object");
        };
        for (name, _) in members {
            if !matches!(name.as_str(), "version" | "domain" | "handles") {
                return schema_err(format!("unknown field {name:?}"));
            }
        }
        match document.member("version") {
            Some(JsonValue::Number(text)) if text == "1" => {}
            _ => return schema_err("version must be the number 1"),
        }
        let Some(domain) = member_str(&document, "domain") else {
            return schema_err("domain must be a string");
        };
        let canonical = canonical_domain(domain)?;
        if canonical != domain {
            return schema_err(format!(
                "domain must be written in its canonical lowercase ASCII IDNA form {canonical:?}"
            ));
        }
        let Some(JsonValue::Array(handles)) = document.member("handles") else {
            return schema_err("handles must be an array");
        };

        let mut mappings: BTreeMap<String, Mapping> = BTreeMap::new();
        for entry in handles {
            let JsonValue::Object(entry_members) = entry else {
                return schema_err("each handles entry must be an object");
            };
            for (name, _) in entry_members {
                if !matches!(name.as_str(), "local" | "did" | "aliases" | "record") {
                    return schema_err(format!("unknown handle field {name:?}"));
                }
            }
            let Some(local) = member_str(entry, "local") else {
                return schema_err("each handle needs a string local");
            };
            let Some(did_text) = member_str(entry, "did") else {
                return schema_err("each handle needs a string did");
            };
            let did = FolloweeDid::parse(did_text)
                .map_err(|e| ConfigError::Schema(format!("did {did_text:?}: {e}")))?;
            let record = match entry.member("record") {
                None => None,
                Some(JsonValue::String(record_path)) => {
                    let bytes = read_record(record_path)?;
                    crate::verify::verify_record_for_target(did.as_str(), &bytes).map_err(
                        |error| ConfigError::Record {
                            path: record_path.clone(),
                            error,
                        },
                    )?;
                    Some(Arc::new(bytes))
                }
                Some(_) => return schema_err("record must be a string path"),
            };
            let mut locals = vec![local.to_owned()];
            match entry.member("aliases") {
                None => {}
                Some(JsonValue::Array(aliases)) => {
                    for alias in aliases {
                        let Some(alias) = alias.as_str() else {
                            return schema_err("aliases must be strings");
                        };
                        locals.push(alias.to_owned());
                    }
                }
                Some(_) => return schema_err("aliases must be an array"),
            }
            for local in locals {
                if !local_part_valid(&local) {
                    return Err(ConfigError::Handle(HandleError::Local));
                }
                if mappings.contains_key(&local) {
                    return Err(ConfigError::DuplicateLocal(local));
                }
                if mappings.len() >= MAX_CONFIG_HANDLES {
                    return schema_err(format!("more than {MAX_CONFIG_HANDLES} locals configured"));
                }
                mappings.insert(
                    local,
                    Mapping {
                        did: did.clone(),
                        record: record.clone(),
                    },
                );
            }
        }

        // The section 10.1 guarantee: within one ASCII-case-fold class,
        // every configured local maps to the same DID. Locals are already
        // exact-unique; a case variant is therefore either absent
        // (rejected at lookup) or an alias of the same DID.
        let mut by_fold: BTreeMap<String, (&String, &Mapping)> = BTreeMap::new();
        for (local, mapping) in &mappings {
            let folded = local.to_ascii_lowercase();
            if let Some((existing_local, existing)) = by_fold.get(&folded) {
                if existing.did != mapping.did {
                    return Err(ConfigError::CaseVariantCollision(
                        (*existing_local).clone(),
                        local.clone(),
                    ));
                }
            } else {
                by_fold.insert(folded, (local, mapping));
            }
        }

        Ok(AuthorityConfig {
            domain: canonical,
            mappings,
        })
    }

    /// The authority's canonical domain.
    #[must_use]
    pub fn domain(&self) -> &str {
        &self.domain
    }

    /// The number of resolvable locals, aliases included.
    #[must_use]
    pub fn handle_count(&self) -> usize {
        self.mappings.len()
    }

    /// The number of locals with a bootstrap record.
    #[must_use]
    pub fn record_count(&self) -> usize {
        self.mappings
            .values()
            .filter(|m| m.record.is_some())
            .count()
    }

    /// Predeployment identity-consistency check (IMPLEMENTATION.md
    /// section 10): a signed record's `alsoKnownAs` claim is immutable —
    /// changing the configuration domain or the deployment environment
    /// never changes it — so a public deployment is consistent only when
    /// every local served **with a bootstrap record** is exactly claimed
    /// by that record.
    ///
    /// For every configured local (aliases included), this re-verifies
    /// any bootstrap record through the production verifier against the
    /// mapped DID and, when a record is present, requires its verified
    /// Contact Document to claim the exact canonical
    /// `acct:<local>@<domain>` resource this authority would serve
    /// (specification section 10.1 matching: case-sensitive local,
    /// canonical domain). The configured mapping already binds that
    /// handle back to the same DID, so a passing entry satisfies both
    /// directions of section 10.4 up to the live inverse lookup.
    ///
    /// Record-less locals are DID-only mappings and always consistent.
    /// The report never mutates anything; deployment tooling fails
    /// before deploying when `consistent` is false.
    #[must_use]
    pub fn deployment_consistency(&self) -> ConsistencyReport {
        let mut entries = Vec::new();
        for (local, mapping) in &self.mappings {
            let handle = super::Handle::parse(&format!("{local}@{}", self.domain))
                .expect("configured locals and domain already validated");
            let claim = mapping.record.as_ref().map(|record| {
                // Load-time verification already succeeded; this is the
                // same production entry point, re-run so the report never
                // trusts cached state.
                crate::verify::verify_record_for_target(mapping.did.as_str(), record)
                    .map(|verified| super::record_handle_claim(&verified, &handle))
            });
            let (has_record, claimed, verified) = match claim {
                None => (false, None, true),
                Some(Ok(claimed)) => (true, claimed, true),
                Some(Err(_)) => (true, None, false),
            };
            let ok = !has_record || (verified && claimed.is_some());
            entries.push(ConsistencyEntry {
                resource: handle.resource(),
                local: local.clone(),
                did: mapping.did.as_str().to_owned(),
                has_record,
                record_verified: verified,
                claimed,
                ok,
            });
        }
        ConsistencyReport {
            consistent: entries.iter().all(|e| e.ok),
            entries,
        }
    }
}

/// One local's predeployment consistency result.
#[derive(Debug, Clone)]
pub struct ConsistencyEntry {
    /// The configured local part.
    pub local: String,
    /// The canonical resource this authority serves for it.
    pub resource: String,
    /// The mapped DID.
    pub did: String,
    /// Whether a bootstrap record is configured for it.
    pub has_record: bool,
    /// Whether the record re-verified through the production verifier.
    pub record_verified: bool,
    /// The record's matching signed `alsoKnownAs` entry, if any.
    pub claimed: Option<String>,
    /// Consistent: no record, or a verified record claiming the exact
    /// canonical resource.
    pub ok: bool,
}

/// The complete predeployment consistency report.
#[derive(Debug, Clone)]
pub struct ConsistencyReport {
    /// Per-local results in deterministic (BTreeMap) order.
    pub entries: Vec<ConsistencyEntry>,
    /// Whether every entry is consistent.
    pub consistent: bool,
}

// ---------------------------------------------------------------------------
// Untrusted request parsing
// ---------------------------------------------------------------------------

/// Query-string rejection for the WebFinger endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum QueryError {
    /// No `resource` parameter is present (RFC 7033 section 4.4: the
    /// server returns 400).
    #[error("the query carries no resource parameter")]
    MissingResource,
    /// More than one `resource` parameter is present: ambiguous.
    #[error("the query carries more than one resource parameter")]
    DuplicateResource,
    /// A percent-escape is malformed or decodes to invalid UTF-8.
    #[error("the query percent-encoding is malformed")]
    BadEncoding,
}

/// Strictly percent-decodes one query component. `+` stays literal (this
/// endpoint uses RFC 3986 percent-encoding, not form encoding); malformed
/// escapes and non-UTF-8 results are rejected, never repaired.
fn percent_decode(component: &str) -> Result<String, QueryError> {
    let bytes = component.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let byte = bytes[i];
        if byte == b'%' {
            let hi = bytes.get(i.saturating_add(1)).copied();
            let lo = bytes.get(i.saturating_add(2)).copied();
            let (Some(hi), Some(lo)) = (hi, lo) else {
                return Err(QueryError::BadEncoding);
            };
            let hex = |b: u8| -> Option<u8> {
                match b {
                    b'0'..=b'9' => Some(b.wrapping_sub(b'0')),
                    b'a'..=b'f' => Some(b.wrapping_sub(b'a').saturating_add(10)),
                    b'A'..=b'F' => Some(b.wrapping_sub(b'A').saturating_add(10)),
                    _ => None,
                }
            };
            let (Some(hi), Some(lo)) = (hex(hi), hex(lo)) else {
                return Err(QueryError::BadEncoding);
            };
            out.push((hi << 4) | lo);
            i = i.saturating_add(3);
        } else {
            out.push(byte);
            i = i.saturating_add(1);
        }
    }
    String::from_utf8(out).map_err(|_| QueryError::BadEncoding)
}

/// Parses the WebFinger query string and returns the decoded `resource`
/// value. Unknown parameters are ignored (RFC 7033 defines only
/// `resource` and the optional `rel` filter, which this minimal authority
/// does not implement); a missing or duplicated `resource` is rejected.
///
/// # Errors
///
/// Returns the [`QueryError`] naming the fault.
pub fn parse_resource_query(query: &str) -> Result<String, QueryError> {
    let mut resource: Option<String> = None;
    for pair in query.split('&') {
        let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
        if percent_decode(name)? != "resource" {
            continue;
        }
        let decoded = percent_decode(value)?;
        if resource.is_some() {
            return Err(QueryError::DuplicateResource);
        }
        resource = Some(decoded);
    }
    resource.ok_or(QueryError::MissingResource)
}

// ---------------------------------------------------------------------------
// The authority server
// ---------------------------------------------------------------------------

/// The running authority: an immutable configuration plus the advertised
/// base URI used to construct bootstrap record links.
#[derive(Debug)]
pub struct HandleAuthority {
    config: AuthorityConfig,
    base_uri: String,
    development_mode: bool,
}

impl HandleAuthority {
    /// Creates an authority over a validated configuration. `base_uri`
    /// must end in `/`; an HTTPS base selects conforming mode (behind
    /// provider TLS termination), anything else is explicitly
    /// non-conforming development mode.
    ///
    /// # Errors
    ///
    /// Returns a message when the base URI is unusable.
    pub fn new(config: AuthorityConfig, base_uri: String) -> Result<HandleAuthority, String> {
        if !base_uri.ends_with('/') {
            return Err("the base URI must end in '/'".to_owned());
        }
        let development_mode = !base_uri.starts_with("https://");
        Ok(HandleAuthority {
            config,
            base_uri,
            development_mode,
        })
    }

    /// Whether the authority runs in explicitly non-conforming
    /// development mode (non-HTTPS base URI).
    #[must_use]
    pub fn development_mode(&self) -> bool {
        self.development_mode
    }

    /// The validated configuration.
    #[must_use]
    pub fn config(&self) -> &AuthorityConfig {
        &self.config
    }

    /// The JRD document for one requested canonical resource, or `None`
    /// when the authority has no mapping for it. Lookup is exact: the
    /// resource must be `acct:<local>@<domain>` with this authority's
    /// canonical domain byte-for-byte and an exactly configured local.
    /// The returned subject names exactly the requested resource
    /// (section 10.1).
    #[must_use]
    pub fn jrd_for_resource(&self, resource: &str) -> Option<String> {
        let rest = resource.strip_prefix("acct:")?;
        let (local, domain) = rest.split_once('@')?;
        if domain != self.config.domain || local.contains('@') {
            return None;
        }
        let mapping = self.config.mappings.get(local)?;
        let mut links = vec![serde_json::json!({
            "rel": super::FOLLOWEE_DID_REL,
            "href": mapping.did.as_str(),
        })];
        if mapping.record.is_some() {
            // Local-part characters are all RFC 3986 unreserved, so the
            // path needs no encoding.
            links.push(serde_json::json!({
                "rel": super::FOLLOWEE_RECORD_REL,
                "type": super::APPLICATION_COSE,
                "href": format!("{}record/{local}", self.base_uri),
            }));
        }
        let document = serde_json::json!({
            "subject": resource,
            "links": links,
        });
        Some(document.to_string())
    }

    /// The bootstrap record bytes for one exactly configured local.
    #[must_use]
    pub fn record_for_local(&self, local: &str) -> Option<Arc<Vec<u8>>> {
        self.config.mappings.get(local)?.record.clone()
    }
}

/// Builds the axum router for the authority.
pub fn router(authority: Arc<HandleAuthority>) -> Router {
    Router::new()
        .route("/.well-known/webfinger", get(webfinger))
        .route("/record/{local}", get(record))
        .with_state(authority)
}

/// Serves the authority on an already bound listener until `shutdown`
/// resolves. In development mode the listener must be bound to a loopback
/// address (IMPLEMENTATION.md section 9.5): plain-HTTP operation is
/// explicitly non-conforming and must not reach a public interface by
/// accident.
///
/// # Errors
///
/// Returns an [`std::io::Error`] for binding violations or accept failures.
pub async fn serve_with_shutdown(
    authority: Arc<HandleAuthority>,
    listener: tokio::net::TcpListener,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> std::io::Result<()> {
    if authority.development_mode() {
        let addr = listener.local_addr()?;
        if !addr.ip().is_loopback() {
            return Err(std::io::Error::other(
                "development mode permits loopback binding only; public \
                 operation requires an HTTPS base URI behind TLS termination",
            ));
        }
    }
    let app = router(authority);
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown)
        .await
}

fn with_cors(mut response: Response) -> Response {
    // Section 10.2: ordinary public WebFinger endpoints SHOULD return
    // Access-Control-Allow-Origin: *. The record endpoint serves the same
    // public bytes and gets the same header.
    response.headers_mut().insert(
        header::ACCESS_CONTROL_ALLOW_ORIGIN,
        header::HeaderValue::from_static("*"),
    );
    response
}

async fn webfinger(
    State(authority): State<Arc<HandleAuthority>>,
    RawQuery(query): RawQuery,
) -> Response {
    let Ok(resource) = parse_resource_query(query.as_deref().unwrap_or("")) else {
        // RFC 7033 section 4.4: a missing or malformed resource parameter
        // is a client error.
        return with_cors(StatusCode::BAD_REQUEST.into_response());
    };
    match authority.jrd_for_resource(&resource) {
        Some(document) => with_cors(
            (
                StatusCode::OK,
                [(header::CONTENT_TYPE, super::APPLICATION_JRD_JSON)],
                document,
            )
                .into_response(),
        ),
        None => with_cors(StatusCode::NOT_FOUND.into_response()),
    }
}

async fn record(
    State(authority): State<Arc<HandleAuthority>>,
    AxumPath(local): AxumPath<String>,
) -> Response {
    match authority.record_for_local(&local) {
        Some(bytes) => with_cors(
            (
                StatusCode::OK,
                [(header::CONTENT_TYPE, super::APPLICATION_COSE)],
                bytes.as_ref().clone(),
            )
                .into_response(),
        ),
        None => with_cors(StatusCode::NOT_FOUND.into_response()),
    }
}
