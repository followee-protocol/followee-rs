//! WebFinger handle discovery, inverse verification, and bootstrap
//! (specification section 10; IMPLEMENTATION.md section 10).
//!
//! The production WebFinger client reuses the exact Milestone 4 bounded
//! HTTP machinery — [`NetworkPolicy`] validation of every requested URL and
//! redirect target, SSRF-safe destination rules in the transport, bounded
//! redirects, media-type enforcement, response-size caps, and one
//! caller-supplied [`BudgetMeter`] under the injected [`Clock`] — through
//! the crate-internal `RelayClient` exchange loop. No transport, policy,
//! or budget decision is
//! reproduced here.
//!
//! Trust boundaries:
//!
//! - a WebFinger response is untrusted JSON from the handle authority; it
//!   is parsed by the strict bounded [`jrd`] parser (byte, nesting, and
//!   member bounds; duplicate-member and invalid-UTF-8 rejection) before
//!   interpretation;
//! - a successful lookup is only the *domain's* mapping claim for the
//!   exact canonical `acct:` resource — it verifies no Identity Record and
//!   is never presented as record verification;
//! - a signed `alsoKnownAs` entry is only the *controller's* claim; the
//!   handle is verified only when both directions bind the exact handle to
//!   the same Followee DID (section 10.4), via [`WebFingerClient::verify_handle`];
//! - a bootstrap record link (section 10.3) supplies opaque candidate
//!   bytes; every candidate passes complete local verification
//!   ([`crate::verify::verify_record_for_target`]) and deterministic
//!   selection ([`crate::ordering::select_current`]) before use.

pub mod authority;
pub mod jrd;

use crate::clock::Clock;
use crate::did::{DidError, FolloweeDid};
use crate::error::VerifyError;
use crate::limits::{MAX_RECORD_BYTES, MAX_URI_BYTES};
use crate::ordering::{AuthorityState, select_current};
use crate::relay::client::{
    BudgetMeter, ClientError, Exchange, Method, NetworkPolicy, RelayClient, Transport,
};
use crate::timestamp::{Freshness, TimeStatus, freshness, time_status};
use crate::verify::{VerifiedRecord, verify_record_for_target};
use jrd::{JrdFault, JsonValue};

/// The proposed Followee DID relation URI (specification section 10.2).
pub const FOLLOWEE_DID_REL: &str = "https://w3id.org/followee/rel/did";
/// The optional current-record bootstrap relation URI (section 10.3).
pub const FOLLOWEE_RECORD_REL: &str = "https://w3id.org/followee/rel/record";
/// The WebFinger response media type (sections 6.4 and 10.2).
pub const APPLICATION_JRD_JSON: &str = "application/jrd+json";
/// The bootstrap record media type (sections 6.4 and 10.3).
pub const APPLICATION_COSE: &str = "application/cose";

/// Bound on a WebFinger response entity. The specification does not bound
/// JRD documents, so this is a local bound over untrusted input, applied
/// before parsing: a conforming mapping (subject, one DID link, an optional
/// record link) is a few hundred bytes, and 64 KiB is far above any
/// legitimate response while still refusing unbounded reads.
pub const MAX_JRD_RESPONSE_BYTES: u64 = 64 * 1024;
/// Bound on JRD nesting depth (top-level object is depth one). A
/// conforming JRD needs four levels (object → links array → link object →
/// titles/properties object); eight mirrors the relay-message bound.
pub const MAX_JRD_DEPTH: u32 = 8;
/// Bound on total JRD object members and array elements, mirroring the
/// record-body member bound.
pub const MAX_JRD_MEMBERS: u32 = 256;

/// Maximum handle local part, in ASCII characters (section 10.1).
pub const MAX_HANDLE_LOCAL_CHARS: usize = 64;

// ---------------------------------------------------------------------------
// Handle form (specification section 10.1)
// ---------------------------------------------------------------------------

/// Handle rejection. One symbol (`invalidHandle`) covers both parts; the
/// message carries the failed rule without echoing hostile input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum HandleError {
    /// The handle is not exactly `local@domain`.
    #[error("a handle is exactly local@domain")]
    Form,
    /// The local part violates the section 10.1 grammar (1–64 ASCII
    /// characters from ALPHA, DIGIT, `.`, `_`, or `-`).
    #[error("the local part must be 1-64 ASCII letters, digits, '.', '_', or '-'")]
    Local,
    /// The domain is not a valid DNS domain under IDNA2008 processing.
    #[error("the domain is not a valid DNS domain")]
    Domain,
}

/// A validated v1 handle: a case-sensitive local part and the domain in
/// its canonical lowercase ASCII IDNA form (specification section 10.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Handle {
    local: String,
    domain: String,
}

/// Whether `local` satisfies the section 10.1 local-part grammar.
fn local_part_valid(local: &str) -> bool {
    !local.is_empty()
        && local.len() <= MAX_HANDLE_LOCAL_CHARS
        && local
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// Canonicalizes `domain` to its lowercase ASCII IDNA form and re-checks
/// the DNS shape explicitly (non-empty LDH labels of at most 63 octets,
/// at most 253 octets in total), so conformance does not silently depend
/// on library internals.
fn canonical_domain(domain: &str) -> Result<String, HandleError> {
    if domain.is_empty() || domain.len() > MAX_URI_BYTES {
        return Err(HandleError::Domain);
    }
    let ascii = idna::domain_to_ascii_strict(domain).map_err(|_| HandleError::Domain)?;
    if ascii.is_empty() || ascii.len() > 253 {
        return Err(HandleError::Domain);
    }
    for label in ascii.split('.') {
        if label.is_empty()
            || label.len() > 63
            || !label
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            || label.starts_with('-')
            || label.ends_with('-')
        {
            return Err(HandleError::Domain);
        }
    }
    Ok(ascii)
}

impl Handle {
    /// Parses `local@domain`, canonicalizing the domain (section 10.1).
    /// The local part stays case-sensitive and is never altered.
    ///
    /// # Errors
    ///
    /// Returns the [`HandleError`] naming the failed rule.
    pub fn parse(text: &str) -> Result<Handle, HandleError> {
        let mut parts = text.split('@');
        let (Some(local), Some(domain), None) = (parts.next(), parts.next(), parts.next()) else {
            return Err(HandleError::Form);
        };
        if !local_part_valid(local) {
            return Err(HandleError::Local);
        }
        Ok(Handle {
            local: local.to_owned(),
            domain: canonical_domain(domain)?,
        })
    }

    /// Parses an `acct:` URI (for example an `alsoKnownAs` entry) into a
    /// handle. The scheme is compared ASCII-case-insensitively per
    /// RFC 3986; the remainder must satisfy the section 10.1 handle form
    /// exactly (in particular, percent-encoding is not part of that
    /// grammar and is rejected rather than decoded).
    ///
    /// # Errors
    ///
    /// Returns the [`HandleError`] naming the failed rule.
    pub fn from_acct_uri(uri: &str) -> Result<Handle, HandleError> {
        let rest = uri
            .get(..5)
            .filter(|scheme| scheme.eq_ignore_ascii_case("acct:"))
            .and_then(|_| uri.get(5..))
            .ok_or(HandleError::Form)?;
        Handle::parse(rest)
    }

    /// The case-sensitive local part.
    #[must_use]
    pub fn local(&self) -> &str {
        &self.local
    }

    /// The canonical lowercase ASCII IDNA domain.
    #[must_use]
    pub fn domain(&self) -> &str {
        &self.domain
    }

    /// The canonical WebFinger resource, `acct:local@domain`.
    #[must_use]
    pub fn resource(&self) -> String {
        format!("acct:{}@{}", self.local, self.domain)
    }
}

impl std::fmt::Display for Handle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}@{}", self.local, self.domain)
    }
}

/// Percent-encodes a query-component value, keeping only RFC 3986
/// unreserved characters literal (so `acct:alice@example.com` becomes
/// `acct%3Aalice%40example.com`, as in the section 10.2 example).
#[must_use]
pub fn percent_encode_component(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(byte));
        } else {
            out.push('%');
            out.push(
                char::from_digit(u32::from(byte >> 4), 16)
                    .unwrap_or('0')
                    .to_ascii_uppercase(),
            );
            out.push(
                char::from_digit(u32::from(byte & 0x0F), 16)
                    .unwrap_or('0')
                    .to_ascii_uppercase(),
            );
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// WebFinger failure. Variants preserve the failing layer — handle form,
/// network policy/transport/HTTP (via [`ClientError`]), JRD parse fault,
/// or the section 10.2 mapping requirement that failed. No variant is ever
/// softened into a partial success, and none implies record verification.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WebFingerError {
    /// The handle text violates section 10.1.
    #[error(transparent)]
    Handle(#[from] HandleError),
    /// An explicit endpoint override was supplied under the public policy.
    /// Overrides exist only for loopback tests of the explicitly
    /// non-conforming development mode; public lookups always derive the
    /// endpoint from the handle domain (section 10.2).
    #[error("an endpoint override requires the development network policy")]
    EndpointOverridePolicy,
    /// The bounded client failed: policy, transport, HTTP status, media
    /// type, response bound, or budget (the layer is preserved).
    #[error(transparent)]
    Client(#[from] ClientError),
    /// The authority answered HTTP 404: no mapping for the requested
    /// resource (RFC 7033 section 4.2). Local absence at that authority,
    /// never proof the handle was never assigned.
    #[error("the handle authority has no mapping for the requested resource")]
    HandleNotFound,
    /// The response body failed strict bounded JRD parsing.
    #[error(transparent)]
    Jrd(#[from] JrdFault),
    /// The JSON parsed but is not a JRD of the shape RFC 7033 requires.
    #[error("JRD shape violation: {0}")]
    Shape(&'static str),
    /// The JRD has no `subject` member (requirement 3 cannot be checked).
    #[error("the JRD carries no subject")]
    MissingSubject,
    /// `subject` is not exactly the requested canonical `acct:` resource.
    #[error("the JRD subject is not the requested canonical resource")]
    SubjectMismatch {
        /// The subject the authority returned (bounded by the response cap).
        subject: String,
    },
    /// No link carries the Followee DID relation: not a verified mapping.
    #[error("the JRD carries no Followee DID link")]
    NoFolloweeLink,
    /// More than one link carries the Followee DID relation: ambiguous,
    /// not a verified mapping.
    #[error("the JRD carries {0} Followee DID links; exactly one is required")]
    MultipleFolloweeLinks(usize),
    /// The one Followee DID link has no `href` value.
    #[error("the Followee DID link carries no href target")]
    MissingDidTarget,
    /// The Followee DID link target is not a canonical v1 Followee DID
    /// (malformed syntax, wrong scheme, or unsupported hash profile — the
    /// production DID parser's classification is preserved).
    #[error("the Followee DID link target is not a canonical v1 Followee DID")]
    InvalidDidTarget(DidError),
}

impl WebFingerError {
    /// Stable symbolic name for machine consumption.
    #[must_use]
    pub fn symbol(&self) -> &'static str {
        match self {
            WebFingerError::Handle(_) => "invalidHandle",
            WebFingerError::EndpointOverridePolicy => "endpointOverridePolicy",
            WebFingerError::Client(e) => e.symbol(),
            WebFingerError::HandleNotFound => "handleNotFound",
            WebFingerError::Jrd(JrdFault::InvalidUtf8) => "jrdInvalidUtf8",
            WebFingerError::Jrd(JrdFault::MalformedJson) => "jrdMalformed",
            WebFingerError::Jrd(JrdFault::DuplicateMember) => "jrdDuplicateMember",
            WebFingerError::Jrd(JrdFault::LimitExceeded) => "jrdLimitExceeded",
            WebFingerError::Shape(_) => "jrdShape",
            WebFingerError::MissingSubject => "missingSubject",
            WebFingerError::SubjectMismatch { .. } => "subjectMismatch",
            WebFingerError::NoFolloweeLink => "noFolloweeLink",
            WebFingerError::MultipleFolloweeLinks(_) => "multipleFolloweeLinks",
            WebFingerError::MissingDidTarget => "missingDidTarget",
            WebFingerError::InvalidDidTarget(DidError::InvalidDid) => "invalidDidTarget",
            WebFingerError::InvalidDidTarget(DidError::UnsupportedHash) => "unsupportedHashTarget",
        }
    }
}

// ---------------------------------------------------------------------------
// Discovery
// ---------------------------------------------------------------------------

/// A successful section 10.2 mapping: the domain's claim that the exact
/// canonical resource maps to one Followee DID. Discovery is not record
/// verification and never establishes identity by itself.
#[derive(Debug, Clone)]
pub struct Discovery {
    /// The canonical resource that was requested and matched exactly.
    pub resource: String,
    /// The mapped Followee DID from the single Followee DID link.
    pub did: FolloweeDid,
    /// Optional section 10.3 bootstrap record URLs, in link order: every
    /// link with the record relation, `application/cose` type, and an
    /// `href`. These are untrusted hints; candidates fetched from them are
    /// opaque bytes until local verification.
    pub record_links: Vec<String>,
    /// Every URL contacted for this lookup (the request plus followed
    /// redirect targets), for the caller's traversal accounting.
    pub contacted: Vec<String>,
}

/// The production WebFinger client: a thin, protocol-specific layer over
/// the Milestone 4 bounded HTTP machinery.
pub struct WebFingerClient<'a> {
    inner: RelayClient<'a>,
}

impl std::fmt::Debug for WebFingerClient<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebFingerClient")
            .field("policy", &self.inner.policy())
            .finish_non_exhaustive()
    }
}

impl<'a> WebFingerClient<'a> {
    /// Creates a client over an injected transport, policy, and clock.
    #[must_use]
    pub fn new(transport: &'a dyn Transport, policy: NetworkPolicy, clock: &'a dyn Clock) -> Self {
        WebFingerClient {
            inner: RelayClient::new(transport, policy, clock),
        }
    }

    /// Overrides the per-request timeout used when the operation budget
    /// has no deadline.
    #[must_use]
    pub fn with_default_timeout_ms(mut self, timeout_ms: u64) -> Self {
        self.inner = self.inner.with_default_timeout_ms(timeout_ms);
        self
    }

    /// The client's network policy.
    #[must_use]
    pub fn policy(&self) -> NetworkPolicy {
        self.inner.policy()
    }

    /// The lookup URL for `handle`: derived from the handle domain under
    /// the public policy, or the explicit loopback `endpoint` base (ending
    /// in `/`) under the development policy.
    fn lookup_url(
        &self,
        handle: &Handle,
        endpoint: Option<&str>,
    ) -> Result<String, WebFingerError> {
        let base = match endpoint {
            None => format!("https://{}/", handle.domain()),
            Some(base) => {
                if self.policy() != NetworkPolicy::Development {
                    return Err(WebFingerError::EndpointOverridePolicy);
                }
                if !base.ends_with('/') {
                    return Err(WebFingerError::Client(ClientError::RequestInvalid(
                        "endpoint base must end in '/'",
                    )));
                }
                base.to_owned()
            }
        };
        Ok(format!(
            "{base}.well-known/webfinger?resource={}",
            percent_encode_component(&handle.resource())
        ))
    }

    /// Performs one section 10.2 lookup for `handle` and enforces every
    /// mapping requirement: policy-validated HTTPS (or explicitly
    /// non-conforming loopback development) connection, an
    /// `application/jrd+json` response within the byte bound, strict
    /// bounded JRD parsing, `subject` exactly equal to the requested
    /// canonical resource, exactly one Followee DID link, and a canonical
    /// v1 Followee DID in its `href`.
    ///
    /// # Errors
    ///
    /// Returns the [`WebFingerError`] preserving the failing layer. A
    /// failure never mutates any caller state; a rejected response is
    /// never a mapping and never proof of non-existence.
    pub fn lookup(
        &self,
        handle: &Handle,
        endpoint: Option<&str>,
        meter: &mut BudgetMeter,
    ) -> Result<Discovery, WebFingerError> {
        let url = self.lookup_url(handle, endpoint)?;
        let resource = handle.resource();
        let mut contacted = Vec::new();
        let body = self
            .inner
            .exchange(
                Exchange {
                    method: Method::Get,
                    url: &url,
                    accept: Some(APPLICATION_JRD_JSON),
                    content_type: None,
                    body: &[],
                    max_response_bytes: MAX_JRD_RESPONSE_BYTES,
                    response_media_type: APPLICATION_JRD_JSON,
                },
                meter,
                &mut contacted,
            )
            .map_err(|error| match error {
                ClientError::HttpStatus { status: 404 } => WebFingerError::HandleNotFound,
                other => WebFingerError::Client(other),
            })?;

        let document = jrd::parse_json(&body, MAX_JRD_DEPTH, MAX_JRD_MEMBERS)?;
        let JsonValue::Object(_) = document else {
            return Err(WebFingerError::Shape("the JRD is not a JSON object"));
        };

        // Requirement 3: subject exactly equal to the requested canonical
        // acct: URI. Missing and mismatched subjects are distinct faults.
        let subject = match document.member("subject") {
            None => return Err(WebFingerError::MissingSubject),
            Some(JsonValue::String(subject)) => subject,
            Some(_) => return Err(WebFingerError::Shape("subject is not a string")),
        };
        if *subject != resource {
            return Err(WebFingerError::SubjectMismatch {
                subject: subject.clone(),
            });
        }

        // Requirement 4: exactly one link with the Followee DID relation.
        // A missing links array has zero matching links.
        let links: &[JsonValue] = match document.member("links") {
            None => &[],
            Some(JsonValue::Array(links)) => links,
            Some(_) => return Err(WebFingerError::Shape("links is not an array")),
        };
        let mut did_targets: Vec<Option<&str>> = Vec::new();
        let mut record_links: Vec<String> = Vec::new();
        for link in links {
            let JsonValue::Object(_) = link else {
                return Err(WebFingerError::Shape("a links entry is not an object"));
            };
            // RFC 7033 section 4.4.4: every link must carry a rel string.
            let rel = match link.member("rel") {
                Some(JsonValue::String(rel)) => rel,
                _ => return Err(WebFingerError::Shape("a links entry has no rel string")),
            };
            let href = match link.member("href") {
                Some(JsonValue::String(href)) => Some(href.as_str()),
                Some(_) => return Err(WebFingerError::Shape("a link href is not a string")),
                None => None,
            };
            if rel == FOLLOWEE_DID_REL {
                did_targets.push(href);
            } else if rel == FOLLOWEE_RECORD_REL {
                // A section 10.3 bootstrap hint requires the exact
                // application/cose type and an href; a record link missing
                // either is not a usable hint and is ignored (it can hide
                // nothing: candidates are always verified locally).
                let record_type = link.member("type").and_then(JsonValue::as_str);
                if let (Some(url), Some(APPLICATION_COSE)) = (href, record_type) {
                    record_links.push(url.to_owned());
                }
            }
        }
        let target = match did_targets.len() {
            0 => return Err(WebFingerError::NoFolloweeLink),
            1 => did_targets[0].ok_or(WebFingerError::MissingDidTarget)?,
            many => return Err(WebFingerError::MultipleFolloweeLinks(many)),
        };

        // Requirement 5: a canonical v1 Followee DID in href, through the
        // production DID parser with its exact classification.
        let did = FolloweeDid::parse(target).map_err(WebFingerError::InvalidDidTarget)?;

        Ok(Discovery {
            resource,
            did,
            record_links,
            contacted,
        })
    }

    /// Fetches one bootstrap record URL (section 10.3) within the shared
    /// budgets: bounded to one byte past the 16 KiB record cap (so the
    /// record verifier states the `recordTooLarge` classification), and
    /// required to answer `application/cose`. The bytes are returned
    /// opaquely; this function performs no verification.
    ///
    /// # Errors
    ///
    /// Returns the [`WebFingerError`] preserving the failing layer.
    pub fn fetch_record(
        &self,
        url: &str,
        meter: &mut BudgetMeter,
    ) -> Result<Vec<u8>, WebFingerError> {
        let mut contacted = Vec::new();
        let body = self.inner.exchange(
            Exchange {
                method: Method::Get,
                url,
                accept: Some(APPLICATION_COSE),
                content_type: None,
                body: &[],
                max_response_bytes: (MAX_RECORD_BYTES as u64).saturating_add(1),
                response_media_type: APPLICATION_COSE,
            },
            meter,
            &mut contacted,
        )?;
        Ok(body)
    }

    /// Fetches and locally verifies every bootstrap candidate from
    /// `discovery`, then selects deterministically through the production
    /// core with the mapped DID as the explicit target and the caller's
    /// retained sticky state. Invalid, mismatched, premature, losing, and
    /// post-revocation candidates are reported and discarded; nothing here
    /// mutates caller state (the caller decides what to persist from the
    /// returned selection).
    #[must_use]
    pub fn bootstrap(
        &self,
        discovery: &Discovery,
        now_ms: u64,
        sticky: AuthorityState,
        meter: &mut BudgetMeter,
    ) -> BootstrapOutcome {
        let mut candidates = Vec::new();
        let mut verified: Vec<(usize, VerifiedRecord)> = Vec::new();
        for (index, url) in discovery.record_links.iter().enumerate() {
            let status = match self.fetch_record(url, meter) {
                Err(error) => CandidateStatus::FetchFailed(error),
                Ok(bytes) => match verify_record_for_target(discovery.did.as_str(), &bytes) {
                    Err(error) => CandidateStatus::Rejected(error),
                    Ok(record) => {
                        let status = if time_status(record.timestamp_ms(), now_ms)
                            == TimeStatus::Premature
                        {
                            CandidateStatus::Premature
                        } else {
                            CandidateStatus::Verified {
                                authority: record.authority(),
                                timestamp_ms: record.timestamp_ms(),
                                body_digest: *record.body_digest(),
                                stale: freshness(record.body().valid_until_ms, now_ms)
                                    == Freshness::Stale,
                            }
                        };
                        verified.push((index, record));
                        status
                    }
                },
            };
            candidates.push(BootstrapCandidate {
                url: url.clone(),
                status,
            });
        }

        // Deterministic selection through the production core: explicit
        // target, premature exclusion, absolute RootRevoked precedence,
        // sticky state, and ordering all live in select_current.
        let records: Vec<VerifiedRecord> = verified.iter().map(|(_, r)| r.clone()).collect();
        let selection = select_current(&discovery.did, &records, now_ms, sticky);
        let winner = selection.winner.map(|winner| {
            let source = verified
                .iter()
                .find(|(_, record)| record.body_digest() == winner.body_digest())
                .map(|(index, _)| discovery.record_links[*index].clone())
                .unwrap_or_default();
            BootstrapWinner {
                stale: freshness(winner.body().valid_until_ms, now_ms) == Freshness::Stale,
                record: winner.clone(),
                source,
            }
        });
        BootstrapOutcome {
            candidates,
            authority_state: selection.authority_state,
            winner,
        }
    }

    /// Section 10.4 inverse handle verification: combines the signed
    /// `alsoKnownAs` claim in an already locally verified record with a
    /// fresh inverse lookup of the exact handle. The handle is verified if
    /// and only if the record claims the exact handle **and** the handle's
    /// authority currently maps the exact canonical resource back to the
    /// record's own DID. A signed claim alone is never verified; a mapping
    /// alone is never verified.
    #[must_use]
    pub fn verify_handle(
        &self,
        handle: &Handle,
        record: &VerifiedRecord,
        endpoint: Option<&str>,
        meter: &mut BudgetMeter,
    ) -> HandleVerification {
        let claim = record_handle_claim(record, handle);
        let inverse = match self.lookup(handle, endpoint, meter) {
            Ok(discovery) => {
                if discovery.did == record.body().id {
                    InverseOutcome::Matched { discovery }
                } else {
                    InverseOutcome::Mismatched { discovery }
                }
            }
            Err(error) => InverseOutcome::Failed(error),
        };
        let verified = claim.is_some() && matches!(inverse, InverseOutcome::Matched { .. });
        HandleVerification {
            claim,
            inverse,
            verified,
        }
    }
}

/// The `alsoKnownAs` entry of `record` claiming exactly `handle`, if any:
/// an `acct:` URI whose local part equals the handle's local part
/// case-sensitively and whose domain canonicalizes to the same lowercase
/// ASCII IDNA form (section 10.1). Entries that are not handle-form
/// `acct:` URIs are ignored here; they remain ordinary signed claims.
#[must_use]
pub fn record_handle_claim(record: &VerifiedRecord, handle: &Handle) -> Option<String> {
    record
        .body()
        .contact
        .also_known_as
        .iter()
        .find(|entry| {
            Handle::from_acct_uri(entry)
                .map(|claimed| {
                    claimed.local() == handle.local() && claimed.domain() == handle.domain()
                })
                .unwrap_or(false)
        })
        .cloned()
}

/// One bootstrap candidate's outcome.
#[derive(Debug, Clone)]
pub struct BootstrapCandidate {
    /// The record URL the candidate came from.
    pub url: String,
    /// What happened to it.
    pub status: CandidateStatus,
}

/// Per-candidate bootstrap classification. Every rejection preserves the
/// production classification; nothing is inferred or normalized.
#[derive(Debug, Clone)]
pub enum CandidateStatus {
    /// The bounded fetch failed (policy, transport, HTTP, media type,
    /// size, or budget — the layer is preserved).
    FetchFailed(WebFingerError),
    /// Local verification rejected the bytes with this classification.
    Rejected(VerifyError),
    /// The record verified but is premature under the caller's clock; it
    /// is excluded from selection.
    Premature,
    /// The record verified and is time-admissible; it entered selection.
    Verified {
        /// The record's authority state.
        authority: crate::record::Authority,
        /// The record's ordering timestamp.
        timestamp_ms: u64,
        /// The record's body digest.
        body_digest: [u8; 32],
        /// Whether the record is stale under the caller's clock.
        stale: bool,
    },
}

/// The bootstrap result: per-candidate outcomes plus the deterministic
/// selection for the mapped DID.
#[derive(Debug, Clone)]
pub struct BootstrapOutcome {
    /// Per-candidate outcomes in link order.
    pub candidates: Vec<BootstrapCandidate>,
    /// The authority state selection produced (sticky rules applied); the
    /// caller persists a learned RootRevoked transition.
    pub authority_state: AuthorityState,
    /// The selected winner, if any admissible candidate survived.
    pub winner: Option<BootstrapWinner>,
}

/// The selected bootstrap winner.
#[derive(Debug, Clone)]
pub struct BootstrapWinner {
    /// The locally verified winning record.
    pub record: VerifiedRecord,
    /// Whether it is stale under the caller's clock.
    pub stale: bool,
    /// The record URL it came from.
    pub source: String,
}

/// The inverse-lookup half of handle verification.
#[derive(Debug, Clone)]
pub enum InverseOutcome {
    /// The authority maps the exact resource to the record's own DID.
    Matched {
        /// The successful discovery.
        discovery: Discovery,
    },
    /// The authority maps the exact resource to a different DID: the
    /// handle is not verified for this record. The mapping changes
    /// nothing about the record, the followed DID, or sticky state.
    Mismatched {
        /// The discovery naming the other DID.
        discovery: Discovery,
    },
    /// The lookup failed (the layer is preserved). Failure is never
    /// treated as a mismatch and never changes local state.
    Failed(WebFingerError),
}

/// A complete section 10.4 handle-verification result for one record.
#[derive(Debug, Clone)]
pub struct HandleVerification {
    /// The record's matching signed `alsoKnownAs` entry, if present.
    pub claim: Option<String>,
    /// The inverse-lookup outcome.
    pub inverse: InverseOutcome,
    /// Verified if and only if the claim is present **and** the inverse
    /// lookup matched the same DID.
    pub verified: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sec_10_1_handle_display_is_the_exact_local_at_domain_form() {
        let handle = Handle::parse("Alice.B_c-1@EXAMPLE.com").expect("parses");
        assert_eq!(handle.to_string(), "Alice.B_c-1@example.com");
        assert_eq!(handle.resource(), "acct:Alice.B_c-1@example.com");
    }

    #[test]
    fn sec_10_2_percent_encoding_keeps_only_unreserved_characters() {
        assert_eq!(percent_encode_component("AZaz09-._~"), "AZaz09-._~");
        assert_eq!(percent_encode_component("a b/%"), "a%20b%2F%25");
    }
}
