//! Strict, bounded production HTTP/CBOR relay client (specification
//! sections 12, 14.1, 15.4; IMPLEMENTATION.md sections 9.5 and 10).
//!
//! This is the one client path used by the synchronization receiver, the
//! direct `followee relay` commands, and the multi-relay resolver. It
//! enforces the exact operation paths, methods, media types, HTTP status
//! handling, and response-size bounds; validates every outer response as one
//! deterministic CBOR item before schema interpretation (byte strings stay
//! opaque); applies an explicit [`NetworkPolicy`] to every requested URL,
//! every redirect target, and — in the production transport — every resolved
//! destination address; and charges every attempted request to an explicit
//! caller-supplied [`BudgetMeter`] under the injected [`Clock`].
//!
//! Nothing here normalizes protocol data, infers a protocol result from a
//! transport condition, or translates a broad exception into a protocol
//! error: every failure is a typed [`ClientError`] variant that preserves
//! the distinction between policy refusal, transport failure, HTTP status,
//! a rejected outer response, and a bounded-budget stop. A rejected outer
//! response is never Absent and never a per-DID Error result
//! (specification sections 12.1 and 14.1).

use super::wire::{
    self, ReceivedChangesResponse, ReceivedDirectory, ReceivedPublishResponse,
    ReceivedResolveResponse,
};
use crate::clock::Clock;
use crate::error::VerifyError;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub use super::wire::{
    ReceivedChangeEntry, ReceivedChangePayload, ReceivedResult, RelayInfo, RelayLimits,
};

/// Media type for relay API CBOR requests and responses.
const APPLICATION_CBOR: &str = "application/cbor";
/// Media type for a complete tagged Identity Record.
const APPLICATION_COSE: &str = "application/cose";

/// Bound on `v1/info` and `v1/publish` response entities: both are small
/// fixed-shape maps; 64 KiB is far above any conforming encoding.
const MAX_SMALL_RESPONSE_BYTES: u64 = 64 * 1024;
/// Bound on `v1/resolve` response entities: the section 12.3 conforming
/// minimum bound.
const MAX_RESOLVE_RESPONSE_BYTES: u64 = 1024 * 1024;
/// Bound on `v1/directory` response entities (section 15.2).
const MAX_DIRECTORY_RESPONSE_BYTES: u64 = 1024 * 1024;
/// Maximum redirects followed for one GET operation. POST operations refuse
/// redirects entirely: replaying a publish/resolve/changes body toward a
/// server-chosen location is an unsafe redirect transition.
const MAX_REDIRECTS: u32 = 5;

/// Explicit network policy for relay endpoints (IMPLEMENTATION.md
/// section 9.5). Discovered endpoints are untrusted input; the policy is
/// applied to every requested URL, every redirect target, and every
/// resolved destination so relay discovery cannot become an unrestricted
/// SSRF primitive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkPolicy {
    /// Default public policy: HTTPS only, no embedded credentials, no
    /// private, loopback, link-local, or otherwise sensitive destination
    /// addresses, and redirects that stay within the same rules.
    Public,
    /// Explicit development/operator policy: HTTP or HTTPS to loopback
    /// destinations only. Explicitly non-conforming; used by tests and the
    /// local demonstration.
    Development,
}

/// One policy violation. The URL itself is not echoed back in full to keep
/// hostile input out of diagnostics; the violation names the failed rule.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PolicyViolation {
    /// The URL does not satisfy the RFC 3986 `URI` production.
    #[error("endpoint is not a valid URI")]
    InvalidUrl,
    /// The scheme is not permitted by the active policy.
    #[error("endpoint scheme is not permitted by the network policy")]
    SchemeNotPermitted,
    /// The URL embeds userinfo credentials.
    #[error("endpoint embeds credentials, which are rejected")]
    EmbeddedCredentials,
    /// The destination host or address is not permitted by the policy.
    #[error("endpoint destination is not permitted by the network policy")]
    DestinationNotPermitted,
    /// A redirect target failed policy validation or the redirect form is
    /// unsupported (relative target, POST redirect, or too many hops).
    #[error("redirect refused: {0}")]
    RedirectRefused(&'static str),
}

/// Destination rule the transport must enforce on every address the request
/// actually connects to, including addresses obtained by name resolution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DestinationRule {
    /// Every resolved address must be a globally routable public address.
    PublicInternet,
    /// Every resolved address must be loopback.
    LoopbackOnly,
}

/// HTTP method for a transport request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    /// `GET`.
    Get,
    /// `POST`.
    Post,
}

/// One bounded transport request. The transport performs exactly this
/// request: it must not follow redirects, retry, or reinterpret anything.
#[derive(Debug, Clone)]
pub struct TransportRequest<'a> {
    /// HTTP method.
    pub method: Method,
    /// Absolute request URL, already policy-validated by the client.
    pub url: &'a str,
    /// Request body media type, when a body is sent.
    pub content_type: Option<&'static str>,
    /// Request body bytes.
    pub body: &'a [u8],
    /// The transport must return at most this many body bytes plus one, so
    /// the client can detect an over-bound response without unbounded reads.
    pub max_response_bytes: u64,
    /// Destination rule to enforce on every address connected to.
    pub destination: DestinationRule,
    /// Per-request timeout in milliseconds.
    pub timeout_ms: u64,
}

/// One transport response: status, media type, redirect target, and bounded
/// body bytes, with no interpretation applied.
#[derive(Debug, Clone)]
pub struct TransportResponse {
    /// HTTP status code.
    pub status: u16,
    /// The `Content-Type` header value, if present.
    pub content_type: Option<String>,
    /// The `Location` header value, if present.
    pub location: Option<String>,
    /// Bounded body bytes.
    pub body: Vec<u8>,
}

/// Transport-layer failure: local or network infrastructure, never a
/// protocol result.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TransportError {
    /// The destination was refused by the transport's address validation.
    #[error("destination refused: {0}")]
    Refused(String),
    /// The request timed out.
    #[error("request timed out")]
    TimedOut,
    /// Connection, I/O, or TLS failure.
    #[error("transport failure: {0}")]
    Io(String),
}

/// A pluggable HTTP transport. Production uses [`HttpTransport`]; tests
/// inject deterministic transports that return exact response bytes without
/// sleeping or touching the network.
pub trait Transport {
    /// Executes exactly one bounded HTTP request.
    ///
    /// # Errors
    ///
    /// Returns a [`TransportError`] for connection, validation, timeout, or
    /// I/O failure.
    fn execute(&self, request: &TransportRequest<'_>) -> Result<TransportResponse, TransportError>;
}

/// An explicit operation budget (specification section 14.1). The deadline
/// is an absolute injected-clock time; byte and request budgets are shared
/// across every request charged to the same meter and are never reset by a
/// relay, reference, or retry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OperationBudget {
    /// Absolute deadline in injected-clock Unix milliseconds, if any.
    pub deadline_ms: Option<u64>,
    /// Maximum total response bytes across the operation.
    pub max_response_bytes: u64,
    /// Maximum requests attempted across the operation.
    pub max_requests: u64,
}

/// Mutable consumption state for one [`OperationBudget`]. Every attempted
/// request is charged, whatever its outcome (specification section 14.1:
/// Absent, Error, and rejected responses consume the same budgets).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BudgetMeter {
    budget: OperationBudget,
    bytes_used: u64,
    requests_used: u64,
}

impl BudgetMeter {
    /// Creates a meter over `budget` with nothing consumed.
    #[must_use]
    pub fn new(budget: OperationBudget) -> Self {
        BudgetMeter {
            budget,
            bytes_used: 0,
            requests_used: 0,
        }
    }

    /// Total response bytes charged so far.
    #[must_use]
    pub fn bytes_used(&self) -> u64 {
        self.bytes_used
    }

    /// Requests charged so far.
    #[must_use]
    pub fn requests_used(&self) -> u64 {
        self.requests_used
    }

    /// Charges one request attempt and checks the deadline, returning the
    /// milliseconds remaining until the deadline (or `default_timeout_ms`
    /// when no deadline is set).
    fn charge_request(
        &mut self,
        clock: &dyn Clock,
        default_timeout_ms: u64,
    ) -> Result<u64, ClientError> {
        if self.requests_used >= self.budget.max_requests {
            return Err(ClientError::BudgetExhausted("request budget"));
        }
        self.requests_used = self.requests_used.saturating_add(1);
        match self.budget.deadline_ms {
            None => Ok(default_timeout_ms),
            Some(deadline) => {
                let now = clock
                    .now_ms()
                    .map_err(|e| ClientError::Environment(e.to_string()))?;
                let remaining = deadline.saturating_sub(now);
                if remaining == 0 {
                    return Err(ClientError::BudgetExhausted("deadline"));
                }
                Ok(remaining.min(default_timeout_ms))
            }
        }
    }

    /// Charges received response bytes against the shared byte budget.
    fn charge_bytes(&mut self, count: u64) -> Result<(), ClientError> {
        self.bytes_used = self.bytes_used.saturating_add(count);
        if self.bytes_used > self.budget.max_response_bytes {
            return Err(ClientError::BudgetExhausted("response-byte budget"));
        }
        Ok(())
    }
}

/// Client failure. Variants preserve the layer that failed: policy,
/// transport, HTTP status, media type, response bound, rejected outer
/// response, protocol-shape violations the caller must treat as a rejected
/// response, or budget exhaustion. No variant is ever synthesized into an
/// Absent or per-DID Error protocol result.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ClientError {
    /// The URL or a redirect failed the explicit network policy.
    #[error(transparent)]
    Policy(#[from] PolicyViolation),
    /// Local or network infrastructure failure.
    #[error(transparent)]
    Transport(#[from] TransportError),
    /// The relay answered with a non-200 HTTP status. `400` means the outer
    /// request was rejected before per-item processing (section 15.4); the
    /// bounded body is discarded unread.
    #[error("relay answered HTTP {status}")]
    HttpStatus {
        /// The received status code.
        status: u16,
    },
    /// The 200 response did not carry `application/cbor`.
    #[error("response media type is not application/cbor")]
    MediaType,
    /// The response body exceeded the applicable size bound.
    #[error("response exceeds the applicable size bound")]
    ResponseTooLarge,
    /// The outer response was rejected at the wrapper layer (section 12.1):
    /// not well-formed, basically valid, deterministic, or
    /// schema-conforming. Never interpreted as Absent for any DID and never
    /// as a per-DID Error result.
    #[error("outer relay response rejected: {0}")]
    OuterResponse(VerifyError),
    /// The resolve result count differs from the request count; the complete
    /// response is rejected (section 12.3).
    #[error("resolve response returned {returned} results for {requested} requested DIDs")]
    CardinalityMismatch {
        /// DIDs requested.
        requested: usize,
        /// Results returned.
        returned: usize,
    },
    /// A shared operation budget was exhausted before the request was made.
    #[error("operation budget exhausted: {0}")]
    BudgetExhausted(&'static str),
    /// The caller's request parameters violate a protocol bound (section
    /// 15.2); the strict client refuses to emit an invalid request.
    #[error("request refused before transmission: {0}")]
    RequestInvalid(&'static str),
    /// The injected clock or another local facility failed.
    #[error("environment failure: {0}")]
    Environment(String),
}

impl ClientError {
    /// Stable symbolic name for machine consumption, preserving the
    /// protocol-versus-infrastructure distinction.
    #[must_use]
    pub fn symbol(&self) -> &'static str {
        match self {
            ClientError::Policy(_) => "networkPolicy",
            ClientError::Transport(TransportError::TimedOut) => "transportTimeout",
            ClientError::Transport(_) => "transport",
            ClientError::HttpStatus { status: 400 } => "outerRequestRejected",
            ClientError::HttpStatus { .. } => "httpStatus",
            ClientError::MediaType => "mediaType",
            ClientError::ResponseTooLarge => "responseTooLarge",
            ClientError::OuterResponse(_) => "outerResponseRejected",
            ClientError::CardinalityMismatch { .. } => "cardinalityMismatch",
            ClientError::BudgetExhausted(_) => "budgetExhausted",
            ClientError::RequestInvalid(_) => "requestInvalid",
            ClientError::Environment(_) => "environment",
        }
    }
}

// ---------------------------------------------------------------------------
// URL policy validation
// ---------------------------------------------------------------------------

/// Whether an IPv4 address is acceptable for the public policy: rejects
/// loopback, private, link-local, unspecified, broadcast, multicast,
/// shared/CGNAT `100.64.0.0/10`, `192.0.0.0/24`, and benchmarking
/// `198.18.0.0/15` space.
fn ipv4_public(addr: Ipv4Addr) -> bool {
    let octets = addr.octets();
    !(addr.is_loopback()
        || addr.is_private()
        || addr.is_link_local()
        || addr.is_unspecified()
        || addr.is_broadcast()
        || addr.is_multicast()
        || addr.is_documentation()
        || (octets[0] == 100 && (octets[1] & 0xC0) == 64)
        || (octets[0] == 192 && octets[1] == 0 && octets[2] == 0)
        || (octets[0] == 198 && (octets[1] & 0xFE) == 18))
}

/// Whether an IPv6 address is acceptable for the public policy: rejects
/// loopback, unspecified, unique-local `fc00::/7`, link-local `fe80::/10`,
/// multicast, and applies the IPv4 rules to IPv4-mapped addresses.
fn ipv6_public(addr: Ipv6Addr) -> bool {
    if let Some(mapped) = addr.to_ipv4_mapped() {
        return ipv4_public(mapped);
    }
    let segments = addr.segments();
    !(addr.is_loopback()
        || addr.is_unspecified()
        || addr.is_multicast()
        || (segments[0] & 0xFE00) == 0xFC00
        || (segments[0] & 0xFFC0) == 0xFE80)
}

/// Whether an address is acceptable under a destination rule.
#[must_use]
pub fn address_permitted(rule: DestinationRule, addr: IpAddr) -> bool {
    match rule {
        DestinationRule::LoopbackOnly => addr.is_loopback(),
        DestinationRule::PublicInternet => match addr {
            IpAddr::V4(v4) => ipv4_public(v4),
            IpAddr::V6(v6) => ipv6_public(v6),
        },
    }
}

impl NetworkPolicy {
    /// The destination rule this policy imposes on connected addresses.
    #[must_use]
    pub fn destination_rule(&self) -> DestinationRule {
        match self {
            NetworkPolicy::Public => DestinationRule::PublicInternet,
            NetworkPolicy::Development => DestinationRule::LoopbackOnly,
        }
    }

    /// Validates one absolute URL against this policy: URI grammar, scheme,
    /// absence of embedded credentials, and — for literal-address hosts and
    /// the loopback-only development policy — the destination itself.
    /// DNS-name destinations under the public policy are additionally
    /// validated at resolution time by the transport.
    ///
    /// # Errors
    ///
    /// Returns the first [`PolicyViolation`].
    pub fn check_url(&self, url: &str) -> Result<(), PolicyViolation> {
        if url.len() > crate::limits::MAX_URI_BYTES {
            return Err(PolicyViolation::InvalidUrl);
        }
        let parsed =
            iri_string::types::UriStr::new(url).map_err(|_| PolicyViolation::InvalidUrl)?;
        let scheme = parsed.scheme_str();
        let https = scheme.eq_ignore_ascii_case("https");
        let http = scheme.eq_ignore_ascii_case("http");
        match self {
            NetworkPolicy::Public => {
                if !https {
                    return Err(PolicyViolation::SchemeNotPermitted);
                }
            }
            NetworkPolicy::Development => {
                if !https && !http {
                    return Err(PolicyViolation::SchemeNotPermitted);
                }
            }
        }
        let authority = parsed
            .authority_components()
            .ok_or(PolicyViolation::InvalidUrl)?;
        if authority.userinfo().is_some() {
            return Err(PolicyViolation::EmbeddedCredentials);
        }
        let raw_host = authority.host();
        if raw_host.is_empty() {
            return Err(PolicyViolation::InvalidUrl);
        }
        let host = raw_host
            .strip_prefix('[')
            .and_then(|h| h.strip_suffix(']'))
            .unwrap_or(raw_host);
        let literal_ip = host
            .parse::<Ipv6Addr>()
            .map(IpAddr::V6)
            .or_else(|_| host.parse::<Ipv4Addr>().map(IpAddr::V4))
            .ok();
        match (self, literal_ip) {
            // A literal address is validated here, before any connection.
            (_, Some(ip)) => {
                if !address_permitted(self.destination_rule(), ip) {
                    return Err(PolicyViolation::DestinationNotPermitted);
                }
            }
            // The development policy accepts one name, `localhost`, whose
            // resolved addresses the transport still restricts to loopback.
            (NetworkPolicy::Development, None) => {
                if !host.eq_ignore_ascii_case("localhost") {
                    return Err(PolicyViolation::DestinationNotPermitted);
                }
            }
            // Public DNS names are validated at resolution time by the
            // transport under DestinationRule::PublicInternet.
            (NetworkPolicy::Public, None) => {}
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// The client
// ---------------------------------------------------------------------------

/// Outcome of one client operation, with the URIs actually contacted (the
/// requested URL plus every followed redirect target) for the caller's
/// traversal accounting.
#[derive(Debug, Clone)]
pub struct ClientOutcome<T> {
    /// The parsed, wrapper-validated value.
    pub value: T,
    /// Every base URL contacted for this operation, in order.
    pub contacted: Vec<String>,
}

/// The strict production relay client.
pub struct RelayClient<'a> {
    transport: &'a dyn Transport,
    policy: NetworkPolicy,
    clock: &'a dyn Clock,
    /// Per-request timeout when no operation deadline applies.
    default_timeout_ms: u64,
}

impl std::fmt::Debug for RelayClient<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RelayClient")
            .field("policy", &self.policy)
            .finish_non_exhaustive()
    }
}

/// One client-level exchange description consumed by [`RelayClient`]'s
/// internal request loop.
struct Exchange<'a> {
    method: Method,
    url: &'a str,
    content_type: Option<&'static str>,
    body: &'a [u8],
    max_response_bytes: u64,
}

/// Joins a base URI ending in `/` with a v1 operation path.
fn operation_url(base: &str, path: &str) -> Result<String, ClientError> {
    if !base.ends_with('/') {
        return Err(ClientError::Policy(PolicyViolation::InvalidUrl));
    }
    let mut url = String::with_capacity(base.len().saturating_add(path.len()));
    url.push_str(base);
    url.push_str(path);
    Ok(url)
}

impl<'a> RelayClient<'a> {
    /// Creates a client over an injected transport, policy, and clock.
    #[must_use]
    pub fn new(transport: &'a dyn Transport, policy: NetworkPolicy, clock: &'a dyn Clock) -> Self {
        RelayClient {
            transport,
            policy,
            clock,
            default_timeout_ms: 10_000,
        }
    }

    /// Overrides the per-request timeout used when the operation budget has
    /// no deadline.
    #[must_use]
    pub fn with_default_timeout_ms(mut self, timeout_ms: u64) -> Self {
        self.default_timeout_ms = timeout_ms;
        self
    }

    /// The client's network policy.
    #[must_use]
    pub fn policy(&self) -> NetworkPolicy {
        self.policy
    }

    /// Performs one bounded exchange: policy validation, the request, HTTP
    /// status handling, bounded redirect following for GET, media-type
    /// enforcement, and response-size accounting. Returns the response body
    /// bytes for wrapper validation by the caller.
    fn exchange(
        &self,
        request: Exchange<'_>,
        meter: &mut BudgetMeter,
        contacted: &mut Vec<String>,
    ) -> Result<Vec<u8>, ClientError> {
        let Exchange {
            method,
            url,
            content_type,
            body,
            max_response_bytes,
        } = request;
        let mut current = url.to_owned();
        let mut redirects: u32 = 0;
        loop {
            self.policy.check_url(&current)?;
            let timeout_ms = meter.charge_request(self.clock, self.default_timeout_ms)?;
            contacted.push(current.clone());
            let response = self.transport.execute(&TransportRequest {
                method,
                url: &current,
                content_type,
                body,
                max_response_bytes,
                destination: self.policy.destination_rule(),
                timeout_ms,
            })?;
            meter.charge_bytes(response.body.len() as u64)?;
            match response.status {
                200 => {
                    if response.body.len() as u64 > max_response_bytes {
                        return Err(ClientError::ResponseTooLarge);
                    }
                    let essence = response.content_type.as_deref().map(|v| {
                        v.split(';')
                            .next()
                            .unwrap_or("")
                            .trim()
                            .to_ascii_lowercase()
                    });
                    if essence.as_deref() != Some(APPLICATION_CBOR) {
                        return Err(ClientError::MediaType);
                    }
                    return Ok(response.body);
                }
                301 | 302 | 303 | 307 | 308 => {
                    // Only GET operations may follow redirects, each target
                    // is fully re-validated, and every hop is charged: a
                    // redirect never resets any budget.
                    if method != Method::Get {
                        return Err(ClientError::Policy(PolicyViolation::RedirectRefused(
                            "POST redirects are refused",
                        )));
                    }
                    if redirects >= MAX_REDIRECTS {
                        return Err(ClientError::Policy(PolicyViolation::RedirectRefused(
                            "too many redirects",
                        )));
                    }
                    let Some(location) = response.location else {
                        return Err(ClientError::Policy(PolicyViolation::RedirectRefused(
                            "redirect without a Location target",
                        )));
                    };
                    // Only absolute targets are accepted, so the complete
                    // new destination is validated, not a spliced path.
                    if iri_string::types::UriStr::new(&location).is_err() {
                        return Err(ClientError::Policy(PolicyViolation::RedirectRefused(
                            "redirect target is not an absolute URI",
                        )));
                    }
                    redirects = redirects.saturating_add(1);
                    current = location;
                }
                status => {
                    // The bounded non-200 body was already read and charged;
                    // it is discarded without parsing (section 15.4).
                    return Err(ClientError::HttpStatus { status });
                }
            }
        }
    }

    /// `GET v1/info` (specification section 12.2).
    ///
    /// # Errors
    ///
    /// Returns a [`ClientError`] preserving the failing layer.
    pub fn info(
        &self,
        base: &str,
        meter: &mut BudgetMeter,
    ) -> Result<ClientOutcome<RelayInfo>, ClientError> {
        let url = operation_url(base, "v1/info")?;
        let mut contacted = Vec::new();
        let body = self.exchange(
            Exchange {
                method: Method::Get,
                url: &url,
                content_type: None,
                body: &[],
                max_response_bytes: MAX_SMALL_RESPONSE_BYTES,
            },
            meter,
            &mut contacted,
        )?;
        let value = wire::parse_info_response(&body).map_err(ClientError::OuterResponse)?;
        Ok(ClientOutcome { value, contacted })
    }

    /// `GET v1/directory` (specification section 12.4).
    ///
    /// # Errors
    ///
    /// Returns a [`ClientError`] preserving the failing layer.
    pub fn directory(
        &self,
        base: &str,
        meter: &mut BudgetMeter,
    ) -> Result<ClientOutcome<ReceivedDirectory>, ClientError> {
        let url = operation_url(base, "v1/directory")?;
        let mut contacted = Vec::new();
        let body = self.exchange(
            Exchange {
                method: Method::Get,
                url: &url,
                content_type: None,
                body: &[],
                max_response_bytes: MAX_DIRECTORY_RESPONSE_BYTES,
            },
            meter,
            &mut contacted,
        )?;
        let value = wire::parse_directory_response(&body).map_err(ClientError::OuterResponse)?;
        Ok(ClientOutcome { value, contacted })
    }

    /// `POST v1/publish` with one complete Identity Record as
    /// `application/cose` (specification section 12.5). The record bytes are
    /// transported opaquely; this client never signs, edits, or verifies
    /// them on the publication path.
    ///
    /// # Errors
    ///
    /// Returns a [`ClientError`] preserving the failing layer.
    pub fn publish(
        &self,
        base: &str,
        record: &[u8],
        meter: &mut BudgetMeter,
    ) -> Result<ClientOutcome<ReceivedPublishResponse>, ClientError> {
        let url = operation_url(base, "v1/publish")?;
        let mut contacted = Vec::new();
        let body = self.exchange(
            Exchange {
                method: Method::Post,
                url: &url,
                content_type: Some(APPLICATION_COSE),
                body: record,
                max_response_bytes: MAX_SMALL_RESPONSE_BYTES,
            },
            meter,
            &mut contacted,
        )?;
        let value = wire::parse_publish_response(&body).map_err(ClientError::OuterResponse)?;
        Ok(ClientOutcome { value, contacted })
    }

    /// `POST v1/resolve` (specification section 12.3). Requested order and
    /// duplicates are preserved exactly; the response wrapper is validated
    /// as deterministic CBOR before schema interpretation; the result count
    /// must equal the request count or the complete response is rejected;
    /// Full byte strings stay opaque for separate section 8.1 verification
    /// against the DID at the same request index.
    ///
    /// # Errors
    ///
    /// Returns a [`ClientError`] preserving the failing layer.
    pub fn resolve(
        &self,
        base: &str,
        dids: &[&str],
        meter: &mut BudgetMeter,
    ) -> Result<ClientOutcome<ReceivedResolveResponse>, ClientError> {
        if dids.is_empty() || dids.len() > super::wire::MAX_RESOLVE_DIDS {
            return Err(ClientError::RequestInvalid(
                "resolve batch must contain 1..=256 DIDs",
            ));
        }
        let url = operation_url(base, "v1/resolve")?;
        let request = wire::encode_resolve_request(dids);
        let mut contacted = Vec::new();
        let body = self.exchange(
            Exchange {
                method: Method::Post,
                url: &url,
                content_type: Some(APPLICATION_CBOR),
                body: &request,
                max_response_bytes: MAX_RESOLVE_RESPONSE_BYTES,
            },
            meter,
            &mut contacted,
        )?;
        let value = wire::parse_resolve_response(&body).map_err(ClientError::OuterResponse)?;
        if value.results.len() != dids.len() {
            return Err(ClientError::CardinalityMismatch {
                requested: dids.len(),
                returned: value.results.len(),
            });
        }
        Ok(ClientOutcome { value, contacted })
    }

    /// `POST v1/changes` (specification section 12.6). The response is
    /// validated with every status-dependent required and forbidden field
    /// rule; a success response with more entries than `item_limit`, or with
    /// a body exceeding `byte_limit`, is rejected completely before any
    /// entry is interpreted, and its `nextCursor` is never returned.
    ///
    /// # Errors
    ///
    /// Returns a [`ClientError`] preserving the failing layer.
    pub fn changes(
        &self,
        base: &str,
        cursor: Option<&[u8]>,
        item_limit: u64,
        byte_limit: u64,
        meter: &mut BudgetMeter,
    ) -> Result<ClientOutcome<ReceivedChangesResponse>, ClientError> {
        if item_limit == 0 || item_limit > super::wire::MAX_CHANGES_ITEMS {
            return Err(ClientError::RequestInvalid("itemLimit must be 1..=1024"));
        }
        if byte_limit == 0 || byte_limit > super::wire::MAX_CHANGES_BYTES {
            return Err(ClientError::RequestInvalid("byteLimit must be 1..=4 MiB"));
        }
        if cursor.is_some_and(|c| c.len() > super::wire::MAX_CURSOR_BYTES) {
            return Err(ClientError::RequestInvalid("cursor exceeds 128 bytes"));
        }
        let url = operation_url(base, "v1/changes")?;
        let request = wire::encode_changes_request(cursor, item_limit, byte_limit);
        let mut contacted = Vec::new();
        let body = self.exchange(
            Exchange {
                method: Method::Post,
                url: &url,
                content_type: Some(APPLICATION_CBOR),
                body: &request,
                max_response_bytes: byte_limit,
            },
            meter,
            &mut contacted,
        )?;
        let value =
            wire::parse_changes_response(&body, item_limit).map_err(ClientError::OuterResponse)?;
        Ok(ClientOutcome { value, contacted })
    }
}

// ---------------------------------------------------------------------------
// Production transport
// ---------------------------------------------------------------------------

/// Production TLS-capable transport over `reqwest` with rustls (no native
/// OpenSSL dependence). Redirects are disabled — the client validates and
/// follows them itself — and DNS names are resolved here first so every
/// resolved address is validated against the destination rule and the
/// connection is pinned to the validated addresses (no re-resolution race).
#[derive(Debug, Default)]
pub struct HttpTransport;

impl Transport for HttpTransport {
    fn execute(&self, request: &TransportRequest<'_>) -> Result<TransportResponse, TransportError> {
        use std::io::Read;

        let parsed = iri_string::types::UriStr::new(request.url)
            .map_err(|e| TransportError::Refused(format!("invalid URL: {e}")))?;
        let authority = parsed
            .authority_components()
            .ok_or_else(|| TransportError::Refused("URL has no authority".to_owned()))?;
        let raw_host = authority.host();
        let host = raw_host
            .strip_prefix('[')
            .and_then(|h| h.strip_suffix(']'))
            .unwrap_or(raw_host);
        let default_port: u16 = if parsed.scheme_str().eq_ignore_ascii_case("https") {
            443
        } else {
            80
        };
        let port: u16 = match authority.port() {
            None | Some("") => default_port,
            Some(text) => text
                .parse()
                .map_err(|_| TransportError::Refused("invalid port".to_owned()))?,
        };

        let mut builder = reqwest::blocking::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(std::time::Duration::from_millis(request.timeout_ms.max(1)))
            .no_proxy();

        let literal: Option<IpAddr> = host
            .parse::<Ipv6Addr>()
            .map(IpAddr::V6)
            .or_else(|_| host.parse::<Ipv4Addr>().map(IpAddr::V4))
            .ok();
        match literal {
            Some(ip) => {
                if !address_permitted(request.destination, ip) {
                    return Err(TransportError::Refused(
                        "destination address violates the network policy".to_owned(),
                    ));
                }
            }
            None => {
                // Resolve the name now, validate every address, and pin the
                // connection to exactly the validated addresses. If any
                // resolved address violates the rule the request is refused
                // outright: partially hostile resolutions (DNS rebinding
                // shapes) are not partially followed.
                use std::net::ToSocketAddrs;
                let addrs: Vec<std::net::SocketAddr> = (host, port)
                    .to_socket_addrs()
                    .map_err(|e| TransportError::Io(format!("name resolution failed: {e}")))?
                    .collect();
                if addrs.is_empty() {
                    return Err(TransportError::Io(
                        "name resolved to no addresses".to_owned(),
                    ));
                }
                if addrs
                    .iter()
                    .any(|a| !address_permitted(request.destination, a.ip()))
                {
                    return Err(TransportError::Refused(
                        "a resolved address violates the network policy".to_owned(),
                    ));
                }
                builder = builder.resolve_to_addrs(host, &addrs);
            }
        }

        let client = builder
            .build()
            .map_err(|e| TransportError::Io(e.to_string()))?;
        let mut req = match request.method {
            Method::Get => client.get(request.url),
            Method::Post => client.post(request.url).body(request.body.to_vec()),
        };
        if let Some(content_type) = request.content_type {
            req = req.header(reqwest::header::CONTENT_TYPE, content_type);
        }
        let response = req.send().map_err(|e| {
            if e.is_timeout() {
                TransportError::TimedOut
            } else {
                TransportError::Io(e.to_string())
            }
        })?;

        let status = response.status().as_u16();
        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let location = response
            .headers()
            .get(reqwest::header::LOCATION)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);

        // Bounded read: at most max+1 bytes, so the caller can detect an
        // over-bound body without this transport buffering it unboundedly.
        let limit = request.max_response_bytes.saturating_add(1);
        let mut body = Vec::new();
        response
            .take(limit)
            .read_to_end(&mut body)
            .map_err(|e| TransportError::Io(e.to_string()))?;
        Ok(TransportResponse {
            status,
            content_type,
            location,
            body,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sec_9_5_public_policy_rejects_unsupported_schemes_and_credentials() {
        let policy = NetworkPolicy::Public;
        assert_eq!(
            policy.check_url("http://relay.example/").unwrap_err(),
            PolicyViolation::SchemeNotPermitted
        );
        assert_eq!(
            policy.check_url("ftp://relay.example/").unwrap_err(),
            PolicyViolation::SchemeNotPermitted
        );
        assert_eq!(
            policy.check_url("file:///etc/passwd").unwrap_err(),
            PolicyViolation::SchemeNotPermitted
        );
        assert_eq!(
            policy
                .check_url("https://user:secret@relay.example/")
                .unwrap_err(),
            PolicyViolation::EmbeddedCredentials
        );
        assert!(policy.check_url("https://relay.example/followee/").is_ok());
    }

    #[test]
    fn sec_9_5_public_policy_rejects_sensitive_literal_destinations() {
        let policy = NetworkPolicy::Public;
        for url in [
            "https://127.0.0.1/",
            "https://127.8.9.1/",
            "https://10.0.0.7/",
            "https://172.16.0.1/",
            "https://192.168.1.1/",
            "https://169.254.169.254/",
            "https://100.64.0.1/",
            "https://192.0.0.192/",
            "https://198.18.0.1/",
            "https://198.19.255.1/",
            "https://192.0.2.1/",
            "https://198.51.100.1/",
            "https://203.0.113.1/",
            "https://0.0.0.0/",
            "https://255.255.255.255/",
            "https://[::1]/",
            "https://[fe80::1]/",
            "https://[fc00::1]/",
            "https://[fd12:3456::1]/",
            "https://[::ffff:10.0.0.7]/",
            "https://[::]/",
        ] {
            assert_eq!(
                policy.check_url(url).unwrap_err(),
                PolicyViolation::DestinationNotPermitted,
                "{url}"
            );
        }
        assert!(policy.check_url("https://93.184.216.34/").is_ok());
        assert!(policy.check_url("https://[2606:2800:220:1::1]/").is_ok());
    }

    #[test]
    fn sec_9_5_public_policy_accepts_neighbours_of_the_sensitive_ranges() {
        // The reject list must not overreach: addresses adjacent to each
        // excluded range remain acceptable public destinations.
        let policy = NetworkPolicy::Public;
        for url in [
            "https://100.128.0.1/",       // beyond 100.64.0.0/10
            "https://100.63.0.1/",        // below 100.64.0.0/10
            "https://192.1.0.1/",         // beyond 192.0.0.0/24
            "https://192.0.1.1/",         // beyond 192.0.0.0/24 (third octet)
            "https://198.20.0.1/",        // beyond 198.18.0.0/15
            "https://198.17.0.1/",        // below 198.18.0.0/15
            "https://172.32.0.1/",        // beyond 172.16.0.0/12
            "https://11.0.0.1/",          // beyond 10.0.0.0/8
            "https://169.255.0.1/",       // beyond 169.254.0.0/16
            "https://[2001:db8:0:1::1]/", // documentation-adjacent global
        ] {
            assert!(policy.check_url(url).is_ok(), "{url}");
        }
    }

    #[test]
    fn sec_15_2_url_length_boundary_is_exact() {
        let policy = NetworkPolicy::Development;
        let base = "http://127.0.0.1/";
        let at_limit = format!(
            "{base}{}",
            "a".repeat(crate::limits::MAX_URI_BYTES - base.len())
        );
        assert_eq!(at_limit.len(), crate::limits::MAX_URI_BYTES);
        assert!(policy.check_url(&at_limit).is_ok(), "exactly 2048 bytes");
        let over = format!("{at_limit}a");
        assert_eq!(
            policy.check_url(&over).unwrap_err(),
            PolicyViolation::InvalidUrl,
            "2049 bytes"
        );
    }

    #[test]
    fn sec_14_1_byte_budget_boundary_is_exact() {
        let mut meter = BudgetMeter::new(OperationBudget {
            deadline_ms: None,
            max_response_bytes: 10,
            max_requests: 8,
        });
        assert!(meter.charge_bytes(10).is_ok(), "exactly consumed is fine");
        assert_eq!(
            meter.charge_bytes(1).unwrap_err(),
            ClientError::BudgetExhausted("response-byte budget"),
            "one past the budget fails"
        );
    }

    #[test]
    fn sec_9_5_production_transport_refuses_disallowed_destinations_before_connecting() {
        let transport = HttpTransport;
        // A sensitive literal destination under the public rule is refused
        // locally; no connection or resolution is attempted.
        let refused = transport.execute(&TransportRequest {
            method: Method::Get,
            url: "https://10.0.0.7/v1/info",
            content_type: None,
            body: &[],
            max_response_bytes: 1024,
            destination: DestinationRule::PublicInternet,
            timeout_ms: 50,
        });
        assert!(
            matches!(refused, Err(TransportError::Refused(_))),
            "{refused:?}"
        );
        // A loopback literal under the loopback rule passes address
        // validation and proceeds to a real (failing) local connection:
        // an Io error, never a policy refusal.
        let io = transport.execute(&TransportRequest {
            method: Method::Get,
            url: "http://127.0.0.1:9/v1/info",
            content_type: None,
            body: &[],
            max_response_bytes: 1024,
            destination: DestinationRule::LoopbackOnly,
            timeout_ms: 500,
        });
        assert!(
            matches!(
                io,
                Err(TransportError::Io(_)) | Err(TransportError::TimedOut)
            ),
            "{io:?}"
        );
        // A DNS name whose every resolved address is loopback passes the
        // resolved-address validation under the loopback rule and likewise
        // proceeds to the (failing) local connection — never a refusal.
        let named = transport.execute(&TransportRequest {
            method: Method::Get,
            url: "http://localhost:9/v1/info",
            content_type: None,
            body: &[],
            max_response_bytes: 1024,
            destination: DestinationRule::LoopbackOnly,
            timeout_ms: 500,
        });
        assert!(
            matches!(
                named,
                Err(TransportError::Io(_)) | Err(TransportError::TimedOut)
            ),
            "{named:?}"
        );
    }

    #[test]
    fn sec_9_5_development_policy_is_loopback_only() {
        let policy = NetworkPolicy::Development;
        assert!(policy.check_url("http://127.0.0.1:8080/").is_ok());
        assert!(policy.check_url("http://[::1]:8080/").is_ok());
        assert!(policy.check_url("http://localhost:8080/").is_ok());
        assert!(policy.check_url("https://127.0.0.1/").is_ok());
        assert_eq!(
            policy.check_url("http://10.0.0.7/").unwrap_err(),
            PolicyViolation::DestinationNotPermitted
        );
        assert_eq!(
            policy.check_url("http://relay.example/").unwrap_err(),
            PolicyViolation::DestinationNotPermitted
        );
        assert_eq!(
            policy.check_url("ftp://127.0.0.1/").unwrap_err(),
            PolicyViolation::SchemeNotPermitted
        );
        assert_eq!(
            policy.check_url("http://user@127.0.0.1/").unwrap_err(),
            PolicyViolation::EmbeddedCredentials
        );
    }
}
