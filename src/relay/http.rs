//! Mandatory HTTP/CBOR relay profile (specification sections 12.1 and 15.4).
//!
//! The five v1 operations are exposed at their exact relative paths with the
//! exact media types. Outer-request CBOR faults answer HTTP `400` with no
//! per-item body; successful protocol processing — including Absent, per-DID
//! Error results, no-change publication, and `ResetRequired` — answers HTTP
//! `200` with the protocol body. Oversized entities are rejected with `413`
//! before protocol parsing, unsupported media types with `415`. Public read
//! operations carry `Access-Control-Allow-Origin: *`.

use super::{Relay, RelayError};
use crate::limits::MAX_RECORD_BYTES;
use axum::Router;
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use std::sync::Arc;

/// Media type for relay API CBOR requests and responses.
const APPLICATION_CBOR: &str = "application/cbor";
/// Media type for a complete tagged Identity Record.
const APPLICATION_COSE: &str = "application/cose";

/// Maximum accepted HTTP entity for `v1/resolve` and `v1/changes` requests:
/// the section 15.2 conforming-batch bound.
const MAX_API_REQUEST_BYTES: usize = 1024 * 1024;

/// Maximum accepted HTTP entity for `v1/publish`: comfortably above the
/// 16 KiB record cap so an oversized record still receives the protocol
/// `recordTooLarge` classification rather than a transport error, while
/// grossly oversized uploads stop at `413` before buffering.
const MAX_PUBLISH_REQUEST_BYTES: usize = 4 * MAX_RECORD_BYTES;

/// Builds the axum router exposing the v1 operations relative to the
/// advertised base URI.
pub fn router(relay: Arc<Relay>) -> Router {
    Router::new()
        .route("/v1/info", get(info))
        .route(
            "/v1/resolve",
            post(resolve).layer(DefaultBodyLimit::max(MAX_API_REQUEST_BYTES)),
        )
        .route("/v1/directory", get(directory))
        .route(
            "/v1/publish",
            post(publish).layer(DefaultBodyLimit::max(MAX_PUBLISH_REQUEST_BYTES)),
        )
        .route(
            "/v1/changes",
            post(changes).layer(DefaultBodyLimit::max(MAX_API_REQUEST_BYTES)),
        )
        .with_state(relay)
}

/// Serves the relay on an already bound listener until the task is dropped.
///
/// In development mode the listener must be bound to a loopback address:
/// plain-HTTP operation is explicitly non-conforming and must not reach a
/// public interface by accident (IMPLEMENTATION.md section 9.5).
///
/// # Errors
///
/// Returns an [`std::io::Error`] for binding violations or accept failures.
pub async fn serve(relay: Arc<Relay>, listener: tokio::net::TcpListener) -> std::io::Result<()> {
    if relay.development_mode() {
        let addr = listener.local_addr()?;
        if !addr.ip().is_loopback() {
            return Err(std::io::Error::other(
                "development mode permits loopback binding only; \
                 public operation requires an HTTPS base URI behind TLS",
            ));
        }
    }
    let app = router(relay);
    axum::serve(listener, app).await
}

fn cbor_ok(bytes: Vec<u8>, cors: bool) -> Response {
    let mut response = (
        StatusCode::OK,
        [(header::CONTENT_TYPE, APPLICATION_CBOR)],
        bytes,
    )
        .into_response();
    if cors {
        response.headers_mut().insert(
            header::ACCESS_CONTROL_ALLOW_ORIGIN,
            header::HeaderValue::from_static("*"),
        );
    }
    response
}

fn relay_failure(error: &RelayError) -> Response {
    match error {
        // Outer request fault: protocol item processing did not begin; no
        // normative per-item CBOR body accompanies the 400 (section 15.4).
        RelayError::BadRequest => StatusCode::BAD_REQUEST.into_response(),
        RelayError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

/// Checks the request media type, ignoring parameters; media-type names are
/// ASCII case-insensitive.
fn content_type_matches(headers: &HeaderMap, expected: &str) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.split(';').next().unwrap_or("").trim())
        .is_some_and(|essence| essence.eq_ignore_ascii_case(expected))
}

async fn info(State(relay): State<Arc<Relay>>) -> Response {
    match relay.info() {
        Ok(bytes) => cbor_ok(bytes, true),
        Err(e) => relay_failure(&e),
    }
}

async fn directory(State(relay): State<Arc<Relay>>) -> Response {
    match relay.directory() {
        Ok(bytes) => cbor_ok(bytes, true),
        Err(e) => relay_failure(&e),
    }
}

async fn resolve(State(relay): State<Arc<Relay>>, headers: HeaderMap, body: Bytes) -> Response {
    if !content_type_matches(&headers, APPLICATION_CBOR) {
        return StatusCode::UNSUPPORTED_MEDIA_TYPE.into_response();
    }
    match relay.resolve(&body) {
        Ok(bytes) => cbor_ok(bytes, true),
        Err(e) => relay_failure(&e),
    }
}

async fn publish(State(relay): State<Arc<Relay>>, headers: HeaderMap, body: Bytes) -> Response {
    if !content_type_matches(&headers, APPLICATION_COSE) {
        return StatusCode::UNSUPPORTED_MEDIA_TYPE.into_response();
    }
    match relay.publish(&body) {
        Ok(bytes) => cbor_ok(bytes, false),
        Err(e) => relay_failure(&e),
    }
}

async fn changes(State(relay): State<Arc<Relay>>, headers: HeaderMap, body: Bytes) -> Response {
    if !content_type_matches(&headers, APPLICATION_CBOR) {
        return StatusCode::UNSUPPORTED_MEDIA_TYPE.into_response();
    }
    match relay.changes(&body) {
        Ok(bytes) => cbor_ok(bytes, true),
        Err(e) => relay_failure(&e),
    }
}
