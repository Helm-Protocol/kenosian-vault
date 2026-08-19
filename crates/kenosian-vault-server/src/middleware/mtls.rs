// Layer 2: mTLS client certificate check.
//
// This module documents the intent and provides the hook. Actual TLS
// termination is done by rustls at the axum-server layer (Phase 3 wiring);
// here we only inspect the peer certificate that rustls attached to the
// connection extensions and reject requests whose client_id is not in the
// active roster.
//
// Reverse-engineering defense:
// - Failure returns the same 401 body as every other middleware.
// - Log the client_id that failed, but never echo it back.
// - Do not distinguish "cert missing" vs "cert revoked" vs "cert not enrolled"
//   in the response.

use axum::{
    body::Body,
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};
use tracing::warn;

use crate::middleware::UNIFORM_UNAUTHORIZED_BODY;
use crate::state::AppState;

/// Phase 1 stub: pass-through when `KLV_REQUIRE_MTLS != "1"`, reject otherwise.
///
/// Once axum-server-dual-protocol + rustls are wired (Phase 3), this reads the
/// verified client cert from request extensions and looks up the client_id
/// in DynamoDB (or the in-memory roster) to decide.
pub async fn enforce_mtls(
    State(_state): State<AppState>,
    req: Request<Body>,
    next: Next,
) -> Response {
    let required = std::env::var("KLV_REQUIRE_MTLS").ok().as_deref() == Some("1");
    if !required {
        return next.run(req).await;
    }
    // Phase 3 will populate this from rustls handshake extensions.
    let has_client_cert = req.extensions().get::<ClientCertClaim>().is_some();
    if !has_client_cert {
        warn!(
            path = %req.uri().path(),
            "mtls: missing client cert on required-mtls endpoint"
        );
        return reject();
    }
    next.run(req).await
}

/// Placeholder marker inserted by the (not-yet-wired) rustls handshake layer.
/// Kept here so downstream code can type-check against the final shape.
#[derive(Debug, Clone)]
pub struct ClientCertClaim {
    pub client_id: String,
    pub cert_serial: String,
    pub not_after: i64,
}

fn reject() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [("content-type", "application/json")],
        UNIFORM_UNAUTHORIZED_BODY,
    )
        .into_response()
}
