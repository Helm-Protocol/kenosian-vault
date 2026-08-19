use axum::{
    extract::{Path, State},
    http::{HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::state::AppState;

/// Anti-exfiltration watermark (Layer 4-A metadata, private).
///
/// blake3(client_id || fqn || commit || issued_at_utc_iso || nonce_random)
///
/// Attached to every response as `_provenance.watermark` (32 bytes hex).
/// Lean source itself is *not* modified — an exfiltrated dataset can be
/// traced back to (client_id, timestamp) via the JSON envelope hash.
/// Decision A of three (Cloco 2026-08-18: source-modifying B/C options
/// break kernel-standard re-audit invariance and were rejected).
fn provenance(state: &AppState, fqn: &str, headers: &HeaderMap) -> Value {
    let client_id = headers
        .get("x-klv-client")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("anonymous");
    let issued_at = chrono::Utc::now().to_rfc3339();
    let nonce: [u8; 16] = rand_16();
    let nonce_hex = hex::encode(nonce);

    let mut hasher = blake3::Hasher::new();
    hasher.update(client_id.as_bytes());
    hasher.update(b"\n");
    hasher.update(fqn.as_bytes());
    hasher.update(b"\n");
    hasher.update(state.commit_hash.as_bytes());
    hasher.update(b"\n");
    hasher.update(issued_at.as_bytes());
    hasher.update(b"\n");
    hasher.update(&nonce);
    let mark = hex::encode(hasher.finalize().as_bytes());

    json!({
        "watermark": mark,
        "issued_at": issued_at,
        "server_id": "kenosian-vault-server",
        "commit": state.commit_hash,
        "algorithm": "blake3(client||fqn||commit||issued_at||nonce)",
        "nonce": nonce_hex,
        // client_id itself is NOT echoed back — buyers see only their own
        // requests, never other tenants'. Watermark is one-way.
    })
}

fn rand_16() -> [u8; 16] {
    // std-only randomness: xorshift over current-time hash. Not for crypto
    // keying, only for making the per-response watermark input unique so a
    // client re-requesting the same FQN cannot cheaply grind identical marks.
    use std::hash::{Hasher, BuildHasher};
    let mut h = std::collections::hash_map::RandomState::new().build_hasher();
    h.write_u128(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0));
    let a = h.finish();
    let mut h2 = std::collections::hash_map::RandomState::new().build_hasher();
    h2.write_u64(a);
    let b = h2.finish();
    let mut out = [0u8; 16];
    out[..8].copy_from_slice(&a.to_le_bytes());
    out[8..].copy_from_slice(&b.to_le_bytes());
    out
}

/// GET /theorems/:fqn — Cloco Python SDK compatible lookup.
///
/// Returns 200 with the certificate JSON when found.
/// Returns 200 with `{ "verified": null, "reason": "not_in_vault" }` when the
/// FQN is unknown at the current commit — mirroring Cloco's tri-state contract
/// (`Some(true)` / `None`, never `false`).
///
/// Always emits `X-KLV-Commit-Hash` so clients can pin against a static
/// manifest without trusting the live server.
pub async fn get_theorem(
    State(state): State<AppState>,
    Path(fqn): Path<String>,
    req_headers: HeaderMap,
) -> Response {
    let mut headers = HeaderMap::new();
    if let Ok(hv) = HeaderValue::from_str(&state.commit_hash) {
        headers.insert("X-KLV-Commit-Hash", hv);
    }
    let prov = provenance(&state, &fqn, &req_headers);

    match state.router.get(&fqn) {
        Some(cert) => {
            let mut body =
                serde_json::to_value(cert).unwrap_or_else(|_| serde_json::Value::Null);
            if let Some(obj) = body.as_object_mut() {
                obj.insert("_provenance".to_string(), prov);
            }
            (StatusCode::OK, headers, Json(body)).into_response()
        }
        None => {
            let body = json!({
                "fqn": fqn,
                "verified": null,
                "reason": "not_in_vault",
                "commit": state.commit_hash,
                "_provenance": prov,
            });
            (StatusCode::OK, headers, Json(body)).into_response()
        }
    }
}

/// GET /theorems/:fqn/ground_truth — paid, rate-limited endpoint that returns
/// the full Lean 4 proof body. **Phase 1 stub**: refuses all requests until
/// mTLS + Ed25519 header signing + per-client rate limiter land in Phase 3.
/// The endpoint exists so the shape is committed; buyers see the door,
/// they just cannot walk through it yet.
pub async fn get_ground_truth(
    State(state): State<AppState>,
    Path(fqn): Path<String>,
    headers: HeaderMap,
) -> Response {
    // Phase 3 hook: client_id watermarking / rate limit / signature verification
    // will consume `headers` (Authorization, X-KLV-Client, X-KLV-Signature)
    // before serving the full proof body. For now: deny.
    let _ = (state, fqn, headers);
    (
        StatusCode::PAYMENT_REQUIRED,
        Json(json!({
            "error": "ground_truth_requires_metered_session",
            "reason": "phase_3_not_deployed",
            "hint": "use GET /theorems/:fqn for masked signature; contact partnerships for metered access",
        })),
    )
        .into_response()
}

/// GET /health — liveness + router size.
pub async fn health(State(state): State<AppState>) -> Json<serde_json::Value> {
    Json(json!({
        "status": "ok",
        "commit": state.commit_hash,
        "theorems_loaded": state.router.len(),
        "dataset_path": state.router.dataset_path(),
        "total_ingested": state.router.total_ingested(),
        "total_skipped": state.router.total_skipped(),
        "manifest_xor": state.router.manifest_xor_hex(),
    }))
}

/// GET /v1/metrics/summary — small JSON snapshot the hero page fetches to
/// replace demo placeholders with live numbers. Independent of the Prometheus
/// `/metrics` scrape (Prometheus is for SREs; this is for the front page).
pub async fn metrics_summary(State(state): State<AppState>) -> Json<serde_json::Value> {
    let loaded = state.router.len();
    let ingested = state.router.total_ingested();
    let coverage_pct = if ingested > 0 {
        ((loaded as f64) / (ingested as f64) * 100.0).round() as u64
    } else {
        0
    };
    Json(json!({
        "sealed": loaded,
        "ingested": ingested,
        "skipped": state.router.total_skipped(),
        "coverage_pct": coverage_pct,
        "commit": state.commit_hash,
    }))
}

/// GET /manifest.json — commit-pinnable set-fingerprint over all served FQNs.
/// Buyers freeze `commit + manifest_xor` in their audit trail; if the server
/// later serves a different set, `manifest_xor` will not match.
pub async fn manifest(State(state): State<AppState>) -> Response {
    let mut headers = HeaderMap::new();
    if let Ok(hv) = HeaderValue::from_str(&state.commit_hash) {
        headers.insert("X-KLV-Commit-Hash", hv);
    }
    let body = json!({
        "commit": state.commit_hash,
        "theorems": state.router.len(),
        "manifest_xor": state.router.manifest_xor_hex(),
        "dataset_path": state.router.dataset_path(),
        "algorithm": "ahash_xor_over_fqn_set_v0",
        "notes": "Merkle root upgrade lands in Phase 3 (blake3 tree over sorted fqn set).",
    });
    (StatusCode::OK, headers, Json(body)).into_response()
}

#[derive(Debug, Deserialize)]
pub struct BatchRequest {
    pub fqns: Vec<String>,
}

/// POST /theorems/batch — up to 1000 FQN lookups in one round-trip.
/// Response is a JSON object keyed by FQN; missing FQNs get `verified: null`.
/// Larger batches are rejected with 413 (still under uniform-body policy for
/// unauthenticated requests, but explicit for authenticated integration debug).
pub async fn batch_theorems(
    State(state): State<AppState>,
    Json(req): Json<BatchRequest>,
) -> Response {
    const MAX_BATCH: usize = 1000;
    if req.fqns.len() > MAX_BATCH {
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            Json(json!({
                "error": "batch_too_large",
                "max": MAX_BATCH,
                "received": req.fqns.len(),
            })),
        )
            .into_response();
    }
    let mut out = serde_json::Map::with_capacity(req.fqns.len());
    for fqn in req.fqns {
        let entry = match state.router.get(&fqn) {
            Some(cert) => serde_json::to_value(cert).unwrap_or(serde_json::Value::Null),
            None => json!({"verified": null, "reason": "not_in_vault"}),
        };
        out.insert(fqn, entry);
    }
    let mut headers = HeaderMap::new();
    if let Ok(hv) = HeaderValue::from_str(&state.commit_hash) {
        headers.insert("X-KLV-Commit-Hash", hv);
    }
    (StatusCode::OK, headers, Json(serde_json::Value::Object(out))).into_response()
}

/// GET /theorems/:fqn/rlvr — RLVR training pair (masked problem + metadata).
///
/// Returns the theorem signature with `:= by exact sorryAx _ _` hole (the
/// problem statement AI trains against). The Ground-Truth `lean4_full_code`
/// stays behind `/ground_truth` (Phase 3 metered).
///
/// Phase 1 shape: since v1 records store only the masked signature in
/// Certificate.statement, we surface that plus the sorryAx template.
pub async fn get_rlvr(
    State(state): State<AppState>,
    Path(fqn): Path<String>,
) -> Response {
    let mut headers = HeaderMap::new();
    if let Ok(hv) = HeaderValue::from_str(&state.commit_hash) {
        headers.insert("X-KLV-Commit-Hash", hv);
    }
    match state.router.get(&fqn) {
        Some(cert) => {
            let sig = cert.statement.clone().unwrap_or_default();
            // Replace the masked body with the sorryAx training hole.
            let problem = sig
                .replace(":= by ⟨omitted⟩", ":= by exact sorryAx _ _");
            let body = json!({
                "fqn": cert.fqn,
                "verified": cert.verified,
                "axiom_level": cert.axiom_level,
                "commit": cert.commit,
                "rlvr_problem_statement_sorryax": problem,
                "citations": cert.citations,
                "d3_tier": cert.d3_tier,
                "notes": "Ground truth (lean4_full_code) available via /theorems/:fqn/ground_truth (metered, NDA).",
            });
            (StatusCode::OK, headers, Json(body)).into_response()
        }
        None => {
            let body = json!({
                "fqn": fqn,
                "verified": null,
                "reason": "not_in_vault",
                "commit": state.commit_hash,
            });
            (StatusCode::OK, headers, Json(body)).into_response()
        }
    }
}
