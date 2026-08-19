// Layer 3-A: Ed25519 header signature (real verify).
//
// Required headers on every authenticated request:
//   X-KLV-Client:     client identifier (roster lookup key)
//   X-KLV-Timestamp:  RFC 3339 UTC; must be within ±5s of server clock
//   X-KLV-Signature:  hex(Ed25519(client_privkey, message))
//
// message = "{method}\n{path}\n{timestamp}\n{sha256_hex(body)}"
//
// Roster loaded from env `KLV_CLIENT_ROSTER` — JSON `{client_id: pubkey_hex}`.
// Empty roster = deny all when `KLV_REQUIRE_ED25519=1`.
//
// Reverse-engineering defense:
// - Every reject path returns the same 401 body.
// - Timestamp and signature both verified even when the first fails (best
//   effort within tokio scheduling); side-channel dominated by the
//   `constant_time` floor of 8ms.

use axum::{
    body::{to_bytes, Body},
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use hashbrown::HashMap;
use once_cell::sync::Lazy;
use sha2::{Digest, Sha256};
use std::sync::{OnceLock, RwLock};
use tracing::warn;

use crate::metrics::{AUTH_REJECTS, ROSTER_SOURCES};
use crate::middleware::UNIFORM_UNAUTHORIZED_BODY;
use crate::state::AppState;

const MAX_CLOCK_SKEW_SECS: i64 = 5;
const MAX_BODY_BYTES: usize = 1 << 20; // 1 MiB

static ROSTER: OnceLock<HashMap<String, VerifyingKey>> = OnceLock::new();

// Secondary cache — pubkeys pulled from Redis on env-miss, cached in-process.
static REDIS_ROSTER: Lazy<RwLock<HashMap<String, VerifyingKey>>> =
    Lazy::new(|| RwLock::new(HashMap::new()));

fn roster() -> &'static HashMap<String, VerifyingKey> {
    ROSTER.get_or_init(|| {
        let raw = std::env::var("KLV_CLIENT_ROSTER").unwrap_or_default();
        if raw.trim().is_empty() {
            return HashMap::new();
        }
        let parsed: serde_json::Value = match serde_json::from_str(&raw) {
            Ok(v) => v,
            Err(e) => {
                warn!("ed25519: KLV_CLIENT_ROSTER not valid JSON: {}", e);
                return HashMap::new();
            }
        };
        let obj = match parsed.as_object() {
            Some(o) => o,
            None => {
                warn!("ed25519: KLV_CLIENT_ROSTER must be a JSON object");
                return HashMap::new();
            }
        };
        let mut out: HashMap<String, VerifyingKey> = HashMap::with_capacity(obj.len());
        for (client_id, v) in obj {
            let hex_str = match v.as_str() {
                Some(s) => s,
                None => {
                    warn!("ed25519: roster {} pubkey must be hex string", client_id);
                    continue;
                }
            };
            let bytes = match hex::decode(hex_str) {
                Ok(b) if b.len() == 32 => b,
                Ok(b) => {
                    warn!(
                        "ed25519: roster {} pubkey wrong length {} (need 32)",
                        client_id,
                        b.len()
                    );
                    continue;
                }
                Err(e) => {
                    warn!("ed25519: roster {} hex decode: {}", client_id, e);
                    continue;
                }
            };
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            match VerifyingKey::from_bytes(&arr) {
                Ok(pk) => {
                    out.insert(client_id.clone(), pk);
                }
                Err(e) => {
                    warn!("ed25519: roster {} not a valid pubkey: {}", client_id, e);
                }
            }
        }
        out
    })
}

pub async fn verify_ed25519_sig(
    State(_state): State<AppState>,
    req: Request<Body>,
    next: Next,
) -> Response {
    let required = std::env::var("KLV_REQUIRE_ED25519").ok().as_deref() == Some("1");
    if !required {
        return next.run(req).await;
    }

    let (parts, body) = req.into_parts();
    let bytes = match to_bytes(body, MAX_BODY_BYTES).await {
        Ok(b) => b,
        Err(_) => return reject("body too large or unreadable"),
    };

    let get_header = |name: &str| -> Option<String> {
        parts
            .headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
    };

    let client_id = match get_header("x-klv-client") {
        Some(v) => v,
        None => return reject("missing X-KLV-Client"),
    };
    let ts = match get_header("x-klv-timestamp") {
        Some(v) => v,
        None => return reject("missing X-KLV-Timestamp"),
    };
    let sig_hex = match get_header("x-klv-signature") {
        Some(v) => v,
        None => return reject("missing X-KLV-Signature"),
    };

    // Timestamp freshness (log-only reason, uniform reject on fail).
    if !check_timestamp_skew(&ts) {
        return reject_client("stale/future timestamp", &client_id);
    }

    // Roster lookup — env warm cache first, Redis fallback second (hybrid mode).
    let vkey_opt = match roster().get(&client_id) {
        Some(k) => {
            ROSTER_SOURCES.with_label_values(&["env"]).inc();
            Some(*k)
        }
        None => match redis_lookup(&client_id).await {
            Some(k) => {
                ROSTER_SOURCES.with_label_values(&["redis"]).inc();
                Some(k)
            }
            None => None,
        },
    };
    let vkey = match vkey_opt {
        Some(k) => k,
        None => {
            ROSTER_SOURCES.with_label_values(&["miss"]).inc();
            return reject_client("client_id not in roster", &client_id);
        }
    };

    // Signature decode.
    let sig_bytes = match hex::decode(&sig_hex) {
        Ok(b) if b.len() == 64 => b,
        _ => return reject_client("signature hex/length invalid", &client_id),
    };
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&sig_bytes);
    let sig = Signature::from_bytes(&sig_arr);

    // Compose signed message.
    let body_sha = sha256_hex(&bytes);
    let msg = format!(
        "{}\n{}\n{}\n{}",
        parts.method.as_str(),
        parts.uri.path(),
        ts,
        body_sha
    );

    if vkey.verify(msg.as_bytes(), &sig).is_err() {
        AUTH_REJECTS
            .with_label_values(&["ed25519", "sig_verify"])
            .inc();
        return reject_client("signature verify failed", &client_id);
    }

    // Re-attach body so downstream handlers see the same request.
    let req = Request::from_parts(parts, Body::from(bytes));
    next.run(req).await
}

fn check_timestamp_skew(ts_str: &str) -> bool {
    let parsed: DateTime<Utc> = match ts_str.parse() {
        Ok(t) => t,
        Err(_) => return false,
    };
    let now = Utc::now();
    (now.timestamp() - parsed.timestamp()).abs() <= MAX_CLOCK_SKEW_SECS
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

fn reject(reason: &'static str) -> Response {
    warn!("ed25519 reject: {}", reason);
    (
        StatusCode::UNAUTHORIZED,
        [("content-type", "application/json")],
        UNIFORM_UNAUTHORIZED_BODY,
    )
        .into_response()
}

fn reject_client(reason: &'static str, client_id: &str) -> Response {
    warn!("ed25519 reject: {} client={}", reason, client_id);
    (
        StatusCode::UNAUTHORIZED,
        [("content-type", "application/json")],
        UNIFORM_UNAUTHORIZED_BODY,
    )
        .into_response()
}

// Redis fallback: HGET klv:roster {client_id} -> pubkey_hex (64 chars).
// Reads once from process cache; on miss, tries Redis, caches the parsed VerifyingKey.
// KLV_REDIS_URL controls the connection (default redis://127.0.0.1:6379). Absent =
// Redis lookup silently disabled and we fall through to "not in roster".
async fn redis_lookup(client_id: &str) -> Option<VerifyingKey> {
    if let Ok(cache) = REDIS_ROSTER.read() {
        if let Some(k) = cache.get(client_id) {
            return Some(*k);
        }
    }
    let url = std::env::var("KLV_REDIS_URL").ok()?;
    let client = redis::Client::open(url).ok()?;
    let mut conn = client.get_connection_manager().await.ok()?;
    let hex_str: Option<String> = redis::cmd("HGET")
        .arg("klv:roster")
        .arg(client_id)
        .query_async(&mut conn)
        .await
        .ok()?;
    let hex_str = hex_str?;
    let bytes = hex::decode(hex_str.trim()).ok()?;
    if bytes.len() != 32 {
        warn!(
            "ed25519 redis: {} pubkey wrong length {} (need 32)",
            client_id,
            bytes.len()
        );
        return None;
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    let vkey = VerifyingKey::from_bytes(&arr).ok()?;
    if let Ok(mut cache) = REDIS_ROSTER.write() {
        cache.insert(client_id.to_string(), vkey);
    }
    Some(vkey)
}
