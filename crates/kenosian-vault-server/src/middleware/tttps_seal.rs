// Layer 3-B: TTTPS seal (private, NDA-only).
//
// This is the internal integrity fabric. Not documented externally until
// draft-helmprotocol-tttps-09 reaches IESG approval. Enterprise customers
// under NDA can opt in via the `x-tttps-seal` header; the pitch deck and
// public docs only mention Layer 3-A (Ed25519).
//
// Header:
//   X-TTTPS-Seal: base64(pot_record_v08 | grg_shell | tttps_signature)
//
// Fields inside the seal (per draft-08 §4 session_binding — currently the
// gating CODE-MEMORY invariant, `pot_verifier.ts` needs the -08 alignment
// patch before this layer goes live):
//   - KTSat anchor (u64 ns)
//   - G-Score integrity (u8 client tier + 32B GRG shell)
//   - Reed-Solomon FEC over the session binding
//   - Ed25519 client signature over the above
//
// Reverse-engineering defense:
// - Same 401 body on every reject; TTTPS-specific decode errors never leak.
// - Timing floor via `constant_time` middleware runs regardless.
// - The header itself is opaque base64; malformed decode logs but returns 401.

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

pub async fn verify_tttps_seal(
    State(_state): State<AppState>,
    req: Request<Body>,
    next: Next,
) -> Response {
    let required = std::env::var("KLV_REQUIRE_TTTPS").ok().as_deref() == Some("1");
    if !required {
        // Public mode: TTTPS is optional (NDA-only). Pass through.
        return next.run(req).await;
    }

    let seal_b64 = match req
        .headers()
        .get("x-tttps-seal")
        .and_then(|v| v.to_str().ok())
    {
        Some(s) => s.to_string(),
        None => {
            warn!("tttps reject: missing X-TTTPS-Seal");
            return reject();
        }
    };

    // Step 1: base64 decode.
    // draft-08 §4 session_binding says the seal is a length-prefixed record.
    // Minimum size we can enforce today = header (8B) + ktsat_ns (8B) +
    // grg_shell (32B) + ed25519_sig (64B) = 112B. Anything shorter is
    // definitely malformed; anything longer we accept and defer to the
    // full parser (blocked on pot_verifier.ts alignment).
    let seal_bytes = match base64_decode_lax(&seal_b64) {
        Some(b) if b.len() >= 112 => b,
        Some(b) => {
            warn!("tttps reject: seal too short ({}B, need ≥112)", b.len());
            return reject();
        }
        None => {
            warn!("tttps reject: seal base64 decode failed");
            return reject();
        }
    };

    // Step 2-5 blocked until draft-08 record alignment:
    // - pot_record_v08 field parse (Jay approval to touch pot_verifier.ts)
    // - GRG shell integrity check (Golomb → Reed-Solomon → Golay)
    // - KTSat anchor freshness (|ktsat_ns - server_ns| ≤ 10 ns skew)
    // - Ed25519 client signature verify over the record
    //
    // Until alignment lands, this middleware performs the minimum viable
    // check (size + decode) and passes through. This is deliberately visible
    // in logs so we can never claim "TTTPS verified" without doing the work.
    let _ = seal_bytes;
    tracing::info!("tttps: seal decoded, full verify pending draft-08 alignment");

    next.run(req).await
}

/// Minimal base64 decoder (standard alphabet, padding tolerant).
/// Deliberately local so we do not pull in the `base64` crate just for this
/// stub — a full parser lands with the alignment patch.
fn base64_decode_lax(input: &str) -> Option<Vec<u8>> {
    const TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut lookup = [255u8; 256];
    for (i, b) in TABLE.iter().enumerate() {
        lookup[*b as usize] = i as u8;
    }
    let clean: Vec<u8> = input
        .as_bytes()
        .iter()
        .copied()
        .filter(|b| !b.is_ascii_whitespace() && *b != b'=')
        .collect();
    let mut out = Vec::with_capacity((clean.len() * 3) / 4);
    let mut buf: u32 = 0;
    let mut bits: u32 = 0;
    for b in clean {
        let v = lookup[b as usize];
        if v == 255 {
            return None;
        }
        buf = (buf << 6) | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((buf >> bits) & 0xff) as u8);
        }
    }
    Some(out)
}

fn reject() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [("content-type", "application/json")],
        UNIFORM_UNAUTHORIZED_BODY,
    )
        .into_response()
}
