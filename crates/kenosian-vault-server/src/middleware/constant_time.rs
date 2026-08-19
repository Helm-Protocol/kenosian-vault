// Layer 0: constant-time response floor (reverse-engineering defense).
//
// Every response — hit, miss, reject — waits until at least `KLV_MIN_LATENCY_MS`
// (default 8 ms) has elapsed since the request entered the middleware stack.
// This blunts timing side channels: an adversary probing "does this FQN
// exist?" or "did my signature fail at layer 3-A vs 3-B?" cannot infer the
// answer from response latency alone.
//
// The floor is intentionally coarse (ms, not µs). Fine-grained side channels
// remain possible via CPU / cache / memory-pressure observation from a
// co-tenant, but at the HTTP layer this closes the obvious channel.
//
// Interaction with `X-Response-Time` header: the header (if any) is set to
// the *padded* elapsed, not the true handler time. Server: header is stripped.

use axum::{body::Body, extract::Request, middleware::Next, response::Response};
use std::time::{Duration, Instant};
use tokio::time::sleep;

const DEFAULT_MIN_LATENCY_MS: u64 = 8;

pub async fn floor_response_time(req: Request<Body>, next: Next) -> Response {
    let start = Instant::now();
    let response = next.run(req).await;
    let elapsed = start.elapsed();

    let floor_ms = std::env::var("KLV_MIN_LATENCY_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(DEFAULT_MIN_LATENCY_MS);
    let floor = Duration::from_millis(floor_ms);

    if elapsed < floor {
        sleep(floor - elapsed).await;
    }

    let mut response = response;
    // Never leak framework / crate version.
    response.headers_mut().remove("server");
    response.headers_mut().remove("x-powered-by");
    response
}
