# Phase 1 additions (2026-08-19)

Two additions, both opt-in, both shadow-safe (server is not yet under systemd).

## SUGG-2 — Prometheus `/metrics`

New route: `GET /metrics` (no auth, text exposition v0.0.4).

Metrics registered in `src/metrics.rs`:

| name | type | labels | meaning |
|---|---|---|---|
| `klv_theorem_requests_total` | counter | `outcome` | theorem lookups by hit/miss/error |
| `klv_theorem_latency_ms` | histogram | `route` | per-route lookup latency |
| `klv_auth_rejects_total` | counter | `layer`, `reason` | mtls/ed25519/tttps rejects |
| `klv_roster_lookups_total` | counter | `source` (`env`/`redis`/`miss`) | Ed25519 roster hits by source |
| `klv_theorems_loaded` | gauge | — | current in-RAM router size |

Scrape example:
```
curl -s http://127.0.0.1:8097/metrics | head -20
```

## Q2 — Ed25519 hybrid roster (env + Redis fallback)

Primary: `KLV_CLIENT_ROSTER` env JSON `{client_id: pubkey_hex}` (unchanged, warm-loaded once).

Secondary: on env-miss, look up Redis hash `klv:roster` field `<client_id>` → 64-char hex.

Env vars:
- `KLV_REDIS_URL` (e.g. `redis://127.0.0.1:6379`) — absent = Redis lookup disabled, behaves as before
- `KLV_REQUIRE_ED25519=1` — gate strict mode

Add a new client without restart:
```
redis-cli HSET klv:roster acme-labs <64-hex-pubkey>
```
First request from `X-KLV-Client: acme-labs` pays the Redis round-trip; the parsed VerifyingKey is cached in-process for subsequent requests.

## Rollback

- Cargo.toml: revert three added deps (`prometheus`, `redis`, `once_cell`)
- `src/metrics.rs`: delete file, delete `mod metrics;` and route registration in `main.rs`
- `src/middleware/ed25519_sig.rs`: remove `REDIS_ROSTER`, `redis_lookup`, metrics counters
- No production impact: server is not yet running under systemd; changes only affect the next build.
