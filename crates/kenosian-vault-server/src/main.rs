mod metrics;
mod middleware;
mod routes;
mod state;

use axum::{middleware::from_fn, middleware::from_fn_with_state, routing::get, Router};
use std::{net::SocketAddr, sync::Arc};
use tracing::{info, warn};

use crate::routes::theorem::{
    batch_theorems, get_ground_truth, get_rlvr, get_theorem, health, manifest, metrics_summary,
};
use axum::routing::post;
use crate::state::{AppState, FormalHashRouter};

const DEFAULT_DATASET: &str =
    "/home/axcpeter/omnivault_data/omnivault_rlvr_gold_training_v1.jsonl";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,tower_http=debug".into()),
        )
        .init();

    let dataset = std::env::var("KLV_DATASET").unwrap_or_else(|_| DEFAULT_DATASET.to_string());
    let bind: SocketAddr = std::env::var("KLV_BIND")
        .unwrap_or_else(|_| "127.0.0.1:8097".to_string())
        .parse()?;
    let commit_hash = std::env::var("KLV_COMMIT").unwrap_or_else(|_| "unset".to_string());

    info!(dataset = %dataset, bind = %bind, "kenosian-vault-server booting");

    let start = std::time::Instant::now();
    let router = FormalHashRouter::from_jsonl(&dataset).await?;
    let elapsed = start.elapsed();
    info!(
        theorems_loaded = router.len(),
        total_ingested = router.total_ingested(),
        total_skipped = router.total_skipped(),
        load_ms = elapsed.as_millis(),
        "index built"
    );

    if router.len() == 0 {
        warn!("router is empty — check dataset path");
    }

    metrics::THEOREMS_LOADED.set(router.len() as i64);

    let state = AppState {
        router: Arc::new(router),
        commit_hash,
    };

    // Middleware stack (outer→inner, request travels top→bottom):
    //   Layer 0: constant-time floor (reverse-engineering timing defense)
    //   Layer 2: mTLS client cert                        (public, Phase 3)
    //   Layer 3-A: Ed25519 header signature              (public, Phase 3)
    //   Layer 3-B: TTTPS seal                            (private NDA, Phase 3)
    // Phase 1 default: all three verifiers are pass-through unless
    //   KLV_REQUIRE_MTLS / KLV_REQUIRE_ED25519 / KLV_REQUIRE_TTTPS = "1".
    // Constant-time floor is always on (default 8ms).
    let app = Router::new()
        .route("/health", get(health))
        .route("/metrics", get(metrics::metrics_handler))
        .route("/v1/metrics/summary", get(metrics_summary))
        .route("/manifest.json", get(manifest))
        .route("/theorems/batch", post(batch_theorems))
        .route("/theorems/:fqn", get(get_theorem))
        .route("/theorems/:fqn/rlvr", get(get_rlvr))
        .route("/theorems/:fqn/ground_truth", get(get_ground_truth))
        .layer(from_fn_with_state(
            state.clone(),
            middleware::tttps_seal::verify_tttps_seal,
        ))
        .layer(from_fn_with_state(
            state.clone(),
            middleware::ed25519_sig::verify_ed25519_sig,
        ))
        .layer(from_fn_with_state(
            state.clone(),
            middleware::mtls::enforce_mtls,
        ))
        .layer(from_fn(middleware::constant_time::floor_response_time))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(bind).await?;
    info!(addr = %bind, "listening");
    axum::serve(listener, app).await?;
    Ok(())
}
