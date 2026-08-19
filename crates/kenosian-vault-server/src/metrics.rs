use axum::{http::StatusCode, response::IntoResponse};
use once_cell::sync::Lazy;
use prometheus::{
    register_histogram_vec_with_registry, register_int_counter_vec_with_registry,
    register_int_gauge_with_registry, Encoder, HistogramVec, IntCounterVec, IntGauge, Registry,
    TextEncoder,
};

pub static REGISTRY: Lazy<Registry> = Lazy::new(Registry::new);

pub static THEOREM_REQUESTS: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec_with_registry!(
        "klv_theorem_requests_total",
        "Theorem lookup requests by outcome",
        &["outcome"],
        REGISTRY
    )
    .expect("register klv_theorem_requests_total")
});

pub static THEOREM_LATENCY_MS: Lazy<HistogramVec> = Lazy::new(|| {
    register_histogram_vec_with_registry!(
        "klv_theorem_latency_ms",
        "Theorem lookup latency (ms)",
        &["route"],
        vec![0.5, 1.0, 2.0, 5.0, 10.0, 25.0, 50.0, 100.0, 250.0, 500.0, 1000.0],
        REGISTRY
    )
    .expect("register klv_theorem_latency_ms")
});

pub static AUTH_REJECTS: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec_with_registry!(
        "klv_auth_rejects_total",
        "Auth middleware rejects by reason",
        &["layer", "reason"],
        REGISTRY
    )
    .expect("register klv_auth_rejects_total")
});

pub static ROSTER_SOURCES: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec_with_registry!(
        "klv_roster_lookups_total",
        "Ed25519 roster lookups by source",
        &["source"],
        REGISTRY
    )
    .expect("register klv_roster_lookups_total")
});

pub static THEOREMS_LOADED: Lazy<IntGauge> = Lazy::new(|| {
    register_int_gauge_with_registry!(
        "klv_theorems_loaded",
        "Number of theorems currently in the in-RAM router",
        REGISTRY
    )
    .expect("register klv_theorems_loaded")
});

pub async fn metrics_handler() -> impl IntoResponse {
    let encoder = TextEncoder::new();
    let mut buf = Vec::new();
    if let Err(e) = encoder.encode(&REGISTRY.gather(), &mut buf) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            [("content-type", "text/plain")],
            format!("encode error: {}", e).into_bytes(),
        )
            .into_response();
    }
    (
        StatusCode::OK,
        [("content-type", "text/plain; version=0.0.4")],
        buf,
    )
        .into_response()
}
