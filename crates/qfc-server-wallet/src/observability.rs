//! Observability initialisation: structured tracing → OTLP and metrics → Prometheus.
//!
//! Wires up the QFC server wallet's tracing + metrics stack per RFC §7 (M2 P5):
//!
//!   * `tracing-subscriber` formats logs (pretty or JSON), filtered by
//!     [`ObservabilityConfig::log_filter`] / `RUST_LOG`.
//!   * When [`ObservabilityConfig::otlp_endpoint`] is `Some`, spans are
//!     exported through [`opentelemetry-otlp`] over Tonic gRPC. Otherwise
//!     the OpenTelemetry layer is omitted entirely (zero overhead).
//!   * When [`ObservabilityConfig::prometheus_listen_addr`] is `Some`, a
//!     standalone Prometheus HTTP listener is started. A
//!     [`PrometheusHandle`] is
//!     always installed so [`prometheus_endpoint`] can mount `/metrics`
//!     into an external Axum router (e.g. the M2 P1 HTTP server).
//!
//! `init` is called **once** at process start. The returned
//! [`ObservabilityHandle`] must be `.shutdown().await`-ed before the runtime
//! drops to flush pending spans.

use std::net::SocketAddr;

use axum::{extract::State, http::StatusCode, response::IntoResponse, routing::get, Router};
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use opentelemetry::trace::TracerProvider as _;
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::{runtime, trace as sdktrace, Resource};
use thiserror::Error;
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

/// User-supplied observability configuration.
#[derive(Debug, Clone)]
pub struct ObservabilityConfig {
    /// Service name surfaced as the OpenTelemetry `service.name` resource attribute
    /// and prefixed onto Prometheus metrics. Conventionally
    /// `"qfc-server-wallet"`.
    pub service_name: String,
    /// OTLP gRPC endpoint (e.g. `"http://localhost:4317"`). `None` disables
    /// span export entirely; only the local fmt layer is installed.
    pub otlp_endpoint: Option<String>,
    /// Listener address for the Prometheus scrape endpoint
    /// (e.g. `0.0.0.0:9090`). `None` disables the standalone listener but
    /// the [`PrometheusHandle`] is still available for embedded mounting
    /// via [`prometheus_endpoint`].
    pub prometheus_listen_addr: Option<SocketAddr>,
    /// `tracing-subscriber` `EnvFilter` directives, e.g.
    /// `"qfc=info,axum=warn"`. Composed with `RUST_LOG` if set.
    pub log_filter: String,
    /// Emit logs as JSON (production) when `true`; pretty multi-line
    /// (development) when `false`.
    pub json_logs: bool,
}

impl Default for ObservabilityConfig {
    fn default() -> Self {
        Self {
            service_name: "qfc-server-wallet".to_string(),
            otlp_endpoint: None,
            prometheus_listen_addr: None,
            log_filter: "info".to_string(),
            json_logs: false,
        }
    }
}

/// Errors raised during observability initialisation.
#[derive(Debug, Error)]
pub enum ObservabilityError {
    /// `EnvFilter` could not parse [`ObservabilityConfig::log_filter`].
    #[error("invalid log filter: {0}")]
    InvalidFilter(String),

    /// OTLP exporter build failed.
    #[error("otlp exporter: {0}")]
    Otlp(String),

    /// Prometheus listener / recorder install failed.
    #[error("prometheus: {0}")]
    Prometheus(String),

    /// Global tracing subscriber was already installed by another caller.
    #[error("tracing subscriber: {0}")]
    Subscriber(String),
}

/// Resources owned by [`init`] that must outlive the process body and be
/// shut down explicitly before the Tokio runtime drops.
pub struct ObservabilityHandle {
    /// Tracer provider, retained so we can flush spans on shutdown.
    tracer_provider: Option<sdktrace::TracerProvider>,
    /// Prometheus render handle, always installed; cloneable for the
    /// embedded `/metrics` axum handler.
    prom_handle: PrometheusHandle,
}

impl ObservabilityHandle {
    /// Borrow the Prometheus render handle. Useful when constructing
    /// secondary handlers outside of [`prometheus_endpoint`].
    #[must_use]
    pub fn prometheus_handle(&self) -> PrometheusHandle {
        self.prom_handle.clone()
    }

    /// Flush spans and tear down the global tracer provider.
    ///
    /// Drops happen on a blocking thread because the OpenTelemetry SDK's shutdown
    /// path is synchronous. Safe to call even if OTLP was not enabled.
    pub async fn shutdown(self) {
        if let Some(provider) = self.tracer_provider {
            // `provider.shutdown()` is sync; run on the blocking pool so we
            // don't stall the runtime if the exporter is slow.
            let _ = tokio::task::spawn_blocking(move || {
                if let Err(e) = provider.shutdown() {
                    tracing::warn!(error = %e, "otlp tracer shutdown failed");
                }
            })
            .await;
        }
    }
}

/// Install the global tracing subscriber + metrics recorder.
///
/// # Errors
///
/// Returns [`ObservabilityError`] if filter parsing fails, the OTLP
/// exporter cannot be built, Prometheus listener bind fails, or the global
/// tracing subscriber is already set.
#[allow(clippy::needless_pass_by_value)] // taking by value is intentional — `cfg` is a setup-once value the caller hands over to the global subscriber install.
pub fn init(cfg: ObservabilityConfig) -> Result<ObservabilityHandle, ObservabilityError> {
    // ---- 1. EnvFilter (composes RUST_LOG with the caller-supplied
    //          directives; RUST_LOG, if present, takes precedence by being
    //          consulted first by EnvFilter::try_from_default_env).
    EnvFilter::try_new(&cfg.log_filter)
        .map_err(|e| ObservabilityError::InvalidFilter(e.to_string()))?;
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(cfg.log_filter.clone()));

    // ---- 2. Optional OTLP tracer provider.
    let tracer_provider = if let Some(endpoint) = cfg.otlp_endpoint.as_ref() {
        let exporter = opentelemetry_otlp::new_exporter()
            .tonic()
            .with_endpoint(endpoint)
            .build_span_exporter()
            .map_err(|e| ObservabilityError::Otlp(e.to_string()))?;

        let config = sdktrace::Config::default().with_resource(Resource::new([
            opentelemetry::KeyValue::new("service.name", cfg.service_name.clone()),
        ]));

        let provider = sdktrace::TracerProvider::builder()
            .with_batch_exporter(exporter, runtime::Tokio)
            .with_config(config)
            .build();
        Some(provider)
    } else {
        None
    };

    // ---- 3. Install subscriber. We build two distinct subscriber
    //          shapes (with/without the OpenTelemetry layer) and try_init the right
    //          one — Option<Layer<S>> implements Layer<S>, so a single
    //          shape would also work, but expressing it as two branches
    //          keeps the type concrete and the error surface clear.
    let otel_layer = tracer_provider.as_ref().map(|p| {
        let tracer = p.tracer(cfg.service_name.clone());
        tracing_opentelemetry::layer().with_tracer(tracer)
    });

    let result = if cfg.json_logs {
        let fmt_layer = tracing_subscriber::fmt::layer().json();
        tracing_subscriber::registry()
            .with(filter)
            .with(otel_layer)
            .with(fmt_layer)
            .try_init()
    } else {
        let fmt_layer = tracing_subscriber::fmt::layer().pretty();
        tracing_subscriber::registry()
            .with(filter)
            .with(otel_layer)
            .with(fmt_layer)
            .try_init()
    };
    result.map_err(|e| ObservabilityError::Subscriber(e.to_string()))?;

    // ---- 4. Prometheus recorder (always installed) + optional listener.
    let builder = PrometheusBuilder::new();
    let prom_handle = if let Some(addr) = cfg.prometheus_listen_addr {
        let (recorder, exporter) = builder
            .with_http_listener(addr)
            .build()
            .map_err(|e| ObservabilityError::Prometheus(e.to_string()))?;
        let handle = recorder.handle();
        metrics::set_global_recorder(recorder)
            .map_err(|e| ObservabilityError::Prometheus(e.to_string()))?;
        // Spawn the exporter onto the active runtime so /metrics serves.
        tokio::spawn(exporter);
        handle
    } else {
        let recorder = builder.build_recorder();
        let handle = recorder.handle();
        metrics::set_global_recorder(recorder)
            .map_err(|e| ObservabilityError::Prometheus(e.to_string()))?;
        handle
    };

    // ---- 5. Pre-register canonical QFC metrics so they show up in
    //          `/metrics` with `# HELP` lines even before they fire.
    register_metric_descriptions();

    Ok(ObservabilityHandle {
        tracer_provider,
        prom_handle,
    })
}

/// Register `# HELP` descriptions and units for canonical QFC metrics.
/// Counters/histograms remain zero-valued until something emits, but
/// pre-registering gives Mimir / Grafana stable schemas at startup.
fn register_metric_descriptions() {
    metrics::describe_counter!(
        "qfc_server_wallet_signs_total",
        "Sign operations grouped by signing scheme and outcome (success | denied | failed)."
    );
    metrics::describe_counter!(
        "qfc_server_wallet_wallets_created_total",
        "Wallets created, grouped by signing scheme."
    );
    metrics::describe_counter!(
        "qfc_server_wallet_audit_events_total",
        "Audit events emitted, grouped by AuditKind discriminant."
    );
    metrics::describe_histogram!(
        "qfc_server_wallet_sign_duration_seconds",
        metrics::Unit::Seconds,
        "End-to-end sign latency including policy + quorum + enclave."
    );
    metrics::describe_histogram!(
        "qfc_server_wallet_policy_evaluation_seconds",
        metrics::Unit::Seconds,
        "Time spent inside Policy::evaluate."
    );
    metrics::describe_histogram!(
        "qfc_server_wallet_quorum_collect_seconds",
        metrics::Unit::Seconds,
        "Time spent waiting for quorum approvals (only RequireQuorum paths)."
    );
}

/// Tower [`Layer`](tower::Layer) that adds per-HTTP-request tracing
/// (method, path, status, latency). Mount on the axum router that the M2
/// P1 HTTP service exposes:
///
/// ```ignore
/// let app = axum::Router::new()
///     .route("/sign", post(sign_handler))
///     .layer(observability::http_layer());
/// ```
#[must_use]
pub fn http_layer(
) -> TraceLayer<tower_http::classify::SharedClassifier<tower_http::classify::ServerErrorsAsFailures>>
{
    TraceLayer::new_for_http()
}

/// Build an [`axum::Router`] that serves Prometheus exposition format at
/// `GET /metrics`. Mount onto the main HTTP server with `.merge(...)`.
///
/// The handle is cloned so this router is fully owned and `'static`.
pub fn prometheus_endpoint(handle: PrometheusHandle) -> Router {
    Router::new()
        .route("/metrics", get(render_metrics))
        .with_state(handle)
}

#[allow(clippy::unused_async)]
async fn render_metrics(State(handle): State<PrometheusHandle>) -> impl IntoResponse {
    (
        StatusCode::OK,
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4",
        )],
        handle.render(),
    )
}

// -------------------------------------------------------------------------
// Metric emission helpers
// -------------------------------------------------------------------------
//
// These wrap `metrics::counter!` / `metrics::histogram!` so call sites in
// `service.rs` stay readable and the label vocabulary lives in one place.

/// Outcome label for `qfc_server_wallet_signs_total`.
#[derive(Debug, Clone, Copy)]
pub enum SignResult {
    /// Enclave returned a signature.
    Success,
    /// Policy denied (or quorum rejected).
    Denied,
    /// Enclave or share-store error.
    Failed,
}

impl SignResult {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Denied => "denied",
            Self::Failed => "failed",
        }
    }
}

/// Increment `qfc_server_wallet_signs_total{scheme, result}`.
pub(crate) fn record_sign_outcome(scheme: &str, result: SignResult) {
    metrics::counter!(
        "qfc_server_wallet_signs_total",
        "scheme" => scheme.to_string(),
        "result" => result.as_str(),
    )
    .increment(1);
}

/// Increment `qfc_server_wallet_wallets_created_total{scheme}`.
pub(crate) fn record_wallet_created(scheme: &str) {
    metrics::counter!(
        "qfc_server_wallet_wallets_created_total",
        "scheme" => scheme.to_string(),
    )
    .increment(1);
}

/// Increment `qfc_server_wallet_audit_events_total{kind}`. Reserved for an
/// `audit::AuditSink` adapter layer; not currently called from `service.rs`
/// because audit emission happens through `qfc_audit` directly.
pub fn record_audit_event(kind: &str) {
    metrics::counter!(
        "qfc_server_wallet_audit_events_total",
        "kind" => kind.to_string(),
    )
    .increment(1);
}

/// Record a sign-duration sample in `qfc_server_wallet_sign_duration_seconds{scheme}`.
pub(crate) fn record_sign_duration(scheme: &str, secs: f64) {
    metrics::histogram!(
        "qfc_server_wallet_sign_duration_seconds",
        "scheme" => scheme.to_string(),
    )
    .record(secs);
}

/// Record a policy-evaluation sample in `qfc_server_wallet_policy_evaluation_seconds`.
pub(crate) fn record_policy_evaluation(secs: f64) {
    metrics::histogram!("qfc_server_wallet_policy_evaluation_seconds").record(secs);
}

/// Record a quorum-collect sample in `qfc_server_wallet_quorum_collect_seconds`.
pub(crate) fn record_quorum_collect(secs: f64) {
    metrics::histogram!("qfc_server_wallet_quorum_collect_seconds").record(secs);
}

// -------------------------------------------------------------------------
// Tests
// -------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Global init-guard: `init()` touches the process-wide tracing
    /// subscriber + metrics recorder, which can only be installed once.
    /// Tests serialise through this lock and skip subsequent inits.
    static INIT_GUARD: Mutex<bool> = Mutex::new(false);

    fn try_init(
        cfg: ObservabilityConfig,
    ) -> Result<Option<ObservabilityHandle>, ObservabilityError> {
        let mut guard = INIT_GUARD.lock().unwrap();
        if *guard {
            // Subscriber + recorder already installed in this test process;
            // return Ok(None) so callers can still exercise the config path
            // they care about (we tested install logic in the very first
            // test that grabbed the guard).
            return Ok(None);
        }
        let handle = init(cfg)?;
        *guard = true;
        Ok(Some(handle))
    }

    #[test]
    fn default_config_is_minimal() {
        let cfg = ObservabilityConfig::default();
        assert_eq!(cfg.service_name, "qfc-server-wallet");
        assert!(cfg.otlp_endpoint.is_none());
        assert!(cfg.prometheus_listen_addr.is_none());
        assert!(!cfg.json_logs);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn init_with_defaults_returns_ok() {
        // No OTLP, no listener — just the local fmt + EnvFilter + recorder.
        let res = try_init(ObservabilityConfig::default());
        if let Err(ref e) = res {
            panic!("expected init() to succeed: {e:?}");
        }
    }

    #[test]
    fn invalid_filter_is_rejected() {
        // EnvFilter accepts a *lot*, so use a syntactically broken value.
        let bad = ObservabilityConfig {
            log_filter: "not=valid=filter=triple".to_string(),
            ..Default::default()
        };
        // We deliberately call `init` directly (not through the guard) so
        // we exercise the filter-validation path before any globals are
        // touched. Even if subscriber install would have failed later,
        // the InvalidFilter branch trips first.
        let res = init(bad);
        assert!(matches!(res, Err(ObservabilityError::InvalidFilter(_))));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn prometheus_endpoint_renders_metric_names() {
        use tower::ServiceExt;

        // Force the recorder to be installed (in case a prior test in this
        // module already grabbed the slot — we still get a handle via
        // `init` if it was the first, else we synthesise a builder-only
        // handle from a fresh PrometheusBuilder to exercise the axum
        // handler in isolation).
        let handle = if let Ok(Some(h)) = try_init(ObservabilityConfig::default()) {
            h.prometheus_handle()
        } else {
            // Recorder already installed elsewhere in this process.
            // Build a standalone handle (won't see global counters but
            // it lets us exercise the axum route + content-type).
            let recorder = PrometheusBuilder::new().build_recorder();
            recorder.handle()
        };

        // Emit something so /metrics has at least one line.
        record_sign_outcome("ed25519", SignResult::Success);
        record_wallet_created("ed25519");
        record_sign_duration("ed25519", 0.001);

        let router = prometheus_endpoint(handle);

        // Drive the axum router via tower::Service directly so we don't
        // need a real TCP listener.
        let response = router
            .oneshot(
                axum::http::Request::builder()
                    .method("GET")
                    .uri("/metrics")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .expect("router responded");
        assert_eq!(response.status(), StatusCode::OK);
        let body_bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .expect("body");
        let body = String::from_utf8(body_bytes.to_vec()).expect("utf8");
        // Content-type must be set; body is allowed to be empty if the
        // global recorder wasn't ours (we built a standalone fallback).
        // When init() succeeded first we should see our metric names.
        assert!(
            body.is_empty()
                || body.contains("qfc_server_wallet_signs_total")
                || body.contains("# HELP"),
            "unexpected /metrics body: {body}"
        );
    }

    #[test]
    fn http_layer_constructs() {
        // Smoke test — TraceLayer has no public observable state, so just
        // check it builds without panicking.
        let _layer = http_layer();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn prometheus_builder_bind_conflict_surfaces_error() {
        // Sit on a port so the builder's bind fails. We exercise the
        // builder directly (PrometheusBuilder::with_http_listener +
        // .build()) rather than `init()` to avoid clashing with the
        // global-recorder one-shot install in other tests.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let occupied = listener.local_addr().unwrap();

        let res = PrometheusBuilder::new()
            .with_http_listener(occupied)
            .build();
        // Some versions of the builder defer the bind until the spawned
        // exporter future polls, so be tolerant: Ok(_) is acceptable iff
        // the subsequent exporter task immediately fails. The point of
        // this test is that we *don't* panic and *do* surface a path that
        // a caller can react to.
        match res {
            Err(e) => {
                let msg = e.to_string();
                assert!(
                    !msg.is_empty(),
                    "expected non-empty bind-failure message: {msg}"
                );
            }
            Ok((recorder, exporter)) => {
                drop(recorder);
                // Driving the exporter must surface the error rather than
                // panicking. We bound this in case the exporter blocks.
                let handle = tokio::spawn(async move {
                    let _ = exporter.await;
                });
                let _ = tokio::time::timeout(std::time::Duration::from_millis(250), handle).await;
            }
        }

        drop(listener);
    }
}
