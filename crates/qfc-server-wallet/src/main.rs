//! `qfc-server-wallet` binary entrypoint.
//!
//! Brings up both the HTTP API (axum on `--http-listen`, default
//! `127.0.0.1:8088`) and the gRPC API (tonic on `--grpc-listen`, default
//! `127.0.0.1:9090`) concurrently. Both share a single
//! `Arc<WalletService>` — there is no logic duplication between the two
//! transports. Either surface can be disabled via `--no-http` / `--no-grpc`.
//!
//! Operator-visible knobs (env-driven; CLI flags are M-future):
//!
//! | Env var                          | Default                    | Purpose                                  |
//! |----------------------------------|----------------------------|------------------------------------------|
//! | `QFC_SERVER_WALLET_BIND`         | `127.0.0.1:8088`           | HTTP TCP bind address (alias for `QFC_SERVER_WALLET_HTTP_BIND`) |
//! | `QFC_SERVER_WALLET_HTTP_BIND`    | `127.0.0.1:8088`           | HTTP bind. Takes precedence over the alias. |
//! | `QFC_SERVER_WALLET_GRPC_BIND`    | `127.0.0.1:9090`           | gRPC bind. |
//! | `QFC_SERVER_WALLET_DISABLE_HTTP` | (unset)                    | If set to a non-empty value, do not start the HTTP server. |
//! | `QFC_SERVER_WALLET_DISABLE_GRPC` | (unset)                    | If set to a non-empty value, do not start the gRPC server. |
//! | `QFC_SERVER_WALLET_DISABLE_REFLECTION` | (unset)              | If set, do not register `grpc.reflection.v1` (recommended for prod). |
//! | `QFC_SERVER_WALLET_API_KEYS`     | (required, comma-separated) | Allow-list for `X-API-Key` (HTTP) and `x-api-key` (gRPC). |
//! | `QFC_SERVER_WALLET_AUDIT_PATH`   | `./audit.ndjson`           | NDJSON audit sink path                    |
//! | `QFC_ALLOW_MOCK_ENCLAVE`         | (required = `yes-i-know`)  | Mock-enclave opt-in (M1/M2 dev only)     |
//! | `RUST_LOG`                       | `info`                     | tracing-subscriber filter                 |
#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::collections::HashSet;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use qfc_audit::FileAuditSink;
use qfc_enclave::MockEnclave;
use qfc_policy::StaticAllowDenyPolicy;
use qfc_quorum::MockQuorumApprover;
use qfc_server_wallet::grpc::{build_router as build_grpc_router, GrpcOptions};
use qfc_server_wallet::{router, AppState, WalletService};
use qfc_sss::MockShareStore;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let http_bind: SocketAddr = std::env::var("QFC_SERVER_WALLET_HTTP_BIND")
        .or_else(|_| std::env::var("QFC_SERVER_WALLET_BIND"))
        .unwrap_or_else(|_| "127.0.0.1:8088".to_string())
        .parse()
        .context("QFC_SERVER_WALLET_HTTP_BIND must be a valid socket address")?;
    let grpc_bind: SocketAddr = std::env::var("QFC_SERVER_WALLET_GRPC_BIND")
        .unwrap_or_else(|_| "127.0.0.1:9090".to_string())
        .parse()
        .context("QFC_SERVER_WALLET_GRPC_BIND must be a valid socket address")?;

    let disable_http = env_flag("QFC_SERVER_WALLET_DISABLE_HTTP");
    let disable_grpc = env_flag("QFC_SERVER_WALLET_DISABLE_GRPC");
    let disable_reflection = env_flag("QFC_SERVER_WALLET_DISABLE_REFLECTION");

    anyhow::ensure!(
        !(disable_http && disable_grpc),
        "both HTTP and gRPC servers disabled — nothing to serve"
    );

    let api_keys_raw = std::env::var("QFC_SERVER_WALLET_API_KEYS")
        .context("QFC_SERVER_WALLET_API_KEYS env var is required (comma-separated allow-list)")?;
    let api_keys: HashSet<String> = qfc_server_wallet::api::auth::load_api_keys(&api_keys_raw);
    anyhow::ensure!(
        !api_keys.is_empty(),
        "QFC_SERVER_WALLET_API_KEYS must contain at least one non-empty key"
    );

    let audit_path: PathBuf = std::env::var("QFC_SERVER_WALLET_AUDIT_PATH")
        .unwrap_or_else(|_| "./audit.ndjson".to_string())
        .into();

    // Wire M1 mocks. The enclave still respects QFC_ALLOW_MOCK_ENCLAVE.
    let enclave: Arc<dyn qfc_enclave::Enclave> =
        Arc::new(MockEnclave::new().context(
            "MockEnclave init failed — set QFC_ALLOW_MOCK_ENCLAVE=yes-i-know for dev runs",
        )?);
    let shares: Arc<dyn qfc_sss::ShareStore> = Arc::new(MockShareStore::new());
    let policy: Arc<dyn qfc_policy::Policy> = Arc::new(StaticAllowDenyPolicy::allow_all());
    let quorum: Arc<dyn qfc_quorum::QuorumApprover> = Arc::new(MockQuorumApprover::new());

    let audit_key = FileAuditSink::random_key();
    let audit = FileAuditSink::open(&audit_path, audit_key)
        .await
        .context("failed to open audit sink")?;
    let audit: Arc<dyn qfc_audit::AuditSink> = Arc::new(audit);

    let service = Arc::new(WalletService::new(enclave, shares, policy, quorum, audit));

    let app_state = AppState {
        service,
        api_keys: Arc::new(api_keys),
        audit_path,
    };
    let shared_state = Arc::new(app_state.clone());

    let mut handles: Vec<tokio::task::JoinHandle<anyhow::Result<()>>> = Vec::new();

    if !disable_http {
        let app = router(app_state);
        tracing::info!(bind = %http_bind, "qfc-server-wallet HTTP API listening");
        let listener = tokio::net::TcpListener::bind(http_bind)
            .await
            .with_context(|| format!("HTTP bind {http_bind}"))?;
        handles.push(tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(shutdown_signal())
                .await
                .context("axum serve failed")
        }));
    }

    if !disable_grpc {
        let opts = GrpcOptions {
            reflection: !disable_reflection,
        };
        let router = build_grpc_router(shared_state.clone(), opts);
        tracing::info!(
            bind = %grpc_bind,
            reflection = opts.reflection,
            "qfc-server-wallet gRPC API listening"
        );
        handles.push(tokio::spawn(async move {
            router
                .serve_with_shutdown(grpc_bind, shutdown_signal())
                .await
                .context("tonic serve failed")
        }));
    }

    // Wait for either server to terminate; report the first error.
    let mut first_err: Option<anyhow::Error> = None;
    for h in handles {
        match h.await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                first_err.get_or_insert(e);
            }
            Err(e) => {
                first_err.get_or_insert_with(|| anyhow::anyhow!("server task panicked: {e}"));
            }
        }
    }
    if let Some(e) = first_err {
        return Err(e);
    }

    Ok(())
}

/// Set by an env var; returns true when the variable is set to a non-empty
/// value (modulo whitespace).
fn env_flag(name: &str) -> bool {
    std::env::var(name)
        .map(|v| !v.trim().is_empty())
        .unwrap_or(false)
}

async fn shutdown_signal() {
    use tokio::signal;
    let ctrl_c = async {
        signal::ctrl_c().await.ok();
    };
    #[cfg(unix)]
    let terminate = async {
        if let Ok(mut s) = signal::unix::signal(signal::unix::SignalKind::terminate()) {
            s.recv().await;
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => tracing::info!("SIGINT received, shutting down"),
        () = terminate => tracing::info!("SIGTERM received, shutting down"),
    }
}
