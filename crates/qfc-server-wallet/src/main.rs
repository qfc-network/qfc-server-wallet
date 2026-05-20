//! `qfc-server-wallet` binary entrypoint.
//!
//! M2 P1 brings up the HTTP surface. For the in-process binary we wire
//! the M1 mocks (mock enclave, in-memory share store, allow-all policy,
//! mock quorum, file audit sink) so the server is *runnable* against
//! `curl` immediately. The real production wiring (Nitro enclave, S3+KMS
//! share store, Postgres audit sink, DSL policy) is the work of M2 P2..P6
//! and M3.
//!
//! Operator-visible knobs (all env-driven; sensible defaults in dev):
//!
//! | Env var                          | Default                    | Purpose                                  |
//! |----------------------------------|----------------------------|------------------------------------------|
//! | `QFC_SERVER_WALLET_BIND`         | `127.0.0.1:8088`           | TCP bind address                          |
//! | `QFC_SERVER_WALLET_API_KEYS`     | (required, comma-separated) | Allow-list for `X-API-Key`               |
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

    let bind: SocketAddr = std::env::var("QFC_SERVER_WALLET_BIND")
        .unwrap_or_else(|_| "127.0.0.1:8088".to_string())
        .parse()
        .context("QFC_SERVER_WALLET_BIND must be a valid socket address")?;

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

    let state = AppState {
        service,
        api_keys: Arc::new(api_keys),
        audit_path,
    };

    let app = router(state);

    tracing::info!(
        bind = %bind,
        "qfc-server-wallet HTTP API listening (M2 P1 dev wiring — mocks)"
    );

    let listener = tokio::net::TcpListener::bind(bind)
        .await
        .with_context(|| format!("bind {bind}"))?;
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("axum serve failed")?;

    Ok(())
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
