//! `qfc-approver` binary — the reference approver-side daemon.
//!
//! See `clients/approver-rs/README.md` for a quickstart. Run
//! `qfc-approver --help` for the CLI surface.

use std::path::PathBuf;
use std::sync::Arc;

use clap::{Parser, ValueEnum};
use qfc_approver::{
    audit, load_secret, router, AppState, ApproverSigner, DecisionPolicy, Processor,
    ProcessorConfig,
};
use qfc_wallet_types::SigningScheme;
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(
    name = "qfc-approver",
    version,
    about = "Reference approver-side client for the QFC server wallet"
)]
struct Cli {
    /// Address the webhook listener binds to.
    #[arg(long, default_value = "0.0.0.0:7000", env = "QFC_APPROVER_LISTEN")]
    listen: String,

    /// Base URL of the qfc-server-wallet (e.g. `https://wallet.example`).
    #[arg(long, env = "QFC_APPROVER_SERVER")]
    server: String,

    /// ULID this client identifies as. Must already be registered on
    /// the server via `POST /approvers`.
    #[arg(long, env = "QFC_APPROVER_ID")]
    approver_id: String,

    /// Path to a file containing exactly 32 raw secret bytes.
    #[arg(long, env = "QFC_APPROVER_SECRET_FILE")]
    secret_file: PathBuf,

    /// Signing scheme.
    #[arg(long, value_enum, default_value_t = SchemeArg::Ed25519, env = "QFC_APPROVER_SCHEME")]
    scheme: SchemeArg,

    /// Shared HMAC secret. Must match what was registered with the
    /// server for this approver's webhook URL. Read from a file if you
    /// don't want it in argv — pass `@/path/to/file`.
    #[arg(long, env = "QFC_APPROVER_WEBHOOK_SECRET")]
    webhook_secret: String,

    /// **Demo / staging only.** Auto-approve every incoming request.
    #[arg(long, default_value_t = false, conflicts_with_all = ["interactive", "auto_reject"])]
    auto_approve: bool,

    /// Auto-reject every incoming request. Useful for end-to-end wiring tests.
    #[arg(long, default_value_t = false, conflicts_with_all = ["interactive", "auto_approve"])]
    auto_reject: bool,

    /// Read approve / reject from stdin per request.
    #[arg(long, default_value_t = false, conflicts_with_all = ["auto_approve", "auto_reject"])]
    interactive: bool,

    /// Optional override for the audit log path. Default
    /// `~/.qfc-approver/audit.log`.
    #[arg(long, env = "QFC_APPROVER_AUDIT_PATH")]
    audit_path: Option<PathBuf>,
}

#[derive(Copy, Clone, Debug, ValueEnum)]
enum SchemeArg {
    Ed25519,
    Secp256k1,
}

impl From<SchemeArg> for SigningScheme {
    fn from(a: SchemeArg) -> Self {
        match a {
            SchemeArg::Ed25519 => Self::Ed25519,
            SchemeArg::Secp256k1 => Self::Secp256k1,
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();

    // Decide policy. Default is fail-closed Refuse — explicit operator
    // intent required to actually sign anything.
    let policy = if cli.auto_approve {
        DecisionPolicy::AutoApprove
    } else if cli.auto_reject {
        DecisionPolicy::AutoReject
    } else if cli.interactive {
        DecisionPolicy::Interactive
    } else {
        tracing::warn!(
            "no decision policy specified; running in Refuse mode (every webhook will be dropped). \
             Pass --interactive, --auto-approve, or --auto-reject."
        );
        DecisionPolicy::Refuse
    };

    // Webhook secret — accept `@/path/to/file` to keep secrets out of argv.
    let webhook_secret = if let Some(path) = cli.webhook_secret.strip_prefix('@') {
        std::fs::read(path)?
    } else {
        cli.webhook_secret.as_bytes().to_vec()
    };

    // Signer
    let secret = load_secret(&cli.secret_file)?;
    let signer = ApproverSigner::new(secret, SigningScheme::from(cli.scheme))?;

    // Audit path
    let audit_path = cli
        .audit_path
        .or_else(audit::default_path)
        .unwrap_or_else(|| PathBuf::from("./qfc-approver-audit.log"));

    // Processor + state
    let http = Arc::new(
        reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()?,
    );
    let cfg = ProcessorConfig {
        server: cli.server.clone(),
        approver_id: cli.approver_id.clone(),
        policy,
        audit_path,
    };
    let processor = Processor::new(signer.clone(), http, cfg);
    let state = AppState {
        hmac_secret: Arc::new(webhook_secret),
        processor,
    };

    tracing::info!(
        listen = %cli.listen,
        server = %cli.server,
        approver_id = %cli.approver_id,
        scheme = ?signer.scheme(),
        pub_key = %hex::encode(signer.public_key()),
        "qfc-approver ready"
    );

    let app = router(state);
    let listener = tokio::net::TcpListener::bind(&cli.listen).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
