//! Connect, fetch the first N audit events for a wallet, print kind +
//! timestamp.
//!
//! Usage:
//!
//! ```sh
//! export QFC_SERVER=http://127.0.0.1:9090
//! export QFC_API_KEY=dev-key-1
//! # Optional: filter by wallet
//! export QFC_WALLET_ID=01HABCDEFGHJKMNPQRSTVWXYZ0
//! # Optional: limit (server caps at 1000)
//! export QFC_LIMIT=50
//! cargo run --example list_audit_events
//! ```

#![allow(clippy::result_large_err)] // SdkError embeds tonic::Status; see lib.rs

use std::env;

use qfc_wallet_grpc::{AuditEventsQuery, SdkError, WalletClient};

#[tokio::main]
async fn main() -> Result<(), SdkError> {
    let endpoint = env::var("QFC_SERVER").unwrap_or_else(|_| "http://127.0.0.1:9090".to_string());
    let api_key = env::var("QFC_API_KEY").unwrap_or_else(|_| "dev-key-1".to_string());
    let wallet_id = env::var("QFC_WALLET_ID").ok();
    let limit = env::var("QFC_LIMIT")
        .ok()
        .and_then(|s| s.parse::<u32>().ok());

    let mut client = WalletClient::connect(endpoint)
        .api_key(api_key)
        .wallet()
        .await?;

    let events = client
        .get_audit_events(AuditEventsQuery { wallet_id, limit })
        .await?;

    println!("got {} event(s)", events.len());
    for (i, e) in events.iter().enumerate() {
        println!(
            "[{i}] kind={} ts_ms={} request_id={} wallet_id={} event_id={}",
            e.kind, e.timestamp_unix_ms, e.request_id, e.wallet_id, e.event_id,
        );
    }
    Ok(())
}
