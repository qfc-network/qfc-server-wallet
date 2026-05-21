//! Connect to a running server, create a new ed25519 wallet, print the
//! wallet ULID + master public key (hex).
//!
//! Usage:
//!
//! ```sh
//! export QFC_SERVER=http://127.0.0.1:9090
//! export QFC_API_KEY=dev-key-1
//! cargo run --example create_wallet
//! ```

#![allow(clippy::result_large_err)] // SdkError embeds tonic::Status; see lib.rs

use std::env;

use qfc_wallet_grpc::{CreateWalletParams, SdkError, SigningScheme, WalletClient};

#[tokio::main]
async fn main() -> Result<(), SdkError> {
    let endpoint = env::var("QFC_SERVER").unwrap_or_else(|_| "http://127.0.0.1:9090".to_string());
    let api_key = env::var("QFC_API_KEY").unwrap_or_else(|_| "dev-key-1".to_string());

    let mut client = WalletClient::connect(endpoint)
        .api_key(api_key)
        .wallet()
        .await?;

    let wallet = client
        .create_wallet(CreateWalletParams {
            scheme: SigningScheme::Ed25519,
            threshold: 2,
            total: 3,
            display_name: "example-wallet".into(),
            owner_id: "tenant-example".into(),
            policy_id: None,
        })
        .await?;

    println!("wallet_id:         {}", wallet.wallet_id);
    println!("scheme:            {}", wallet.scheme);
    println!("threshold/total:   {}/{}", wallet.threshold, wallet.total);
    println!("owner_id:          {}", wallet.owner_id);
    println!(
        "master_public_key: {}",
        hex_encode(&wallet.master_public_key)
    );
    Ok(())
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut s, "{b:02x}");
    }
    s
}
