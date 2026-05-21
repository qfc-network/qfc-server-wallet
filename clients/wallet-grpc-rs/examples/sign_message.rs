//! Connect, look up an existing wallet, sign a raw payload, print the
//! signature (hex).
//!
//! Usage:
//!
//! ```sh
//! export QFC_SERVER=http://127.0.0.1:9090
//! export QFC_API_KEY=dev-key-1
//! export QFC_WALLET_ID=01HABCDEFGHJKMNPQRSTVWXYZ0
//! cargo run --example sign_message
//! ```

#![allow(clippy::result_large_err)] // SdkError embeds tonic::Status; see lib.rs

use std::env;

use qfc_wallet_grpc::{
    requester, signing_payload, HashAlg, Requester, SdkError, SignParams, SigningPayload,
    WalletClient,
};

#[tokio::main]
async fn main() -> Result<(), SdkError> {
    let endpoint = env::var("QFC_SERVER").unwrap_or_else(|_| "http://127.0.0.1:9090".to_string());
    let api_key = env::var("QFC_API_KEY").unwrap_or_else(|_| "dev-key-1".to_string());
    let wallet_id = env::var("QFC_WALLET_ID").expect("QFC_WALLET_ID required");

    let mut client = WalletClient::connect(endpoint)
        .api_key(api_key)
        .wallet()
        .await?;

    // Verify the wallet exists first — gives a friendlier error than a
    // server-side NotFound returned mid-sign.
    let wallet = client.get_wallet(&wallet_id).await?;
    println!(
        "wallet:    {} ({}/{})",
        wallet.wallet_id, wallet.threshold, wallet.total
    );

    let payload = b"hello qfc";
    let signed = client
        .sign(SignParams {
            wallet_id: wallet_id.clone(),
            payload: SigningPayload {
                payload: Some(signing_payload::Payload::Raw(signing_payload::Raw {
                    bytes: payload.to_vec(),
                })),
            },
            requester: Requester {
                requester: Some(requester::Requester::ApiKey(requester::ApiKey {
                    key_id: "example".into(),
                })),
            },
            hd_path: String::new(),
            hash_alg: HashAlg::None,
            context: None,
        })
        .await?;

    println!("payload:   {}", hex_encode(payload));
    println!("signature: {}", hex_encode(&signed.signature));
    println!("pubkey:    {}", hex_encode(&signed.public_key));
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
