//! Signing-request input shape passed to `Policy::evaluate`.
//!
//! Minimal in M1 — the full payload decoder + decoded-shape constraints
//! land in M2 (RFC §2.4 VM-shape constraints).

use qfc_wallet_types::{HdPath, RequestId, WalletId};
use serde::{Deserialize, Serialize};

/// Who is asking for the signature.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Requester {
    /// API key identifier.
    ApiKey {
        /// Stable key identifier.
        key_id: String,
    },
    /// OAuth-style subject.
    OAuthSubject {
        /// `sub` claim from the `IdP`.
        sub: String,
    },
    /// Another QFC server wallet acting as the requester (nested
    /// composition).
    NestedWallet {
        /// The nested wallet's ULID.
        wallet_id: WalletId,
    },
    /// An on-chain contract acting as the requester (off-chain message
    /// receipt anchored to a chain-side event).
    OnChainContract {
        /// Chain identifier.
        chain_id: u64,
        /// Contract address as raw bytes.
        address: Vec<u8>,
    },
}

/// VM the payload targets.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VmType {
    /// EVM.
    Evm,
    /// QFC's native QVM.
    Qvm,
    /// WASM contract VM (not yet implemented in `qfc-core` as of v1.0).
    Wasm,
}

/// The payload to be signed. M1 keeps this minimal — full per-VM decoders
/// land in M2 (RFC §2.4) and M5 (RFC §9.6 — QVM minimal decoder).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum SigningPayload {
    /// Sign arbitrary raw bytes.
    Raw {
        /// Raw bytes to sign.
        bytes: Vec<u8>,
    },
    /// Personal-sign / EIP-191-style envelope. Carried as raw bytes for now.
    PersonalSign {
        /// The personal-sign envelope bytes.
        bytes: Vec<u8>,
    },
    /// EIP-712 typed data, opaque to M1 policy.
    TypedData {
        /// Canonical JSON of the typed data.
        json: serde_json::Value,
    },
    /// VM-specific transaction. M1 doesn't decode further than `to`/`value`.
    VmTransaction {
        /// The VM this transaction targets.
        vm: VmType,
        /// Chain identifier.
        chain_id: u64,
        /// Optional decoded target address (raw bytes).
        to: Option<Vec<u8>>,
        /// Raw transaction body — opaque envelope.
        raw: Vec<u8>,
    },
}

impl SigningPayload {
    /// Convenience: the VM this payload targets, if known.
    #[must_use]
    pub fn vm(&self) -> Option<VmType> {
        match self {
            Self::VmTransaction { vm, .. } => Some(*vm),
            _ => None,
        }
    }

    /// Convenience: the chain id this payload targets, if known.
    #[must_use]
    pub fn chain_id(&self) -> Option<u64> {
        match self {
            Self::VmTransaction { chain_id, .. } => Some(*chain_id),
            _ => None,
        }
    }
}

/// The request shape fed to `Policy::evaluate`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SigningRequest {
    /// Stable identifier set by the API layer when the request is accepted.
    pub request_id: RequestId,
    /// Wallet to sign on behalf of.
    pub wallet_id: WalletId,
    /// Who initiated the request.
    pub requester: Requester,
    /// What to sign.
    pub payload: SigningPayload,
    /// Optional HD path for the derivation. Policy may match on this.
    pub hd_path: Option<HdPath>,
    /// Unix-millisecond receive timestamp.
    pub received_at_unix_ms: i64,
}
