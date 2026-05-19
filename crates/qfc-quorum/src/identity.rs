//! Approver identity types (RFC decision #3 — all four variants).

use qfc_wallet_types::{SigningScheme, WalletId};
use serde::{Deserialize, Serialize};

/// Opaque hardware-approver handle. Approver-side clients map this to a
/// specific device and slot. The server treats it as transparent
/// identification material.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct HardwareApproverHandle {
    /// Stable identifier of the device + slot (e.g. `"yubikey:slot9c"`).
    pub handle: String,
    /// 32+ byte raw public key the device is expected to use to sign.
    pub public_key: Vec<u8>,
    /// Curve the device signs with.
    pub scheme: SigningScheme,
}

/// Approver identity. All four variants per RFC §2.5 decision #3.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum ApproverIdentity {
    /// QFC on-chain account. Approvals are signed by that account's key.
    Chain {
        /// Chain identifier.
        chain_id: u64,
        /// 20-byte (or chain-specific) raw address.
        address: Vec<u8>,
        /// Public key the chain account signs with.
        public_key: Vec<u8>,
        /// Curve.
        scheme: SigningScheme,
    },
    /// Externally-registered raw public key.
    External {
        /// Stable identifier (for audit, distinct from the pubkey).
        id: String,
        /// Raw public key bytes.
        public_key: Vec<u8>,
        /// Curve.
        scheme: SigningScheme,
    },
    /// Hardware-token-backed identity.
    Hardware(HardwareApproverHandle),
    /// Another server wallet (treasury-of-treasuries composition).
    /// The nested wallet performs the approval via its own enclave +
    /// signer; we hold the wallet id and the registered master pubkey
    /// for cross-check.
    NestedWallet {
        /// The nested wallet's ULID.
        wallet_id: WalletId,
        /// The nested wallet's registered master public key.
        public_key: Vec<u8>,
        /// Curve.
        scheme: SigningScheme,
    },
}

impl ApproverIdentity {
    /// Borrow the approver's public key bytes. Every variant exposes one,
    /// since approvals are always pubkey-anchored.
    #[must_use]
    pub fn public_key(&self) -> &[u8] {
        match self {
            Self::Chain { public_key, .. }
            | Self::External { public_key, .. }
            | Self::NestedWallet { public_key, .. } => public_key,
            Self::Hardware(h) => &h.public_key,
        }
    }

    /// Borrow the approver's signing scheme.
    #[must_use]
    pub fn scheme(&self) -> SigningScheme {
        match self {
            Self::Chain { scheme, .. }
            | Self::External { scheme, .. }
            | Self::NestedWallet { scheme, .. } => *scheme,
            Self::Hardware(h) => h.scheme,
        }
    }

    /// Stable text identifier (used as a map key / audit anchor).
    #[must_use]
    pub fn key(&self) -> String {
        match self {
            Self::Chain {
                chain_id, address, ..
            } => format!("chain:{chain_id}:{}", hex_encode(address)),
            Self::External { id, .. } => format!("external:{id}"),
            Self::Hardware(h) => format!("hardware:{}", h.handle),
            Self::NestedWallet { wallet_id, .. } => format!("nested:{wallet_id}"),
        }
    }
}

fn hex_encode(b: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(b.len() * 2);
    for byte in b {
        let _ = write!(s, "{byte:02x}");
    }
    s
}
