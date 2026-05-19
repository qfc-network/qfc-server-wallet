//! Wallet record kept by the orchestrator. Lightweight wrapper that the
//! `WalletService` persists in-memory (M1) or in Postgres (M2).
//!
//! Per RFC §3.1 (decision #4): `wallet_id` is the stable ULID;
//! `qfc_address` is an optional secondary identifier for chain-compatible
//! schemes.

use qfc_wallet_types::{OwnerId, PolicyId, SigningScheme, WalletId};
use serde::{Deserialize, Serialize};

/// Static configuration captured at wallet creation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletConfig {
    /// Display name for operator dashboards. Optional.
    pub display_name: String,
    /// Owning tenant.
    pub owner_id: OwnerId,
    /// Curve.
    pub scheme: SigningScheme,
    /// SSS threshold M (`>= 2`).
    pub threshold: u8,
    /// SSS total N (`>= threshold`).
    pub total: u8,
    /// Policy version the wallet evaluates under.
    pub policy_id: PolicyId,
}

/// Status of a wallet in the orchestrator's registry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WalletStatus {
    /// Wallet can sign.
    Active,
    /// Wallet is paused (policy returns Deny but the record is retained).
    Frozen,
    /// Wallet shares have been deleted; signing is impossible.
    Revoked,
}

/// In-memory wallet record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletRecord {
    /// ULID identifying this wallet.
    pub wallet_id: WalletId,
    /// Configuration captured at creation time.
    pub config: WalletConfig,
    /// Master public key (curve-specific encoding).
    pub master_public_key: Vec<u8>,
    /// Current lifecycle status.
    pub status: WalletStatus,
    /// Unix-millisecond creation timestamp.
    pub created_at_unix_ms: i64,
}
