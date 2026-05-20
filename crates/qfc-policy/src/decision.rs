//! Policy decisions, rule trace, and error types.

use qfc_wallet_types::{ApproverSetId, DecisionId, PolicyId};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// One rule that contributed to a decision. The rule trace is exposed so
/// operators and auditors can trace why a decision came out the way it did
/// even when many rules matched.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleHit {
    /// Stable identifier of the rule (e.g. `"deny-frozen-wallets"`).
    pub rule_id: String,
    /// Whether the rule contributed to allow / deny / quorum.
    pub effect: RuleEffect,
    /// Optional human-readable reason.
    pub reason: Option<String>,
}

/// The effect a single rule had on the decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleEffect {
    /// The rule allowed the request.
    Allow,
    /// The rule denied the request.
    Deny,
    /// The rule required a quorum approval.
    RequireQuorum,
}

/// Symbolic reason for a deny outcome.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DenyReason {
    /// The requested chain is not on the wallet's allow list.
    ChainNotAllowed,
    /// The requested chain is on the wallet's deny list.
    ChainDenied,
    /// The requester is not authorized for this wallet.
    RequesterNotAllowed,
    /// The wallet is frozen / revoked.
    WalletInactive,
    /// Catch-all: a rule denied but no specific category fits.
    Other(String),
}

/// The output of `Policy::evaluate`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyDecision {
    /// Sign immediately.
    Allow {
        /// Unique identifier for this decision (for audit / cross-ref).
        decision_id: DecisionId,
        /// Policy version that produced the decision.
        policy_id: PolicyId,
        /// Rules that matched, in match order.
        rationale: Vec<RuleHit>,
    },
    /// Refuse to sign.
    Deny {
        /// Unique identifier for this decision.
        decision_id: DecisionId,
        /// Policy version that produced the decision.
        policy_id: PolicyId,
        /// Symbolic reason.
        reason: DenyReason,
        /// Rules that matched, in match order.
        rationale: Vec<RuleHit>,
    },
    /// Sign only if M-of-N approvers sign off.
    RequireQuorum {
        /// Unique identifier for this decision.
        decision_id: DecisionId,
        /// Policy version that produced the decision.
        policy_id: PolicyId,
        /// Minimum approvals required.
        threshold: u8,
        /// Total approvers in the set.
        total: u8,
        /// Identifier of the approver set to ask.
        approver_set: ApproverSetId,
        /// Rules that matched, in match order.
        rationale: Vec<RuleHit>,
    },
}

impl PolicyDecision {
    /// Whether the decision permits signing without further quorum
    /// collection.
    #[must_use]
    pub fn is_immediate_allow(&self) -> bool {
        matches!(self, Self::Allow { .. })
    }

    /// Whether the decision is a hard deny.
    #[must_use]
    pub fn is_deny(&self) -> bool {
        matches!(self, Self::Deny { .. })
    }

    /// Whether the decision requires quorum collection before signing.
    #[must_use]
    pub fn requires_quorum(&self) -> bool {
        matches!(self, Self::RequireQuorum { .. })
    }

    /// Borrow the decision identifier.
    #[must_use]
    pub fn decision_id(&self) -> DecisionId {
        match self {
            Self::Allow { decision_id, .. }
            | Self::Deny { decision_id, .. }
            | Self::RequireQuorum { decision_id, .. } => *decision_id,
        }
    }
}

/// Errors raised by `Policy::evaluate`.
#[derive(Debug, Error)]
pub enum PolicyError {
    /// The wallet's policy configuration was malformed.
    #[error("policy misconfiguration: {0}")]
    Misconfiguration(&'static str),

    /// Evaluation panicked or produced an internal inconsistency.
    #[error("policy internal error: {0}")]
    Internal(String),
}
