//! `StaticAllowDenyPolicy` — the M1 minimum policy backend.
//!
//! Decision precedence:
//! 1. Wallet-inactive → Deny(`WalletInactive`).
//! 2. If `chain_id` is in `denied_chains` → Deny(`ChainDenied`).
//! 3. If `allowed_chains` is set and the chain isn't in it → Deny(`ChainNotAllowed`).
//! 4. If the requester is in `denied_requesters` → Deny(`RequesterNotAllowed`).
//! 5. If `allowed_requesters` is set and the requester isn't in it →
//!    Deny(`RequesterNotAllowed`).
//! 6. `default` decides — `Allow` or `Deny(Other("policy default"))`.
//!
//! The decision precedence is fixed and visible — operators don't get a
//! configurable order, because that's where almost every Privy-style misuse
//! comes from. Add rate limits, value caps, and method allowlists in M2.

use std::collections::HashSet;

use async_trait::async_trait;
use qfc_wallet_types::{DecisionId, PolicyId};
use serde::{Deserialize, Serialize};

use crate::decision::{DenyReason, PolicyDecision, PolicyError, RuleEffect, RuleHit};
use crate::policy::Policy;
use crate::request::{Requester, SigningRequest};

/// Default outcome when no rule explicitly matches.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AllowDefault {
    /// No-match → Allow.
    Allow,
    /// No-match → Deny.
    #[default]
    Deny,
}

/// The static allow/deny backend. Intended for tests and tightly-scoped
/// deployments; production wallets in M2+ will plug in the full DSL.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct StaticAllowDenyPolicy {
    /// Policy version identifier (carried into decisions for audit).
    pub policy_id: PolicyId,
    /// If `Some`, *only* these chains are allowed.
    pub allowed_chains: Option<HashSet<u64>>,
    /// Chains explicitly denied (checked before `allowed_chains`).
    pub denied_chains: HashSet<u64>,
    /// If `Some`, *only* these requesters are allowed (by `requester_key()`).
    pub allowed_requesters: Option<HashSet<String>>,
    /// Requesters explicitly denied.
    pub denied_requesters: HashSet<String>,
    /// Wallet is frozen / revoked → always deny.
    pub wallet_inactive: bool,
    /// Outcome when no explicit rule matches.
    pub default: AllowDefault,
}

impl StaticAllowDenyPolicy {
    /// An "allow everything" policy. Useful for tests; do not use in
    /// production.
    #[must_use]
    pub fn allow_all() -> Self {
        Self {
            default: AllowDefault::Allow,
            ..Self::default()
        }
    }

    /// A "deny everything" policy.
    #[must_use]
    pub fn deny_all() -> Self {
        Self {
            default: AllowDefault::Deny,
            ..Self::default()
        }
    }

    /// Canonical key used for requester allow/deny set membership.
    /// Distinguishes among the four `Requester` variants by prefix so an
    /// API key cannot impersonate an on-chain address that happens to
    /// hash to the same string.
    #[must_use]
    pub fn requester_key(req: &Requester) -> String {
        match req {
            Requester::ApiKey { key_id } => format!("api:{key_id}"),
            Requester::OAuthSubject { sub } => format!("oauth:{sub}"),
            Requester::NestedWallet { wallet_id } => format!("wallet:{wallet_id}"),
            Requester::OnChainContract { chain_id, address } => {
                format!("contract:{chain_id}:{}", hex_encode(address))
            }
        }
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

#[async_trait]
impl Policy for StaticAllowDenyPolicy {
    #[allow(clippy::too_many_lines)]
    async fn evaluate(&self, request: &SigningRequest) -> Result<PolicyDecision, PolicyError> {
        let mut rationale: Vec<RuleHit> = Vec::new();
        let decision_id = DecisionId::new();

        if self.wallet_inactive {
            rationale.push(RuleHit {
                rule_id: "wallet-inactive".to_string(),
                effect: RuleEffect::Deny,
                reason: Some("wallet is frozen or revoked".to_string()),
            });
            return Ok(PolicyDecision::Deny {
                decision_id,
                policy_id: self.policy_id,
                reason: DenyReason::WalletInactive,
                rationale,
            });
        }

        if let Some(chain_id) = request.payload.chain_id() {
            if self.denied_chains.contains(&chain_id) {
                rationale.push(RuleHit {
                    rule_id: "denied-chain".to_string(),
                    effect: RuleEffect::Deny,
                    reason: Some(format!("chain {chain_id} is denied")),
                });
                return Ok(PolicyDecision::Deny {
                    decision_id,
                    policy_id: self.policy_id,
                    reason: DenyReason::ChainDenied,
                    rationale,
                });
            }
            if let Some(allow) = &self.allowed_chains {
                if !allow.contains(&chain_id) {
                    rationale.push(RuleHit {
                        rule_id: "chain-not-on-allow-list".to_string(),
                        effect: RuleEffect::Deny,
                        reason: Some(format!("chain {chain_id} not in allow list")),
                    });
                    return Ok(PolicyDecision::Deny {
                        decision_id,
                        policy_id: self.policy_id,
                        reason: DenyReason::ChainNotAllowed,
                        rationale,
                    });
                }
            }
        }

        let req_key = Self::requester_key(&request.requester);
        if self.denied_requesters.contains(&req_key) {
            rationale.push(RuleHit {
                rule_id: "denied-requester".to_string(),
                effect: RuleEffect::Deny,
                reason: Some(format!("requester {req_key} is denied")),
            });
            return Ok(PolicyDecision::Deny {
                decision_id,
                policy_id: self.policy_id,
                reason: DenyReason::RequesterNotAllowed,
                rationale,
            });
        }
        if let Some(allow) = &self.allowed_requesters {
            if !allow.contains(&req_key) {
                rationale.push(RuleHit {
                    rule_id: "requester-not-on-allow-list".to_string(),
                    effect: RuleEffect::Deny,
                    reason: Some(format!("requester {req_key} not in allow list")),
                });
                return Ok(PolicyDecision::Deny {
                    decision_id,
                    policy_id: self.policy_id,
                    reason: DenyReason::RequesterNotAllowed,
                    rationale,
                });
            }
        }

        match self.default {
            AllowDefault::Allow => {
                rationale.push(RuleHit {
                    rule_id: "default-allow".to_string(),
                    effect: RuleEffect::Allow,
                    reason: Some("no explicit deny matched; default is allow".to_string()),
                });
                Ok(PolicyDecision::Allow {
                    decision_id,
                    policy_id: self.policy_id,
                    rationale,
                })
            }
            AllowDefault::Deny => {
                rationale.push(RuleHit {
                    rule_id: "default-deny".to_string(),
                    effect: RuleEffect::Deny,
                    reason: Some("no explicit allow matched; default is deny".to_string()),
                });
                Ok(PolicyDecision::Deny {
                    decision_id,
                    policy_id: self.policy_id,
                    reason: DenyReason::Other("policy default".to_string()),
                    rationale,
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::request::{Requester, SigningPayload, SigningRequest, VmType};
    use qfc_wallet_types::{PolicyId, RequestId, WalletId};

    fn req_vm(chain_id: u64) -> SigningRequest {
        SigningRequest {
            request_id: RequestId::new(),
            wallet_id: WalletId::new(),
            requester: Requester::ApiKey {
                key_id: "alice".to_string(),
            },
            payload: SigningPayload::VmTransaction {
                vm: VmType::Evm,
                chain_id,
                to: None,
                raw: vec![1, 2, 3],
            },
            hd_path: None,
            received_at_unix_ms: 0,
        }
    }

    #[tokio::test]
    async fn allow_all_yields_allow() {
        let policy = StaticAllowDenyPolicy::allow_all();
        let decision = policy.evaluate(&req_vm(1)).await.unwrap();
        assert!(decision.is_immediate_allow());
    }

    #[tokio::test]
    async fn deny_all_yields_deny() {
        let policy = StaticAllowDenyPolicy::deny_all();
        let decision = policy.evaluate(&req_vm(1)).await.unwrap();
        assert!(decision.is_deny());
    }

    #[tokio::test]
    async fn wallet_inactive_dominates() {
        let mut policy = StaticAllowDenyPolicy::allow_all();
        policy.wallet_inactive = true;
        let d = policy.evaluate(&req_vm(1)).await.unwrap();
        match d {
            PolicyDecision::Deny { reason, .. } => assert_eq!(reason, DenyReason::WalletInactive),
            other => panic!("expected Deny(WalletInactive), got {other:?}"),
        }
    }

    #[tokio::test]
    async fn denied_chain_rejects() {
        let mut policy = StaticAllowDenyPolicy::allow_all();
        policy.denied_chains.insert(9001);
        let d = policy.evaluate(&req_vm(9001)).await.unwrap();
        match d {
            PolicyDecision::Deny { reason, .. } => assert_eq!(reason, DenyReason::ChainDenied),
            other => panic!("expected Deny(ChainDenied), got {other:?}"),
        }
    }

    #[tokio::test]
    async fn allowed_chains_filter() {
        let mut policy = StaticAllowDenyPolicy::allow_all();
        policy.allowed_chains = Some([1u64].into_iter().collect());
        assert!(policy
            .evaluate(&req_vm(1))
            .await
            .unwrap()
            .is_immediate_allow());
        let d = policy.evaluate(&req_vm(2)).await.unwrap();
        match d {
            PolicyDecision::Deny { reason, .. } => assert_eq!(reason, DenyReason::ChainNotAllowed),
            other => panic!("expected Deny(ChainNotAllowed), got {other:?}"),
        }
    }

    #[tokio::test]
    async fn requester_allow_list_blocks_others() {
        let mut policy = StaticAllowDenyPolicy::allow_all();
        policy.allowed_requesters = Some(["api:bob".to_string()].into_iter().collect());
        let d = policy.evaluate(&req_vm(1)).await.unwrap();
        match d {
            PolicyDecision::Deny { reason, .. } => {
                assert_eq!(reason, DenyReason::RequesterNotAllowed);
            }
            other => panic!("expected Deny(RequesterNotAllowed), got {other:?}"),
        }
    }

    #[tokio::test]
    async fn denied_requester_rejects() {
        let mut policy = StaticAllowDenyPolicy::allow_all();
        policy.denied_requesters.insert("api:alice".to_string());
        let d = policy.evaluate(&req_vm(1)).await.unwrap();
        assert!(d.is_deny());
    }

    #[tokio::test]
    async fn decision_id_is_present_on_every_outcome() {
        let policy = StaticAllowDenyPolicy::allow_all();
        let d = policy.evaluate(&req_vm(1)).await.unwrap();
        assert_eq!(d.decision_id().to_string().len(), 26); // ULID is 26 chars.
    }

    #[tokio::test]
    async fn rationale_records_default_allow() {
        let policy = StaticAllowDenyPolicy::allow_all();
        let d = policy.evaluate(&req_vm(1)).await.unwrap();
        match d {
            PolicyDecision::Allow { rationale, .. } => {
                assert!(rationale.iter().any(|r| r.rule_id == "default-allow"));
            }
            other => panic!("expected Allow, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn requester_keys_distinguish_variants() {
        let api = Requester::ApiKey {
            key_id: "x".to_string(),
        };
        let oauth = Requester::OAuthSubject {
            sub: "x".to_string(),
        };
        // Same human name "x" but different namespaces → distinct keys.
        assert_ne!(
            StaticAllowDenyPolicy::requester_key(&api),
            StaticAllowDenyPolicy::requester_key(&oauth)
        );
    }

    #[tokio::test]
    async fn allow_with_policy_id_carried_through() {
        let policy_id = PolicyId::new();
        let policy = StaticAllowDenyPolicy {
            policy_id,
            ..StaticAllowDenyPolicy::allow_all()
        };
        let d = policy.evaluate(&req_vm(1)).await.unwrap();
        match d {
            PolicyDecision::Allow { policy_id: p, .. } => assert_eq!(p, policy_id),
            other => panic!("expected Allow, got {other:?}"),
        }
    }
}
