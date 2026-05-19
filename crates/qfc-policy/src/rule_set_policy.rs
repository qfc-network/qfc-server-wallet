//! `RuleSetPolicy` — the full M2 P3 DSL evaluator.
//!
//! Loads a `RuleSet` from JSON, evaluates it against a `SigningRequest`,
//! emits a `PolicyDecision` with a complete `rationale` (`Vec<RuleHit>`).
//!
//! ## Precedence (FIXED, per RFC §2.4 + D14)
//!
//! 1. `DenyChain`  → `Deny(ChainDenied)`
//! 2. `DenyContract` → `Deny(Other("contract denied"))`
//! 3. `AllowChain` filter unmatched → `Deny(ChainNotAllowed)`
//! 4. `AllowContract` filter unmatched → `Deny(Other("contract not on allow list"))`
//! 5. `AllowMethod` filter unmatched → `Deny(Other("method not allowed"))`
//! 6. `ValueCap` exceeded → `Deny(Other("value cap exceeded"))`
//! 7. `TimeWindow` outside → `Deny(Other("outside time window"))`
//! 8. `RateLimit` exhausted → `Deny(Other("rate limited"))`
//! 9. `VmShape` violated → `Deny(Other("vm-shape constraint"))`
//! 10. `RequireQuorum` triggered → `RequireQuorum { .. }`
//! 11. default → `Allow` or `Deny`
//!
//! Operators configure list *contents*, not order — every Privy /
//! Fireblocks postmortem cites configurable-order as the failure mode.

use std::sync::Arc;

use async_trait::async_trait;
use primitive_types::U256;
use qfc_wallet_types::DecisionId;
use time::OffsetDateTime;

use crate::decision::{DenyReason, PolicyDecision, PolicyError, RuleEffect, RuleHit};
use crate::policy::Policy;
use crate::rate_limit::TokenBucketLimiter;
use crate::request::{Requester, SigningPayload, SigningRequest};
use crate::rules::{hex_to_bytes, normalize_hex, QuorumTrigger, RateLimitScope, Rule, RuleSet};
use crate::static_policy::{AllowDefault, StaticAllowDenyPolicy};
use crate::vm::{DecodedTx, VmDecoder};

/// Full-DSL policy backend. Wrap with `Arc` to share across requests.
pub struct RuleSetPolicy {
    rules: RuleSet,
    limiter: TokenBucketLimiter,
    decoder: Option<Arc<dyn VmDecoder>>,
}

impl std::fmt::Debug for RuleSetPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RuleSetPolicy")
            .field("policy_id", &self.rules.policy_id)
            .field("rule_count", &self.rules.rules.len())
            .field("default", &self.rules.default)
            .field("has_decoder", &self.decoder.is_some())
            .finish_non_exhaustive()
    }
}

impl RuleSetPolicy {
    /// Construct a fresh policy from a parsed `RuleSet`. Validates that
    /// the schema version is supported.
    ///
    /// # Errors
    ///
    /// `PolicyError::Misconfiguration` if `rules.version != 1`, if any hex
    /// address / selector fails to parse, or if a `RateLimit` rule has
    /// `tokens == 0`.
    pub fn new(rules: RuleSet) -> Result<Self, PolicyError> {
        Self::with_components(rules, TokenBucketLimiter::new(), None)
    }

    /// Construct with an injected limiter (for tests with a `ManualClock`)
    /// and an optional VM decoder.
    ///
    /// # Errors
    ///
    /// See `new`.
    pub fn with_components(
        rules: RuleSet,
        limiter: TokenBucketLimiter,
        decoder: Option<Arc<dyn VmDecoder>>,
    ) -> Result<Self, PolicyError> {
        validate(&rules)?;
        Ok(Self {
            rules,
            limiter,
            decoder,
        })
    }

    /// Load a policy from JSON bytes.
    ///
    /// # Errors
    ///
    /// `PolicyError::Misconfiguration` if the JSON does not deserialize
    /// into a valid `RuleSet`.
    pub fn from_json(bytes: &[u8]) -> Result<Self, PolicyError> {
        let rules: RuleSet = serde_json::from_slice(bytes)
            .map_err(|_| PolicyError::Misconfiguration("malformed policy JSON"))?;
        Self::new(rules)
    }

    /// Borrow the rule set.
    #[must_use]
    pub fn rules(&self) -> &RuleSet {
        &self.rules
    }
}

#[allow(clippy::too_many_lines)]
fn validate(rs: &RuleSet) -> Result<(), PolicyError> {
    if rs.version != 1 {
        return Err(PolicyError::Misconfiguration("unsupported policy version"));
    }
    for rule in &rs.rules {
        match rule {
            Rule::AllowContract { addresses, .. } | Rule::DenyContract { addresses, .. } => {
                for a in addresses {
                    if hex_to_bytes(a).is_none() {
                        return Err(PolicyError::Misconfiguration(
                            "invalid hex address in contract rule",
                        ));
                    }
                }
            }
            Rule::AllowMethod {
                contract,
                selectors,
                ..
            } => {
                if let Some(c) = contract {
                    if hex_to_bytes(c).is_none() {
                        return Err(PolicyError::Misconfiguration(
                            "invalid hex contract in allow_method rule",
                        ));
                    }
                }
                for sel in selectors {
                    let bytes = hex_to_bytes(sel).ok_or(PolicyError::Misconfiguration(
                        "invalid hex selector in allow_method rule",
                    ))?;
                    if bytes.len() != 4 {
                        return Err(PolicyError::Misconfiguration(
                            "method selector must be exactly 4 bytes",
                        ));
                    }
                }
            }
            Rule::ValueCap { max_value, .. } => {
                parse_u256(max_value).ok_or(PolicyError::Misconfiguration(
                    "invalid decimal U256 in value_cap rule",
                ))?;
            }
            Rule::RateLimit { tokens, .. } => {
                if *tokens == 0 {
                    return Err(PolicyError::Misconfiguration(
                        "rate_limit tokens must be > 0",
                    ));
                }
            }
            Rule::TimeWindow {
                weekday_mask,
                hour_utc_start,
                hour_utc_end,
            } => {
                if *weekday_mask & 0x80 != 0 {
                    return Err(PolicyError::Misconfiguration(
                        "weekday_mask bit 7 is reserved",
                    ));
                }
                if *hour_utc_start > 23 || *hour_utc_end > 24 {
                    return Err(PolicyError::Misconfiguration(
                        "time_window hours out of range",
                    ));
                }
            }
            Rule::RequireQuorum {
                threshold,
                total,
                trigger,
                ..
            } => {
                if *threshold == 0 || *total == 0 || *threshold > *total {
                    return Err(PolicyError::Misconfiguration(
                        "quorum threshold/total invalid",
                    ));
                }
                if let QuorumTrigger::ValueGte { value, .. } = trigger {
                    parse_u256(value).ok_or(PolicyError::Misconfiguration(
                        "invalid decimal U256 in quorum trigger",
                    ))?;
                }
            }
            Rule::VmShape { constraints, .. } => {
                if let Some(v) = &constraints.max_value {
                    parse_u256(v).ok_or(PolicyError::Misconfiguration(
                        "invalid decimal U256 in vm_shape.max_value",
                    ))?;
                }
                if let Some(sels) = &constraints.allowed_method_selectors {
                    for sel in sels {
                        let bytes = hex_to_bytes(sel).ok_or(PolicyError::Misconfiguration(
                            "invalid hex selector in vm_shape rule",
                        ))?;
                        if bytes.len() != 4 {
                            return Err(PolicyError::Misconfiguration(
                                "vm_shape selector must be exactly 4 bytes",
                            ));
                        }
                    }
                }
            }
            Rule::AllowChain { .. } | Rule::DenyChain { .. } => {}
        }
    }
    Ok(())
}

fn parse_u256(s: &str) -> Option<U256> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return None;
    }
    U256::from_dec_str(trimmed).ok()
}

fn requester_key(req: &Requester) -> String {
    StaticAllowDenyPolicy::requester_key(req)
}

/// Build the bucket key for a `RateLimit` rule.
fn rate_limit_key(scope: RateLimitScope, req: &SigningRequest) -> String {
    let r = requester_key(&req.requester);
    match scope {
        RateLimitScope::PerWallet => format!("wallet:{}", req.wallet_id),
        RateLimitScope::PerRequester => format!("req:{r}"),
        RateLimitScope::PerWalletRequester => format!("wr:{}|{r}", req.wallet_id),
    }
}

/// True if `unix_ms` falls inside the UTC window `[start_hour, end_hour)`
/// on a day whose weekday bit is set in `mask`. `end <= start` wraps
/// midnight (e.g. start=22, end=4 → 22:00-23:59 + 00:00-03:59).
fn time_window_contains(
    unix_ms: i64,
    weekday_mask: u8,
    hour_utc_start: u8,
    hour_utc_end: u8,
) -> bool {
    let Ok(odt) = OffsetDateTime::from_unix_timestamp(unix_ms / 1000) else {
        return false;
    };
    // `time::Weekday::number_days_from_monday()` is 0=Mon..6=Sun → matches
    // the documented `weekday_mask` shape.
    let weekday_idx = odt.weekday().number_days_from_monday();
    let day_ok = (weekday_mask >> weekday_idx) & 1 == 1;
    if !day_ok {
        return false;
    }
    let hour = odt.hour();
    if hour_utc_end > hour_utc_start {
        hour >= hour_utc_start && hour < hour_utc_end
    } else {
        // Wraps midnight.
        hour >= hour_utc_start || hour < hour_utc_end
    }
}

fn push(rationale: &mut Vec<RuleHit>, rule_id: &str, effect: RuleEffect, reason: &str) {
    rationale.push(RuleHit {
        rule_id: rule_id.to_string(),
        effect,
        reason: Some(reason.to_string()),
    });
}

#[async_trait]
impl Policy for RuleSetPolicy {
    #[allow(clippy::too_many_lines)]
    async fn evaluate(&self, request: &SigningRequest) -> Result<PolicyDecision, PolicyError> {
        let policy_id = self.rules.policy_id;
        let mut rationale: Vec<RuleHit> = Vec::new();
        let decision_id = DecisionId::new();

        let req_chain = request.payload.chain_id();
        let req_to = match &request.payload {
            SigningPayload::VmTransaction { to, .. } => to.clone(),
            _ => None,
        };
        let req_vm = request.payload.vm();
        let raw_bytes = match &request.payload {
            SigningPayload::VmTransaction { raw, .. } => raw.clone(),
            _ => Vec::new(),
        };

        // Optional decoded view (only valid for VmTransaction payloads).
        let decoded: Option<DecodedTx> = match (&self.decoder, req_vm) {
            (Some(dec), Some(vm)) => dec.decode(vm, &raw_bytes),
            _ => None,
        };

        // -------------------------------------------------------------
        // 1. DenyChain
        // -------------------------------------------------------------
        if let Some(chain) = req_chain {
            for rule in &self.rules.rules {
                if let Rule::DenyChain { chain_ids } = rule {
                    if chain_ids.contains(&chain) {
                        push(
                            &mut rationale,
                            "deny-chain",
                            RuleEffect::Deny,
                            &format!("chain {chain} is on deny list"),
                        );
                        return Ok(PolicyDecision::Deny {
                            decision_id,
                            policy_id,
                            reason: DenyReason::ChainDenied,
                            rationale,
                        });
                    }
                }
            }
        }

        // -------------------------------------------------------------
        // 2. DenyContract
        // -------------------------------------------------------------
        if let (Some(chain), Some(to)) = (req_chain, req_to.as_deref()) {
            for rule in &self.rules.rules {
                if let Rule::DenyContract {
                    chain_id,
                    addresses,
                } = rule
                {
                    if *chain_id == chain && address_in(addresses, to) {
                        push(
                            &mut rationale,
                            "deny-contract",
                            RuleEffect::Deny,
                            "contract address is on deny list",
                        );
                        return Ok(PolicyDecision::Deny {
                            decision_id,
                            policy_id,
                            reason: DenyReason::Other("contract denied".to_string()),
                            rationale,
                        });
                    }
                }
            }
        }

        // -------------------------------------------------------------
        // 3. AllowChain filter
        // -------------------------------------------------------------
        let any_allow_chain = self
            .rules
            .rules
            .iter()
            .any(|r| matches!(r, Rule::AllowChain { .. }));
        if any_allow_chain {
            let chain = req_chain;
            let chain_allowed = chain.is_some_and(|c| {
                self.rules
                    .rules
                    .iter()
                    .any(|r| matches!(r, Rule::AllowChain { chain_ids } if chain_ids.contains(&c)))
            });
            if !chain_allowed {
                push(
                    &mut rationale,
                    "allow-chain-filter",
                    RuleEffect::Deny,
                    "chain not present in any allow_chain rule",
                );
                return Ok(PolicyDecision::Deny {
                    decision_id,
                    policy_id,
                    reason: DenyReason::ChainNotAllowed,
                    rationale,
                });
            }
            push(
                &mut rationale,
                "allow-chain-filter",
                RuleEffect::Allow,
                "chain present in allow_chain rule",
            );
        }

        // -------------------------------------------------------------
        // 4. AllowContract filter (per-chain)
        // -------------------------------------------------------------
        if let Some(chain) = req_chain {
            let any_allow_contract_for_chain =
                self.rules.rules.iter().any(
                    |r| matches!(r, Rule::AllowContract { chain_id, .. } if *chain_id == chain),
                );
            if any_allow_contract_for_chain {
                let allowed = req_to.as_deref().is_some_and(|to| {
                    self.rules.rules.iter().any(|r| match r {
                        Rule::AllowContract {
                            chain_id,
                            addresses,
                        } => *chain_id == chain && address_in(addresses, to),
                        _ => false,
                    })
                });
                if !allowed {
                    push(
                        &mut rationale,
                        "allow-contract-filter",
                        RuleEffect::Deny,
                        "contract not on allow list for chain",
                    );
                    return Ok(PolicyDecision::Deny {
                        decision_id,
                        policy_id,
                        reason: DenyReason::Other("contract not on allow list".to_string()),
                        rationale,
                    });
                }
                push(
                    &mut rationale,
                    "allow-contract-filter",
                    RuleEffect::Allow,
                    "contract on allow list",
                );
            }
        }

        // -------------------------------------------------------------
        // 5. AllowMethod filter (requires decoded selector)
        // -------------------------------------------------------------
        if let Some(chain) = req_chain {
            // Filter rules that apply to this (chain, contract).
            let applicable: Vec<&Rule> = self
                .rules
                .rules
                .iter()
                .filter(|r| match r {
                    Rule::AllowMethod {
                        chain_id, contract, ..
                    } => {
                        *chain_id == chain
                            && match (contract, req_to.as_deref()) {
                                (None, _) => true,
                                (Some(addr), Some(to)) => address_eq(addr, to),
                                (Some(_), None) => false,
                            }
                    }
                    _ => false,
                })
                .collect();

            if !applicable.is_empty() {
                let selector = decoded.as_ref().and_then(|d| d.method_selector);
                let ok = selector.is_some_and(|sel| {
                    applicable.iter().any(|r| {
                        if let Rule::AllowMethod { selectors, .. } = r {
                            selectors.iter().any(|s| {
                                hex_to_bytes(s).is_some_and(|b| b.as_slice() == sel.as_slice())
                            })
                        } else {
                            false
                        }
                    })
                });
                if !ok {
                    push(
                        &mut rationale,
                        "allow-method-filter",
                        RuleEffect::Deny,
                        "method selector not on allow list (or missing decoder)",
                    );
                    return Ok(PolicyDecision::Deny {
                        decision_id,
                        policy_id,
                        reason: DenyReason::Other("method not allowed".to_string()),
                        rationale,
                    });
                }
                push(
                    &mut rationale,
                    "allow-method-filter",
                    RuleEffect::Allow,
                    "method selector on allow list",
                );
            }
        }

        // -------------------------------------------------------------
        // 6. ValueCap
        // -------------------------------------------------------------
        if let Some(chain) = req_chain {
            let req_value = decoded.as_ref().and_then(|d| d.value);
            for rule in &self.rules.rules {
                if let Rule::ValueCap {
                    chain_id,
                    max_value,
                } = rule
                {
                    if *chain_id != chain {
                        continue;
                    }
                    let max = parse_u256(max_value)
                        .ok_or(PolicyError::Misconfiguration("invalid U256 in value_cap"))?;
                    if let Some(v) = req_value {
                        if v > max {
                            push(
                                &mut rationale,
                                "value-cap",
                                RuleEffect::Deny,
                                "transaction value exceeds cap",
                            );
                            return Ok(PolicyDecision::Deny {
                                decision_id,
                                policy_id,
                                reason: DenyReason::Other("value cap exceeded".to_string()),
                                rationale,
                            });
                        }
                    }
                }
            }
        }

        // -------------------------------------------------------------
        // 7. TimeWindow
        // -------------------------------------------------------------
        for rule in &self.rules.rules {
            if let Rule::TimeWindow {
                weekday_mask,
                hour_utc_start,
                hour_utc_end,
            } = rule
            {
                let in_window = time_window_contains(
                    request.received_at_unix_ms,
                    *weekday_mask,
                    *hour_utc_start,
                    *hour_utc_end,
                );
                if !in_window {
                    push(
                        &mut rationale,
                        "time-window",
                        RuleEffect::Deny,
                        "request outside permitted UTC time window",
                    );
                    return Ok(PolicyDecision::Deny {
                        decision_id,
                        policy_id,
                        reason: DenyReason::Other("outside time window".to_string()),
                        rationale,
                    });
                }
            }
        }

        // -------------------------------------------------------------
        // 8. RateLimit
        // -------------------------------------------------------------
        for rule in &self.rules.rules {
            if let Rule::RateLimit {
                tokens,
                refill_per_secs,
                scope,
            } = rule
            {
                let key = rate_limit_key(*scope, request);
                let ok = self
                    .limiter
                    .try_acquire(&key, *tokens, *refill_per_secs)
                    .await;
                if !ok {
                    push(
                        &mut rationale,
                        "rate-limit",
                        RuleEffect::Deny,
                        "token-bucket exhausted",
                    );
                    return Ok(PolicyDecision::Deny {
                        decision_id,
                        policy_id,
                        reason: DenyReason::Other("rate limited".to_string()),
                        rationale,
                    });
                }
            }
        }

        // -------------------------------------------------------------
        // 9. VmShape
        // -------------------------------------------------------------
        if let Some(req_vm) = req_vm {
            for rule in &self.rules.rules {
                if let Rule::VmShape { vm, constraints } = rule {
                    if *vm != req_vm {
                        continue;
                    }
                    // max_value: use decoded value if available, else raw
                    // value is unknown so the constraint is vacuous.
                    if let Some(max_v_str) = &constraints.max_value {
                        let max = parse_u256(max_v_str).ok_or(PolicyError::Misconfiguration(
                            "invalid U256 in vm_shape.max_value",
                        ))?;
                        if let Some(v) = decoded.as_ref().and_then(|d| d.value) {
                            if v > max {
                                push(
                                    &mut rationale,
                                    "vm-shape-max-value",
                                    RuleEffect::Deny,
                                    "vm_shape.max_value exceeded",
                                );
                                return Ok(PolicyDecision::Deny {
                                    decision_id,
                                    policy_id,
                                    reason: DenyReason::Other("vm-shape constraint".to_string()),
                                    rationale,
                                });
                            }
                        }
                    }
                    if let Some(max_gas) = constraints.max_gas {
                        if let Some(g) = decoded.as_ref().and_then(|d| d.gas_limit) {
                            if g > max_gas {
                                push(
                                    &mut rationale,
                                    "vm-shape-max-gas",
                                    RuleEffect::Deny,
                                    "vm_shape.max_gas exceeded",
                                );
                                return Ok(PolicyDecision::Deny {
                                    decision_id,
                                    policy_id,
                                    reason: DenyReason::Other("vm-shape constraint".to_string()),
                                    rationale,
                                });
                            }
                        }
                    }
                    if let Some(allowed_sels) = &constraints.allowed_method_selectors {
                        if let Some(sel) = decoded.as_ref().and_then(|d| d.method_selector) {
                            let ok = allowed_sels.iter().any(|s| {
                                hex_to_bytes(s).is_some_and(|b| b.as_slice() == sel.as_slice())
                            });
                            if !ok {
                                push(
                                    &mut rationale,
                                    "vm-shape-method",
                                    RuleEffect::Deny,
                                    "vm_shape selector not allowed",
                                );
                                return Ok(PolicyDecision::Deny {
                                    decision_id,
                                    policy_id,
                                    reason: DenyReason::Other("vm-shape constraint".to_string()),
                                    rationale,
                                });
                            }
                        }
                    }
                }
            }
        }

        // -------------------------------------------------------------
        // 10. RequireQuorum
        // -------------------------------------------------------------
        for rule in &self.rules.rules {
            if let Rule::RequireQuorum {
                threshold,
                total,
                approver_set,
                trigger,
            } = rule
            {
                let fires = match trigger {
                    QuorumTrigger::Always => true,
                    QuorumTrigger::ValueGte { chain_id, value } => {
                        let thresh = parse_u256(value).ok_or(PolicyError::Misconfiguration(
                            "invalid U256 in quorum value_gte trigger",
                        ))?;
                        match (req_chain, decoded.as_ref().and_then(|d| d.value)) {
                            (Some(c), Some(v)) => c == *chain_id && v >= thresh,
                            _ => false,
                        }
                    }
                    QuorumTrigger::OutsideTimeWindow {
                        weekday_mask,
                        hour_utc_start,
                        hour_utc_end,
                    } => !time_window_contains(
                        request.received_at_unix_ms,
                        *weekday_mask,
                        *hour_utc_start,
                        *hour_utc_end,
                    ),
                };
                if fires {
                    push(
                        &mut rationale,
                        "require-quorum",
                        RuleEffect::RequireQuorum,
                        "quorum trigger matched",
                    );
                    return Ok(PolicyDecision::RequireQuorum {
                        decision_id,
                        policy_id,
                        threshold: *threshold,
                        total: *total,
                        approver_set: *approver_set,
                        rationale,
                    });
                }
            }
        }

        // -------------------------------------------------------------
        // 11. default
        // -------------------------------------------------------------
        match self.rules.default {
            AllowDefault::Allow => {
                push(
                    &mut rationale,
                    "default-allow",
                    RuleEffect::Allow,
                    "no terminating rule matched; default is allow",
                );
                Ok(PolicyDecision::Allow {
                    decision_id,
                    policy_id,
                    rationale,
                })
            }
            AllowDefault::Deny => {
                push(
                    &mut rationale,
                    "default-deny",
                    RuleEffect::Deny,
                    "no terminating rule matched; default is deny",
                );
                Ok(PolicyDecision::Deny {
                    decision_id,
                    policy_id,
                    reason: DenyReason::Other("policy default".to_string()),
                    rationale,
                })
            }
        }
    }
}

/// True if the hex `addr` (config) matches the raw `to` bytes (request).
/// Case-insensitive on the hex form.
fn address_eq(addr_hex: &str, to_bytes: &[u8]) -> bool {
    let Some(canonical) = normalize_hex(addr_hex) else {
        return false;
    };
    let Some(bytes) = hex::decode(canonical).ok() else {
        return false;
    };
    bytes.as_slice() == to_bytes
}

fn address_in(addresses: &[String], to_bytes: &[u8]) -> bool {
    addresses.iter().any(|a| address_eq(a, to_bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rate_limit::ManualClock;
    use crate::request::{Requester, SigningPayload, SigningRequest, VmType};
    use crate::rules::{QuorumTrigger, RateLimitScope, Rule, RuleSet, VmShapeConstraints};
    use crate::vm::{DecodedTx, VmDecoder};
    use crate::AllowDefault;
    use proptest::prelude::*;
    use qfc_wallet_types::{ApprovalId, PolicyId, RequestId, WalletId};

    fn empty_rs() -> RuleSet {
        RuleSet {
            version: 1,
            policy_id: PolicyId::new(),
            rules: vec![],
            default: AllowDefault::Allow,
        }
    }

    fn req(chain_id: u64) -> SigningRequest {
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
                raw: vec![0u8; 4],
            },
            hd_path: None,
            received_at_unix_ms: 0,
        }
    }

    fn req_with_to(chain_id: u64, to: Vec<u8>) -> SigningRequest {
        let mut r = req(chain_id);
        if let SigningPayload::VmTransaction { to: t, .. } = &mut r.payload {
            *t = Some(to);
        }
        r
    }

    /// Stub decoder returning a single canned shape.
    struct CannedDecoder(DecodedTx);
    impl VmDecoder for CannedDecoder {
        fn decode(&self, _vm: VmType, _raw: &[u8]) -> Option<DecodedTx> {
            Some(self.0.clone())
        }
    }

    fn canned(d: DecodedTx) -> Arc<dyn VmDecoder> {
        Arc::new(CannedDecoder(d))
    }

    // --------- validate / loader ---------

    #[tokio::test]
    async fn rejects_unsupported_version() {
        let rs = RuleSet {
            version: 2,
            ..empty_rs()
        };
        assert!(RuleSetPolicy::new(rs).is_err());
    }

    #[tokio::test]
    async fn from_json_round_trips() {
        let policy_id = PolicyId::new();
        let rs = RuleSet {
            version: 1,
            policy_id,
            rules: vec![Rule::DenyChain {
                chain_ids: vec![9001],
            }],
            default: AllowDefault::Allow,
        };
        let bytes = serde_json::to_vec(&rs).unwrap();
        let p = RuleSetPolicy::from_json(&bytes).unwrap();
        assert_eq!(p.rules().policy_id, policy_id);
    }

    #[tokio::test]
    async fn from_json_rejects_garbage() {
        assert!(RuleSetPolicy::from_json(b"not json").is_err());
    }

    #[tokio::test]
    async fn treasury_example_loads() {
        let bytes = include_bytes!("../../../examples/policies/treasury.json");
        let p = RuleSetPolicy::from_json(bytes).expect("treasury.json should load");
        assert_eq!(p.rules().version, 1);
        // Spot-check: 5 rules in the canonical example.
        assert_eq!(p.rules().rules.len(), 5);
    }

    #[tokio::test]
    async fn rejects_bad_hex_in_contract_rule() {
        let rs = RuleSet {
            rules: vec![Rule::AllowContract {
                chain_id: 1,
                addresses: vec!["nope".to_string()],
            }],
            ..empty_rs()
        };
        assert!(RuleSetPolicy::new(rs).is_err());
    }

    #[tokio::test]
    async fn rejects_three_byte_selector() {
        let rs = RuleSet {
            rules: vec![Rule::AllowMethod {
                chain_id: 1,
                contract: None,
                selectors: vec!["0xaabbcc".to_string()],
            }],
            ..empty_rs()
        };
        assert!(RuleSetPolicy::new(rs).is_err());
    }

    #[tokio::test]
    async fn rejects_zero_token_rate_limit() {
        let rs = RuleSet {
            rules: vec![Rule::RateLimit {
                tokens: 0,
                refill_per_secs: 1,
                scope: RateLimitScope::PerWallet,
            }],
            ..empty_rs()
        };
        assert!(RuleSetPolicy::new(rs).is_err());
    }

    #[tokio::test]
    async fn rejects_bad_quorum_threshold() {
        let rs = RuleSet {
            rules: vec![Rule::RequireQuorum {
                threshold: 6,
                total: 5,
                approver_set: ApprovalId::new(),
                trigger: QuorumTrigger::Always,
            }],
            ..empty_rs()
        };
        assert!(RuleSetPolicy::new(rs).is_err());
    }

    #[tokio::test]
    async fn rejects_reserved_weekday_bit() {
        let rs = RuleSet {
            rules: vec![Rule::TimeWindow {
                weekday_mask: 0x80,
                hour_utc_start: 9,
                hour_utc_end: 17,
            }],
            ..empty_rs()
        };
        assert!(RuleSetPolicy::new(rs).is_err());
    }

    // --------- precedence: deny dominates ---------

    #[tokio::test]
    async fn deny_chain_beats_allow_chain() {
        let rs = RuleSet {
            rules: vec![
                Rule::AllowChain { chain_ids: vec![1] },
                Rule::DenyChain { chain_ids: vec![1] },
            ],
            ..empty_rs()
        };
        let p = RuleSetPolicy::new(rs).unwrap();
        let d = p.evaluate(&req(1)).await.unwrap();
        match d {
            PolicyDecision::Deny { reason, .. } => assert_eq!(reason, DenyReason::ChainDenied),
            other => panic!("expected ChainDenied, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn allow_chain_filter_blocks_other_chains() {
        let rs = RuleSet {
            rules: vec![Rule::AllowChain {
                chain_ids: vec![1, 2],
            }],
            default: AllowDefault::Allow,
            ..empty_rs()
        };
        let p = RuleSetPolicy::new(rs).unwrap();
        assert!(p.evaluate(&req(1)).await.unwrap().is_immediate_allow());
        let d = p.evaluate(&req(99)).await.unwrap();
        match d {
            PolicyDecision::Deny { reason, .. } => assert_eq!(reason, DenyReason::ChainNotAllowed),
            other => panic!("expected ChainNotAllowed, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn deny_contract_fires() {
        let addr = vec![0xab; 20];
        let rs = RuleSet {
            rules: vec![Rule::DenyContract {
                chain_id: 1,
                addresses: vec![hex::encode(&addr)],
            }],
            ..empty_rs()
        };
        let p = RuleSetPolicy::new(rs).unwrap();
        let d = p.evaluate(&req_with_to(1, addr)).await.unwrap();
        assert!(d.is_deny());
    }

    #[tokio::test]
    async fn allow_contract_filter_blocks_other_addrs() {
        let good = vec![0xaa; 20];
        let bad = vec![0xbb; 20];
        let rs = RuleSet {
            rules: vec![Rule::AllowContract {
                chain_id: 1,
                addresses: vec![hex::encode(&good)],
            }],
            default: AllowDefault::Allow,
            ..empty_rs()
        };
        let p = RuleSetPolicy::new(rs).unwrap();
        assert!(p
            .evaluate(&req_with_to(1, good))
            .await
            .unwrap()
            .is_immediate_allow());
        assert!(p.evaluate(&req_with_to(1, bad)).await.unwrap().is_deny());
    }

    #[tokio::test]
    async fn allow_contract_filter_other_chain_unaffected() {
        let good = vec![0xaa; 20];
        let other = vec![0xcc; 20];
        let rs = RuleSet {
            rules: vec![Rule::AllowContract {
                chain_id: 1,
                addresses: vec![hex::encode(&good)],
            }],
            default: AllowDefault::Allow,
            ..empty_rs()
        };
        let p = RuleSetPolicy::new(rs).unwrap();
        // Chain 2 has no allow_contract rule → unfiltered → allow.
        assert!(p
            .evaluate(&req_with_to(2, other))
            .await
            .unwrap()
            .is_immediate_allow());
    }

    // --------- allow_method requires decoder ---------

    #[tokio::test]
    async fn allow_method_without_decoder_denies() {
        let rs = RuleSet {
            rules: vec![Rule::AllowMethod {
                chain_id: 1,
                contract: None,
                selectors: vec!["0xa9059cbb".to_string()], // ERC20.transfer
            }],
            ..empty_rs()
        };
        let p = RuleSetPolicy::new(rs).unwrap();
        let d = p.evaluate(&req(1)).await.unwrap();
        assert!(d.is_deny());
    }

    #[tokio::test]
    async fn allow_method_with_decoder_allows_matching() {
        let dec = canned(DecodedTx {
            chain_id: 1,
            method_selector: Some([0xa9, 0x05, 0x9c, 0xbb]),
            ..DecodedTx::minimal(1)
        });
        let rs = RuleSet {
            rules: vec![Rule::AllowMethod {
                chain_id: 1,
                contract: None,
                selectors: vec!["0xa9059cbb".to_string()],
            }],
            default: AllowDefault::Allow,
            ..empty_rs()
        };
        let p = RuleSetPolicy::with_components(rs, TokenBucketLimiter::new(), Some(dec)).unwrap();
        assert!(p.evaluate(&req(1)).await.unwrap().is_immediate_allow());
    }

    #[tokio::test]
    async fn allow_method_with_decoder_blocks_wrong_selector() {
        let dec = canned(DecodedTx {
            chain_id: 1,
            method_selector: Some([0xde, 0xad, 0xbe, 0xef]),
            ..DecodedTx::minimal(1)
        });
        let rs = RuleSet {
            rules: vec![Rule::AllowMethod {
                chain_id: 1,
                contract: None,
                selectors: vec!["0xa9059cbb".to_string()],
            }],
            ..empty_rs()
        };
        let p = RuleSetPolicy::with_components(rs, TokenBucketLimiter::new(), Some(dec)).unwrap();
        assert!(p.evaluate(&req(1)).await.unwrap().is_deny());
    }

    // --------- value cap ---------

    #[tokio::test]
    async fn value_cap_with_decoded_value() {
        let big = U256::from_dec_str("2000000000000000000000").unwrap();
        let dec = canned(DecodedTx {
            chain_id: 1,
            value: Some(big),
            ..DecodedTx::minimal(1)
        });
        let rs = RuleSet {
            rules: vec![Rule::ValueCap {
                chain_id: 1,
                max_value: "1000000000000000000000".to_string(),
            }],
            default: AllowDefault::Allow,
            ..empty_rs()
        };
        let p = RuleSetPolicy::with_components(rs, TokenBucketLimiter::new(), Some(dec)).unwrap();
        assert!(p.evaluate(&req(1)).await.unwrap().is_deny());
    }

    #[tokio::test]
    async fn value_cap_under_limit_allows() {
        let small = U256::from_dec_str("500000000000000000000").unwrap();
        let dec = canned(DecodedTx {
            chain_id: 1,
            value: Some(small),
            ..DecodedTx::minimal(1)
        });
        let rs = RuleSet {
            rules: vec![Rule::ValueCap {
                chain_id: 1,
                max_value: "1000000000000000000000".to_string(),
            }],
            default: AllowDefault::Allow,
            ..empty_rs()
        };
        let p = RuleSetPolicy::with_components(rs, TokenBucketLimiter::new(), Some(dec)).unwrap();
        assert!(p.evaluate(&req(1)).await.unwrap().is_immediate_allow());
    }

    #[tokio::test]
    async fn value_cap_without_decoder_is_vacuous() {
        // No decoder → no decoded value → cap can't fire.
        let rs = RuleSet {
            rules: vec![Rule::ValueCap {
                chain_id: 1,
                max_value: "0".to_string(),
            }],
            default: AllowDefault::Allow,
            ..empty_rs()
        };
        let p = RuleSetPolicy::new(rs).unwrap();
        assert!(p.evaluate(&req(1)).await.unwrap().is_immediate_allow());
    }

    // --------- time window ---------

    #[tokio::test]
    async fn time_window_in_window_allows() {
        // 2026-05-19 12:00:00 UTC → Tuesday (bit 1).
        let mut r = req(1);
        r.received_at_unix_ms = 1_779_192_000_000;
        let rs = RuleSet {
            rules: vec![Rule::TimeWindow {
                weekday_mask: 0b0111_1111, // every day
                hour_utc_start: 0,
                hour_utc_end: 24,
            }],
            default: AllowDefault::Allow,
            ..empty_rs()
        };
        let p = RuleSetPolicy::new(rs).unwrap();
        assert!(p.evaluate(&r).await.unwrap().is_immediate_allow());
    }

    #[tokio::test]
    async fn time_window_outside_denies() {
        let mut r = req(1);
        // Tuesday, but rule requires Saturday/Sunday only.
        r.received_at_unix_ms = 1_779_192_000_000; // Tue
        let rs = RuleSet {
            rules: vec![Rule::TimeWindow {
                weekday_mask: 0b0110_0000, // Sat (bit 5) + Sun (bit 6)
                hour_utc_start: 0,
                hour_utc_end: 24,
            }],
            ..empty_rs()
        };
        let p = RuleSetPolicy::new(rs).unwrap();
        assert!(p.evaluate(&r).await.unwrap().is_deny());
    }

    #[tokio::test]
    async fn time_window_wrap_midnight() {
        // 23:30 UTC on a Tuesday.
        let mut r = req(1);
        r.received_at_unix_ms = 1_779_233_400_000;
        let rs = RuleSet {
            rules: vec![Rule::TimeWindow {
                weekday_mask: 0b0111_1111,
                hour_utc_start: 22,
                hour_utc_end: 4,
            }],
            default: AllowDefault::Allow,
            ..empty_rs()
        };
        let p = RuleSetPolicy::new(rs).unwrap();
        assert!(p.evaluate(&r).await.unwrap().is_immediate_allow());
    }

    // --------- rate limit ---------

    #[tokio::test]
    async fn rate_limit_exhausts() {
        let clock = Arc::new(ManualClock::new(0));
        let limiter = TokenBucketLimiter::with_clock(clock.clone());
        let rs = RuleSet {
            rules: vec![Rule::RateLimit {
                tokens: 2,
                refill_per_secs: 60,
                scope: RateLimitScope::PerWalletRequester,
            }],
            default: AllowDefault::Allow,
            ..empty_rs()
        };
        let p = RuleSetPolicy::with_components(rs, limiter, None).unwrap();
        let r = req(1);
        assert!(p.evaluate(&r).await.unwrap().is_immediate_allow());
        assert!(p.evaluate(&r).await.unwrap().is_immediate_allow());
        let third = p.evaluate(&r).await.unwrap();
        assert!(third.is_deny());
    }

    #[tokio::test]
    async fn rate_limit_refills_with_time() {
        let clock = Arc::new(ManualClock::new(0));
        let limiter = TokenBucketLimiter::with_clock(clock.clone());
        let rs = RuleSet {
            rules: vec![Rule::RateLimit {
                tokens: 1,
                refill_per_secs: 60,
                scope: RateLimitScope::PerWallet,
            }],
            default: AllowDefault::Allow,
            ..empty_rs()
        };
        let p = RuleSetPolicy::with_components(rs, limiter, None).unwrap();
        let r = req(1);
        assert!(p.evaluate(&r).await.unwrap().is_immediate_allow());
        assert!(p.evaluate(&r).await.unwrap().is_deny());
        clock.advance_ms(60_000);
        assert!(p.evaluate(&r).await.unwrap().is_immediate_allow());
    }

    #[tokio::test]
    async fn rate_limit_per_requester_distinct_buckets() {
        let clock = Arc::new(ManualClock::new(0));
        let limiter = TokenBucketLimiter::with_clock(clock);
        let rs = RuleSet {
            rules: vec![Rule::RateLimit {
                tokens: 1,
                refill_per_secs: 60,
                scope: RateLimitScope::PerRequester,
            }],
            default: AllowDefault::Allow,
            ..empty_rs()
        };
        let p = RuleSetPolicy::with_components(rs, limiter, None).unwrap();
        let r1 = req(1);
        let mut r2 = req(1);
        r2.requester = Requester::ApiKey {
            key_id: "bob".to_string(),
        };
        assert!(p.evaluate(&r1).await.unwrap().is_immediate_allow());
        // Same requester depleted...
        assert!(p.evaluate(&r1).await.unwrap().is_deny());
        // ...but bob's bucket is fresh.
        assert!(p.evaluate(&r2).await.unwrap().is_immediate_allow());
    }

    // --------- vm shape ---------

    #[tokio::test]
    async fn vm_shape_gas_cap() {
        let dec = canned(DecodedTx {
            chain_id: 1,
            gas_limit: Some(500_000),
            ..DecodedTx::minimal(1)
        });
        let rs = RuleSet {
            rules: vec![Rule::VmShape {
                vm: VmType::Evm,
                constraints: VmShapeConstraints {
                    max_gas: Some(100_000),
                    ..VmShapeConstraints::default()
                },
            }],
            default: AllowDefault::Allow,
            ..empty_rs()
        };
        let p = RuleSetPolicy::with_components(rs, TokenBucketLimiter::new(), Some(dec)).unwrap();
        assert!(p.evaluate(&req(1)).await.unwrap().is_deny());
    }

    #[tokio::test]
    async fn vm_shape_method_selector() {
        let dec = canned(DecodedTx {
            chain_id: 1,
            method_selector: Some([0x01, 0x02, 0x03, 0x04]),
            ..DecodedTx::minimal(1)
        });
        let rs = RuleSet {
            rules: vec![Rule::VmShape {
                vm: VmType::Evm,
                constraints: VmShapeConstraints {
                    allowed_method_selectors: Some(vec!["0xa9059cbb".to_string()]),
                    ..VmShapeConstraints::default()
                },
            }],
            ..empty_rs()
        };
        let p = RuleSetPolicy::with_components(rs, TokenBucketLimiter::new(), Some(dec)).unwrap();
        assert!(p.evaluate(&req(1)).await.unwrap().is_deny());
    }

    #[tokio::test]
    async fn vm_shape_different_vm_skipped() {
        // Constraint says QVM but request is EVM → constraint doesn't apply.
        let rs = RuleSet {
            rules: vec![Rule::VmShape {
                vm: VmType::Qvm,
                constraints: VmShapeConstraints {
                    max_gas: Some(0),
                    ..VmShapeConstraints::default()
                },
            }],
            default: AllowDefault::Allow,
            ..empty_rs()
        };
        let p = RuleSetPolicy::new(rs).unwrap();
        assert!(p.evaluate(&req(1)).await.unwrap().is_immediate_allow());
    }

    // --------- quorum triggers ---------

    #[tokio::test]
    async fn quorum_always() {
        let approver = ApprovalId::new();
        let rs = RuleSet {
            rules: vec![Rule::RequireQuorum {
                threshold: 2,
                total: 3,
                approver_set: approver,
                trigger: QuorumTrigger::Always,
            }],
            ..empty_rs()
        };
        let p = RuleSetPolicy::new(rs).unwrap();
        let d = p.evaluate(&req(1)).await.unwrap();
        match d {
            PolicyDecision::RequireQuorum {
                threshold,
                total,
                approver_set,
                ..
            } => {
                assert_eq!(threshold, 2);
                assert_eq!(total, 3);
                assert_eq!(approver_set, approver);
            }
            other => panic!("expected RequireQuorum, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn quorum_value_gte_fires() {
        let dec = canned(DecodedTx {
            chain_id: 1,
            value: Some(U256::from_dec_str("2000").unwrap()),
            ..DecodedTx::minimal(1)
        });
        let rs = RuleSet {
            rules: vec![Rule::RequireQuorum {
                threshold: 2,
                total: 3,
                approver_set: ApprovalId::new(),
                trigger: QuorumTrigger::ValueGte {
                    chain_id: 1,
                    value: "1000".to_string(),
                },
            }],
            default: AllowDefault::Allow,
            ..empty_rs()
        };
        let p = RuleSetPolicy::with_components(rs, TokenBucketLimiter::new(), Some(dec)).unwrap();
        assert!(p.evaluate(&req(1)).await.unwrap().requires_quorum());
    }

    #[tokio::test]
    async fn quorum_value_gte_does_not_fire_below() {
        let dec = canned(DecodedTx {
            chain_id: 1,
            value: Some(U256::from_dec_str("500").unwrap()),
            ..DecodedTx::minimal(1)
        });
        let rs = RuleSet {
            rules: vec![Rule::RequireQuorum {
                threshold: 2,
                total: 3,
                approver_set: ApprovalId::new(),
                trigger: QuorumTrigger::ValueGte {
                    chain_id: 1,
                    value: "1000".to_string(),
                },
            }],
            default: AllowDefault::Allow,
            ..empty_rs()
        };
        let p = RuleSetPolicy::with_components(rs, TokenBucketLimiter::new(), Some(dec)).unwrap();
        assert!(p.evaluate(&req(1)).await.unwrap().is_immediate_allow());
    }

    #[tokio::test]
    async fn quorum_outside_time_window_fires() {
        let mut r = req(1);
        // 2026-05-19 12:00:00 UTC — Tuesday — but window says weekend only,
        // so the outside-window trigger fires and quorum is required.
        r.received_at_unix_ms = 1_779_192_000_000;
        let rs = RuleSet {
            rules: vec![Rule::RequireQuorum {
                threshold: 2,
                total: 3,
                approver_set: ApprovalId::new(),
                trigger: QuorumTrigger::OutsideTimeWindow {
                    weekday_mask: 0b0110_0000,
                    hour_utc_start: 0,
                    hour_utc_end: 24,
                },
            }],
            default: AllowDefault::Allow,
            ..empty_rs()
        };
        let p = RuleSetPolicy::new(rs).unwrap();
        assert!(p.evaluate(&r).await.unwrap().requires_quorum());
    }

    // --------- default ---------

    #[tokio::test]
    async fn default_deny() {
        let rs = RuleSet {
            default: AllowDefault::Deny,
            ..empty_rs()
        };
        let p = RuleSetPolicy::new(rs).unwrap();
        assert!(p.evaluate(&req(1)).await.unwrap().is_deny());
    }

    #[tokio::test]
    async fn default_allow() {
        let rs = empty_rs();
        let p = RuleSetPolicy::new(rs).unwrap();
        assert!(p.evaluate(&req(1)).await.unwrap().is_immediate_allow());
    }

    #[tokio::test]
    async fn rationale_records_each_step() {
        let rs = RuleSet {
            rules: vec![Rule::AllowChain { chain_ids: vec![1] }],
            default: AllowDefault::Allow,
            ..empty_rs()
        };
        let p = RuleSetPolicy::new(rs).unwrap();
        let d = p.evaluate(&req(1)).await.unwrap();
        match d {
            PolicyDecision::Allow { rationale, .. } => {
                assert!(rationale.iter().any(|h| h.rule_id == "allow-chain-filter"));
                assert!(rationale.iter().any(|h| h.rule_id == "default-allow"));
            }
            other => panic!("expected Allow, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn precedence_value_cap_before_time_window() {
        // ValueCap (#6) fires before TimeWindow (#7) — so a request that
        // exceeds the cap AND is outside the window should report the
        // value-cap reason, not the time-window one.
        let big = U256::from_dec_str("2000").unwrap();
        let dec = canned(DecodedTx {
            chain_id: 1,
            value: Some(big),
            ..DecodedTx::minimal(1)
        });
        let mut r = req(1);
        r.received_at_unix_ms = 0; // 1970-01-01 Thursday
        let rs = RuleSet {
            rules: vec![
                Rule::ValueCap {
                    chain_id: 1,
                    max_value: "1000".to_string(),
                },
                Rule::TimeWindow {
                    weekday_mask: 0b0000_0001, // Monday only
                    hour_utc_start: 0,
                    hour_utc_end: 24,
                },
            ],
            ..empty_rs()
        };
        let p = RuleSetPolicy::with_components(rs, TokenBucketLimiter::new(), Some(dec)).unwrap();
        let d = p.evaluate(&r).await.unwrap();
        match d {
            PolicyDecision::Deny { reason, .. } => {
                assert_eq!(reason, DenyReason::Other("value cap exceeded".to_string()));
            }
            other => panic!("expected Deny(value cap exceeded), got {other:?}"),
        }
    }

    #[tokio::test]
    async fn precedence_rate_limit_before_quorum() {
        // RateLimit (#8) fires before RequireQuorum (#10).
        let clock = Arc::new(ManualClock::new(0));
        let limiter = TokenBucketLimiter::with_clock(clock);
        let rs = RuleSet {
            rules: vec![
                Rule::RateLimit {
                    tokens: 1,
                    refill_per_secs: 60,
                    scope: RateLimitScope::PerWallet,
                },
                Rule::RequireQuorum {
                    threshold: 1,
                    total: 1,
                    approver_set: ApprovalId::new(),
                    trigger: QuorumTrigger::Always,
                },
            ],
            ..empty_rs()
        };
        let p = RuleSetPolicy::with_components(rs, limiter, None).unwrap();
        let r = req(1);
        // First call: token available, quorum fires.
        assert!(p.evaluate(&r).await.unwrap().requires_quorum());
        // Second call: token exhausted, rate-limit deny wins over quorum.
        let d = p.evaluate(&r).await.unwrap();
        match d {
            PolicyDecision::Deny { reason, .. } => {
                assert_eq!(reason, DenyReason::Other("rate limited".to_string()));
            }
            other => panic!("expected rate-limited Deny, got {other:?}"),
        }
    }

    // --------- proptests ---------

    proptest! {
        // Allow + Deny chain combo: deny always wins.
        #[test]
        fn pt_deny_dominates_allow(chain_id in 1u64..1000) {
            let rt = tokio::runtime::Runtime::new().unwrap();
            let rs = RuleSet {
                rules: vec![
                    Rule::AllowChain { chain_ids: vec![chain_id] },
                    Rule::DenyChain { chain_ids: vec![chain_id] },
                ],
                ..empty_rs()
            };
            let p = RuleSetPolicy::new(rs).unwrap();
            let d = rt.block_on(p.evaluate(&req(chain_id))).unwrap();
            prop_assert!(d.is_deny());
        }

        // TimeWindow with mask=all-days, start=0, end=24 must always
        // accept any timestamp.
        #[test]
        fn pt_time_window_full_day_always_in(ts in 0i64..(60i64 * 60 * 24 * 365 * 100 * 1000)) {
            let rt = tokio::runtime::Runtime::new().unwrap();
            let mut r = req(1);
            r.received_at_unix_ms = ts;
            let rs = RuleSet {
                rules: vec![Rule::TimeWindow {
                    weekday_mask: 0b0111_1111,
                    hour_utc_start: 0,
                    hour_utc_end: 24,
                }],
                default: AllowDefault::Allow,
                ..empty_rs()
            };
            let p = RuleSetPolicy::new(rs).unwrap();
            prop_assert!(rt.block_on(p.evaluate(&r)).unwrap().is_immediate_allow());
        }

        // TimeWindow with empty mask must always deny.
        #[test]
        fn pt_time_window_empty_mask_always_out(ts in 0i64..(60i64 * 60 * 24 * 365 * 100 * 1000)) {
            let rt = tokio::runtime::Runtime::new().unwrap();
            let mut r = req(1);
            r.received_at_unix_ms = ts;
            let rs = RuleSet {
                rules: vec![Rule::TimeWindow {
                    weekday_mask: 0,
                    hour_utc_start: 0,
                    hour_utc_end: 24,
                }],
                ..empty_rs()
            };
            let p = RuleSetPolicy::new(rs).unwrap();
            prop_assert!(rt.block_on(p.evaluate(&r)).unwrap().is_deny());
        }

        // ValueCap with realistic U256 values:
        //   value > cap → deny;
        //   value <= cap → allow.
        #[test]
        fn pt_value_cap_consistent(
            cap in 0u128..u128::MAX,
            v in 0u128..u128::MAX,
        ) {
            let rt = tokio::runtime::Runtime::new().unwrap();
            let dec = canned(DecodedTx {
                chain_id: 1,
                value: Some(U256::from(v)),
                ..DecodedTx::minimal(1)
            });
            let rs = RuleSet {
                rules: vec![Rule::ValueCap {
                    chain_id: 1,
                    max_value: cap.to_string(),
                }],
                default: AllowDefault::Allow,
                ..empty_rs()
            };
            let p = RuleSetPolicy::with_components(rs, TokenBucketLimiter::new(), Some(dec))
                .unwrap();
            let d = rt.block_on(p.evaluate(&req(1))).unwrap();
            if v > cap {
                prop_assert!(d.is_deny());
            } else {
                prop_assert!(d.is_immediate_allow());
            }
        }

        // RequireQuorum + ValueGte: fires when value >= threshold,
        // doesn't fire when value < threshold.
        #[test]
        fn pt_quorum_value_gte(
            thresh in 1u128..u128::MAX,
            v in 0u128..u128::MAX,
        ) {
            let rt = tokio::runtime::Runtime::new().unwrap();
            let dec = canned(DecodedTx {
                chain_id: 1,
                value: Some(U256::from(v)),
                ..DecodedTx::minimal(1)
            });
            let rs = RuleSet {
                rules: vec![Rule::RequireQuorum {
                    threshold: 2,
                    total: 3,
                    approver_set: ApprovalId::new(),
                    trigger: QuorumTrigger::ValueGte {
                        chain_id: 1,
                        value: thresh.to_string(),
                    },
                }],
                default: AllowDefault::Allow,
                ..empty_rs()
            };
            let p = RuleSetPolicy::with_components(rs, TokenBucketLimiter::new(), Some(dec))
                .unwrap();
            let d = rt.block_on(p.evaluate(&req(1))).unwrap();
            if v >= thresh {
                prop_assert!(d.requires_quorum());
            } else {
                prop_assert!(d.is_immediate_allow());
            }
        }

        // RateLimit: after N immediately-back-to-back calls (clock
        // frozen), call N+1 must deny.
        #[test]
        fn pt_rate_limit_exhausts(tokens in 1u32..16u32) {
            let rt = tokio::runtime::Runtime::new().unwrap();
            let clock = Arc::new(ManualClock::new(0));
            let limiter = TokenBucketLimiter::with_clock(clock);
            let rs = RuleSet {
                rules: vec![Rule::RateLimit {
                    tokens,
                    refill_per_secs: 60,
                    scope: RateLimitScope::PerWalletRequester,
                }],
                default: AllowDefault::Allow,
                ..empty_rs()
            };
            let p = RuleSetPolicy::with_components(rs, limiter, None).unwrap();
            let r = req(1);
            for _ in 0..tokens {
                prop_assert!(rt.block_on(p.evaluate(&r)).unwrap().is_immediate_allow());
            }
            prop_assert!(rt.block_on(p.evaluate(&r)).unwrap().is_deny());
        }
    }
}
