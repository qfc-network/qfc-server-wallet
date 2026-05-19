//! The full policy DSL rule schema (M2 P3).
//!
//! Loaded from JSON via `serde_json`. The schema is versioned (`version: 1`
//! for now) — future breaking changes bump the version and the loader
//! refuses unknown versions rather than silently mis-parsing.
//!
//! Schema is described in RFC §2.4. Wire shape is intentionally
//! tag-discriminated (`{"kind": "deny_chain", ...}`) so an unknown rule
//! kind is a parse error rather than a silently-skipped allow-by-default.

use qfc_wallet_types::{ApprovalId, PolicyId};
use serde::{Deserialize, Serialize};

use crate::request::VmType;
use crate::static_policy::AllowDefault;

/// Top-level policy document. `version == 1` for M2.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleSet {
    /// Schema version. Loaders MUST reject anything other than `1`.
    pub version: u32,
    /// Stable policy identifier (carried through every decision).
    pub policy_id: PolicyId,
    /// Ordered list of rules. Evaluation order is fixed (see
    /// `rule_set_policy.rs`), not the order in this vector.
    pub rules: Vec<Rule>,
    /// Fallback outcome when no terminating rule fires.
    pub default: AllowDefault,
}

/// A single declarative rule.
///
/// The set of rule kinds is closed (no extension points). Each rule has at
/// most one structural meaning; combinations are interpreted by the
/// evaluator with fixed precedence per RFC §2.4 + decision D14.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum Rule {
    /// Allow only requests targeting these chains. Multiple `AllowChain`
    /// rules are OR-ed.
    AllowChain {
        /// Chain ids that are permitted.
        chain_ids: Vec<u64>,
    },
    /// Always deny these chains.
    DenyChain {
        /// Chain ids that are forbidden.
        chain_ids: Vec<u64>,
    },
    /// Allow only these contract addresses on the given chain. Hex strings,
    /// case-insensitive, optional `0x` prefix. Mis-encoded addresses fail
    /// to parse at load time.
    AllowContract {
        /// Chain id this rule applies to.
        chain_id: u64,
        /// Allowed contract addresses (hex strings, optional `0x` prefix).
        addresses: Vec<String>,
    },
    /// Always deny these contract addresses on the given chain.
    DenyContract {
        /// Chain id this rule applies to.
        chain_id: u64,
        /// Denied contract addresses (hex strings, optional `0x` prefix).
        addresses: Vec<String>,
    },
    /// Allow only these 4-byte method selectors. Scoped to a chain, and
    /// optionally to a contract. Methods are matched on the decoded
    /// selector exposed by the configured `VmDecoder`; without a decoder,
    /// `AllowMethod` is a no-op.
    AllowMethod {
        /// Chain id this rule applies to.
        chain_id: u64,
        /// Optional contract scope. `None` = applies to every contract on
        /// the chain.
        contract: Option<String>,
        /// 4-byte selectors (hex, optional `0x` prefix; case-insensitive).
        selectors: Vec<String>,
    },
    /// Maximum transferred value per transaction on a chain. Decimal U256
    /// string so values larger than `u128` are representable.
    ValueCap {
        /// Chain id this cap applies to.
        chain_id: u64,
        /// Maximum value, decimal U256 string. Values greater than this
        /// are denied.
        max_value: String,
    },
    /// Sign only during a UTC weekday/hour window. All times are UTC —
    /// DST is irrelevant by construction.
    TimeWindow {
        /// Bit 0 = Monday … bit 6 = Sunday. Bit 7 is reserved (must be 0).
        weekday_mask: u8,
        /// Start of allowed window, inclusive, UTC hour `[0..=23]`.
        hour_utc_start: u8,
        /// End of allowed window, exclusive, UTC hour `[0..=24]`.
        /// `end <= start` wraps around midnight.
        hour_utc_end: u8,
    },
    /// Token-bucket rate limit.
    RateLimit {
        /// Bucket capacity (max burst).
        tokens: u32,
        /// Number of seconds it takes to refill one token. Equivalent
        /// units: `1 / refill_per_secs` tokens per second.
        refill_per_secs: u32,
        /// What identifier scope the bucket is keyed on.
        scope: RateLimitScope,
    },
    /// Require quorum approval when the trigger fires.
    RequireQuorum {
        /// Minimum approvals required.
        threshold: u8,
        /// Total approvers in the set.
        total: u8,
        /// Identifier of the approver set to ask.
        approver_set: ApprovalId,
        /// Condition that activates the quorum requirement.
        trigger: QuorumTrigger,
    },
    /// Per-VM decoded-shape constraints. EVM decoding lands in M2 P4; QVM
    /// and WASM are deferred (RFC §9.6). Without a decoder the evaluator
    /// applies only the constraints visible on the raw `SigningPayload`
    /// (the `max_value` field against the payload's `value`).
    VmShape {
        /// VM this shape applies to.
        vm: VmType,
        /// Constraints to apply when the VM matches.
        constraints: VmShapeConstraints,
    },
}

/// Identifier scope for a token-bucket rate limit.
///
/// `PerWalletRequester` is the RFC-decision-10 default and is the most
/// useful in practice (an attacker who steals a single requester
/// credential can't exhaust the wallet's bucket for honest callers).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RateLimitScope {
    /// One bucket per wallet (shared across all requesters).
    PerWallet,
    /// One bucket per requester (shared across all wallets the requester
    /// can act on).
    PerRequester,
    /// One bucket per `(wallet, requester)` tuple — the RFC §2.4 + D10
    /// recommendation.
    PerWalletRequester,
}

/// Condition that activates a `RequireQuorum` rule.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum QuorumTrigger {
    /// Always require quorum when this rule applies.
    Always,
    /// Require quorum when the request value (on `chain_id`) is `>=
    /// value` (decimal U256 string).
    ValueGte {
        /// Chain id this trigger applies to.
        chain_id: u64,
        /// Threshold value, decimal U256 string.
        value: String,
    },
    /// Require quorum for requests received *outside* a UTC window.
    /// Useful for "outside business hours, force human in the loop."
    OutsideTimeWindow {
        /// Bit 0 = Monday … bit 6 = Sunday.
        weekday_mask: u8,
        /// Start of normal window, inclusive UTC hour.
        hour_utc_start: u8,
        /// End of normal window, exclusive UTC hour.
        hour_utc_end: u8,
    },
}

/// Decoded-shape constraints, applied per VM. None of the optional fields
/// being `None` is a permissive no-op; setting them is restrictive.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct VmShapeConstraints {
    /// Hard upper bound on gas-limit (EVM) / equivalent (QVM compute
    /// units). Requires a decoder to be enforceable.
    pub max_gas: Option<u64>,
    /// Permitted 4-byte method selectors (hex, optional `0x` prefix).
    /// Requires a decoder.
    pub allowed_method_selectors: Option<Vec<String>>,
    /// Maximum value (decimal U256 string). Enforced against the raw
    /// payload's value when no decoder is present.
    pub max_value: Option<String>,
}

/// Parse 0..N hex byte strings, accepting an optional `0x` prefix and
/// ignoring ASCII case. Returns the lowercase-canonical form.
#[must_use]
pub fn normalize_hex(s: &str) -> Option<String> {
    let stripped = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    if stripped.is_empty() || !stripped.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    if stripped.len() % 2 != 0 {
        return None;
    }
    Some(stripped.to_ascii_lowercase())
}

/// Decode a hex string to raw bytes. Returns `None` on invalid input.
#[must_use]
pub fn hex_to_bytes(s: &str) -> Option<Vec<u8>> {
    let canonical = normalize_hex(s)?;
    hex::decode(canonical).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn normalize_hex_handles_prefix_and_case() {
        assert_eq!(normalize_hex("0xAbCd").as_deref(), Some("abcd"));
        assert_eq!(normalize_hex("ABCD").as_deref(), Some("abcd"));
        assert_eq!(normalize_hex("0Xabcd").as_deref(), Some("abcd"));
    }

    #[test]
    fn normalize_hex_rejects_garbage() {
        assert!(normalize_hex("").is_none());
        assert!(normalize_hex("0x").is_none());
        assert!(normalize_hex("0xZZ").is_none());
        assert!(normalize_hex("abc").is_none()); // odd length
    }

    #[test]
    fn hex_to_bytes_round_trip() {
        assert_eq!(
            hex_to_bytes("0xdeadbeef").unwrap(),
            vec![0xde, 0xad, 0xbe, 0xef]
        );
        assert_eq!(
            hex_to_bytes("DEADBEEF").unwrap(),
            vec![0xde, 0xad, 0xbe, 0xef]
        );
        assert!(hex_to_bytes("nope").is_none());
    }

    #[test]
    fn json_round_trip_deny_chain() {
        let rule = Rule::DenyChain {
            chain_ids: vec![9001, 31337],
        };
        let v = serde_json::to_value(&rule).unwrap();
        assert_eq!(v["kind"], json!("deny_chain"));
        let back: Rule = serde_json::from_value(v).unwrap();
        assert_eq!(rule, back);
    }

    #[test]
    fn json_round_trip_rate_limit() {
        let rule = Rule::RateLimit {
            tokens: 5,
            refill_per_secs: 60,
            scope: RateLimitScope::PerWalletRequester,
        };
        let v = serde_json::to_value(&rule).unwrap();
        assert_eq!(v["kind"], json!("rate_limit"));
        assert_eq!(v["scope"], json!("per_wallet_requester"));
        let back: Rule = serde_json::from_value(v).unwrap();
        assert_eq!(rule, back);
    }

    #[test]
    fn json_round_trip_quorum_value_gte() {
        let approver = ApprovalId::new();
        let rule = Rule::RequireQuorum {
            threshold: 3,
            total: 5,
            approver_set: approver,
            trigger: QuorumTrigger::ValueGte {
                chain_id: 9001,
                value: "1000000000000000000000".to_string(),
            },
        };
        let v = serde_json::to_value(&rule).unwrap();
        let back: Rule = serde_json::from_value(v).unwrap();
        assert_eq!(rule, back);
    }

    #[test]
    fn json_unknown_kind_fails() {
        let bad = json!({ "kind": "make_coffee" });
        let err = serde_json::from_value::<Rule>(bad).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("variant") || msg.contains("unknown") || msg.contains("kind"),
            "expected unknown-variant error, got {msg}"
        );
    }
}
