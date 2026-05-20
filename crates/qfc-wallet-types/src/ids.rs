//! Identifier types.
//!
//! The wallet, request, decision, and event identifiers are all ULIDs
//! (lexicographically sortable, 128-bit, time-ordered). They are wrapped in
//! distinct newtypes so that mixing them up is a compile error.
//!
//! See `docs/server-wallet-rfc.md` §3.

use core::fmt;
use core::str::FromStr;
use serde::{Deserialize, Serialize};
use ulid::Ulid;

use crate::errors::ParseError;

macro_rules! ulid_newtype {
    ($(#[$attr:meta])* $name:ident) => {
        $(#[$attr])*
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(Ulid);

        impl $name {
            /// Produce a fresh time-ordered identifier.
            #[must_use]
            pub fn new() -> Self {
                Self(Ulid::new())
            }

            /// Construct from an existing ULID.
            #[must_use]
            pub const fn from_ulid(u: Ulid) -> Self {
                Self(u)
            }

            /// Borrow the underlying ULID.
            #[must_use]
            pub const fn as_ulid(&self) -> &Ulid {
                &self.0
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, concat!(stringify!($name), "({})"), self.0)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::Display::fmt(&self.0, f)
            }
        }

        impl FromStr for $name {
            type Err = ParseError;
            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Ulid::from_str(s)
                    .map(Self)
                    .map_err(|e| ParseError::InvalidUlid(e.to_string()))
            }
        }
    };
}

ulid_newtype!(
    /// Stable logical identifier for a server wallet. ULID; survives PQ migration.
    /// See RFC §3.1 (decision #4).
    WalletId
);

ulid_newtype!(
    /// Identifier for a single signing request, set by the API layer when the
    /// request is accepted. Carried through policy, quorum, and the enclave so
    /// that attestations and audit events can reference it.
    RequestId
);

ulid_newtype!(
    /// Identifier emitted by the policy engine for an evaluated decision.
    /// Audit log references this so policy traces are reproducible.
    DecisionId
);

ulid_newtype!(
    /// Identifier for a single approver action (one approval / rejection).
    ApprovalId
);

ulid_newtype!(
    /// Identifier for a single audit-log event.
    EventId
);

ulid_newtype!(
    /// Identifier for a policy *version* bound to a wallet.
    PolicyId
);

ulid_newtype!(
    /// Identifier for an approver set (M-of-N quorum group). See RFC §2.5
    /// and `qfc-quorum::registry::ApproverSet`. Distinct from `ApprovalId`
    /// which identifies an individual signed approval action.
    ApproverSetId
);

ulid_newtype!(
    /// Identifier for an approver record (an individual person/key) inside
    /// the approver registry. See RFC §2.5.
    ApproverId
);

/// Identifier for a single Shamir share within a wallet's share set.
///
/// `ShareId` is *not* a ULID. It is structurally `(wallet_id, index)` so that
/// shares can be looked up deterministically by their owning wallet plus their
/// position in the secret-sharing scheme.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ShareId {
    /// Wallet that owns this share.
    pub wallet_id: WalletId,
    /// Position in the SSS scheme. 1-indexed (SSS shares are 1..=N, 0 reserved).
    pub index: u8,
}

impl ShareId {
    /// Build a `ShareId`. `index` must be in `1..=255`; the caller is responsible
    /// for enforcing the SSS scheme's actual N upper bound.
    #[must_use]
    pub const fn new(wallet_id: WalletId, index: u8) -> Self {
        Self { wallet_id, index }
    }
}

impl fmt::Debug for ShareId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ShareId({}#{})", self.wallet_id, self.index)
    }
}

impl fmt::Display for ShareId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}#{}", self.wallet_id, self.index)
    }
}

/// Tenant / customer identifier. Wrapped `String` so that we can swap the
/// representation later (e.g. a UUID, an OAuth subject) without churning call
/// sites.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct OwnerId(String);

impl OwnerId {
    /// Construct an `OwnerId` from any string-like value.
    pub fn new<S: Into<String>>(s: S) -> Self {
        Self(s.into())
    }

    /// Borrow the inner string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for OwnerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "OwnerId({})", self.0)
    }
}

impl fmt::Display for OwnerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for OwnerId {
    type Err = core::convert::Infallible;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(s.to_owned()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ulid_newtypes_are_distinct() {
        let w = WalletId::new();
        let r = RequestId::new();
        // Display / FromStr round-trip
        let s = w.to_string();
        let parsed: WalletId = s.parse().unwrap();
        assert_eq!(w, parsed);
        // The two IDs are different runtime values; this is a smoke test against
        // accidental sharing of the inner ULID via the constructor.
        assert_ne!(w.as_ulid(), r.as_ulid());
    }

    #[test]
    fn share_id_display_round_trips_visually() {
        let w = WalletId::new();
        let s = ShareId::new(w, 3);
        let text = s.to_string();
        assert!(text.ends_with("#3"));
        assert!(text.starts_with(&w.to_string()));
    }

    #[test]
    fn ulid_parse_rejects_garbage() {
        let err: Result<WalletId, _> = "not-a-ulid".parse();
        assert!(matches!(err, Err(ParseError::InvalidUlid(_))));
    }

    #[test]
    fn owner_id_basic() {
        let o = OwnerId::new("tenant-42");
        assert_eq!(o.as_str(), "tenant-42");
        let p: OwnerId = "tenant-42".parse().unwrap();
        assert_eq!(o, p);
    }

    #[test]
    fn ulid_newtype_serde_round_trip() {
        let w = WalletId::new();
        let j = serde_json::to_string(&w).unwrap();
        let w2: WalletId = serde_json::from_str(&j).unwrap();
        assert_eq!(w, w2);
    }
}
