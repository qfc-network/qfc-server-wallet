//! Unit tests for the in-memory registry. Postgres-flavoured tests live in
//! `tests/postgres_registry.rs` and use `testcontainers`.

use qfc_wallet_types::{OwnerId, SigningScheme, WalletId};

use crate::identity::ApproverIdentity;
use crate::registry::types::{
    ApproverCreate, ApproverRegistry, ApproverSetCreate, ApproverStatus, RegistryError,
};
use crate::registry::MemoryApproverRegistry;

fn external_approver(label: &str) -> ApproverCreate {
    ApproverCreate {
        identity: ApproverIdentity::External {
            id: label.to_string(),
            public_key: vec![0u8; 32],
            scheme: SigningScheme::Ed25519,
        },
        label: label.to_string(),
        owner_id: OwnerId::new("tenant-a"),
        webhook_url: None,
    }
}

fn nested_approver(label: &str, wallet_id: WalletId) -> ApproverCreate {
    ApproverCreate {
        identity: ApproverIdentity::NestedWallet {
            wallet_id,
            public_key: vec![0u8; 32],
            scheme: SigningScheme::Ed25519,
        },
        label: label.to_string(),
        owner_id: OwnerId::new("tenant-a"),
        webhook_url: None,
    }
}

#[tokio::test]
async fn add_and_get_round_trip() {
    let r = MemoryApproverRegistry::new();
    let rec = r.add_approver(external_approver("alice")).await.unwrap();
    let fetched = r.get_approver(rec.approver_id).await.unwrap();
    assert_eq!(rec, fetched);
    assert_eq!(rec.status, ApproverStatus::Active);
}

#[tokio::test]
async fn revoke_marks_revoked() {
    let r = MemoryApproverRegistry::new();
    let rec = r.add_approver(external_approver("alice")).await.unwrap();
    r.revoke_approver(rec.approver_id).await.unwrap();
    let fetched = r.get_approver(rec.approver_id).await.unwrap();
    assert_eq!(fetched.status, ApproverStatus::Revoked);
}

#[tokio::test]
async fn list_filters_revoked_by_default() {
    let r = MemoryApproverRegistry::new();
    let a = r.add_approver(external_approver("alice")).await.unwrap();
    let b = r.add_approver(external_approver("bob")).await.unwrap();
    r.revoke_approver(b.approver_id).await.unwrap();

    let active = r
        .list_approvers_by_owner(&OwnerId::new("tenant-a"), false)
        .await
        .unwrap();
    assert_eq!(active.len(), 1);
    assert_eq!(active[0].approver_id, a.approver_id);

    let all = r
        .list_approvers_by_owner(&OwnerId::new("tenant-a"), true)
        .await
        .unwrap();
    assert_eq!(all.len(), 2);
}

#[tokio::test]
async fn create_set_validates_threshold_zero() {
    let r = MemoryApproverRegistry::new();
    let a = r.add_approver(external_approver("alice")).await.unwrap();
    let err = r
        .create_approver_set(ApproverSetCreate {
            name: "treasury".into(),
            owner_id: OwnerId::new("tenant-a"),
            members: vec![a.approver_id],
            threshold: 0,
            total: 1,
            quorum_timeout_secs: None,
        })
        .await;
    assert!(matches!(err, Err(RegistryError::InvalidThreshold { .. })));
}

#[tokio::test]
async fn create_set_validates_threshold_gt_total() {
    let r = MemoryApproverRegistry::new();
    let a = r.add_approver(external_approver("alice")).await.unwrap();
    let err = r
        .create_approver_set(ApproverSetCreate {
            name: "treasury".into(),
            owner_id: OwnerId::new("tenant-a"),
            members: vec![a.approver_id],
            threshold: 2,
            total: 1,
            quorum_timeout_secs: None,
        })
        .await;
    assert!(matches!(err, Err(RegistryError::InvalidThreshold { .. })));
}

#[tokio::test]
async fn create_set_validates_member_count_mismatch() {
    let r = MemoryApproverRegistry::new();
    let a = r.add_approver(external_approver("alice")).await.unwrap();
    let err = r
        .create_approver_set(ApproverSetCreate {
            name: "treasury".into(),
            owner_id: OwnerId::new("tenant-a"),
            members: vec![a.approver_id],
            threshold: 1,
            total: 3,
            quorum_timeout_secs: None,
        })
        .await;
    assert!(matches!(
        err,
        Err(RegistryError::MemberCountMismatch { .. })
    ));
}

#[tokio::test]
async fn create_set_rejects_duplicate_members() {
    let r = MemoryApproverRegistry::new();
    let a = r.add_approver(external_approver("alice")).await.unwrap();
    let err = r
        .create_approver_set(ApproverSetCreate {
            name: "treasury".into(),
            owner_id: OwnerId::new("tenant-a"),
            members: vec![a.approver_id, a.approver_id],
            threshold: 1,
            total: 2,
            quorum_timeout_secs: None,
        })
        .await;
    assert!(matches!(err, Err(RegistryError::DuplicateMember(_))));
}

#[tokio::test]
async fn create_set_rejects_unknown_member() {
    let r = MemoryApproverRegistry::new();
    let phantom = qfc_wallet_types::ApproverId::new();
    let err = r
        .create_approver_set(ApproverSetCreate {
            name: "treasury".into(),
            owner_id: OwnerId::new("tenant-a"),
            members: vec![phantom],
            threshold: 1,
            total: 1,
            quorum_timeout_secs: None,
        })
        .await;
    assert!(matches!(err, Err(RegistryError::UnknownMember(_))));
}

#[tokio::test]
async fn create_set_rejects_revoked_member() {
    let r = MemoryApproverRegistry::new();
    let a = r.add_approver(external_approver("alice")).await.unwrap();
    r.revoke_approver(a.approver_id).await.unwrap();
    let err = r
        .create_approver_set(ApproverSetCreate {
            name: "treasury".into(),
            owner_id: OwnerId::new("tenant-a"),
            members: vec![a.approver_id],
            threshold: 1,
            total: 1,
            quorum_timeout_secs: None,
        })
        .await;
    assert!(matches!(err, Err(RegistryError::RevokedMember(_))));
}

#[tokio::test]
async fn create_set_detects_nesting_cycle() {
    let r = MemoryApproverRegistry::new();
    // Two distinct nested wallets W1 and W2. Build a set that contains
    // *both* as members. That set has not yet been attached to any wallet —
    // creation succeeds.
    //
    // Now try to create a SECOND set that also contains both W1 and W2.
    // The walker, starting from W1, finds the existing set (which points at
    // W1) and pivots to its co-members, including W2. From W2 it finds the
    // same existing set and pivots back to W1 — visited → NestingCycle.
    let w1 = WalletId::new();
    let w2 = WalletId::new();
    let a1 = r
        .add_approver(nested_approver("nest-w1", w1))
        .await
        .unwrap();
    let a2 = r
        .add_approver(nested_approver("nest-w2", w2))
        .await
        .unwrap();
    // First creation has no existing sets to walk → succeeds.
    r.create_approver_set(ApproverSetCreate {
        name: "first".into(),
        owner_id: OwnerId::new("tenant-a"),
        members: vec![a1.approver_id, a2.approver_id],
        threshold: 1,
        total: 2,
        quorum_timeout_secs: None,
    })
    .await
    .unwrap();
    // Second creation must walk through the prior set and detect the cycle.
    let err = r
        .create_approver_set(ApproverSetCreate {
            name: "second".into(),
            owner_id: OwnerId::new("tenant-a"),
            members: vec![a1.approver_id, a2.approver_id],
            threshold: 1,
            total: 2,
            quorum_timeout_secs: None,
        })
        .await;
    assert!(
        matches!(
            err,
            Err(RegistryError::NestingCycle(_) | RegistryError::NestingTooDeep(_))
        ),
        "expected cycle / depth, got {err:?}"
    );
}

#[tokio::test]
async fn create_set_with_shallow_nesting_succeeds() {
    let r = MemoryApproverRegistry::new();
    // A single NestedWallet member with no existing sets that reference it:
    // depth is 0, no cycle, should succeed.
    let w = WalletId::new();
    let nested = r.add_approver(nested_approver("nest", w)).await.unwrap();
    let set = r
        .create_approver_set(ApproverSetCreate {
            name: "depth-zero".into(),
            owner_id: OwnerId::new("tenant-a"),
            members: vec![nested.approver_id],
            threshold: 1,
            total: 1,
            quorum_timeout_secs: None,
        })
        .await
        .unwrap();
    assert_eq!(set.members.len(), 1);
}

#[tokio::test]
async fn create_set_happy_path() {
    let r = MemoryApproverRegistry::new();
    let a = r.add_approver(external_approver("alice")).await.unwrap();
    let b = r.add_approver(external_approver("bob")).await.unwrap();
    let c = r.add_approver(external_approver("carol")).await.unwrap();
    let set = r
        .create_approver_set(ApproverSetCreate {
            name: "treasury".into(),
            owner_id: OwnerId::new("tenant-a"),
            members: vec![a.approver_id, b.approver_id, c.approver_id],
            threshold: 2,
            total: 3,
            quorum_timeout_secs: Some(600),
        })
        .await
        .unwrap();
    assert_eq!(set.threshold, 2);
    assert_eq!(set.members.len(), 3);
    let fetched = r.get_approver_set(set.id).await.unwrap();
    assert_eq!(fetched.members, set.members);
}
