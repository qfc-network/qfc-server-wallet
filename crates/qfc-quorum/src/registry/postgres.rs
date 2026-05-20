//! Postgres-backed `ApproverRegistry`. Pattern mirrors `qfc-audit::PostgresAuditSink`.

use std::collections::{HashMap, HashSet};
use std::str::FromStr;

use async_trait::async_trait;
use qfc_wallet_types::{ApproverId, ApproverSetId, OwnerId, SigningScheme, WalletId};
use sqlx::postgres::{PgPool, PgPoolOptions};
use sqlx::Row;

use crate::identity::ApproverIdentity;
use crate::registry::types::{
    validate_set_shape, ApproverCreate, ApproverRecord, ApproverRegistry, ApproverSet,
    ApproverSetCreate, ApproverStatus, RegistryError, MAX_NESTING_DEPTH,
};

/// Embedded migrations. See `crates/qfc-quorum/migrations/`.
pub static REGISTRY_MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

/// Postgres-backed registry. Holds a `PgPool` and nothing else.
pub struct PostgresApproverRegistry {
    pool: PgPool,
}

impl PostgresApproverRegistry {
    /// Connect to Postgres and build a registry.
    ///
    /// # Errors
    ///
    /// `RegistryError::Io` on connect failure.
    pub async fn connect(db_url: &str) -> Result<Self, RegistryError> {
        let pool = PgPoolOptions::new()
            .max_connections(8)
            .connect(db_url)
            .await
            .map_err(|e| RegistryError::Io(format!("postgres connect: {e}")))?;
        Ok(Self { pool })
    }

    /// Build a registry from an existing pool.
    #[must_use]
    pub fn from_pool(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Apply embedded migrations.
    ///
    /// # Errors
    ///
    /// `RegistryError::Io` on any sqlx migration failure.
    pub async fn migrate(&self) -> Result<(), RegistryError> {
        REGISTRY_MIGRATOR
            .run(&self.pool)
            .await
            .map_err(|e| RegistryError::Io(format!("migrate: {e}")))
    }

    /// Borrow the underlying pool. Shared with `PostgresApprovalStore`.
    #[must_use]
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }
}

#[async_trait]
impl ApproverRegistry for PostgresApproverRegistry {
    async fn add_approver(&self, create: ApproverCreate) -> Result<ApproverRecord, RegistryError> {
        let approver_id = ApproverId::new();
        let scheme = create.identity.scheme();
        let public_key = create.identity.public_key().to_vec();
        let identity_json = serde_json::to_value(&create.identity)
            .map_err(|e| RegistryError::Io(format!("identity json: {e}")))?;
        let added_at = now_unix_ms();

        sqlx::query(
            "INSERT INTO approvers
                (approver_id, identity, scheme, public_key, label, owner_id, webhook_url,
                 status, added_at_unix_ms)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
        )
        .bind(approver_id.to_string())
        .bind(&identity_json)
        .bind(scheme_byte(scheme))
        .bind(&public_key)
        .bind(&create.label)
        .bind(create.owner_id.as_str())
        .bind(create.webhook_url.as_deref())
        .bind(i16::from(status_byte(ApproverStatus::Active)))
        .bind(added_at)
        .execute(&self.pool)
        .await
        .map_err(|e| RegistryError::Io(format!("insert approver: {e}")))?;

        Ok(ApproverRecord {
            approver_id,
            identity: create.identity,
            scheme,
            label: create.label,
            owner_id: create.owner_id,
            webhook_url: create.webhook_url,
            status: ApproverStatus::Active,
            added_at_unix_ms: added_at,
        })
    }

    async fn revoke_approver(&self, id: ApproverId) -> Result<(), RegistryError> {
        let res = sqlx::query("UPDATE approvers SET status = $1 WHERE approver_id = $2")
            .bind(i16::from(status_byte(ApproverStatus::Revoked)))
            .bind(id.to_string())
            .execute(&self.pool)
            .await
            .map_err(|e| RegistryError::Io(format!("revoke approver: {e}")))?;
        if res.rows_affected() == 0 {
            return Err(RegistryError::ApproverNotFound(id));
        }
        Ok(())
    }

    async fn get_approver(&self, id: ApproverId) -> Result<ApproverRecord, RegistryError> {
        let row = sqlx::query(
            "SELECT approver_id, identity, scheme, label, owner_id, webhook_url, status,
                    added_at_unix_ms
               FROM approvers
              WHERE approver_id = $1",
        )
        .bind(id.to_string())
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| RegistryError::Io(format!("select approver: {e}")))?;
        let Some(row) = row else {
            return Err(RegistryError::ApproverNotFound(id));
        };
        row_to_approver(&row)
    }

    async fn list_approvers_by_owner(
        &self,
        owner: &OwnerId,
        include_revoked: bool,
    ) -> Result<Vec<ApproverRecord>, RegistryError> {
        let rows = if include_revoked {
            sqlx::query(
                "SELECT approver_id, identity, scheme, label, owner_id, webhook_url, status,
                        added_at_unix_ms
                   FROM approvers
                  WHERE owner_id = $1
                  ORDER BY added_at_unix_ms ASC",
            )
            .bind(owner.as_str())
            .fetch_all(&self.pool)
            .await
        } else {
            sqlx::query(
                "SELECT approver_id, identity, scheme, label, owner_id, webhook_url, status,
                        added_at_unix_ms
                   FROM approvers
                  WHERE owner_id = $1 AND status = $2
                  ORDER BY added_at_unix_ms ASC",
            )
            .bind(owner.as_str())
            .bind(i16::from(status_byte(ApproverStatus::Active)))
            .fetch_all(&self.pool)
            .await
        }
        .map_err(|e| RegistryError::Io(format!("list approvers: {e}")))?;

        let mut out = Vec::with_capacity(rows.len());
        for row in &rows {
            out.push(row_to_approver(row)?);
        }
        Ok(out)
    }

    #[allow(clippy::too_many_lines)]
    async fn create_approver_set(
        &self,
        create: ApproverSetCreate,
    ) -> Result<ApproverSet, RegistryError> {
        validate_set_shape(&create)?;

        // Load all referenced approvers + every existing nested-wallet set
        // for cycle detection. We perform the validation in application code
        // (consistent with the in-memory backend) inside a single transaction
        // so concurrent writers cannot smuggle a cycle past the check.
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| RegistryError::Io(format!("begin tx: {e}")))?;

        let mut approvers_map: HashMap<ApproverId, ApproverRecord> = HashMap::new();
        for m in &create.members {
            let row = sqlx::query(
                "SELECT approver_id, identity, scheme, label, owner_id, webhook_url, status,
                        added_at_unix_ms
                   FROM approvers
                  WHERE approver_id = $1
                  FOR SHARE",
            )
            .bind(m.to_string())
            .fetch_optional(&mut *tx)
            .await
            .map_err(|e| RegistryError::Io(format!("select member: {e}")))?;
            let Some(row) = row else {
                return Err(RegistryError::UnknownMember(*m));
            };
            let rec = row_to_approver(&row)?;
            if rec.status != ApproverStatus::Active {
                return Err(RegistryError::RevokedMember(*m));
            }
            approvers_map.insert(rec.approver_id, rec);
        }

        // Pull *all* sets + their members (small at M4 scale; if it grows we
        // narrow this scan to sets that include nested-wallet members).
        let set_rows = sqlx::query(
            "SELECT approver_set_id, name, owner_id, threshold, total, quorum_timeout_secs,
                    created_at_unix_ms
               FROM approver_sets",
        )
        .fetch_all(&mut *tx)
        .await
        .map_err(|e| RegistryError::Io(format!("scan sets: {e}")))?;

        let mut sets_map: HashMap<ApproverSetId, ApproverSet> = HashMap::new();
        for row in &set_rows {
            let id_s: String = row
                .try_get("approver_set_id")
                .map_err(|e| RegistryError::Io(format!("set id: {e}")))?;
            let id = ApproverSetId::from_str(&id_s)
                .map_err(|e| RegistryError::Io(format!("set id parse: {e}")))?;
            let members = fetch_set_members(&mut tx, id).await?;
            // Build a record stub; we don't need name/timeouts for the walk.
            sets_map.insert(
                id,
                ApproverSet {
                    id,
                    name: row.try_get::<String, _>("name").unwrap_or_default(),
                    owner_id: OwnerId::new(
                        row.try_get::<String, _>("owner_id").unwrap_or_default(),
                    ),
                    members,
                    threshold: u8_from_smallint(row.try_get("threshold").unwrap_or(0))?,
                    total: u8_from_smallint(row.try_get("total").unwrap_or(0))?,
                    quorum_timeout_secs: row
                        .try_get::<Option<i32>, _>("quorum_timeout_secs")
                        .ok()
                        .flatten()
                        .and_then(|v| u32::try_from(v).ok()),
                    created_at_unix_ms: row.try_get("created_at_unix_ms").unwrap_or(0),
                },
            );
        }

        // To do the walk we need the identity of every approver referenced
        // by every existing set, not just the new members. Pull those too.
        let mut needed: HashSet<ApproverId> = HashSet::new();
        for set in sets_map.values() {
            for m in &set.members {
                if !approvers_map.contains_key(m) {
                    needed.insert(*m);
                }
            }
        }
        for n in needed {
            let row = sqlx::query(
                "SELECT approver_id, identity, scheme, label, owner_id, webhook_url, status,
                        added_at_unix_ms
                   FROM approvers
                  WHERE approver_id = $1",
            )
            .bind(n.to_string())
            .fetch_optional(&mut *tx)
            .await
            .map_err(|e| RegistryError::Io(format!("select walk approver: {e}")))?;
            if let Some(row) = row {
                let rec = row_to_approver(&row)?;
                approvers_map.insert(rec.approver_id, rec);
            }
        }

        // Cycle detection: same algorithm as the in-memory backend.
        let nested_starts: Vec<WalletId> = create
            .members
            .iter()
            .filter_map(|m| approvers_map.get(m))
            .filter_map(|rec| match &rec.identity {
                ApproverIdentity::NestedWallet { wallet_id, .. } => Some(*wallet_id),
                _ => None,
            })
            .collect();
        for w in nested_starts {
            walk_nested(w, &sets_map, &approvers_map, 0)?;
        }

        let id = ApproverSetId::new();
        let created_at = now_unix_ms();
        sqlx::query(
            "INSERT INTO approver_sets
                (approver_set_id, name, owner_id, threshold, total, quorum_timeout_secs,
                 created_at_unix_ms)
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(id.to_string())
        .bind(&create.name)
        .bind(create.owner_id.as_str())
        .bind(i16::from(create.threshold))
        .bind(i16::from(create.total))
        .bind(
            create
                .quorum_timeout_secs
                .and_then(|v| i32::try_from(v).ok()),
        )
        .bind(created_at)
        .execute(&mut *tx)
        .await
        .map_err(|e| RegistryError::Io(format!("insert set: {e}")))?;

        for (pos, m) in create.members.iter().enumerate() {
            sqlx::query(
                "INSERT INTO approver_set_members (approver_set_id, approver_id, position)
                 VALUES ($1, $2, $3)",
            )
            .bind(id.to_string())
            .bind(m.to_string())
            .bind(i16::try_from(pos).map_err(|_| {
                RegistryError::Io("position overflow (more than 32k members?)".into())
            })?)
            .execute(&mut *tx)
            .await
            .map_err(|e| RegistryError::Io(format!("insert set member: {e}")))?;
        }

        tx.commit()
            .await
            .map_err(|e| RegistryError::Io(format!("commit set: {e}")))?;

        Ok(ApproverSet {
            id,
            name: create.name,
            owner_id: create.owner_id,
            members: create.members,
            threshold: create.threshold,
            total: create.total,
            quorum_timeout_secs: create.quorum_timeout_secs,
            created_at_unix_ms: created_at,
        })
    }

    async fn get_approver_set(&self, id: ApproverSetId) -> Result<ApproverSet, RegistryError> {
        let row = sqlx::query(
            "SELECT approver_set_id, name, owner_id, threshold, total, quorum_timeout_secs,
                    created_at_unix_ms
               FROM approver_sets
              WHERE approver_set_id = $1",
        )
        .bind(id.to_string())
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| RegistryError::Io(format!("select set: {e}")))?;
        let Some(row) = row else {
            return Err(RegistryError::ApproverSetNotFound(id));
        };
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| RegistryError::Io(format!("get_set tx: {e}")))?;
        let members = fetch_set_members(&mut tx, id).await?;
        tx.rollback().await.ok();
        row_to_set(&row, members)
    }

    async fn list_approver_sets(&self, owner: &OwnerId) -> Result<Vec<ApproverSet>, RegistryError> {
        let rows = sqlx::query(
            "SELECT approver_set_id, name, owner_id, threshold, total, quorum_timeout_secs,
                    created_at_unix_ms
               FROM approver_sets
              WHERE owner_id = $1
              ORDER BY created_at_unix_ms ASC",
        )
        .bind(owner.as_str())
        .fetch_all(&self.pool)
        .await
        .map_err(|e| RegistryError::Io(format!("list sets: {e}")))?;

        let mut out = Vec::with_capacity(rows.len());
        for row in &rows {
            let id_s: String = row
                .try_get("approver_set_id")
                .map_err(|e| RegistryError::Io(format!("set id: {e}")))?;
            let id = ApproverSetId::from_str(&id_s)
                .map_err(|e| RegistryError::Io(format!("set id parse: {e}")))?;
            let mut tx = self
                .pool
                .begin()
                .await
                .map_err(|e| RegistryError::Io(format!("list tx: {e}")))?;
            let members = fetch_set_members(&mut tx, id).await?;
            tx.rollback().await.ok();
            out.push(row_to_set(row, members)?);
        }
        Ok(out)
    }
}

async fn fetch_set_members(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    set_id: ApproverSetId,
) -> Result<Vec<ApproverId>, RegistryError> {
    let rows = sqlx::query(
        "SELECT approver_id FROM approver_set_members
          WHERE approver_set_id = $1
          ORDER BY position ASC",
    )
    .bind(set_id.to_string())
    .fetch_all(&mut **tx)
    .await
    .map_err(|e| RegistryError::Io(format!("set members: {e}")))?;
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let s: String = row
            .try_get("approver_id")
            .map_err(|e| RegistryError::Io(format!("set member id: {e}")))?;
        out.push(
            ApproverId::from_str(&s)
                .map_err(|e| RegistryError::Io(format!("set member parse: {e}")))?,
        );
    }
    Ok(out)
}

fn row_to_approver(row: &sqlx::postgres::PgRow) -> Result<ApproverRecord, RegistryError> {
    let id_s: String = row
        .try_get("approver_id")
        .map_err(|e| RegistryError::Io(format!("approver id: {e}")))?;
    let identity_v: serde_json::Value = row
        .try_get("identity")
        .map_err(|e| RegistryError::Io(format!("identity: {e}")))?;
    let identity: ApproverIdentity = serde_json::from_value(identity_v)
        .map_err(|e| RegistryError::Io(format!("identity decode: {e}")))?;
    let scheme_i: i16 = row
        .try_get("scheme")
        .map_err(|e| RegistryError::Io(format!("scheme: {e}")))?;
    let label: String = row
        .try_get("label")
        .map_err(|e| RegistryError::Io(format!("label: {e}")))?;
    let owner_s: String = row
        .try_get("owner_id")
        .map_err(|e| RegistryError::Io(format!("owner_id: {e}")))?;
    let webhook_url: Option<String> = row
        .try_get("webhook_url")
        .map_err(|e| RegistryError::Io(format!("webhook_url: {e}")))?;
    let status_i: i16 = row
        .try_get("status")
        .map_err(|e| RegistryError::Io(format!("status: {e}")))?;
    let added: i64 = row
        .try_get("added_at_unix_ms")
        .map_err(|e| RegistryError::Io(format!("added_at: {e}")))?;
    Ok(ApproverRecord {
        approver_id: ApproverId::from_str(&id_s)
            .map_err(|e| RegistryError::Io(format!("approver id parse: {e}")))?,
        identity,
        scheme: scheme_from_byte(u8_from_smallint(scheme_i)?)?,
        label,
        owner_id: OwnerId::new(owner_s),
        webhook_url,
        status: status_from_byte(u8_from_smallint(status_i)?)?,
        added_at_unix_ms: added,
    })
}

fn row_to_set(
    row: &sqlx::postgres::PgRow,
    members: Vec<ApproverId>,
) -> Result<ApproverSet, RegistryError> {
    let id_s: String = row
        .try_get("approver_set_id")
        .map_err(|e| RegistryError::Io(format!("set id: {e}")))?;
    let name: String = row
        .try_get("name")
        .map_err(|e| RegistryError::Io(format!("set name: {e}")))?;
    let owner_s: String = row
        .try_get("owner_id")
        .map_err(|e| RegistryError::Io(format!("set owner: {e}")))?;
    let threshold_i: i16 = row
        .try_get("threshold")
        .map_err(|e| RegistryError::Io(format!("set threshold: {e}")))?;
    let total_i: i16 = row
        .try_get("total")
        .map_err(|e| RegistryError::Io(format!("set total: {e}")))?;
    let timeout_i: Option<i32> = row
        .try_get("quorum_timeout_secs")
        .map_err(|e| RegistryError::Io(format!("set timeout: {e}")))?;
    let created: i64 = row
        .try_get("created_at_unix_ms")
        .map_err(|e| RegistryError::Io(format!("set created: {e}")))?;
    Ok(ApproverSet {
        id: ApproverSetId::from_str(&id_s)
            .map_err(|e| RegistryError::Io(format!("set id parse: {e}")))?,
        name,
        owner_id: OwnerId::new(owner_s),
        members,
        threshold: u8_from_smallint(threshold_i)?,
        total: u8_from_smallint(total_i)?,
        quorum_timeout_secs: timeout_i.and_then(|v| u32::try_from(v).ok()),
        created_at_unix_ms: created,
    })
}

fn walk_nested(
    start: WalletId,
    sets: &HashMap<ApproverSetId, ApproverSet>,
    approvers: &HashMap<ApproverId, ApproverRecord>,
    depth: u8,
) -> Result<(), RegistryError> {
    let mut visited: HashSet<WalletId> = HashSet::new();
    let mut stack: Vec<(WalletId, u8)> = vec![(start, depth)];
    while let Some((w, d)) = stack.pop() {
        if d > MAX_NESTING_DEPTH {
            return Err(RegistryError::NestingTooDeep(MAX_NESTING_DEPTH));
        }
        if !visited.insert(w) {
            return Err(RegistryError::NestingCycle(w));
        }
        for set in sets.values() {
            for member in &set.members {
                let Some(rec) = approvers.get(member) else {
                    continue;
                };
                if let ApproverIdentity::NestedWallet { wallet_id, .. } = &rec.identity {
                    if *wallet_id == w {
                        for other in &set.members {
                            let Some(orec) = approvers.get(other) else {
                                continue;
                            };
                            if let ApproverIdentity::NestedWallet { wallet_id: ow, .. } =
                                &orec.identity
                            {
                                if *ow != w {
                                    stack.push((*ow, d + 1));
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

fn scheme_byte(s: SigningScheme) -> i16 {
    match s {
        SigningScheme::Ed25519 => 1,
        SigningScheme::Secp256k1 => 2,
        SigningScheme::Secp256k1Recoverable => 3,
        SigningScheme::MlDsa44 => 4,
        SigningScheme::MlDsa65 => 5,
        SigningScheme::MlDsa87 => 6,
    }
}

fn scheme_from_byte(b: u8) -> Result<SigningScheme, RegistryError> {
    Ok(match b {
        1 => SigningScheme::Ed25519,
        2 => SigningScheme::Secp256k1,
        3 => SigningScheme::Secp256k1Recoverable,
        4 => SigningScheme::MlDsa44,
        5 => SigningScheme::MlDsa65,
        6 => SigningScheme::MlDsa87,
        other => return Err(RegistryError::Io(format!("unknown scheme byte: {other}"))),
    })
}

fn status_byte(s: ApproverStatus) -> u8 {
    match s {
        ApproverStatus::Active => 1,
        ApproverStatus::Revoked => 2,
    }
}

fn status_from_byte(b: u8) -> Result<ApproverStatus, RegistryError> {
    Ok(match b {
        1 => ApproverStatus::Active,
        2 => ApproverStatus::Revoked,
        other => return Err(RegistryError::Io(format!("unknown status byte: {other}"))),
    })
}

fn u8_from_smallint(i: i16) -> Result<u8, RegistryError> {
    u8::try_from(i).map_err(|_| RegistryError::Io(format!("smallint out of u8 range: {i}")))
}

fn now_unix_ms() -> i64 {
    let nanos = time::OffsetDateTime::now_utc().unix_timestamp_nanos();
    i64::try_from(nanos / 1_000_000).unwrap_or(i64::MAX)
}
