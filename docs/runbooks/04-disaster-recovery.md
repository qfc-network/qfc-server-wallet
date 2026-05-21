# 04 — Disaster recovery

**Status:** Targets stated as targets, not promises. Parts of the recovery
flow are Pending M3-GA (`S3KmsShareStore` restore) and Pending `qfc-core`
integration (live on-chain anchor commits per
[retro-m1-m2 §3.7](../retro-m1-m2.md)). The in-memory wallet registry
gap (RFC §3.1 not yet backed by Postgres in M1–M5 per
[retro-m1-m2 §3.3](../retro-m1-m2.md)) is called out as a known DR gap.
**Audience:** ops, incident commander during a DR event.
**Last reviewed:** 2026-05-21.

## Recovery targets

These are **targets**, not SLAs. They will firm up into commitments as
ops capacity matures and as quarterly DR drills produce evidence.

- **RPO (Recovery Point Objective):** < 1 hour. Postgres backups
  emit at least hourly; the audit chain's per-event anchor (file
  backend today, on-chain anchor pending) bounds the data-loss
  window.
- **RTO (Recovery Time Objective):** < 4 hours from incident declaration
  to a functional service serving signing requests.

These targets assume:
- The incident is recoverable (not a CMK compromise — see "Not
  recoverable" below).
- The backup infrastructure itself is intact (the backup S3 bucket is
  in a separate region; the Postgres backups are not co-located with
  the primary).
- An incident commander is paged within the first 15 minutes.

## What is recoverable

### Audit chain

**Live.** The audit chain is recoverable from:

1. Postgres backup of the `audit_events` table (`PostgresAuditSink`).
2. The daily anchor commit — file-backed today via
   `qfc-audit::anchor::LocalFileAnchor`
   (per [m3-decisions D28](../m3-decisions.md#d28)); on-chain anchor
   commit is **Pending `qfc-core` workspace integration**.

Recovery:

1. Restore the `audit_events` table from the most recent backup.
2. Replay-verify the chain (`qfc_audit::replay_verify`) using the
   published server pubkey. The replay walks the chain from genesis to
   head, checking the `prev_event_hash` link and the `server_signature`
   on each event.
3. Compare the recovered chain head against the most recent anchor
   commit. If they match, recovery is clean. If the recovered head is
   *behind* the anchor, the gap is the data-loss window — events
   between the recovered head and the anchored head are lost; classify
   as a P0 if customer-impacting.

### Approver registry + approvals

**Live.** Both back-ended by Postgres (`PostgresApproverRegistry` and
`PostgresApprovalStore`, M4-GA). Recovery is a Postgres restore.

After restore, in-flight approvals (the `approvals` rows for a
`request_id` that hadn't reached threshold) replay correctly because
the orchestrator re-resolves the set from the registry on the next
`sign` retry.

The `UNIQUE (request_id, approver_id)` constraint on the `approvals`
table protects against duplicate-approval ingestion during the
restore window.

### Wallet records

**Known gap.** In M1–M5 the wallet registry is an in-memory
`HashMap<WalletId, WalletRecord>` (per
[retro-m1-m2 §3.3](../retro-m1-m2.md)). On a process restart **the
registry is lost**. The shares in storage are still valid, but the
orchestrator no longer knows which wallets exist.

Mitigations today:
- Wallet creation is idempotent at the share-store level — re-creating
  a wallet with the same `wallet_id` collides at storage.
- The audit chain has every `WalletCreated` event (kind byte `1`),
  so the registry can in principle be reconstructed from audit
  replay.

**Pending M3-GA:** the wallet registry moves to Postgres backing in
the M3-GA work. Until then, **do not deploy without an audit-replay
warm-up step** in the boot sequence. The ops repo's runbook covers the
warm-up procedure.

### Key shares

**Pending M3-GA.** Shares live in S3 wrapped under KMS. Recovery from
backup:

1. Restore the S3 bucket from cross-region backup. The bucket
   versioning + replication policy lives in the ops repo's terraform.
2. **The KMS policy stays.** The CMK ARN does not change; the wrapped
   DEK in each share is still unwrappable by KMS as long as the CMK is
   intact.
3. The new EIF (which has the post-incident PCR0) is added to the KMS
   allowlist per `01-eif-upgrade.md`.
4. Resume signing.

This path **only works if the CMK itself is intact**. CMK loss is in
the "Not recoverable" section below.

## What is NOT recoverable without full operator intervention

### CMK compromise / loss

If the KMS CMK is compromised (key material exfiltrated, or AWS
loses the CMK), every wrapped DEK is at risk and every share is
effectively gone. There is no way to re-wrap shares that were already
written under the lost CMK.

The recovery path is **wallet regeneration**:

1. Generate new wallets (new addresses per RFC §3.1 D4) using a fresh
   CMK.
2. Notify every affected customer that their existing wallets are
   compromised and they must migrate funds to the new wallets through
   the customer-side wallet-migration flow.
3. Coordinate with the bug bounty program (per RFC §8.3) and
   `<SECURITY_TEAM_HANDLE>` for disclosure timing.
4. The wallet-migration customer tooling itself is
   **deferred** per [m5-decisions D42](../m5-decisions.md#d42); a
   manual ceremony with the customer is the interim path.

This scenario is rare but planning for it is part of the DR drill
cadence (see below).

### Total enclave compromise across all PCRs

If every PCR0 in the KMS allowlist is suspected compromised
simultaneously, all shares are at risk. Same recovery as CMK
compromise — wallet regeneration.

## DR drill cadence

**Target: quarterly.**

Each drill:

1. Runs in staging only — never against production wallets.
2. Picks one recovery scenario from the matrix:
   - Audit-chain restore from backup.
   - Approver registry restore.
   - S3 share-store restore from backup (Pending M3-GA).
   - Cross-region failover (Pending M3-GA's region terraform).
3. Walks through this runbook end-to-end against the staging
   environment.
4. Produces a drill report with:
   - Actual recovery time vs target RTO.
   - Actual data-loss window vs target RPO.
   - Any runbook step that was wrong (fix it in the same PR cycle as
     the report).
5. Files the report in `<OPS_REPO>/incidents/dr-drill-<DATE>.md`.

The first drill happens in the first month of an ops engineer's
onboarding (per `05-operator-onboarding.md` first-month exercises).

## Cross-region considerations

**Pending M3-GA.** The terraform module for the secondary region lives
in `<OPS_REPO>/terraform/regions/` and is part of the M3-GA scope.
Until then, the recovery path is single-region with cross-region
backup only — failover requires bringing up the secondary region from
terraform, which is hours not minutes.

## Pre-DR-drill checklist

Before running a drill:

- Confirm the staging environment is in a known-good state.
- Confirm the most recent staging backup is < 1 hour old.
- Coordinate with `<OPS_TEAM_HANDLE>` so no parallel deploy is in
  flight.
- Confirm the drill scenario is documented and the success criteria
  are agreed before starting.

## What this runbook does NOT cover

- Customer-side recovery (their hardware-approver device is lost) —
  customer runbook.
- Chain re-org / chain halt — `qfc-core` on-call.
- Region-wide AWS outage of the primary region — handled by the
  cross-region failover path (Pending M3-GA).
- Long-term archive recovery (> 1 year backups) — separate ops repo
  runbook covering Glacier retrieval timelines.
