# 03 — Incident response

**Status:** Live; the P0 enclave-compromise commands depend on M3-GA
work (real `S3KmsShareStore` + KMS policy revocation) and are marked
inline. The P1/P2 paths are live against the current M2 stack.
**Audience:** on-call engineer, security responder, incident commander.
**Last reviewed:** 2026-05-21.

## Three triage tiers

| Tier | Definition                                            | Initial response window | Pager target                      |
|------|-------------------------------------------------------|--------------------------|-----------------------------------|
| P0   | Suspected enclave compromise OR audit-chain break     | Immediate                | `<SECURITY_TEAM_HANDLE>` + ops    |
| P1   | Quorum subsystem outage (approvals not landing)       | Within 15 min            | `<OPS_TEAM_HANDLE>`               |
| P2   | Operational degradation (latency, error rate)         | Within 1 hr              | `<OPS_TEAM_HANDLE>`               |

If unsure, escalate. P0 false-positives are recoverable; P0
false-negatives are not.

---

## P0 — Suspected enclave compromise

### Triggers

Any one of:

- Unexplained signature on the chain that doesn't appear in
  `qfc-audit` `SigningSucceeded` events.
- Attestation chain break: `verify_attestation` returns failure on a
  live attestation that should be valid.
- PCR0 mismatch in metrics (a sign request that succeeded carries an
  attestation with a PCR0 that isn't in the KMS allowlist).
- Sudden spike in `qfc_server_wallet_signs_total{result!="ok"}` with
  the error class being attestation-related.
- An external party (security researcher, blockchain monitor) reports
  a suspicious signature.

### Immediate response (do this in order)

1. **Page `<SECURITY_TEAM_HANDLE>`.** This is incident-commander
   territory; do not solo-debug.
2. **Revoke KMS decrypt for the affected PCR0.**

   ```sh
   # in <OPS_REPO>/terraform/kms/, remove the suspect PCR0 from
   # the allowed_pcrs list and apply. Second reviewer required.
   terraform apply -var "allowed_pcrs=[<KNOWN_GOOD_PCR0>]"
   ```

   **Pending M3-GA** for real `S3KmsShareStore` integration; under M2,
   KMS is not yet decrypt-gating shares, so this step is a no-op
   today.

3. **Freeze affected wallets.**

   Set `WalletStatus::Frozen` (see [`wallet.rs`](../../crates/qfc-server-wallet/src/wallet.rs))
   on every wallet the compromised PCR0 could have served. The freeze
   is reversible (`Frozen` retains the wallet record; `Revoked` deletes
   shares — **do not Revoke during a P0**, forensics needs the shares).

   The exact API call shape is in the ops repo's runbook; the public
   shape:

   ```sh
   # pseudocode — see <OPS_REPO>/runbooks/03-incident-response.md
   # for the actual admin endpoint and auth
   POST /admin/wallets/<WALLET_ID>/freeze
     X-Admin-Key: <ADMIN_KEY>
     body: { reason: "P0 incident <TICKET_ID>", operator_id: "<OPERATOR>" }
   ```

4. **Snapshot the audit chain.**

   Take a Postgres dump of the `audit_events` table and copy the
   `LocalFileAnchor` JSONL to a forensic-hold S3 bucket. The dump must
   include the chain head at the moment of snapshot — the responder
   replaying after the incident verifies the chain from this exact
   head backwards.

   ```sh
   pg_dump --table=audit_events --format=custom \
       "<POSTGRES_URL>" > audit-snapshot-<TICKET_ID>-<TIMESTAMP>.dump
   aws s3 cp audit-snapshot-<TICKET_ID>-<TIMESTAMP>.dump \
       s3://<FORENSIC_HOLD_BUCKET>/
   ```

5. **Do NOT delete shares.** Forensics needs every share that was in
   storage at the time of the incident. `Frozen` keeps them; `Revoked`
   deletes them. The KMS revocation above already makes the shares
   undecryptable from any new enclave; deletion would destroy the
   forensic trail.

6. **Open a P0 ticket** and link the audit-snapshot S3 URI, the KMS
   policy diff, the frozen-wallet list, and the trigger event.

### Triage commands

Run these (read-only) to confirm the trigger:

- Audit chain replay against the most recent anchor commit:

  ```sh
  # pseudocode — the actual tool is `qfc-audit-cli replay`
  # (binary not yet shipped; the library function
  # `qfc_audit::replay_verify` exists)
  qfc-audit-cli replay --from-file <SNAPSHOT> --pubkey <SERVER_PUBKEY>
  ```

- Attestation re-verify on a known-good recent sign:

  ```sh
  curl -s https://<PRODUCTION_HOST>/wallets/<WALLET_ID>/sign/<REQUEST_ID>/attestation \
      | qfc-enclave verify --expected-pcr0 <KNOWN_GOOD_PCR0>
  ```

- Grafana check on `<GRAFANA_DASHBOARD>`: sign-success rate,
  attestation-fail rate, audit-events rate. Don't paste the URL —
  it's the ops repo's.

### Comms template

Initial page (within 5 min of trigger):

```
P0 INCIDENT <TICKET_ID>: suspected enclave compromise
Affected wallets: <COUNT> frozen
KMS decrypt revoked on PCR0: <SUSPECT_PCR0>
Audit chain snapshot at: s3://<FORENSIC_HOLD>/<KEY>
Incident commander: <SECURITY_TEAM_HANDLE>
War room: <WAR_ROOM_HANDLE>
Status updates every 30 minutes.
```

Do **not** publish the trigger details externally until
`<SECURITY_TEAM_HANDLE>` clears it — coordinated disclosure per
RFC §8.3 (90-day default embargo).

### Rollback paths

A P0 doesn't have a rollback in the deploy sense — once shares are
suspected leaked, the affected wallets need wallet-regeneration
(separate customer-facing flow, see `04-disaster-recovery.md`). The
"unfreeze" path is taken only after forensics clears the wallet as
unaffected.

---

## P1 — Quorum subsystem outage

### Triggers

- Webhook delivery failing in bulk (`qfc-quorum::WebhookApprover`
  emitting persistent timeouts).
- Approvals not landing — `POST /requests/{request_id}/approvals` is
  failing for multiple approvers.
- `qfc_server_wallet_quorum_collect_seconds` histogram p99 climbing
  past nominal.
- `QuorumTimedOut` audit events spiking (kind byte `8`).

### Response

1. **Page `<OPS_TEAM_HANDLE>`.** Not security territory unless P0
   triggers also fire.
2. **Confirm scope.** Is it one approver-set or all of them? One
   webhook destination or many? Use Grafana
   (`<GRAFANA_DASHBOARD>`) and Postgres queries against the
   `approvals` table.
3. **Scale `qfc-server-wallet` replicas.** If the orchestrator is
   CPU-bound or fan-out-bound, more replicas help. The ops repo's
   runbook has the exact terraform scale lever; public shape:

   ```sh
   # in <OPS_REPO>/terraform/ec2/
   terraform apply -var "qfc_server_wallet_replicas=<N+M>"
   ```

4. **Check downstream dependencies:**
   - Postgres reachability + read/write latency.
   - Webhook destination reachability (the approver's URL).
   - `OnChainQfcEventApprover` — currently a `tokio::broadcast` stub
     per [m4-decisions D28](../m4-decisions.md#d28); if the on-chain
     event channel is the path failing, it's already a known
     limitation.

5. **Operator-sign-off fallback.** With explicit operator approval
   (two operators on the war-room call, both ack in the incident
   ticket), switch affected wallets to a "single approver" override
   mode. This is a degraded mode — the M-of-N invariant is loosened
   for the duration of the incident only. The override is
   approver-set-update flow (`POST /approver-sets` with
   `threshold = 1`), audit-logged via `ApproverSetChanged` (kind
   byte `13`).

   **Do not skip the two-operator sign-off.** A single operator
   loosening a customer's quorum during an incident is itself a
   threat (RFC §5.2 — "operator with prod KMS admin access" row).

### Triage commands

```sh
# count outstanding approvals per request
psql "<POSTGRES_URL>" -c \
    "SELECT request_id, COUNT(*) FROM approvals
     GROUP BY request_id ORDER BY COUNT(*) DESC LIMIT 20;"

# recent quorum-timeout audit events
psql "<POSTGRES_URL>" -c \
    "SELECT * FROM audit_events
     WHERE kind = 8
     ORDER BY ts DESC LIMIT 20;"
```

### Comms template

```
P1 INCIDENT <TICKET_ID>: quorum subsystem degradation
Symptom: <e.g. "webhook timeouts for set <SET_ID>">
Scope: <N> approver-sets, <M> pending requests
Mitigation: scaled to <REPLICAS>, monitoring
Status updates every hour or on change.
```

### Rollback paths

If a recent deploy is the suspected cause, roll back per
`00-deploy.md`'s Rollback section. Otherwise the fix is
forward-only (config, scale, code).

---

## P2 — Operational degradation

### Triggers

- `qfc_server_wallet_sign_duration_seconds` p99 elevated.
- `qfc_server_wallet_signs_total{result!="ok"}` rate elevated but
  attestation is healthy.
- Postgres CPU / IOPS approaching saturation.
- Disk-fill alerts on a `qfc-server-wallet` host.

### Response

Standard SRE playbook:

1. Page `<OPS_TEAM_HANDLE>` (no need for security).
2. Identify whether the regression is recent-deploy-correlated. If
   yes, prepare a rollback per `00-deploy.md`.
3. Scale horizontally (more replicas) or vertically (larger instance
   class) per the ops repo's terraform.
4. Restart `qfc-server-wallet` processes if a single host shows
   degraded behaviour and the others don't — rule out single-host
   resource exhaustion.
5. If Postgres is the bottleneck, escalate to the DB on-call.

### Triage commands

- Grafana `<GRAFANA_DASHBOARD>` panels: sign latency p50/p95/p99,
  policy-evaluation latency, error rate by class.
- Per-host Loki / log query: search for `level=error` over the last
  hour, group by host.
- Postgres pg_stat queries (the ops repo carries the canonical set).

### Comms template

```
P2 INCIDENT <TICKET_ID>: operational degradation
Symptom: <e.g. "sign p99 at 1200ms, baseline 200ms">
Suspected cause: <e.g. "recent deploy v0.3.2">
Mitigation: <scale / rollback / config>
Status updates every 2 hours.
```

---

## Post-incident (every tier)

After the incident is resolved:

1. **Audit chain replay.** Re-run `qfc_audit::replay_verify` from the
   pre-incident anchor commit forward through the incident window.
   The chain must verify. If it doesn't, the incident is reclassified
   as P0 and the audit-chain-break path runs.
2. **Root cause doc.** Within 5 business days. Sections: timeline,
   trigger, response, what worked, what didn't, action items. The
   doc lives in `<OPS_REPO>/incidents/<TICKET_ID>.md`.
3. **RFC fold-back.** If the incident surfaced a gap in the RFC
   (missing primitive, ambiguous spec, wrong assumption), add a row
   to the next retro's "what to fold back" section.
4. **Runbook update.** If any step in this runbook was wrong, fix it
   in the same PR cycle as the root-cause doc. The "Last reviewed"
   date at the top moves forward.
5. **External disclosure.** Per RFC §8.3 — 90-day coordinated
   disclosure default; `<SECURITY_TEAM_HANDLE>` owns the timeline.

## What this runbook does NOT cover

- Customer-side incidents (a customer reports their approvers were
  phished) — handled by the customer-success runbook in
  `<OPS_REPO>/runbooks/customer/`. RFC §5.2 is explicit that "if a
  customer's M approvers all get phished, their wallet drains. This
  is by design — we don't replace the customer's judgment, just
  enforce it."
- Legal / compelled-signing scenarios (subpoena, court order) —
  handled by `<OPS_REPO>/runbooks/legal/`. Not on-call territory.
- Chain re-org / chain halt — handled by the `qfc-core` on-call
  rotation, not the `qfc-server-wallet` on-call.
