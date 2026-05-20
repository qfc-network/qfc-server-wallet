# M4 — key technical decisions

A record of the non-obvious calls made during M4 (real M-of-N quorum
backend) implementation. Each entry: **what** was decided, **why**, and
**what the alternatives were**. Decisions that follow directly from the
RFC are not repeated here — see `server-wallet-rfc.md` §10.

Generated alongside the `feat/m4-quorum` branch (2026-05-21).

Mirrors `docs/m1-decisions.md` in format.

---

## D21 — Add `ApproverSetId` + `ApproverId` newtypes to `qfc-wallet-types`

**What:** Two new ULID newtypes — `ApproverSetId` (the M-of-N group) and
`ApproverId` (one registered approver record). Replaces the M1 placeholder
where `qfc-policy::PolicyDecision::RequireQuorum` carried `ApprovalId` (the
single-action id) as a stand-in for the set id.

**Why:** Three distinct domain concepts had been collapsing onto
`ApprovalId`:

- the set of approvers (configuration)
- the individual approver record (registry)
- the action of approving (one signed payload)

Carrying all three on the same ULID type means a typo can route an audit
event to the wrong subject. Distinct types make the difference a compile
error.

**Alternatives considered:**

- Continue using `ApprovalId` for both action and set. Rejected — it
  hides the conceptual error.
- Use `String`s everywhere. Rejected — strings don't enforce that the
  policy decision and registry use the same id space.

---

## D22 — Approver registry, approval store, and policy all live in `qfc-quorum`

**What:** `qfc-quorum` grew three new modules — `registry`, `store`,
`approvers` — without splitting into a separate crate.

**Why:** Each module is small (≤ 400 LoC), and they share the
`ApproverIdentity` + `SignedApproval` types defined here. Splitting would
have created a new workspace edge with no real seam — the same code, more
boilerplate. The crate boundary `qfc-quorum` is already "approver
coordination"; this is approver coordination.

**Alternatives considered:**

- Spin out `qfc-approvers` for the registry. Rejected — circular dep
  with `qfc-quorum` for `ApproverIdentity`.
- Split `approval-store` from `quorum`. Rejected — the orchestrator
  needs both; splitting forces an `Arc<dyn ApprovalStore>` import that
  buys nothing.

---

## D23 — `ApprovalStore::record_approval` returns an outcome enum, not a bool

**What:** The store returns `RecordOutcome::{Inserted, AlreadyRecorded}`
on success, and `StoreError::DuplicateApproval(ApproverId, RequestId)` on
a *different* payload from the same approver.

**Why:** Three cases — "first persist", "idempotent retry", "duplicate
payload" — collapse poorly onto bool/error. Idempotent retry must be
silent success (the HTTP handler returns 200, not 409), but a different
payload from the same approver is a 409. The enum makes the contract
explicit and the HTTP mapping unambiguous.

**Alternatives considered:**

- Return `Result<(), Error>` with `AlreadyRecorded` as a soft error.
  Rejected — Rust idiom is `Result` for "did the operation succeed";
  retry detection isn't a failure.
- Always insert and dedupe on read. Rejected — race window between
  insert and dedupe; the DB-level UNIQUE constraint is the only honest
  source of truth.

---

## D24 — Replay protection is a DB UNIQUE constraint, not an application-level lock

**What:** `(request_id, approver_id) UNIQUE` on the `approvals` table.
The Postgres backend does a SELECT-then-INSERT inside a transaction; the
race window between the two operations is closed by the DB raising the
unique-violation error, which the application maps to `DuplicateApproval`.

**Why:** The DB constraint is the single source of truth — concurrent
inserts from two pods would race past any application-level lock that
isn't DB-backed. Carrying the UNIQUE constraint and handling the race
through error-on-conflict is more honest than building a distributed
locking layer.

**Alternatives considered:**

- Pessimistic application-level lock per `(request_id, approver_id)`.
  Rejected — only works in single-process deployments.
- `pg_advisory_lock` per pair. Rejected — UNIQUE plus race-detection is
  cleaner; advisory locks add a tx-overhead penalty per submission.

---

## D25 — Approval freshness check uses `MAX_APPROVAL_AGE_SECS = 3600`, same as M1

**What:** The default age cap stays at one hour (see M1 D17). Per-set
override is exposed as `ApproverSet::quorum_timeout_secs`, but the
*signature freshness* limit (how stale the signed payload itself can be)
remains the M1 constant.

**Why:** Two distinct timeouts here — the *signature freshness* (how stale
the signed approval payload can be at verification time) and the *quorum
collection window* (how long the orchestrator waits for enough approvals).
M4 introduces the second; M1 picked the first. Keeping them separate
avoids the API gotcha "I set my collection timeout to 60 minutes but my
signatures expire at 1 hour anyway".

**Alternatives considered:**

- Merge the two into one knob per set. Rejected — they answer different
  questions.

---

## D26 — Cycle detection via DFS over co-membership, capped at depth 3

**What:** `MAX_NESTING_DEPTH = 3`. The walker starts from each
`NestedWallet(WalletId)` member in the new set, finds existing sets that
contain `NestedWallet(W)` for that wallet, and recurses through their
*other* nested-wallet co-members. Visiting the same wallet twice → cycle;
exceeding depth → too-deep.

**Why:** The registry has no `WalletId → ApproverSetId` map at the
storage layer (sets exist before attachment). The cycle check we can run
*at create-set time* is therefore "does the new set, plus the existing
sets, form a cycle through nested-wallet membership?" — which is what the
DFS computes. Depth-3 is a hard cap so even pathologically wide nesting
gets rejected fast.

**Alternatives considered:**

- Defer cycle detection to wallet-attach time. Rejected — the brief
  asked for it at create-set time, and once a set has been used by any
  wallet, "we should not have allowed the create" is too late.
- Allow arbitrary depth and rely on runtime quorum-collection timeout.
  Rejected — silent recursion to depth 100 burns operator time. Depth-3
  matches the M5 plan for cross-TEE composition.

**Honest caveat:** the registry's cycle check is necessarily conservative
— it walks every existing set that mentions a nested wallet, even sets
that are unattached. The walk may "see" a cycle the operator wouldn't
actually trip in practice. Operators who hit this surface the error
message and remove the redundant set.

---

## D27 — Webhook uses HMAC-SHA256 in `X-QFC-Signature` (hex-lowercase)

**What:** `WebhookApprover` POSTs `application/json` and sets
`X-QFC-Signature` to `hex(HMAC-SHA256(secret, body))`. Receivers
recompute and compare constant-time.

**Why:** Industry-standard webhook signing (Stripe, GitHub, Slack all use
this shape). Hex (not base64) because the QFC ecosystem already uses
hex everywhere else; one less encoding for operators to remember.
SHA-256 because it's available everywhere; SHA-512 is overkill for a
≤4KiB body.

**Alternatives considered:**

- Ed25519 signature over the body. Rejected — requires the server to
  ship a public key out-of-band, complicating onboarding. HMAC's shared
  secret is friendlier for a webhook UX.
- mTLS instead of HMAC. Rejected — too heavy for a notification channel;
  customers can layer TLS independently.

---

## D28 — `OnChainQfcEventApprover` is a STUB behind `tokio::broadcast`

**What:** Today the on-chain approver emits an `OnChainEvent` into an
in-memory broadcast channel. Real chain submission is gated on
`qfc-core` integration (RFC §1.4) which is not in the workspace yet. The
type, trait impls, and a fan-out path exist so M5 can replace just the
emit body with a real chain tx.

**Why:** Per retro-m1-m2 §3.6, the workspace deliberately has zero
`qfc-core` dependency. Shipping a stub keeps the M4 task closed without
introducing that dependency. The audit event "we tried to notify the
on-chain channel" still fires; subscribers can prove behavior.

**Alternatives considered:**

- Skip the channel entirely until `qfc-core` lands. Rejected — the
  notifier trait shape gets exercised, including failure modes.
- Submit via the QFC RPC (no `qfc-core` needed). Rejected — encoding the
  tx without `qfc-core` types means duplicating types that will diverge.

---

## D29 — `HardwareApproverNotifier` is structurally distinct from `WebhookApprover`

**What:** Same wire shape (POST + HMAC), but a separate type that
identifies as `"hardware"` in audit logs and is composable via
`OrchestratingApprover`.

**Why:** In ops dashboards "this approver dispatches over webhook" and
"this approver dispatches to a hardware-token client" are different
categories the SRE wants to see at a glance. Code-wise it's a 50-line
wrapper; the type system enforces "you can't drop a hardware approver
where a generic webhook one is expected" without a rename.

**Alternatives considered:**

- One `WebhookApprover` with a `kind` field. Rejected — extra runtime
  check, weaker dashboards.

---

## D30 — `OrchestratingApprover` polls + uses `Notify` to wake on arrival

**What:** The collector polls the approval store with a configurable
backoff (default 50ms) but also waits on a `tokio::sync::Notify`. The
HTTP submission handler calls `notify_arrival` after a successful
`record_approval`, so the collector wakes immediately and re-checks.

**Why:** Polling-only handles the case where the submitter is a separate
process / a Postgres-backed deployment with multiple readers. Notify-only
handles the in-process case. Combining both gives correctness across
deployments (long-poll-style latency in-process, polling fallback
cross-process) without locking either case to a specific deployment.

**Alternatives considered:**

- Pure polling. Rejected — adds up-to-`backoff` latency to every
  in-process approval flow.
- Pure `broadcast` channel. Rejected — sender-side fan-out doesn't
  cross process boundaries. Postgres-backed deployments need polling.
- Postgres `LISTEN/NOTIFY`. Deferred — requires extending the store
  trait; revisit if polling latency becomes a real problem.

---

## D31 — Audit emits `QuorumThresholdReached` distinct from `QuorumApprovalReceived`

**What:** New `AuditKind::QuorumThresholdReached(16)` lands as kind byte
16. It fires once per quorum after the orchestrator has collected
`threshold` Approve approvals, BEFORE the enclave sign call.

**Why:** Operators reading the audit log want to distinguish "we got the
2nd Approve" (data-plane event) from "we reached threshold and the
sign is unblocked" (control-flow milestone). Without a separate event the
two collapse; with it, dashboards can render "time to threshold" as a
single metric.

**Alternatives considered:**

- Reuse `QuorumApprovalReceived` with a `threshold_reached: bool` flag.
  Rejected — flag-in-payload pattern complicates downstream pipelines.

---

## D32 — `WalletService` defaults to in-memory registry + store; opt-in to Postgres

**What:** `WalletService::new(...)` creates `MemoryApproverRegistry` and
`MemoryApprovalStore` by default. Production swaps via
`with_approver_registry` / `with_approval_store`.

**Why:** Most M1+M2 tests already build `WalletService::new(...)`;
keeping the default in-memory means those tests don't need to know about
the registry. Production binaries (the `qfc-server-wallet` binary that
lands in M3) will explicitly wire the Postgres-backed instances.

**Alternatives considered:**

- Require explicit registry on construction. Rejected — churns every
  existing test signature.
- Ship two constructors (`new_in_memory`, `new_with_postgres`).
  Rejected — the builder pattern (`.with_*`) composes cleaner with
  future backends (Vault, etc.).

---

## D33 — Migration lives in `qfc-quorum/migrations/0002_approvers.sql`

**What:** The new migration is named `0002_approvers.sql` and lives in
the `qfc-quorum` crate, parallel to `qfc-audit/migrations/0001_init.sql`.
Each crate carries its own migrator.

**Why:** Two migration sources, two embedded migrators, no shared
schema metadata table needed (sqlx tracks `_sqlx_migrations` per
migrator). Mirrors the qfc-audit pattern and avoids a "central
migrations crate" anti-pattern.

**Trade-off:** if the two crates ever need a join-table or a foreign
key crossing crate boundaries, this layout makes that awkward. Today
they don't — approvals don't FK to audit_events or vice versa.

**Alternatives considered:**

- Single `qfc-server-wallet/migrations/` directory. Rejected — couples
  the orchestrator to schema concerns of subordinate crates.

---

## D34 — Registry trait surface accepts owned values, not borrowed slices

**What:** `add_approver(create: ApproverCreate)`, not
`add_approver(create: &ApproverCreate)`. Same for
`create_approver_set(create: ApproverSetCreate)`.

**Why:** Both backends move fields out of the create payload
(memory inserts into the map, postgres binds into the query). Borrowing
would force every call site to either clone or live with awkward
lifetime obligations. Owned values is one extra clone at the HTTP
boundary, which already deserializes a fresh struct.

**Alternatives considered:**

- Borrow + clone internally. Rejected — silent clones surprise readers.

---

## D35 — Approval submission API verifies signature *before* persisting

**What:** `WalletService::record_approval` runs `SignedApproval::verify`
against the freshly-stored approver identity *before* calling
`ApprovalStore::record_approval`. A failed signature rejects with HTTP
422 (`UnprocessableEntity`).

**Why:** Persisting an unverified approval pollutes the store with
"someone tried to submit garbage" rows. Failing fast keeps the store
clean and gives the submitter an immediate diagnostic.

**Trade-off:** an attacker can probe by sending malformed signatures —
they get the same 422 every time, no information leak.

**Alternatives considered:**

- Persist first, verify on collection. Rejected — garbage retention.
- Verify on collection only. Rejected — signature failures become
  silent (collector just doesn't count them).

---

## D36 — `OnChainQfcEventApprover` exposes `subscribe()` only, no synchronous read

**What:** Tests and downstream consumers receive a fresh
`broadcast::Receiver` via `subscribe()`. No `try_recv_all` or
"give me everything queued" surface.

**Why:** `broadcast` is fire-and-forget; once a subscriber misses an
event (closed channel, lag), that event is gone. Keeping the API
deliberately minimal forces consumers to be honest about that
contract — and matches what a real chain submitter would offer (you
either watched the event when it fired, or you didn't).

---

## D37 — No telemetry-level changes for M4 metrics

**What:** We reuse the M2 P5 `qfc_server_wallet_quorum_collect_seconds`
histogram; no new metrics are added in M4.

**Why:** The new HTTP routes naturally pick up the existing
`tower_http::trace::TraceLayer`, and the orchestrator's
`collect_approvals` runs inside the same `WalletService::sign` span the
M2 P5 instrumentation captured. Adding more metrics would have made
the M4 footprint noisier without surfacing genuinely new signals.

**Alternatives considered:**

- Per-channel notify counter (webhook vs hardware vs onchain). Deferred
  — operators don't yet have a "by channel" dashboard.
- Per-approver-set quorum-collection histogram. Deferred — useful but
  needs cardinality controls (one bucket per set blows up Prometheus
  series).
