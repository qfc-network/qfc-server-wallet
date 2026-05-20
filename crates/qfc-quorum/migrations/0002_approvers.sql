-- M4: approver registry + approval store schemas.
--
-- See `docs/server-wallet-rfc.md` §2.5 and `docs/m4-decisions.md` (M4).
--
-- This migration ships THREE tables that together replace the M1 mock
-- `MockQuorumApprover` with a real backend:
--
--   * `approvers`            — one row per registered approver (person/key/HW/nested wallet).
--   * `approver_sets`        — one row per approver set; M-of-N + owner.
--   * `approver_set_members` — join table; preserves member order via `position`.
--   * `approvals`            — one row per submitted SignedApproval, with the
--                              `(request_id, approver_id)` UNIQUE constraint that
--                              gives us replay protection at the DB layer.
--
-- Identity is stored as JSONB so the four variants of `ApproverIdentity`
-- (Chain / External / Hardware / NestedWallet) round-trip without forcing a
-- column-per-variant schema. The public key + scheme are duplicated to
-- columns alongside JSONB to make GIN queries cheap (rarely needed today
-- but the cost is one row).

CREATE TABLE IF NOT EXISTS approvers (
    approver_id       TEXT        PRIMARY KEY,
    identity          JSONB       NOT NULL,
    scheme            SMALLINT    NOT NULL,
    public_key        BYTEA       NOT NULL,
    label             TEXT        NOT NULL,
    owner_id          TEXT        NOT NULL,
    webhook_url       TEXT,
    status            SMALLINT    NOT NULL,  -- 1 = Active, 2 = Revoked
    added_at_unix_ms  BIGINT      NOT NULL,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS approvers_owner_idx ON approvers(owner_id);
CREATE INDEX IF NOT EXISTS approvers_status_idx ON approvers(status);

CREATE TABLE IF NOT EXISTS approver_sets (
    approver_set_id     TEXT        PRIMARY KEY,
    name                TEXT        NOT NULL,
    owner_id            TEXT        NOT NULL,
    threshold           SMALLINT    NOT NULL,
    total               SMALLINT    NOT NULL,
    quorum_timeout_secs INTEGER,
    created_at_unix_ms  BIGINT      NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS approver_sets_owner_idx ON approver_sets(owner_id);

CREATE TABLE IF NOT EXISTS approver_set_members (
    approver_set_id  TEXT        NOT NULL REFERENCES approver_sets(approver_set_id) ON DELETE CASCADE,
    approver_id      TEXT        NOT NULL REFERENCES approvers(approver_id) ON DELETE RESTRICT,
    position         SMALLINT    NOT NULL,
    PRIMARY KEY (approver_set_id, approver_id),
    UNIQUE (approver_set_id, position)
);

CREATE INDEX IF NOT EXISTS approver_set_members_approver_idx ON approver_set_members(approver_id);

-- Submitted approvals.
--
-- The `(request_id, approver_id)` UNIQUE constraint is the load-bearing
-- replay-protection rule: a given approver can record at most one decision
-- per signing request. Re-submission of the SAME approval payload (same
-- approval_id) is handled application-side as idempotent success; a
-- different payload from the same approver for the same request is a
-- 409-style violation surfaced as `DuplicateApproval`.
CREATE TABLE IF NOT EXISTS approvals (
    approval_id        TEXT        PRIMARY KEY,
    request_id         TEXT        NOT NULL,
    approver_id        TEXT        NOT NULL,  -- registry approver id (ApproverId)
    approver_key       TEXT        NOT NULL,  -- ApproverIdentity::key() (audit anchor)
    approver_identity  JSONB       NOT NULL,  -- full ApproverIdentity payload
    message_hash       BYTEA       NOT NULL,
    decision           SMALLINT    NOT NULL,  -- 1 = Approve, 0 = Reject
    signature          BYTEA       NOT NULL,
    timestamp_unix_ms  BIGINT      NOT NULL,
    received_at_unix_ms BIGINT     NOT NULL,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (request_id, approver_id)
);

CREATE INDEX IF NOT EXISTS approvals_request_idx ON approvals(request_id);
CREATE INDEX IF NOT EXISTS approvals_approver_idx ON approvals(approver_id);
