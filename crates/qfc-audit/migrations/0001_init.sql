-- M2 P2: PostgresAuditSink schema.
--
-- See `docs/server-wallet-rfc.md` §2.6 and `docs/m1-decisions.md` D12/D13.
--
-- Layout:
--   - `event_id`          ULID string (PRIMARY KEY).
--   - `prev_event_hash`   32-byte SHA-256 hash; `SHA256(preimage ‖ signature)` of the
--                         immediately-preceding event. Genesis = 32 zero bytes.
--   - `kind`              SMALLINT — `AuditKind::kind_byte()` stable u8 tag (D13).
--   - `actor_kind`        SMALLINT — 1=Requester, 2=Approver, 3=System, 4=Enclave.
--   - `actor_id`          Nullable; populated only for Requester/Approver.
--   - `details`           JSONB; freeform per-kind payload.
--   - `server_signature`  64-byte ed25519 signature over the canonical preimage.
--   - `created_at`        DB-side timestamp (not signed, observability only).
--
-- Chain integrity is enforced application-side via `pg_advisory_xact_lock` on a
-- deterministic key + an ORDER BY-LIMIT-1 chain-head SELECT inside the same
-- transaction. See `src/postgres.rs::PostgresAuditSink::emit`.

CREATE TABLE IF NOT EXISTS audit_events (
    event_id          TEXT        PRIMARY KEY,
    prev_event_hash   BYTEA       NOT NULL,
    timestamp_unix_ms BIGINT      NOT NULL,
    actor_kind        SMALLINT    NOT NULL,
    actor_id          TEXT,
    kind              SMALLINT    NOT NULL,
    request_id        TEXT,
    wallet_id         TEXT,
    details           JSONB       NOT NULL,
    server_signature  BYTEA       NOT NULL,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS audit_events_wallet_id_idx
    ON audit_events(wallet_id) WHERE wallet_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS audit_events_request_id_idx
    ON audit_events(request_id) WHERE request_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS audit_events_timestamp_idx
    ON audit_events(timestamp_unix_ms);
