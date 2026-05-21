# `qfc-approver` — reference approver daemon (Rust)

A standalone Cargo project that:

1. Listens on `--listen` for `POST /` webhooks from `qfc-server-wallet`.
2. Verifies the `X-QFC-Signature` HMAC-SHA256 header (constant-time).
3. Decides per `--auto-approve` / `--auto-reject` / `--interactive` /
   default-refuse policy.
4. Signs the canonical preimage via `qfc_quorum::SignedApproval::signing_preimage`.
5. POSTs `SubmitApprovalRequest` to `{server}/requests/{request_id}/approvals`.
6. Appends an NDJSON audit record to `~/.qfc-approver/audit.log`.

It is **not** a workspace member of `qfc-server-wallet`. Fork this
directory as a starting point for your production daemon.

## Quickstart

```sh
# 0. Have Rust 1.88+ installed.
rustup default 1.88

# 1. Build.
cd clients/approver-rs
cargo build --release

# 2. Generate a 32-byte signing key.
head -c 32 /dev/urandom > approver.key
chmod 600 approver.key

# 3. Register yourself on the server (out of band, by the wallet operator):
#    POST /approvers
#    {
#      "identity": {
#        "kind": "external",
#        "id": "alice@example",
#        "public_key_hex": "<hex of `ed25519::PublicKey::from(approver.key)`>",
#        "scheme": "ed25519"
#      },
#      "label": "alice@example",
#      "owner_id": "tenant-alpha",
#      "webhook_url": "https://alice.example/approver"
#    }
#    Save the returned `approver_id` ULID.

# 4. Generate a webhook secret and share it with the server operator
#    (passed into WebhookApproverConfig::hmac_secret when the server
#    builds its WebhookApprover for your URL).
head -c 32 /dev/urandom | base64 > webhook.secret

# 5. Run.
cargo run --release -- \
  --listen 0.0.0.0:7000 \
  --server https://qfc-wallet.example \
  --approver-id 01HABCDEFGHJKMNPQRSTVWXYZ0 \
  --secret-file ./approver.key \
  --scheme ed25519 \
  --webhook-secret "@./webhook.secret" \
  --interactive
```

## CLI

```
qfc-approver --help
```

| Flag | Default | Meaning |
| --- | --- | --- |
| `--listen` | `0.0.0.0:7000` | Where the webhook receiver binds. |
| `--server` | required | qfc-server-wallet base URL. |
| `--approver-id` | required | Your registered ULID. |
| `--secret-file` | required | 32 raw bytes (ed25519 seed / secp256k1 scalar). |
| `--scheme` | `ed25519` | `ed25519` or `secp256k1`. |
| `--webhook-secret` | required | HMAC secret; prefix with `@` to read from a file. |
| `--auto-approve` | `false` | Approve every request. **Demo only.** |
| `--auto-reject` | `false` | Reject every request. |
| `--interactive` | `false` | Prompt the operator on stdin. |
| `--audit-path` | `~/.qfc-approver/audit.log` | NDJSON audit destination. |

If none of `--auto-approve` / `--auto-reject` / `--interactive` are set
the daemon runs in fail-closed `refuse` mode: every webhook is logged
and dropped.

## Embedding

The `qfc_approver` library exports the `Processor`, `AppState`, and
`router(...)` so you can embed the receiver into your own axum service
without taking on the binary:

```rust
use qfc_approver::{router, AppState, ApproverSigner, DecisionPolicy, Processor, ProcessorConfig};

let signer = ApproverSigner::new(secret, qfc_wallet_types::SigningScheme::Ed25519)?;
let processor = Processor::new(signer, http_client, ProcessorConfig {
    server: "https://wallet.example".into(),
    approver_id: my_id,
    policy: DecisionPolicy::Interactive,
    audit_path: "/var/log/qfc/approver.log".into(),
});
let app = router(AppState {
    hmac_secret: Arc::new(my_webhook_secret),
    processor,
});
```

## Tests

```sh
cargo test
```

15 tests: unit tests for HMAC verification (4), signer round-trip (3),
audit NDJSON (1), processor refuse / approve flows (2), end-to-end
webhook-to-POST (2), preimage compat against the server-side helper (2),
plus the `lib.rs` re-exports.

## Security notes

See [`../README.md`](../README.md). In short:

- The webhook secret authenticates the server to you.
- The signing key authorises wallet operations on your behalf.
- `--auto-approve` is fine for staging / demos but never for production.
