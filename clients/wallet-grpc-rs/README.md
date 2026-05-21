# `qfc-wallet-grpc` — reference Rust gRPC client SDK

A standalone Rust crate that wraps the `tonic`-generated stubs for
`qfc-server-wallet`'s gRPC API (`qfc.wallet.v1`) with:

- ergonomic `WalletClient` + `ApproverClient` wrappers (builder pattern,
  no `Option<*View>` envelopes on the success path);
- a typed `SdkError` that maps the common `tonic::Status` codes to
  named variants (`Unauthenticated`, `NotFound`, `AlreadyExists`, …);
- a client-side `ApiKeyInterceptor` that injects `x-api-key` on every
  outgoing RPC, mirroring the server-side interceptor.

The crate is **not** a member of the `qfc-server-wallet` workspace —
its `[workspace]` table is empty, so cargo treats it as a workspace root
of its own. Fork this directory as a starting point for your production
client; you won't inherit axum, sqlx, or the rest of the wallet's dep
tree.

The deferred deliverable from
[`docs/grpc-decisions.md` D47](../../docs/grpc-decisions.md#d47).

## Quickstart

```sh
# 0. Have Rust 1.88+ and protoc on PATH. (protoc is required at build
# time by tonic-build.)
rustup default 1.88
brew install protobuf      # or apt-get install protobuf-compiler

# 1. Run a server somewhere — see runbooks/00-deploy.md.
export QFC_SERVER=http://127.0.0.1:9090
export QFC_API_KEY=dev-key-1

# 2. Build + run an example.
cd clients/wallet-grpc-rs
cargo run --example create_wallet
```

## Library use

```toml
# Cargo.toml — point at the checkout (the crate isn't published).
[dependencies]
qfc-wallet-grpc = { path = "../qfc-server-wallet/clients/wallet-grpc-rs" }
tokio = { version = "1", features = ["full"] }
```

```rust
use qfc_wallet_grpc::{
    CreateWalletParams, SdkError, SigningScheme, WalletClient,
};

#[tokio::main]
async fn main() -> Result<(), SdkError> {
    let mut client = WalletClient::connect("http://127.0.0.1:9090")
        .api_key("dev-key-1")
        .wallet()
        .await?;

    let wallet = client
        .create_wallet(CreateWalletParams {
            scheme: SigningScheme::Ed25519,
            threshold: 2,
            total: 3,
            display_name: "demo".into(),
            owner_id: "tenant-a".into(),
            policy_id: None,
        })
        .await?;
    println!("wallet_id: {}", wallet.wallet_id);
    Ok(())
}
```

## API surface

### `WalletClient`

| Method                | RPC               | HTTP analog                |
|-----------------------|-------------------|----------------------------|
| `create_wallet`       | `CreateWallet`    | `POST /wallets`            |
| `get_wallet`          | `GetWallet`       | `GET /wallets/{id}`        |
| `sign`                | `Sign`            | `POST /wallets/{id}/sign`  |
| `get_audit_events`    | `GetAuditEvents`  | `GET /audit/events`        |

### `ApproverClient`

| Method                 | RPC                  | HTTP analog                          |
|------------------------|----------------------|--------------------------------------|
| `register_approver`    | `RegisterApprover`   | `POST /approvers`                    |
| `revoke_approver`      | `RevokeApprover`     | `DELETE /approvers/{id}`             |
| `get_approver`         | `GetApprover`        | `GET /approvers/{id}`                |
| `list_approvers`       | `ListApprovers`      | `GET /approvers?owner=`              |
| `create_approver_set`  | `CreateApproverSet`  | `POST /approver-sets`                |
| `get_approver_set`     | `GetApproverSet`     | `GET /approver-sets/{id}`            |
| `list_approver_sets`   | `ListApproverSets`   | `GET /approver-sets?owner=`          |
| `submit_approval`      | `SubmitApproval`     | `POST /requests/{id}/approvals`      |
| `list_approvals`       | `ListApprovals`      | `GET /requests/{id}/approvals`       |

Full operator-facing reference: [`docs/grpc-api.md`](../../docs/grpc-api.md).

## Auth

Every RPC carries an `x-api-key` metadata key, validated against the
same allow-list as the HTTP middleware. Obtain a key from the operator
(see [`docs/runbooks/00-deploy.md`](../../docs/runbooks/00-deploy.md))
and pass it to the builder:

```rust
WalletClient::connect("http://127.0.0.1:9090")
    .api_key(std::env::var("QFC_API_KEY")?)
    .wallet()
    .await?;
```

## Error handling

All client methods return `Result<_, SdkError>`. The well-known gRPC
status codes are mapped to typed variants:

```rust
use qfc_wallet_grpc::SdkError;

match client.get_wallet(&id).await {
    Ok(w) => { /* … */ }
    Err(SdkError::NotFound(msg)) => eprintln!("no such wallet: {msg}"),
    Err(SdkError::Unauthenticated(_)) => eprintln!("check api_key"),
    Err(SdkError::Transport(e)) => eprintln!("connection lost: {e}"),
    Err(e) => return Err(e),
}
```

The full mapping (and which server-side error each one comes from) is
in [`docs/grpc-api.md`](../../docs/grpc-api.md#status-code-mapping).

## Why a separate workspace

Same reason as [`clients/approver-rs`](../approver-rs/README.md): a
production fork shouldn't inherit `qfc-server-wallet`'s axum + sqlx +
full audit + policy stack. The empty `[workspace]` table makes cargo
treat this `Cargo.toml` as its own workspace root.

We do depend on `qfc-server-wallet` (and its sibling crates) in
`[dev-dependencies]` — but only so the e2e tests can spin up a real
server in-process. Production users that consume this SDK do not pull
those crates in. See
[`docs/clients-decisions.md`](../../docs/clients-decisions.md#d56)
D56 for why this trade-off is OK.

## Proto sourcing

`proto/*.proto` are a **copy** of `crates/qfc-server-wallet/proto/*.proto`,
not a symlink. Run [`tools/sync-protos.sh`](../../tools/sync-protos.sh)
to refresh; CI's `proto-sync-check` job enforces `git diff --exit-code`
on the copy. See
[`docs/clients-decisions.md`](../../docs/clients-decisions.md#d55) D55
for the trade-off.

## Tests

```sh
cd clients/wallet-grpc-rs
cargo test
```

11 tests: 3 unit (`error::tests::*` + `auth::tests::*` + `convert::tests::*`)
plus 8 e2e in `tests/e2e.rs` driving a real in-process tonic server.
Coverage: wallet happy path (create → get → sign → audit), approver
happy path (register → set → submit → list → revoke), auth failures
(missing key + wrong key), bad input (malformed ULID), not-found,
transport failure (dead port), failed-precondition (bad threshold),
client-side validation (short message_hash).

## Versioning

Tracks `qfc-server-wallet` minor versions. Major bump on a wire-format
break (e.g. proto message field renumbering). Until the server is at
1.0 we ship `0.1.x` and treat `0.x` minor bumps as potentially
wire-breaking.

## Requirements

- Rust 1.88+ (per the workspace `rust-toolchain.toml`).
- `protoc` on `PATH` at build time. The crate compiles its protos via
  `tonic-build`; bring your own `protoc` (e.g. `brew install protobuf`
  / `apt-get install protobuf-compiler`).

## What's NOT here

- A CLI binary. This crate is a library; the four `examples/` are
  runnable but they're examples, not a daily-use CLI.
- Streaming RPCs. The M2 surface is unary; an audit-tailing stream is a
  separate proposal.
- A TypeScript / Go / Python gRPC client. Each language gets its own
  package; this crate is Rust-only.
