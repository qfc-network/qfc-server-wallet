# Rust gRPC client SDK

The reference Rust gRPC client SDK lives at
[`clients/wallet-grpc-rs/`](../clients/wallet-grpc-rs/). It is a
standalone Cargo project — **not** a member of the main
`qfc-server-wallet` workspace — so production integrators can fork it
without inheriting the wallet's dep tree (axum + sqlx + utoipa + the
full enclave / policy / quorum / audit stack).

See [`clients/wallet-grpc-rs/README.md`](../clients/wallet-grpc-rs/README.md)
for the quickstart, API surface, and usage examples.

## Why this is a separate deliverable

`feat/grpc-api` (PR #23) shipped the server-side gRPC surface but
deliberately deferred the published client SDK — see
[`grpc-decisions.md` D47](grpc-decisions.md#d47). The four reasons
listed there:

1. The server's `tonic-build` already emits client stubs for the
   integration tests. Anyone who needs raw stubs can lift them from
   `qfc_server_wallet::grpc::proto` (with the caveat that they pull
   the whole wallet dep tree).
2. Most M2/M3 integrators are HTTP-first; gRPC is a follow-on.
3. A published SDK needs versioning + a backwards-compat story; that
   work belongs after the proto layout stabilises.
4. Hand-rolling the client from the `.proto` files is a few hours of
   work for anyone comfortable with tonic.

This SDK closes (1) and (4) — the integration-test stubs become a
proper crate with ergonomic wrappers, typed errors, and runnable
examples. Versioning (3) is documented in the SDK's README.

## What's in the box

- Ergonomic `WalletClient` + `ApproverClient` wrappers (builder pattern,
  no `Option<*View>` envelopes on the success path).
- A typed `SdkError` that maps the common `tonic::Status` codes to
  named variants (`Unauthenticated`, `NotFound`, `AlreadyExists`, …).
- A client-side `ApiKeyInterceptor` mirroring the server-side
  `qfc_server_wallet::grpc::auth::ApiKeyInterceptor`.
- Four runnable examples (`create_wallet`, `sign_message`,
  `submit_approval`, `list_audit_events`).
- An in-process e2e test suite that spins up a real tonic server on an
  ephemeral port and drives the SDK against it.

## What's NOT in the box

- A CLI binary. The crate is a library; the examples are runnable but
  they're not a daily-use CLI.
- Streaming RPCs. The M2 surface is unary; an audit-event tailing
  stream is a separate proposal.
- A TypeScript / Go / Python gRPC client. Each language gets its own
  package; this crate is Rust-only.
- TLS termination. Same story as the server: operators terminate at
  envoy / nginx in production.

## Related docs

- [`grpc-api.md`](grpc-api.md) — operator-facing gRPC surface (service
  map, wire conventions, auth, status-code mapping, env knobs).
- [`grpc-decisions.md`](grpc-decisions.md) — server-side gRPC decisions
  (D46–D52). Most relevant: D47 (this SDK is the deferred deliverable)
  and D49 (the `result_large_err` trade-off the SDK inherits).
- [`clients-decisions.md`](clients-decisions.md) — client-pattern
  decisions, including D55 (proto file copy vs symlink), D56 (dev-dep
  on the wallet crate), D57 (local SDK types), D58 (typed `SdkError`).
- [`runbooks/00-deploy.md`](runbooks/00-deploy.md) — how to obtain an
  API key for the SDK to authenticate with.
