# gRPC surface — non-obvious decisions

Continuation of the project-wide decision log (D1–D45 across
`m1-decisions.md` … `m5-decisions.md`). These cover the `feat/grpc-api`
PR specifically — RFC §10 decision #7 ("HTTP first, gRPC later") becoming
"HTTP plus gRPC, now."

## D46 — Proto types are NOT the same as the HTTP DTOs

The HTTP DTOs in `api::schemas` are hex-string-flavored (`signature_hex:
String`, `master_public_key_hex: String`, …) and depend on `utoipa` for
OpenAPI annotations. The gRPC surface needs raw `bytes` (no hex detour)
and must not pull `utoipa` into the proto types.

We could have used the HTTP DTOs as the source of truth and added a
`From<Dto> for ProtoMessage` adapter layer. That would couple every
future HTTP DTO tweak to a proto recompile, and force every gRPC handler
through a hex-encode/decode pass that the binary surface specifically
exists to avoid.

Instead: the proto definitions are their own type system. The
`convert::*` helpers translate **between proto types and domain types**
(`SigningPayload`, `Requester`, `ApproverIdentity`, …), not between proto
and HTTP. HTTP and gRPC are siblings, both adapting to the domain.

Trade-off: enum names live in two places (snake-case strings in HTTP
JSON; explicit `*_UNSPECIFIED`-prefixed proto enums in gRPC). The mirror
is mechanical and the mismatch is detected at build time (proto enum
exhaustiveness check). Acceptable.

## D47 — No published gRPC client SDK in this PR

The build script enables `tonic_build::build_client(true)` so the
integration tests can use auto-generated stubs in-process. The crate
does **not** publish a separate `qfc-server-wallet-client` crate; doing
so would either:

- Force the consumer to depend on the full `qfc-server-wallet` (which
  drags in axum, utoipa, swagger-ui, the policy engine, …), or
- Require a third top-level crate (`crates/qfc-server-wallet-client`)
  that owns just the proto files + client stubs + a `transport` shim.

Both are reasonable; both can be added later without rework. For now,
external consumers can run `tonic-build` themselves over the
`crates/qfc-server-wallet/proto/` directory — the protos are
intentionally vendor-free (only `import "common.proto"`).

## D48 — Reflection is feature-gated, default-on

`tonic-reflection` enables `grpc.reflection.v1.ServerReflection`, which
lets `grpcurl` describe / list / fire methods without compiled stubs.
This is a huge dev-loop win and adds nothing material to the attack
surface (proto schemas are not secrets — they're committed in the repo).

But: prod deployments may want minimal surface area, and reflection
pulls in `prost-types` + a static `FileDescriptorSet`. We gate it behind
a `reflection` cargo feature (default on) so prod builds can drop it
with `cargo build --no-default-features`, and we expose a runtime
`QFC_SERVER_WALLET_DISABLE_REFLECTION` knob for operators who want the
feature compiled in but disabled at runtime (e.g. behind a feature flag).

## D49 — `tonic::Status::Err` is intrinsically large; `clippy::result_large_err` is silenced module-wide

`tonic::Status` carries a `hyper::HeaderMap` for trailing metadata; it
clocks in around 176 bytes. Every handler returns `Result<_, Status>`,
which trips clippy's `result_large_err` at the workspace's `-D warnings`
clippy gate. Boxing the Status (`Result<_, Box<Status>>`) would force
every call site to unbox, defeat the auto-impls the generated server
stubs rely on, and break the standard tonic ergonomics.

We `#![allow(clippy::result_large_err)]` at the top of each `grpc/*.rs`
file with a one-line comment pointing back to this decision. The other
crates' `Result<_, ApiError>` etc. are unaffected.

## D50 — `tonic` 0.12 / `prost` 0.13 / `tonic-reflection` 0.12

Pinned by workspace alignment with `opentelemetry-otlp 0.26`'s
`grpc-tonic` feature, which already depends on `tonic 0.12`. Bumping
either independently risks a duplicate-tonic build (and a confusing
compile error about mismatched `Status` types). When `opentelemetry-otlp`
bumps next, we bump in lockstep.

## D51 — Both servers start by default, share state via `Arc<AppState>`

The binary `main.rs` constructs a single `AppState` (containing the
`Arc<WalletService>`, the API-key set, and the audit path) and spawns
two tokio tasks: one for axum/HTTP, one for tonic/gRPC. Both block on
the same `shutdown_signal()` future (SIGINT / SIGTERM races). If either
server returns an error, the binary surfaces the first one and exits.

Alternative considered: a single `tower::Service` that multiplexes
HTTP/1.1 + gRPC on one port. Rejected: the multiplexing trick (axum's
`merge` with `tonic_web`) is brittle (HTTP/2 prior-knowledge issues,
TLS termination splits) and forces every operator to terminate two
protocols on the same listener. Cleaner to bind two ports and let the
reverse-proxy layer route by ALPN / port.

## D52 — Audit-log reader is duplicated between HTTP and gRPC handlers

`api::handlers::read_audit_events` and
`grpc::wallet::read_audit_events` are both private file-tailing readers
over the same NDJSON file. They are byte-identical save for the error
type (`ApiError` vs `String`).

This violates the "zero logic duplication" rule on its face. The
rationale for not extracting to `WalletService`:

1. The audit reader is M2 P1 scaffolding. M2 P2 lands
   `pg_audit_sink` which makes the file-tailer obsolete. Lifting the
   reader to `WalletService` only to delete it in the next PR adds
   churn for no gain.
2. The "duplication" is 30 lines of NDJSON line-iteration. The
   business logic is in `WalletService`; the audit reader is pure I/O.

When M2 P2 lands, both handlers will call into a new
`WalletService::list_audit_events(filter)` method and these two private
helpers disappear together. Tracked in `docs/retro-m1-m2.md`.
