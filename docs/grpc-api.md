# gRPC API

**Status:** v1 — shipped 2026-05-21
**RFC reference:** §1.5 (tonic chosen), §7 M4 (gRPC alongside HTTP), §10 decision #7 (HTTP first → gRPC now)

`qfc-server-wallet` exposes its wallet, sign, audit, and quorum surfaces over
**both** HTTP/JSON (axum) and gRPC (tonic). Both transports back the same
`Arc<WalletService>` handler core — there is zero logic duplication.

## Why both transports

- **HTTP** stays the friendliest surface for browsers, low-volume
  integrations, manual `curl` debugging, and the auto-generated Swagger
  UI under `/docs`. It's also what the M2 P1 reference docs already
  show, so existing operator runbooks keep working.
- **gRPC** is the high-throughput, strongly-typed surface for backend-to-
  backend integrations: language clients are auto-generated from the
  protos, payloads are smaller (binary encoding + raw `bytes` for keys/
  hashes instead of hex strings), and connections are multiplexed over
  HTTP/2.

Both bind by default; either can be disabled at startup via env vars
(see "Operator knobs" below). Streaming RPCs are deliberately out of
scope for this PR — the M2 surface is unary. Streaming for audit-event
tailing is a separate proposal.

## Service map

The proto package is `qfc.wallet.v1`.

### `Wallet`
| RPC              | HTTP analog                |
|------------------|----------------------------|
| `CreateWallet`   | `POST /wallets`            |
| `GetWallet`      | `GET /wallets/{id}`        |
| `Sign`           | `POST /wallets/{id}/sign`  |
| `GetAuditEvents` | `GET /audit/events`        |

### `Approver`
| RPC                  | HTTP analog                                 |
|----------------------|---------------------------------------------|
| `RegisterApprover`   | `POST /approvers`                           |
| `RevokeApprover`     | `DELETE /approvers/{id}`                    |
| `GetApprover`        | `GET /approvers/{id}`                       |
| `ListApprovers`      | `GET /approvers?owner=`                     |
| `CreateApproverSet`  | `POST /approver-sets`                       |
| `GetApproverSet`     | `GET /approver-sets/{id}`                   |
| `ListApproverSets`   | `GET /approver-sets?owner=`                 |
| `SubmitApproval`     | `POST /requests/{id}/approvals`             |
| `ListApprovals`      | `GET /requests/{id}/approvals`              |

## Wire conventions

| HTTP/JSON              | gRPC/proto                    | Why |
|------------------------|-------------------------------|-----|
| ULIDs as strings       | strings                       | Same human-readable form; trivially copy/paste between curl and grpcurl |
| Keys / signatures / hashes as **hex strings** | raw `bytes` | Binary surfaces don't need a hex detour; saves CPU and bytes on the wire |
| Timestamps as `int64` unix-ms | `int64` unix-ms        | Already the audit-event convention |
| Enums as snake-case strings | proto enums with explicit numeric values + `*_UNSPECIFIED` zero variant | proto convention; `_UNSPECIFIED` makes the default-zero case fail loudly instead of silently mapping to a real choice |
| JSON `extra` blobs (typed-data, audit details, attestation) | `string` carrying the JSON | Keeps protos out of the structured-JSON business; HTTP and gRPC see the same bytes |
| Optional fields  | proto3 `optional` / empty-string / zero-value sentinels per field | See per-message comments in `proto/*.proto` |

## Auth

gRPC clients authenticate with the same `x-api-key` allow-list as the
HTTP server. Pass the key in request metadata:

```rust
let mut req = Request::new(message);
req.metadata_mut().insert("x-api-key", "dev-key-1".parse().unwrap());
```

Missing or unknown keys return `tonic::Code::Unauthenticated`. The key
store is loaded once at startup from `QFC_SERVER_WALLET_API_KEYS`
(comma-separated). The membership check is constant-time per the same
`subtle::ConstantTimeEq` helper the HTTP middleware uses.

## Reflection (dev convenience)

When built with the default `reflection` feature, the server registers
`grpc.reflection.v1.ServerReflection` so `grpcurl` / `evans` / `bloomrpc`
can introspect the schema without compiled stubs:

```bash
# List services
grpcurl -plaintext localhost:9090 list

# Describe a method
grpcurl -plaintext localhost:9090 describe qfc.wallet.v1.Wallet.CreateWallet

# Fire a request
grpcurl \
  -plaintext \
  -H 'x-api-key: dev-key-1' \
  -d '{"scheme":"SIGNING_SCHEME_ED25519","threshold":2,"total":3,"display_name":"demo","owner_id":"tenant-x"}' \
  localhost:9090 qfc.wallet.v1.Wallet/CreateWallet
```

For production deployments, set `QFC_SERVER_WALLET_DISABLE_REFLECTION=1`
(or build with `--no-default-features`) to drop the reflection service.
Reflection itself is harmless — it only exposes proto definitions, not
business data — but reducing surface area is good hygiene.

## Operator knobs

| Env var                                | Default            | Purpose |
|----------------------------------------|--------------------|---------|
| `QFC_SERVER_WALLET_HTTP_BIND`          | `127.0.0.1:8088`   | HTTP TCP bind. Falls back to `QFC_SERVER_WALLET_BIND` for back-compat. |
| `QFC_SERVER_WALLET_GRPC_BIND`          | `127.0.0.1:9090`   | gRPC TCP bind. |
| `QFC_SERVER_WALLET_DISABLE_HTTP`       | (unset)            | If set non-empty, skip starting the HTTP server. |
| `QFC_SERVER_WALLET_DISABLE_GRPC`       | (unset)            | If set non-empty, skip starting the gRPC server. |
| `QFC_SERVER_WALLET_DISABLE_REFLECTION` | (unset)            | If set non-empty, do not register `grpc.reflection.v1`. |
| `QFC_SERVER_WALLET_API_KEYS`           | (required)         | Comma-separated allow-list. Applies to both transports. |

Both servers share a single graceful-shutdown future. SIGINT / SIGTERM
terminates both concurrently.

## Status-code mapping

The two transports use different conventions; the mapping is consistent.

| Failure                                 | HTTP                          | gRPC                                |
|-----------------------------------------|-------------------------------|-------------------------------------|
| Malformed request body / hex / ULID     | 400 `bad_request`             | `INVALID_ARGUMENT`                  |
| Missing / wrong API key                 | 401 `unauthorized`            | `UNAUTHENTICATED`                   |
| Policy denied                           | 403 `policy_denied`           | `PERMISSION_DENIED`                 |
| Wallet / approver / set not found       | 404 `wallet_not_found`        | `NOT_FOUND`                         |
| Quorum collection failed / duplicate    | 409 `quorum_failed`           | `ABORTED` / `ALREADY_EXISTS`        |
| Signature / freshness / binding failed  | 422 `approval_verification_failed` | `FAILED_PRECONDITION`           |
| Backend failure                         | 500 `internal_error`          | `INTERNAL`                          |

See `grpc/convert.rs::map_service_error` / `map_registry_error` for the
authoritative source.

## What's NOT in this PR

- A stand-alone gRPC client SDK. Clients can either generate stubs from
  the `proto/*.proto` files themselves, or build off the auto-generated
  ones the test suite uses internally. A published client crate is a
  follow-up (`docs/grpc-decisions.md` D47).
- Streaming RPCs. `GetAuditEvents` is unary, returning a bounded
  most-recent batch. Server-streaming audit tailing is a separate
  proposal — it needs a paging cursor + backpressure design.
- TLS termination. In production the gRPC server is expected to sit
  behind a reverse proxy (envoy, nginx) that terminates TLS; the
  reverse-proxy story is identical to the HTTP server's. Direct-TLS
  support via `tonic`'s `tls` feature is a one-line opt-in if needed.
