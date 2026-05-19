# qfc-server-wallet

Server-side wallet subsystem for the QFC ecosystem: programmable treasury, agent wallets, enterprise approval flows.

- TEE-isolated key custody (AWS Nitro reference backend; trait-abstracted for SGX, TDX, Mock)
- Shamir Secret Sharing with M-of-N quorum and pluggable share stores
- Declarative policy DSL with multi-VM aware decoders (EVM today, QVM growing)
- Hash-chained audit log with daily on-chain anchor commitments
- Reproducible enclave image builds; public attestation verification

**Status:** pre-M1 bootstrap. See [`docs/server-wallet-rfc.md`](docs/server-wallet-rfc.md) for the v1.0 design RFC.

## Layout

```
crates/
  qfc-server-wallet/    # binary + top-level lib (HTTP API)
  qfc-enclave/          # TEE trait + MockEnclave (M1) + NitroEnclave (M3)
  qfc-sss/              # Shamir wrapper + ShareStore trait
  qfc-policy/           # Policy DSL + evaluator + VM decoders
  qfc-quorum/           # M-of-N approver coordination
  qfc-audit/            # AuditSink trait + backends
  qfc-wallet-types/     # internal: shared IDs, scheme/hash enums, SecretBytes
```

## Running locally with Docker

The repo ships a complete local-dev stack — server-wallet binary, Postgres,
OpenTelemetry collector, Mimir (Prometheus-compatible TSDB), and Grafana —
behind a single `docker compose` file. The compose file is wired to the
M2 surface (HTTP API on `:8080`, Prometheus exposition on `:9090`,
Postgres-backed audit, OTLP metrics -> Mimir -> Grafana). Until M2 P1
lands the server binary is still the M1 stub, but every other service in
the stack is fully functional and ready to receive traffic the moment
the new entrypoint ships.

### Bring up

```sh
docker compose up --build
```

After the build settles you'll have:

| Service          | URL                                            | Notes                              |
|------------------|------------------------------------------------|------------------------------------|
| HTTP API         | http://localhost:8080                          | API key header `X-API-Key: dev-key-1` |
| Prometheus scrape| http://localhost:9090/metrics                  | unauthenticated, text exposition   |
| Grafana          | http://localhost:3000 (admin / admin)          | Mimir datasource + stub dashboard pre-provisioned |
| Mimir            | http://localhost:9009                          | internal; queried via Grafana      |
| Postgres         | postgres://qfc:qfc@localhost:5432/qfc_wallet   | local-dev creds only               |

### Exercise the API with Bruno

[Bruno](https://github.com/usebruno/bruno) is a Postman-style API client
that stores requests as plain-text `.bru` files so they live happily in
git. Install Bruno, open the collection at `dev/bruno/qfc-server-wallet/`,
pick the **local** environment, and run the requests in order. Request
`02 - Create wallet (ed25519)` captures the new `wallet_id` into the
`walletId` variable so subsequent requests (sign, audit, etc.) reuse it.

### Smoke test

Once the stack is up, run the integration smoke check:

```sh
./tests/dev_stack_smoke.sh
```

It exercises `/health` -> create wallet -> sign -> audit events -> metrics,
and prints a coloured pass/fail summary. The script is NOT part of
`cargo test`; it is manual / CI only.

### Tear down

```sh
docker compose down -v   # `-v` also removes Postgres / Grafana / Mimir data
```

## Security

Reporting: see [`SECURITY.md`](SECURITY.md). Do **not** open public issues for security reports.

## License

Apache 2.0. See [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).
