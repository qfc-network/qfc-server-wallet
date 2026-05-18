# Contributing to qfc-server-wallet

Thanks for your interest. This document covers the basics.

## Before opening a PR

- **Read the RFC.** Architecture, threat model, and decisions live in [`docs/server-wallet-rfc.md`](docs/server-wallet-rfc.md). Open an issue first if your change diverges from the RFC.
- **Don't report security issues here.** See [`SECURITY.md`](SECURITY.md).

## Development workflow

```bash
# clippy + fmt
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings

# test
cargo test --workspace

# supply chain
cargo deny --workspace check
cargo audit
cargo vet --locked
```

All four of these must be clean before CI will go green.

## DCO sign-off

All commits must be signed off under the [Developer Certificate of Origin](https://developercertificate.org/):

```
git commit -s -m "..."
```

This adds `Signed-off-by: Your Name <you@example.com>` to the commit, certifying that you wrote the code or are otherwise authorized to contribute it under the project license.

## Crypto and enclave changes

PRs touching any of the following require **two reviewers**, at least one from the crypto/enclave reviewer team:

- `crates/qfc-enclave/`
- `crates/qfc-sss/`
- `crates/*/src/crypto/`
- `enclave/` (M3+)
- Any change to a dependency in the cryptography category (`k256`, `ed25519-dalek`, `vsss-rs`, `bip32`, `bip39`, `pqcrypto-*`)

If your PR adds or replaces a cryptographic primitive, link the relevant audit or specification document in the PR description.

## Coding style

- Rust 2021 edition; `rustc` version pinned in `rust-toolchain.toml`.
- `#![forbid(unsafe_code)]` on every crate. `unsafe` is allowed only in the Nitro IPC module, with explicit `SAFETY:` comments.
- Prefer concrete error types (`thiserror`) over `anyhow` in library crates; `anyhow` is fine in the binary.
- No `unwrap` / `expect` in non-test code unless the invariant is proven on the line above.

## Commit message style

Conventional Commits, lower-case scope:

```
feat(quorum): add nested-wallet cycle check
fix(audit): handle prev_event_hash on empty log
docs: expand §9.6 with QVM ABI findings
```

## License

By contributing, you agree your contribution is licensed under Apache 2.0.
