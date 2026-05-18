## Summary

<!-- 1-3 sentences. What does this change and why? -->

## Linked RFC section / issue

<!-- e.g. RFC §2.4, Issue #42 -->

## Checklist

- [ ] `cargo fmt --all` is clean
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` is clean
- [ ] `cargo test --workspace` passes
- [ ] `cargo deny check` passes
- [ ] DCO sign-off on every commit (`git commit -s`)
- [ ] If this PR touches cryptography or the enclave: a second reviewer from the crypto team is requested
- [ ] CHANGELOG.md updated under `[Unreleased]`
- [ ] New public APIs have `#[doc]` comments

## Notes for reviewers

<!-- Anything reviewers should pay extra attention to: subtle invariants, performance, security surface. -->
