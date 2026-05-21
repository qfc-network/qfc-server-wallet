#!/usr/bin/env bash
# Sync the canonical proto files from the server crate to the standalone
# gRPC client SDK.
#
# The SDK at `clients/wallet-grpc-rs/` lives outside the main workspace
# (see `clients-decisions.md` D55) so it can build without dragging in
# the wallet's full dep tree. To do that it carries a *copy* of the
# protos rather than a symlink (cross-platform pain on Windows).
#
# CI's `proto-sync-check` job runs this script and then asserts
# `git diff --exit-code` to make sure the copy in the SDK is always
# byte-identical to the source under `crates/qfc-server-wallet/proto/`.
#
# Re-run after editing any `crates/qfc-server-wallet/proto/*.proto`.

set -euo pipefail

# Resolve to the repo root regardless of where this is invoked from.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

SRC="$REPO_ROOT/crates/qfc-server-wallet/proto"
DST="$REPO_ROOT/clients/wallet-grpc-rs/proto"

if [[ ! -d "$SRC" ]]; then
  echo "error: source proto dir not found: $SRC" >&2
  exit 1
fi
if [[ ! -d "$DST" ]]; then
  echo "error: destination proto dir not found: $DST" >&2
  exit 1
fi

for f in common.proto wallet.proto approver.proto; do
  if [[ ! -f "$SRC/$f" ]]; then
    echo "error: missing source proto: $SRC/$f" >&2
    exit 1
  fi
  cp "$SRC/$f" "$DST/$f"
done

echo "synced: $SRC -> $DST"
