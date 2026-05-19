#!/usr/bin/env bash
#
# tests/dev_stack_smoke.sh — manual / CI smoke test for the
# `docker compose` dev stack defined at repo root.
#
# This is NOT part of `cargo test`. It is invoked manually after the
# stack is up:
#
#     docker compose up --build -d
#     ./tests/dev_stack_smoke.sh
#
# Exit codes:
#   0  all checks passed
#   1  precondition failure (stack not running, curl missing, etc.)
#   2  an HTTP / contract assertion failed
#
# Dependencies: bash 4+, curl, jq, (docker if you want the "is the
# stack running?" precheck to actually work).

set -euo pipefail

# -------------------------------------------------------------------
# Config
# -------------------------------------------------------------------
BASE_URL="${BASE_URL:-http://localhost:8080}"
METRICS_URL="${METRICS_URL:-http://localhost:9090}"
API_KEY="${API_KEY:-dev-key-1}"
COMPOSE_SERVICE="${COMPOSE_SERVICE:-qfc-server-wallet}"

# -------------------------------------------------------------------
# Helpers
# -------------------------------------------------------------------
red()   { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
blue()  { printf '\033[34m%s\033[0m\n' "$*"; }

die()      { red "FAIL: $*"; exit 2; }
precond()  { red "PRECONDITION: $*"; exit 1; }
step()     { blue "==> $*"; }

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || precond "$1 not found on PATH"
}

# -------------------------------------------------------------------
# Step 0: deps + stack-running precheck
# -------------------------------------------------------------------
require_cmd curl
require_cmd jq

if command -v docker >/dev/null 2>&1; then
  step "Checking that '${COMPOSE_SERVICE}' is running under docker compose"
  if ! docker compose ps --services --filter status=running 2>/dev/null \
       | grep -qx "${COMPOSE_SERVICE}"; then
    precond "service '${COMPOSE_SERVICE}' is not running. Try:\n    docker compose up --build -d"
  fi
else
  blue "(docker not on PATH — skipping compose precheck; will rely on curl below)"
fi

# -------------------------------------------------------------------
# Step 1: /health -> 200
# -------------------------------------------------------------------
step "GET ${BASE_URL}/health"
HEALTH_CODE="$(curl -sS -o /dev/null -w '%{http_code}' "${BASE_URL}/health" || true)"
if [[ "${HEALTH_CODE}" != "200" ]]; then
  die "expected 200 from /health, got ${HEALTH_CODE} (is the server bound on :8080?)"
fi
green "  /health OK (200)"

# -------------------------------------------------------------------
# Step 2: POST /wallets -> capture wallet_id
# -------------------------------------------------------------------
step "POST ${BASE_URL}/wallets (ed25519)"
CREATE_RESP="$(curl -sS \
  -H "Content-Type: application/json" \
  -H "X-API-Key: ${API_KEY}" \
  -X POST \
  -d '{"scheme":"ed25519","label":"smoke-test"}' \
  "${BASE_URL}/wallets")"

WALLET_ID="$(printf '%s' "${CREATE_RESP}" | jq -r '.wallet_id // empty')"
if [[ -z "${WALLET_ID}" ]]; then
  die "POST /wallets did not return wallet_id. Response: ${CREATE_RESP}"
fi
green "  created wallet_id=${WALLET_ID}"

# -------------------------------------------------------------------
# Step 3: POST /wallets/{id}/sign -> expect non-empty signature
# -------------------------------------------------------------------
step "POST ${BASE_URL}/wallets/${WALLET_ID}/sign"
SIGN_RESP="$(curl -sS \
  -H "Content-Type: application/json" \
  -H "X-API-Key: ${API_KEY}" \
  -X POST \
  -d '{"payload":"48656c6c6f2c20514643","encoding":"hex"}' \
  "${BASE_URL}/wallets/${WALLET_ID}/sign")"

SIGNATURE="$(printf '%s' "${SIGN_RESP}" | jq -r '.signature // empty')"
if [[ -z "${SIGNATURE}" ]]; then
  die "POST /sign did not return signature. Response: ${SIGN_RESP}"
fi
SIG_LEN="${#SIGNATURE}"
green "  signature ok (${SIG_LEN} chars)"

# -------------------------------------------------------------------
# Step 4: GET /audit/events?wallet_id=... -> expect >= 2 events
# -------------------------------------------------------------------
step "GET ${BASE_URL}/audit/events?wallet_id=${WALLET_ID}&limit=20"
AUDIT_RESP="$(curl -sS \
  -H "X-API-Key: ${API_KEY}" \
  "${BASE_URL}/audit/events?wallet_id=${WALLET_ID}&limit=20")"

EVENT_COUNT="$(printf '%s' "${AUDIT_RESP}" | jq -r '.events | length // 0')"
if [[ "${EVENT_COUNT}" -lt 2 ]]; then
  die "expected >=2 audit events, got ${EVENT_COUNT}. Response: ${AUDIT_RESP}"
fi
green "  audit events: ${EVENT_COUNT}"

# -------------------------------------------------------------------
# Step 5: /metrics on port 9090 (not strictly required, informational)
# -------------------------------------------------------------------
step "GET ${METRICS_URL}/metrics"
METRICS_CODE="$(curl -sS -o /dev/null -w '%{http_code}' "${METRICS_URL}/metrics" || true)"
if [[ "${METRICS_CODE}" == "200" ]]; then
  green "  /metrics OK (200)"
else
  red "  /metrics returned ${METRICS_CODE} (non-fatal; check P5 observability)"
fi

# -------------------------------------------------------------------
# Summary
# -------------------------------------------------------------------
echo
green "=========================================="
green "  qfc-server-wallet dev stack smoke: PASS"
green "    wallet_id     = ${WALLET_ID}"
green "    audit events  = ${EVENT_COUNT}"
green "    signature len = ${SIG_LEN}"
green "=========================================="
