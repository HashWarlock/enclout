#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

echo "[verify] starting M1 verification"

if ! command -v go >/dev/null 2>&1; then
  echo "[verify] ERROR: go toolchain not found in PATH"
  exit 1
fi

if ! command -v node >/dev/null 2>&1; then
  echo "[verify] ERROR: node not found in PATH"
  exit 1
fi

echo "[verify] running control-plane tests"
(cd services/control-plane && go test ./... -v)

echo "[verify] running local-agent tests"
(cd services/local-agent && go test ./... -v)

echo "[verify] running connector-tee tests"
(cd services/connector-tee && npm test)

echo "[verify] M1 verification passed"
