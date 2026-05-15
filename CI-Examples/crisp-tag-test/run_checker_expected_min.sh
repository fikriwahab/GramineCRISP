#!/usr/bin/env bash
set -euo pipefail

PORT=${1:-19999}
EXPECTED_MIN=${2:-1}

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
GRAMINE_MANIFEST=${GRAMINE_MANIFEST:-gramine-manifest}
GRAMINE=${GRAMINE:-gramine-direct}

if ! command -v python3 >/dev/null; then
  echo "python3 not found" >&2
  exit 1
fi

GRAMINE_MANIFEST_BIN=$(command -v "$GRAMINE_MANIFEST" || true)
if [[ -z "$GRAMINE_MANIFEST_BIN" ]]; then
  echo "gramine-manifest not found; install Gramine or set GRAMINE_MANIFEST" >&2
  exit 1
fi

MANIFEST_CMD=(python3 "$GRAMINE_MANIFEST_BIN")

if ! command -v "$GRAMINE" >/dev/null; then
  echo "gramine-direct not found in PATH" >&2
  exit 1
fi

"${MANIFEST_CMD[@]}" --no-check main.checker.manifest.template main.manifest

mkdir -p pf_dir
mkdir -p tmp

./checker_query.py "$PORT" 1 "$EXPECTED_MIN" &
QUERY_PID=$!

"$GRAMINE" ./main &
APP_PID=$!

wait "$QUERY_PID"
QUERY_RC=$?
if [[ $QUERY_RC -ne 0 ]]; then
  kill "$APP_PID" >/dev/null 2>&1 || true
  wait "$APP_PID" >/dev/null 2>&1 || true
  exit "$QUERY_RC"
fi

wait "$APP_PID"
