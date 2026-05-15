#!/usr/bin/env bash
set -euo pipefail

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

if ! command -v "$GRAMINE" >/dev/null; then
  echo "gramine-direct not found in PATH" >&2
  exit 1
fi

MANIFEST_CMD=(python3 "$GRAMINE_MANIFEST_BIN")

mkdir -p pf_dir
mkdir -p tmp

run_case() {
  local mode=$1
  local expect_ok=$2

  "${MANIFEST_CMD[@]}" --no-check \
    -Dmode="$mode" \
    main.mode.manifest.template main.manifest

  set +e
  "$GRAMINE" ./main >/dev/null 2>&1
  local rc=$?
  set -e

  if [[ $expect_ok -eq 1 && $rc -ne 0 ]]; then
    echo "FAIL: mode '$mode' expected success, got rc=$rc" >&2
    exit 1
  fi

  if [[ $expect_ok -eq 0 && $rc -eq 0 ]]; then
    echo "FAIL: mode '$mode' expected failure, got rc=0" >&2
    exit 1
  fi

  echo "OK: mode '$mode' rc=$rc"
}

run_case optimistic 1
run_case synchronous 1
run_case checker 1
run_case badvalue 0
