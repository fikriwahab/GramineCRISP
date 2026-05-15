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

"${MANIFEST_CMD[@]}" --no-check main.sync.manifest.template main.manifest

"$GRAMINE" ./main >/dev/null 2>&1
echo "OK: synchronous close smoke test"
