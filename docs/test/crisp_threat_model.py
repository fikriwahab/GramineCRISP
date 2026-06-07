#!/usr/bin/env python3
# CRISP threat-model coverage suite
#   python3 docs/crisp_threat_model.py                      run every category
#   python3 docs/crisp_threat_model.py CATEGORY_NAME ...    run only the named categories
# Categories live in the exploits/ package, each one is a focused attack scenario against
# a specific layer of the CRISP discipline
#   close_sync_gateways   close and exit hook ordering and drain semantics
#   config_integrity      manifest-driven configuration parsing and validation
#   mc_consistency        monotonic counter invariants across runs
#   pf_data_freshness     protected file content reverts and substitutions
#   vault_freshness       vault file replacement and downgrade
# A per-run log mirroring stdout is written to docs/microbench/crisp_threat_model_<mode>.log,
# the LOG_FILE env var overrides the default path

import os
import sys
from pathlib import Path


class Tee:
    def __init__(self, *streams):
        self.streams = streams

    def write(self, s):
        for stream in self.streams:
            stream.write(s)
            stream.flush()

    def flush(self):
        for stream in self.streams:
            stream.flush()


GRAMINE_CMD = os.environ.get("GRAMINE_CMD", "gramine-direct")
IS_SGX = GRAMINE_CMD == "gramine-sgx"
SCRIPT_DIR = Path(__file__).resolve().parent


def log_path():
    mode_suffix = "sgx" if IS_SGX else "direct"
    SCRIPT_DIR.mkdir(parents=True, exist_ok=True)
    override = os.environ.get("LOG_FILE")
    if override:
        return Path(override)
    return SCRIPT_DIR / f"crisp_threat_model_{mode_suffix}.log"


# The exploits package lives at the docs/exploits sibling directory of the test folder
sys.path.insert(0, str(SCRIPT_DIR.parent / "exploits"))

from lib import main  # noqa: E402

log_file = log_path().open("w")
real_stdout = sys.stdout
sys.stdout = Tee(real_stdout, log_file)
try:
    rc = main()
finally:
    sys.stdout = real_stdout
    log_file.close()

raise SystemExit(rc)
