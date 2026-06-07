#!/usr/bin/env python3
# SQLite application benchmark under CRISP modes
#   python3 docs/benchmarking/sqlite.py --out sqlite_results.csv --profile-out sqlite_profile.csv
# The application opens a SQLite database on the encrypted Protected File mount with
# PRAGMA synchronous=FULL and PRAGMA journal_mode=DELETE so every INSERT transaction
# issues an fsync. The script sweeps mode in {disabled, synchronous, optimistic, checker},
# optionally sweeps checker_prob for the L3 mode, then records transactions per second
# Outputs default to the script directory, both CSV and a stdout-mirroring log file

import argparse
import csv
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

GRAMINE_CMD = os.environ.get("GRAMINE_CMD", "gramine-direct")
IS_SGX = GRAMINE_CMD == "gramine-sgx"
KEY = "ff000000000000000000000000000000"
RUNTIME = "/usr/local/lib/x86_64-linux-gnu/gramine/runtime/glibc"
ARCH_LIBDIR = "/lib/x86_64-linux-gnu"
SCRIPT_DIR = Path(__file__).resolve().parent


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


APP_SRC = r"""
#include <sqlite3.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

static uint64_t now_us(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000000 + tv.tv_usec;
}

int main(int argc, char** argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s n_txn\n", argv[0]);
        return 1;
    }
    int n = atoi(argv[1]);

    sqlite3* db = NULL;
    if (sqlite3_open("/cr/test.db", &db) != SQLITE_OK) {
        fprintf(stderr, "open failed: %s\n", sqlite3_errmsg(db));
        return 1;
    }

    char* err = NULL;
    if (sqlite3_exec(db, "PRAGMA synchronous=FULL", NULL, NULL, &err) != SQLITE_OK) {
        fprintf(stderr, "pragma synchronous failed: %s\n", err);
        sqlite3_free(err);
        return 1;
    }
    if (sqlite3_exec(db, "PRAGMA journal_mode=DELETE", NULL, NULL, &err) != SQLITE_OK) {
        fprintf(stderr, "pragma journal_mode failed: %s\n", err);
        sqlite3_free(err);
        return 1;
    }
    if (sqlite3_exec(db,
                     "CREATE TABLE IF NOT EXISTS t (id INTEGER PRIMARY KEY, data TEXT)",
                     NULL, NULL, &err) != SQLITE_OK) {
        fprintf(stderr, "create failed: %s\n", err);
        sqlite3_free(err);
        return 1;
    }

    uint64_t t0 = now_us();
    for (int i = 0; i < n; i++) {
        char sql[256];
        snprintf(sql, sizeof(sql), "INSERT INTO t (data) VALUES ('row_%d')", i);
        if (sqlite3_exec(db, sql, NULL, NULL, &err) != SQLITE_OK) {
            fprintf(stderr, "insert failed: %s\n", err);
            sqlite3_free(err);
            return 1;
        }
    }
    uint64_t t1 = now_us();

    sqlite3_close(db);

    uint64_t elapsed_us = t1 - t0;
    double txn_per_sec = (double)n * 1000000.0 / (double)elapsed_us;
    printf("SQLITE_BENCH n=%d elapsed_us=%lu txn_per_sec=%.2f\n", n, elapsed_us, txn_per_sec);
    return 0;
}
"""

MANIFEST_BASE = """
libos.entrypoint = "/app"
loader.log_level = "error"
loader.env.LD_LIBRARY_PATH = "/lib:{arch_libdir}:/usr{arch_libdir}"
loader.insecure__use_cmdline_argv = true

fs.insecure__keys.default = "{key}"

fs.mounts = [
  {{ path = "/lib", uri = "file:{runtime}" }},
  {{ path = "{arch_libdir}", uri = "file:{arch_libdir}" }},
  {{ path = "/usr{arch_libdir}", uri = "file:/usr{arch_libdir}" }},
  {{ path = "/app", uri = "file:app" }},
  {{ type = "encrypted", path = "/cr", uri = "file:pf_dir" }},
]

{crisp_block}
sgx.debug = true
sgx.enclave_size = "512M"
{max_threads}
sgx.trusted_files = [
  "file:app",
  "file:{runtime}/",
  "file:{arch_libdir}/",
  "file:/usr{arch_libdir}/",
]
"""

CSV_LINE_RE = re.compile(r"\[CRISP CSV\] (.+?)$", re.MULTILINE)
METRIC_RE = re.compile(r"SQLITE_BENCH n=(\d+) elapsed_us=(\d+) txn_per_sec=([\d.]+)")


def build_app(workdir):
    src = workdir / "app.c"
    src.write_text(APP_SRC)
    subprocess.run(
        ["gcc", "-O2", "-o", "app", "app.c", "-lsqlite3"],
        cwd=workdir, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    (workdir / "pf_dir").mkdir(exist_ok=True)


def crisp_block_for(mode, mc_path, prob):
    if mode == "disabled":
        return "sgx.crisp.enabled = false\n"
    block = (
        "sgx.crisp.enabled = true\n"
        'sgx.crisp.vault_path = "/cr/vault.dat"\n'
        f'sgx.crisp.mc_path = "{mc_path}"\n'
        'sgx.crisp.tracked_pfs = ["/cr/test.db"]\n'
        f'sgx.crisp.mode = "{mode}"\n'
        "sgx.crisp.profile = true\n"
    )
    if prob is not None and prob > 0:
        block += f"sgx.crisp.checker_prob = {prob}\n"
    return block


def write_manifest(workdir, mode, mc_path, prob=None):
    max_threads = "sgx.max_threads = 16\n" if IS_SGX else ""
    manifest = MANIFEST_BASE.format(
        key=KEY,
        runtime=RUNTIME,
        arch_libdir=ARCH_LIBDIR,
        crisp_block=crisp_block_for(mode, mc_path, prob),
        max_threads=max_threads,
    )
    (workdir / "app.manifest.template").write_text(manifest)
    subprocess.run(
        ["gramine-manifest", "app.manifest.template", "app.manifest"],
        cwd=workdir, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    if IS_SGX:
        subprocess.run(
            ["gramine-sgx-sign", "--manifest", "app.manifest",
             "--output", "app.manifest.sgx"],
            cwd=workdir, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )


def run_one(workdir, n_txn, timeout):
    p = subprocess.run(
        [GRAMINE_CMD, "app", str(n_txn)],
        cwd=workdir, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, timeout=timeout,
    )
    out = p.stdout
    m = METRIC_RE.search(out)
    if not m:
        raise RuntimeError(f"no SQLITE_BENCH line in output:\n{out[-2000:]}")
    elapsed_us = int(m.group(2))
    txn_per_sec = float(m.group(3))
    csv_rows = CSV_LINE_RE.findall(out)
    return elapsed_us, txn_per_sec, csv_rows


def default_log_path():
    mode_suffix = "sgx" if IS_SGX else "direct"
    return SCRIPT_DIR / f"sqlite_{mode_suffix}.log"


def parse_args():
    p = argparse.ArgumentParser(
        description="SQLite per-mode application benchmark under CRISP",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--out", default=str(SCRIPT_DIR / "sqlite_results.csv"),
                   help="output CSV path")
    p.add_argument("--profile-out", default=str(SCRIPT_DIR / "sqlite_profile.csv"),
                   help="per-slot profile CSV path")
    p.add_argument("--log", default=str(default_log_path()),
                   help="log file mirroring stdout")
    p.add_argument("--modes", default="disabled,synchronous,optimistic,checker",
                   help="comma-separated modes")
    p.add_argument("--prob-sweep", default=None,
                   help="comma-separated checker_prob values for the checker mode")
    p.add_argument("--n-txn", type=int, default=500,
                   help="number of INSERT transactions per run")
    p.add_argument("--iter", type=int, default=10,
                   help="iterations per (mode, prob) combination")
    p.add_argument("--checker-prob", type=int, default=0)
    p.add_argument("--timeout", type=int, default=600)
    return p.parse_args()


def main():
    args = parse_args()

    modes = args.modes.split(",")
    prob_sweep = [int(x) for x in args.prob_sweep.split(",")] if args.prob_sweep else None

    log_file = open(args.log, "w")
    real_stdout = sys.stdout
    sys.stdout = Tee(real_stdout, log_file)

    try:
        print(
            f"# modes={modes} n_txn={args.n_txn} iter={args.iter} "
            f"prob_sweep={prob_sweep} gramine={GRAMINE_CMD}"
        )

        bench_rows = []
        profile_rows = []

        for mode in modes:
            if mode == "checker":
                probs_for_mode = prob_sweep if prob_sweep is not None else [args.checker_prob]
            else:
                probs_for_mode = [0]
            for prob in probs_for_mode:
                for iteration in range(args.iter):
                    with tempfile.TemporaryDirectory(prefix="sqlite_bench_") as td:
                        workdir = Path(td)
                        mc_path = f"/tmp/crisp_mc_sqlite_{os.getpid()}_{iteration}.dat"
                        Path(mc_path).unlink(missing_ok=True)
                        Path(mc_path + ".tmp").unlink(missing_ok=True)
                        build_app(workdir)
                        manifest_prob = prob if mode == "checker" else None
                        write_manifest(workdir, mode, mc_path, manifest_prob)
                        label = f"mode={mode} prob={prob} iter={iteration}"
                        try:
                            elapsed_us, tps, csv_lines = run_one(
                                workdir, args.n_txn, args.timeout,
                            )
                        except Exception as exc:
                            print(f"FAIL {label}: {exc}", file=real_stdout)
                            continue
                        print(
                            f"OK {label} -> {tps:.2f} txn/s "
                            f"in {elapsed_us / 1000:.1f} ms"
                        )
                        bench_rows.append({
                            "mode": mode,
                            "checker_prob": prob,
                            "iteration": iteration,
                            "n_txn": args.n_txn,
                            "elapsed_us": elapsed_us,
                            "txn_per_sec": tps,
                        })
                        for line in csv_lines:
                            if line.startswith("slot,"):
                                continue
                            parts = line.split(",")
                            if len(parts) != 4:
                                continue
                            profile_rows.append({
                                "mode": mode,
                                "checker_prob": prob,
                                "iteration": iteration,
                                "slot": parts[0],
                                "count": int(parts[1]),
                                "total_us": int(parts[2]),
                                "avg_us": int(parts[3]),
                            })
                        Path(mc_path).unlink(missing_ok=True)
                        Path(mc_path + ".tmp").unlink(missing_ok=True)

        if not bench_rows:
            print("no successful runs", file=real_stdout)
            sys.exit(1)

        with open(args.out, "w", newline="") as f:
            writer = csv.DictWriter(
                f,
                fieldnames=["mode", "checker_prob", "iteration",
                            "n_txn", "elapsed_us", "txn_per_sec"],
            )
            writer.writeheader()
            writer.writerows(bench_rows)
        print(f"wrote {len(bench_rows)} rows to {args.out}")

        if profile_rows:
            with open(args.profile_out, "w", newline="") as f:
                writer = csv.DictWriter(
                    f,
                    fieldnames=["mode", "checker_prob", "iteration",
                                "slot", "count", "total_us", "avg_us"],
                )
                writer.writeheader()
                writer.writerows(profile_rows)
            print(f"wrote {len(profile_rows)} rows to {args.profile_out}")
    finally:
        sys.stdout = real_stdout
        log_file.close()


if __name__ == "__main__":
    main()
