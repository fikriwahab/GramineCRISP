#!/usr/bin/env python3
"""Redis AOF (Append-Only File) workload benchmark under CRISP modes.

Workload: N synthetic SET operations into an AOF-style log file
(append + fsync per write, matching Redis appendfsync=always behavior).
Each SET appends "SET key:N value:<32 bytes>\n" to /cr/redis.aof and
calls fsync. Captures the append-heavy pattern that microbench's
truncating writes don't exercise.

Light scope: 1 iter, 4 modes default, ~5-10 menit total.

Run on the SGX VM with:
    GRAMINE_CMD=gramine-sgx python3 redis.py --out microbench/redis.csv
"""

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

APP_SRC = r"""
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

static uint64_t now_us(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000000 + tv.tv_usec;
}

int main(int argc, char** argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s n_ops\n", argv[0]);
        return 1;
    }
    int n = atoi(argv[1]);

    // O_APPEND so each write appends atomically (matching real AOF behavior)
    int fd = open("/cr/redis.aof", O_WRONLY | O_CREAT | O_APPEND, 0600);
    if (fd < 0) { perror("open"); return 1; }

    char line[128];
    uint64_t t0 = now_us();
    for (int i = 0; i < n; i++) {
        int len = snprintf(line, sizeof(line),
                           "*3\r\n$3\r\nSET\r\n$5\r\nkey:%d\r\n$32\r\n"
                           "0123456789abcdef0123456789abcdef\r\n", i);
        if (write(fd, line, len) != len) { perror("write"); return 1; }
        if (fsync(fd) != 0) { perror("fsync"); return 1; }
    }
    uint64_t t1 = now_us();
    close(fd);

    uint64_t elapsed_us = t1 - t0;
    double ops_per_sec = (double)n * 1000000.0 / (double)elapsed_us;
    printf("REDIS_BENCH n=%d elapsed_us=%lu ops_per_sec=%.2f\n", n, elapsed_us, ops_per_sec);
    return 0;
}
"""

MANIFEST_BASE = """
libos.entrypoint = "/app"
loader.log_level = "error"
loader.env.LD_LIBRARY_PATH = "/lib"
loader.insecure__use_cmdline_argv = true

fs.insecure__keys.default = "{key}"

fs.mounts = [
  {{ path = "/lib", uri = "file:{runtime}" }},
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
]
"""

CSV_LINE_RE = re.compile(r"\[CRISP CSV\] (.+?)$", re.MULTILINE)
METRIC_RE = re.compile(r"REDIS_BENCH n=(\d+) elapsed_us=(\d+) ops_per_sec=([\d.]+)")


def build_app(workdir):
    src = workdir / "app.c"
    src.write_text(APP_SRC)
    subprocess.run(["gcc", "-O2", "-o", "app", "app.c"], cwd=workdir, check=True,
                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    (workdir / "pf_dir").mkdir(exist_ok=True)


def crisp_block_for(mode, mc_path, prob):
    if mode == "disabled":
        return "sgx.crisp.enabled = false\n"
    block = (
        "sgx.crisp.enabled = true\n"
        f'sgx.crisp.vault_path = "/cr/vault.dat"\n'
        f'sgx.crisp.mc_path = "{mc_path}"\n'
        'sgx.crisp.tracked_pfs = ["/cr/redis.aof"]\n'
        f'sgx.crisp.mode = "{mode}"\n'
        "sgx.crisp.profile = true\n"
    )
    if prob is not None and prob > 0:
        block += f"sgx.crisp.checker_prob = {prob}\n"
    return block


def write_manifest(workdir, mode, mc_path, prob=None):
    max_threads = "sgx.max_threads = 16\n" if IS_SGX else ""
    manifest = MANIFEST_BASE.format(
        key=KEY, runtime=RUNTIME,
        crisp_block=crisp_block_for(mode, mc_path, prob),
        max_threads=max_threads,
    )
    (workdir / "app.manifest.template").write_text(manifest)
    subprocess.run(["gramine-manifest", "app.manifest.template", "app.manifest"],
                   cwd=workdir, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if IS_SGX:
        subprocess.run(["gramine-sgx-sign", "--manifest", "app.manifest",
                        "--output", "app.manifest.sgx"],
                       cwd=workdir, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def run_one(workdir, n_ops, timeout):
    p = subprocess.run([GRAMINE_CMD, "app", str(n_ops)],
                       cwd=workdir, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                       text=True, timeout=timeout)
    out = p.stdout
    m = METRIC_RE.search(out)
    if not m:
        raise RuntimeError(f"no REDIS_BENCH line in output:\n{out[-2000:]}")
    elapsed_us = int(m.group(2))
    ops_per_sec = float(m.group(3))
    csv_rows = CSV_LINE_RE.findall(out)
    return elapsed_us, ops_per_sec, csv_rows


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--out", default="redis_results.csv", help="output CSV path")
    p.add_argument("--profile-out", default="redis_profile.csv", help="per-slot profile CSV path")
    p.add_argument("--modes", default="disabled,synchronous,optimistic,checker",
                   help="comma-separated modes")
    p.add_argument("--prob-sweep", default=None,
                   help="comma-separated checker_prob values (only used when mode includes checker)")
    p.add_argument("--n-ops", type=int, default=1000,
                   help="number of SET operations per run")
    p.add_argument("--iter", type=int, default=1, help="iterations per (mode, prob) combination")
    p.add_argument("--checker-prob", type=int, default=0)
    p.add_argument("--timeout", type=int, default=600)
    args = p.parse_args()

    modes = args.modes.split(",")
    prob_sweep = [int(x) for x in args.prob_sweep.split(",")] if args.prob_sweep else None

    print(f"# modes={modes} n_ops={args.n_ops} iter={args.iter} prob_sweep={prob_sweep} "
          f"gramine={GRAMINE_CMD}")

    bench_rows = []
    profile_rows = []

    for mode in modes:
        if mode == "checker":
            probs_for_mode = prob_sweep if prob_sweep is not None else [args.checker_prob]
        else:
            probs_for_mode = [0]
        for prob in probs_for_mode:
            for iteration in range(args.iter):
                with tempfile.TemporaryDirectory(prefix="redis_bench_") as td:
                    workdir = Path(td)
                    mc_path = f"/tmp/crisp_mc_redis_{os.getpid()}_{iteration}.dat"
                    Path(mc_path).unlink(missing_ok=True)
                    Path(mc_path + ".tmp").unlink(missing_ok=True)
                    build_app(workdir)
                    manifest_prob = prob if mode == "checker" else None
                    write_manifest(workdir, mode, mc_path, manifest_prob)
                    label = f"mode={mode} prob={prob} iter={iteration}"
                    try:
                        elapsed_us, ops, csv_lines = run_one(workdir, args.n_ops, args.timeout)
                    except Exception as exc:
                        print(f"FAIL {label}: {exc}", file=sys.stderr)
                        continue
                    print(f"OK {label} -> {ops:.2f} ops/s in {elapsed_us / 1000:.1f} ms")
                    bench_rows.append({
                        "mode": mode, "checker_prob": prob, "iteration": iteration,
                        "n_ops": args.n_ops, "elapsed_us": elapsed_us, "ops_per_sec": ops,
                    })
                    for line in csv_lines:
                        if line.startswith("slot,"):
                            continue
                        parts = line.split(",")
                        if len(parts) != 4:
                            continue
                        profile_rows.append({
                            "mode": mode, "checker_prob": prob, "iteration": iteration,
                            "slot": parts[0], "count": int(parts[1]),
                            "total_us": int(parts[2]), "avg_us": int(parts[3]),
                        })
                    Path(mc_path).unlink(missing_ok=True)
                    Path(mc_path + ".tmp").unlink(missing_ok=True)

    if not bench_rows:
        print("no successful runs", file=sys.stderr)
        sys.exit(1)

    with open(args.out, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["mode", "checker_prob", "iteration",
                                               "n_ops", "elapsed_us", "ops_per_sec"])
        writer.writeheader()
        writer.writerows(bench_rows)
    print(f"wrote {len(bench_rows)} rows to {args.out}")

    if profile_rows:
        with open(args.profile_out, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=["mode", "checker_prob", "iteration",
                                                   "slot", "count", "total_us", "avg_us"])
            writer.writeheader()
            writer.writerows(profile_rows)
        print(f"wrote {len(profile_rows)} rows to {args.profile_out}")


if __name__ == "__main__":
    main()
