#!/usr/bin/env python3
"""Microbenchmark CRISP write+fsync throughput across modes and buffer sizes.

Raw disk experiment: write a file in fixed-size chunks each followed by
fsync(), measure total throughput. Sweep mode in {disabled, optimistic,
synchronous, checker} times buffer sizes in {512B..32KB log scale} times N
iterations, write a CSV row per run plus per-slot profile stats from
crisp_profile_dump.

Modes:
    disabled    sgx.crisp.enabled = false, baseline overhead (SGX+FSPF only)
    optimistic  L2 async batching via mc-thread
    synchronous L1 inline commit per fsync
    checker     L3 optimistic plus probabilistic Checker drain

Run on the SGX VM with:
    GRAMINE_CMD=gramine-sgx python3 microbench.py --out results.csv

Probabilistic checker sweep (paper Table II reproduction):
    GRAMINE_CMD=gramine-sgx python3 microbench.py --modes checker \\
        --prob-sweep 0,1,10,20,100 --out results_prob.csv

Include disabled baseline so throughput overhead is measurable:
    GRAMINE_CMD=gramine-sgx python3 microbench.py \\
        --modes disabled,synchronous,optimistic,checker --out results.csv
"""

import argparse
import csv
import os
import re
import subprocess
import sys
import tempfile
import time
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
    if (argc < 3) {
        fprintf(stderr, "usage: %s buffer_size total_bytes\n", argv[0]);
        return 1;
    }
    size_t buf_sz = (size_t)atol(argv[1]);
    size_t total = (size_t)atol(argv[2]);
    char* buf = malloc(buf_sz);
    if (!buf) { fprintf(stderr, "alloc failed\n"); return 1; }
    memset(buf, 'x', buf_sz);

    int fd = open("/cr/data.bin", O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) { perror("open"); return 1; }

    size_t writes = total / buf_sz;
    uint64_t t0 = now_us();
    for (size_t i = 0; i < writes; i++) {
        if (write(fd, buf, buf_sz) != (ssize_t)buf_sz) { perror("write"); return 1; }
        if (fsync(fd) != 0) { perror("fsync"); return 1; }
    }
    uint64_t t1 = now_us();
    close(fd);
    free(buf);

    uint64_t elapsed_us = t1 - t0;
    double throughput_kbps = (double)total / 1024.0 / ((double)elapsed_us / 1000000.0);
    printf("MICROBENCH buf=%zu total=%zu writes=%zu elapsed_us=%lu throughput_kbps=%.2f\n",
           buf_sz, total, writes, elapsed_us, throughput_kbps);
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
METRIC_RE = re.compile(r"MICROBENCH .* elapsed_us=(\d+) throughput_kbps=([\d.]+)")


def build_app(workdir):
    src = workdir / "app.c"
    src.write_text(APP_SRC)
    subprocess.run(["gcc", "-O2", "-o", "app", "app.c"], cwd=workdir, check=True,
                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    (workdir / "pf_dir").mkdir(exist_ok=True)


def crisp_block_for(mode, mc_path, prob):
    """Build the sgx.crisp.* block for the manifest, or the disable line for baseline."""
    if mode == "disabled":
        return "sgx.crisp.enabled = false\n"
    block = (
        "sgx.crisp.enabled = true\n"
        f'sgx.crisp.vault_path = "/cr/vault.dat"\n'
        f'sgx.crisp.mc_path = "{mc_path}"\n'
        'sgx.crisp.tracked_pfs = ["/cr/data.bin"]\n'
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


def run_one(workdir, buf_sz, total_bytes, timeout):
    p = subprocess.run([GRAMINE_CMD, "app", str(buf_sz), str(total_bytes)],
                       cwd=workdir, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                       text=True, timeout=timeout)
    out = p.stdout
    m = METRIC_RE.search(out)
    if not m:
        raise RuntimeError(f"no MICROBENCH line in output:\n{out}")
    elapsed_us = int(m.group(1))
    throughput_kbps = float(m.group(2))
    csv_rows = CSV_LINE_RE.findall(out)
    return elapsed_us, throughput_kbps, csv_rows


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--out", default="microbench_results.csv", help="output CSV path")
    p.add_argument("--profile-out", default="microbench_profile.csv", help="per-slot profile CSV path")
    p.add_argument("--modes", default="optimistic,synchronous,checker",
                   help="comma-separated modes (disabled, optimistic, synchronous, checker)")
    p.add_argument("--buffers", default="512,1024,2048,4096,8192,16384,32768",
                   help="comma-separated buffer sizes in bytes")
    p.add_argument("--iter", type=int, default=3, help="iterations per (mode, buffer, prob) combination")
    p.add_argument("--file-size", type=int, default=16, help="total file size in MB")
    p.add_argument("--checker-prob", type=int, default=0,
                   help="single checker_prob value for checker mode when --prob-sweep is not used")
    p.add_argument("--prob-sweep", default=None,
                   help="comma-separated checker_prob values to sweep when mode includes checker (e.g. 0,1,10,20,100)")
    p.add_argument("--timeout", type=int, default=600, help="per-run timeout seconds")
    args = p.parse_args()

    modes = args.modes.split(",")
    buffers = [int(b) for b in args.buffers.split(",")]
    total_bytes = args.file_size * 1024 * 1024
    prob_sweep = [int(x) for x in args.prob_sweep.split(",")] if args.prob_sweep else None

    print(f"# mode={modes} buffers={buffers} iter={args.iter} file_size={args.file_size}MB "
          f"prob_sweep={prob_sweep} gramine={GRAMINE_CMD}")

    bench_rows = []
    profile_rows = []

    for mode in modes:
        if mode == "checker":
            probs_for_mode = prob_sweep if prob_sweep is not None else [args.checker_prob]
        else:
            probs_for_mode = [0]
        for prob in probs_for_mode:
            for buf_sz in buffers:
                for iteration in range(args.iter):
                    with tempfile.TemporaryDirectory(prefix="microbench_") as td:
                        workdir = Path(td)
                        mc_path = f"/tmp/crisp_mc_microbench_{os.getpid()}_{iteration}.dat"
                        Path(mc_path).unlink(missing_ok=True)
                        Path(mc_path + ".tmp").unlink(missing_ok=True)
                        build_app(workdir)
                        manifest_prob = prob if mode == "checker" else None
                        write_manifest(workdir, mode, mc_path, manifest_prob)
                        label = f"mode={mode} prob={prob} buf={buf_sz} iter={iteration}"
                        try:
                            elapsed_us, kbps, csv_lines = run_one(workdir, buf_sz, total_bytes, args.timeout)
                        except Exception as exc:
                            print(f"FAIL {label}: {exc}", file=sys.stderr)
                            continue
                        print(f"OK {label} -> {kbps:.2f} kB/s in {elapsed_us / 1000:.1f} ms")
                        bench_rows.append({
                            "mode": mode, "checker_prob": prob, "buffer_size": buf_sz,
                            "iteration": iteration, "elapsed_us": elapsed_us, "throughput_kbps": kbps,
                        })
                        for line in csv_lines:
                            if line.startswith("slot,"):
                                continue
                            parts = line.split(",")
                            if len(parts) != 4:
                                continue
                            profile_rows.append({
                                "mode": mode, "checker_prob": prob, "buffer_size": buf_sz,
                                "iteration": iteration,
                                "slot": parts[0], "count": int(parts[1]),
                                "total_us": int(parts[2]), "avg_us": int(parts[3]),
                            })
                        Path(mc_path).unlink(missing_ok=True)
                        Path(mc_path + ".tmp").unlink(missing_ok=True)

    if not bench_rows:
        print("no successful runs", file=sys.stderr)
        sys.exit(1)

    with open(args.out, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["mode", "checker_prob", "buffer_size",
                                               "iteration", "elapsed_us", "throughput_kbps"])
        writer.writeheader()
        writer.writerows(bench_rows)
    print(f"wrote {len(bench_rows)} rows to {args.out}")

    if profile_rows:
        with open(args.profile_out, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=["mode", "checker_prob", "buffer_size",
                                                   "iteration", "slot", "count", "total_us", "avg_us"])
            writer.writeheader()
            writer.writerows(profile_rows)
        print(f"wrote {len(profile_rows)} rows to {args.profile_out}")


if __name__ == "__main__":
    main()
