#!/usr/bin/env python3
"""Real SPIRE workload benchmark under CRISP modes.

Uses a custom Go binary built against SPIRE's actual sqlstore package
(github.com/spiffe/spire/pkg/server/datastore/sqlstore). Each operation
calls ds.CreateRegistrationEntry against SPIRE's in-process DataStore,
exercising the real SPIRE storage path on SQLite (WAL journal mode).

Single-process design avoids Gramine's multi-process fork limitation
that blocks the spire-server + spire-cli wrapper approach. CRISP
intercepts SQLite fsyncs on the AOF-equivalent storage layer.

Prerequisite (one-time on VM):
    # SPIRE source for sqlstore package
    cd ~ && git clone --depth 1 --branch v1.15.1 \
        https://github.com/spiffe/spire.git spire-source

    # Build the bench binary
    mkdir ~/spire-bench && cd ~/spire-bench
    # Place main.go (see docs/spire.py for source) and go.mod with
    # replace github.com/spiffe/spire => /home/azureuser/spire-source
    go mod tidy
    go build -o spire-bench main.go

Run benchmark with:
    GRAMINE_CMD=gramine-sgx python3 spire.py --out microbench/spire.csv
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
ARCH_LIBDIR = "/lib/x86_64-linux-gnu"

SPIRE_BENCH_BIN = Path.home() / "spire-bench" / "spire-bench"

MANIFEST_TEMPLATE = """
libos.entrypoint = "/spire-bench"
loader.log_level = "error"
loader.argv = ["spire-bench", "-n", "{n_ops}", "-db", "/cr/spire.sqlite3"]
loader.env.LD_LIBRARY_PATH = "/lib:{arch_libdir}"
loader.env.HOME = "/home/azureuser"

fs.insecure__keys.default = "{key}"

fs.mounts = [
  {{ path = "/lib", uri = "file:{runtime}" }},
  {{ path = "{arch_libdir}", uri = "file:{arch_libdir}" }},
  {{ path = "/spire-bench", uri = "file:spire-bench" }},
  {{ type = "encrypted", path = "/cr", uri = "file:pf_dir" }},
]

{crisp_block}
sgx.debug = true
sgx.enclave_size = "8G"
{max_threads}
sgx.trusted_files = [
  "file:spire-bench",
  "file:{runtime}/",
  "file:{arch_libdir}/",
]
"""

CSV_LINE_RE = re.compile(r"\[CRISP CSV\] (.+?)$", re.MULTILINE)
METRIC_RE = re.compile(r"SPIRE_BENCH n=(\d+) elapsed_us=(\d+) ops_per_sec=([\d.]+)")


def setup_workdir(workdir, mode, mc_path, n_ops, prob=None):
    bench_link = workdir / "spire-bench"
    if not bench_link.exists():
        bench_link.symlink_to(SPIRE_BENCH_BIN)
    (workdir / "pf_dir").mkdir(exist_ok=True)

    max_threads = "sgx.max_threads = 32\n" if IS_SGX else ""
    manifest = MANIFEST_TEMPLATE.format(
        key=KEY, runtime=RUNTIME, arch_libdir=ARCH_LIBDIR, n_ops=n_ops,
        crisp_block=crisp_block_for(mode, mc_path, prob),
        max_threads=max_threads,
    )
    (workdir / "app.manifest.template").write_text(manifest)
    subprocess.run(["gramine-manifest", "app.manifest.template", "app.manifest"],
                   cwd=workdir, check=True,
                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if IS_SGX:
        subprocess.run(["gramine-sgx-sign", "--manifest", "app.manifest",
                        "--output", "app.manifest.sgx"],
                       cwd=workdir, check=True,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def crisp_block_for(mode, mc_path, prob):
    if mode == "disabled":
        return "sgx.crisp.enabled = false\n"
    block = (
        "sgx.crisp.enabled = true\n"
        f'sgx.crisp.vault_path = "/cr/vault.dat"\n'
        f'sgx.crisp.mc_path = "{mc_path}"\n'
        'sgx.crisp.tracked_pfs = ["/cr/spire.sqlite3"]\n'
        f'sgx.crisp.mode = "{mode}"\n'
        "sgx.crisp.profile = true\n"
    )
    if prob is not None and prob > 0:
        block += f"sgx.crisp.checker_prob = {prob}\n"
    return block


def run_one(workdir, timeout):
    p = subprocess.run([GRAMINE_CMD, "app"],
                       cwd=workdir, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                       text=True, timeout=timeout)
    out = p.stdout
    m = METRIC_RE.search(out)
    if not m:
        raise RuntimeError(f"no SPIRE_BENCH line in output:\n{out[-2000:]}")
    elapsed_us = int(m.group(2))
    ops_per_sec = float(m.group(3))
    csv_rows = CSV_LINE_RE.findall(out)
    return elapsed_us, ops_per_sec, csv_rows


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--out", default="spire_results.csv")
    p.add_argument("--profile-out", default="spire_profile.csv")
    p.add_argument("--modes", default="disabled,synchronous,optimistic,checker")
    p.add_argument("--prob-sweep", default=None)
    p.add_argument("--n-ops", type=int, default=200)
    p.add_argument("--iter", type=int, default=1)
    p.add_argument("--checker-prob", type=int, default=0)
    p.add_argument("--timeout", type=int, default=600)
    args = p.parse_args()

    if not SPIRE_BENCH_BIN.exists():
        print(f"ERROR: {SPIRE_BENCH_BIN} not found. Build it first per docstring.",
              file=sys.stderr)
        sys.exit(1)

    modes = args.modes.split(",")
    prob_sweep = [int(x) for x in args.prob_sweep.split(",")] if args.prob_sweep else None

    print(f"# modes={modes} n_ops={args.n_ops} iter={args.iter} "
          f"prob_sweep={prob_sweep} gramine={GRAMINE_CMD}")

    bench_rows = []
    profile_rows = []

    for mode in modes:
        if mode == "checker":
            probs_for_mode = prob_sweep if prob_sweep is not None else [args.checker_prob]
        else:
            probs_for_mode = [0]
        for prob in probs_for_mode:
            for iteration in range(args.iter):
                with tempfile.TemporaryDirectory(prefix="spire_bench_") as td:
                    workdir = Path(td)
                    mc_path = f"/tmp/crisp_mc_spire_{os.getpid()}_{iteration}.dat"
                    Path(mc_path).unlink(missing_ok=True)
                    Path(mc_path + ".tmp").unlink(missing_ok=True)
                    setup_workdir(workdir, mode, mc_path, args.n_ops,
                                  prob if mode == "checker" else None)
                    label = f"mode={mode} prob={prob} iter={iteration}"
                    try:
                        elapsed_us, ops, csv_lines = run_one(workdir, args.timeout)
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
