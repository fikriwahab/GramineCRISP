#!/usr/bin/env python3
# SPIRE workload benchmark under CRISP modes (embedded design)
#   python3 docs/benchmarking/spire.py --out spire_results.csv --profile-out spire_profile.csv
# A single-process Go binary links the SPIRE sqlstore package and calls
# ds.CreateRegistrationEntry in a loop. Each call exercises the real SPIRE storage
# code path on SQLite with WAL journal mode. The single-process design avoids the
# multi-process fork limitation in Gramine's untrusted PAL on Go binaries
# Prerequisite (one-time on the host)
#   cd ~ && git clone --depth 1 --branch v1.15.1 \
#       https://github.com/spiffe/spire.git spire-source
#   mkdir ~/spire-bench && cd ~/spire-bench
#   # place main.go and go.mod with: replace github.com/spiffe/spire => ~/spire-source
#   go mod tidy && go build -o spire-bench main.go
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

SPIRE_BENCH_BIN = Path.home() / "spire-bench" / "spire-bench"


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


def crisp_block_for(mode, mc_path, prob):
    if mode == "disabled":
        return "sgx.crisp.enabled = false\n"
    block = (
        "sgx.crisp.enabled = true\n"
        'sgx.crisp.vault_path = "/cr/vault.dat"\n'
        f'sgx.crisp.mc_path = "{mc_path}"\n'
        'sgx.crisp.tracked_pfs = ["/cr/spire.sqlite3"]\n'
        f'sgx.crisp.mode = "{mode}"\n'
        "sgx.crisp.profile = true\n"
    )
    if prob is not None and prob > 0:
        block += f"sgx.crisp.checker_prob = {prob}\n"
    return block


def setup_workdir(workdir, mode, mc_path, n_ops, prob=None):
    bench_link = workdir / "spire-bench"
    if not bench_link.exists():
        bench_link.symlink_to(SPIRE_BENCH_BIN)
    (workdir / "pf_dir").mkdir(exist_ok=True)

    max_threads = "sgx.max_threads = 32\n" if IS_SGX else ""
    manifest = MANIFEST_TEMPLATE.format(
        key=KEY,
        runtime=RUNTIME,
        arch_libdir=ARCH_LIBDIR,
        n_ops=n_ops,
        crisp_block=crisp_block_for(mode, mc_path, prob),
        max_threads=max_threads,
    )
    (workdir / "app.manifest.template").write_text(manifest)
    subprocess.run(
        ["gramine-manifest", "app.manifest.template", "app.manifest"],
        cwd=workdir, check=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    if IS_SGX:
        subprocess.run(
            ["gramine-sgx-sign", "--manifest", "app.manifest",
             "--output", "app.manifest.sgx"],
            cwd=workdir, check=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )


def run_one(workdir, timeout):
    p = subprocess.run(
        [GRAMINE_CMD, "app"],
        cwd=workdir, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, timeout=timeout,
    )
    out = p.stdout
    m = METRIC_RE.search(out)
    if not m:
        raise RuntimeError(f"no SPIRE_BENCH line in output:\n{out[-2000:]}")
    elapsed_us = int(m.group(2))
    ops_per_sec = float(m.group(3))
    csv_rows = CSV_LINE_RE.findall(out)
    return elapsed_us, ops_per_sec, csv_rows


def default_log_path():
    mode_suffix = "sgx" if IS_SGX else "direct"
    return SCRIPT_DIR / f"spire_{mode_suffix}.log"


def parse_args():
    p = argparse.ArgumentParser(
        description="SPIRE per-mode application benchmark under CRISP",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--out", default=str(SCRIPT_DIR / "spire_results.csv"))
    p.add_argument("--profile-out", default=str(SCRIPT_DIR / "spire_profile.csv"))
    p.add_argument("--log", default=str(default_log_path()),
                   help="log file mirroring stdout")
    p.add_argument("--modes", default="disabled,synchronous,optimistic,checker")
    p.add_argument("--prob-sweep", default=None,
                   help="comma-separated checker_prob values for the checker mode")
    p.add_argument("--n-ops", type=int, default=200,
                   help="CreateRegistrationEntry calls per run")
    p.add_argument("--iter", type=int, default=10,
                   help="iterations per (mode, prob) combination")
    p.add_argument("--checker-prob", type=int, default=0)
    p.add_argument("--timeout", type=int, default=600)
    return p.parse_args()


def main():
    args = parse_args()

    if not SPIRE_BENCH_BIN.exists():
        print(
            f"ERROR: {SPIRE_BENCH_BIN} not found, "
            "build the embedded Go bench first per the header comment",
            file=sys.stderr,
        )
        sys.exit(1)

    modes = args.modes.split(",")
    prob_sweep = [int(x) for x in args.prob_sweep.split(",")] if args.prob_sweep else None

    log_file = open(args.log, "w")
    real_stdout = sys.stdout
    sys.stdout = Tee(real_stdout, log_file)

    try:
        print(
            f"# modes={modes} n_ops={args.n_ops} iter={args.iter} "
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
                    with tempfile.TemporaryDirectory(prefix="spire_bench_") as td:
                        workdir = Path(td)
                        mc_path = f"/tmp/crisp_mc_spire_{os.getpid()}_{iteration}.dat"
                        Path(mc_path).unlink(missing_ok=True)
                        Path(mc_path + ".tmp").unlink(missing_ok=True)
                        setup_workdir(
                            workdir, mode, mc_path, args.n_ops,
                            prob if mode == "checker" else None,
                        )
                        label = f"mode={mode} prob={prob} iter={iteration}"
                        try:
                            elapsed_us, ops, csv_lines = run_one(workdir, args.timeout)
                        except Exception as exc:
                            print(f"FAIL {label}: {exc}", file=real_stdout)
                            continue
                        print(
                            f"OK {label} -> {ops:.2f} ops/s "
                            f"in {elapsed_us / 1000:.1f} ms"
                        )
                        bench_rows.append({
                            "mode": mode,
                            "checker_prob": prob,
                            "iteration": iteration,
                            "n_ops": args.n_ops,
                            "elapsed_us": elapsed_us,
                            "ops_per_sec": ops,
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
                            "n_ops", "elapsed_us", "ops_per_sec"],
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
