#!/usr/bin/env python3
# SPIRE-server-equivalent network gating benchmark
#   python3 docs/gate-benchmark/spire_server.py \
#       --out spire_server_gate_results.csv --profile-out spire_server_gate_profile.csv
# The embedded Go binary opens a TCP listener that accepts JSON-line registration
# entry requests, calls ds.CreateRegistrationEntry through the real SPIRE sqlstore,
# then sends a JSON response. The combination exercises the real storage path plus
# the network egress hook so the network shield can be evaluated end to end
# Prerequisite (one-time on the host)
#   build ~/spire-server-bench/spire-server-bench from the Go source described
#   in the project reproduction guide
# Outputs default to the script directory, both CSV and a stdout-mirroring log file

import argparse
import csv
import json
import os
import re
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

GRAMINE_CMD = os.environ.get("GRAMINE_CMD", "gramine-direct")
IS_SGX = GRAMINE_CMD == "gramine-sgx"
KEY = "ff000000000000000000000000000000"
RUNTIME = "/usr/local/lib/x86_64-linux-gnu/gramine/runtime/glibc"
ARCH_LIBDIR = "/lib/x86_64-linux-gnu"
SCRIPT_DIR = Path(__file__).resolve().parent
BENCH_BIN = Path.home() / "spire-server-bench" / "spire-server-bench"


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
libos.entrypoint = "/spire-server-bench"
loader.log_level = "error"
loader.argv = ["spire-server-bench", "-port", "{port}", "-db", "/cr/spire.sqlite3"]
loader.env.LD_LIBRARY_PATH = "/lib:{arch_libdir}"
loader.env.HOME = "/home/azureuser"

sys.enable_sigterm_injection = true

fs.insecure__keys.default = "{key}"

fs.mounts = [
  {{ path = "/lib", uri = "file:{runtime}" }},
  {{ path = "{arch_libdir}", uri = "file:{arch_libdir}" }},
  {{ path = "/spire-server-bench", uri = "file:spire-server-bench" }},
  {{ type = "encrypted", path = "/cr", uri = "file:pf_dir" }},
]

{crisp_block}
sgx.debug = true
sgx.enclave_size = "8G"
{max_threads}
sgx.trusted_files = [
  "file:spire-server-bench",
  "file:{runtime}/",
  "file:{arch_libdir}/",
]
"""

CSV_LINE_RE = re.compile(r"\[CRISP CSV\] (.+?)$", re.MULTILINE)


def find_free_port(start=18099):
    for port in range(start, start + 200):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(("127.0.0.1", port))
                return port
            except OSError:
                continue
    raise RuntimeError("no free port")


def crisp_block_for(mode, mc_path, prob, gate_policy="none"):
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
    if gate_policy and gate_policy != "none":
        block += "sgx.crisp.network_gate = true\n"
        block += f'sgx.crisp.gate_policy = "{gate_policy}"\n'
        block += "sgx.crisp.gate_timeout_ms = 30000\n"
    return block


def setup_workdir(workdir, mode, mc_path, port, prob=None, gate_policy="none"):
    bench_link = workdir / "spire-server-bench"
    if not bench_link.exists():
        bench_link.symlink_to(BENCH_BIN)
    (workdir / "pf_dir").mkdir(exist_ok=True)

    max_threads = "sgx.max_threads = 32\n" if IS_SGX else ""
    manifest = MANIFEST_TEMPLATE.format(
        key=KEY,
        runtime=RUNTIME,
        arch_libdir=ARCH_LIBDIR,
        port=port,
        crisp_block=crisp_block_for(mode, mc_path, prob, gate_policy),
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


def wait_listen(server_proc, port, deadline_sec):
    end = time.time() + deadline_sec
    while time.time() < end:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                s.connect(("127.0.0.1", port))
                return True
        except (ConnectionRefusedError, OSError, socket.timeout):
            time.sleep(0.3)
    return False


def drive_workload(port, n_ops):
    # One connection, n_ops sequential request and response cycles
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(30)
    s.connect(("127.0.0.1", port))
    t0 = time.time()
    f = s.makefile("rwb")
    for i in range(n_ops):
        req = json.dumps({
            "parent_id": f"spiffe://example.org/agent{i}",
            "spiffe_id": f"spiffe://example.org/workload{i}",
            "selector": f"uid:{i}",
        }) + "\n"
        f.write(req.encode())
        f.flush()
        resp_line = f.readline()
        if not resp_line:
            raise RuntimeError(f"empty response at op {i}")
    elapsed = time.time() - t0
    s.close()
    return elapsed


def run_one(workdir, mode, prob, n_ops, port, timeout):
    server_proc = subprocess.Popen(
        [GRAMINE_CMD, "app"],
        cwd=workdir, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    try:
        if not wait_listen(server_proc, port, deadline_sec=30 if IS_SGX else 10):
            raise RuntimeError("server did not start listening within deadline")
        elapsed = drive_workload(port, n_ops)
        server_proc.terminate()
        try:
            out, _ = server_proc.communicate(timeout=15)
        except subprocess.TimeoutExpired:
            server_proc.kill()
            out, _ = server_proc.communicate()
        ops_per_sec = n_ops / elapsed
        csv_rows = CSV_LINE_RE.findall(out)
        return int(elapsed * 1e6), ops_per_sec, csv_rows
    finally:
        if server_proc.poll() is None:
            server_proc.kill()
            server_proc.communicate()


def default_log_path():
    mode_suffix = "sgx" if IS_SGX else "direct"
    return SCRIPT_DIR / f"spire_server_gate_{mode_suffix}.log"


def parse_args():
    p = argparse.ArgumentParser(
        description="SPIRE-server-equivalent network egress gating benchmark",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--out",
                   default=str(SCRIPT_DIR / "spire_server_gate_results.csv"))
    p.add_argument("--profile-out",
                   default=str(SCRIPT_DIR / "spire_server_gate_profile.csv"))
    p.add_argument("--log", default=str(default_log_path()),
                   help="log file mirroring stdout")
    p.add_argument("--modes", default="optimistic")
    p.add_argument("--prob", default=None)
    p.add_argument("--gate-policy", default="none,block",
                   help="comma-separated gate policies to sweep")
    p.add_argument("--n-ops", type=int, default=200)
    p.add_argument("--iter", type=int, default=10)
    p.add_argument("--checker-prob", type=int, default=0)
    p.add_argument("--timeout", type=int, default=300)
    return p.parse_args()


def main():
    args = parse_args()

    if not BENCH_BIN.exists():
        print(f"ERROR: {BENCH_BIN} not found", file=sys.stderr)
        sys.exit(1)

    modes = args.modes.split(",")
    prob_sweep = [int(x) for x in args.prob.split(",")] if args.prob else None
    gate_policies = args.gate_policy.split(",") if args.gate_policy else ["none"]

    log_file = open(args.log, "w")
    real_stdout = sys.stdout
    sys.stdout = Tee(real_stdout, log_file)

    try:
        print(
            f"# modes={modes} n_ops={args.n_ops} iter={args.iter} "
            f"prob_sweep={prob_sweep} gate_policies={gate_policies} "
            f"gramine={GRAMINE_CMD}"
        )

        bench_rows = []
        profile_rows = []

        for mode in modes:
            if mode == "checker" and prob_sweep:
                probs_for_mode = prob_sweep
            elif mode == "checker":
                probs_for_mode = [args.checker_prob]
            else:
                probs_for_mode = [0]
            for prob in probs_for_mode:
                for gate_policy in gate_policies:
                    if mode == "disabled" and gate_policy != "none":
                        continue
                    for iteration in range(args.iter):
                        with tempfile.TemporaryDirectory(prefix="spire_server_") as td:
                            workdir = Path(td)
                            port = find_free_port(18099 + iteration * 10)
                            mc_path = (
                                f"/tmp/crisp_mc_spireserver_"
                                f"{os.getpid()}_{iteration}.dat"
                            )
                            Path(mc_path).unlink(missing_ok=True)
                            Path(mc_path + ".tmp").unlink(missing_ok=True)
                            setup_workdir(
                                workdir, mode, mc_path, port,
                                prob if mode == "checker" else None,
                                gate_policy=gate_policy,
                            )
                            label = (
                                f"mode={mode} prob={prob} gate={gate_policy} "
                                f"iter={iteration} port={port}"
                            )
                            try:
                                elapsed_us, ops, csv_lines = run_one(
                                    workdir, mode, prob,
                                    args.n_ops, port, args.timeout,
                                )
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
                                "gate_policy": gate_policy,
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
                                    "gate_policy": gate_policy,
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
                fieldnames=["mode", "checker_prob", "gate_policy",
                            "iteration", "n_ops",
                            "elapsed_us", "ops_per_sec"],
            )
            writer.writeheader()
            writer.writerows(bench_rows)
        print(f"wrote {len(bench_rows)} rows to {args.out}")

        if profile_rows:
            with open(args.profile_out, "w", newline="") as f:
                writer = csv.DictWriter(
                    f,
                    fieldnames=["mode", "checker_prob", "gate_policy",
                                "iteration", "slot", "count",
                                "total_us", "avg_us"],
                )
                writer.writeheader()
                writer.writerows(profile_rows)
            print(f"wrote {len(profile_rows)} rows to {args.profile_out}")
    finally:
        sys.stdout = real_stdout
        log_file.close()


if __name__ == "__main__":
    main()
