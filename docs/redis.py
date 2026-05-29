#!/usr/bin/env python3
"""Real Redis benchmark under CRISP modes.

Uses actual Redis 6.0.5 (built via Gramine CI-Examples/redis), runs server
inside Gramine SGX with AOF persistence (appendonly=yes, appendfsync=always),
drives load via redis-benchmark, measures throughput, captures CRISP profile
on graceful shutdown.

Prerequisite (one-time setup on VM):
    cd ~/gramine/CI-Examples/redis
    make SGX=1
    # This downloads + builds Redis 6.0.5 and the example manifest.
    # Result: redis-server, src/src/redis-cli, src/src/redis-benchmark

Run benchmark with:
    GRAMINE_CMD=gramine-sgx python3 redis.py --out microbench/redis.csv
"""

import argparse
import csv
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

REDIS_DIR = Path.home() / "gramine" / "CI-Examples" / "redis"
REDIS_SERVER_SRC = REDIS_DIR / "redis-server"
REDIS_CLI = REDIS_DIR / "src" / "src" / "redis-cli"
REDIS_BENCH = REDIS_DIR / "src" / "src" / "redis-benchmark"

MANIFEST_TEMPLATE = """
libos.entrypoint = "/redis-server"
loader.log_level = "error"
loader.argv = ["redis-server", "--save", "", "--appendonly", "yes",
               "--appendfsync", "always", "--dir", "/cr",
               "--bind", "127.0.0.1", "--protected-mode", "no",
               "--port", "{port}"]
loader.env.LD_LIBRARY_PATH = "/lib"

sys.enable_sigterm_injection = true

fs.insecure__keys.default = "{key}"

fs.mounts = [
  {{ path = "/lib", uri = "file:{runtime}" }},
  {{ path = "/redis-server", uri = "file:redis-server" }},
  {{ type = "encrypted", path = "/cr", uri = "file:pf_dir" }},
]

{crisp_block}
sgx.debug = true
sgx.enclave_size = "1024M"
{max_threads}
sgx.trusted_files = [
  "file:redis-server",
  "file:{runtime}/",
]
"""

CSV_LINE_RE = re.compile(r"\[CRISP CSV\] (.+?)$", re.MULTILINE)
BENCH_RE = re.compile(r"([\d.]+) requests per second")


def find_free_port(start=16500):
    for port in range(start, start + 200):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(("127.0.0.1", port))
                return port
            except OSError:
                continue
    raise RuntimeError("no free port")


def crisp_block_for(mode, mc_path, prob):
    if mode == "disabled":
        return "sgx.crisp.enabled = false\n"
    block = (
        "sgx.crisp.enabled = true\n"
        f'sgx.crisp.vault_path = "/cr/vault.dat"\n'
        f'sgx.crisp.mc_path = "{mc_path}"\n'
        'sgx.crisp.tracked_pfs = ["/cr/appendonly.aof"]\n'
        f'sgx.crisp.mode = "{mode}"\n'
        "sgx.crisp.profile = true\n"
    )
    if prob is not None and prob > 0:
        block += f"sgx.crisp.checker_prob = {prob}\n"
    return block


def setup_workdir(workdir, mode, mc_path, port, prob=None):
    # Symlink redis-server into workdir so manifest can reference it
    server_link = workdir / "redis-server"
    if not server_link.exists():
        server_link.symlink_to(REDIS_SERVER_SRC)
    (workdir / "pf_dir").mkdir(exist_ok=True)

    max_threads = "sgx.max_threads = 16\n" if IS_SGX else ""
    manifest = MANIFEST_TEMPLATE.format(
        key=KEY, runtime=RUNTIME, port=port,
        crisp_block=crisp_block_for(mode, mc_path, prob),
        max_threads=max_threads,
    )
    (workdir / "redis-server.manifest.template").write_text(manifest)
    subprocess.run(["gramine-manifest", "redis-server.manifest.template",
                    "redis-server.manifest"],
                   cwd=workdir, check=True,
                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if IS_SGX:
        subprocess.run(["gramine-sgx-sign", "--manifest", "redis-server.manifest",
                        "--output", "redis-server.manifest.sgx"],
                       cwd=workdir, check=True,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def wait_server_ready(port, deadline_sec=30):
    end = time.time() + deadline_sec
    while time.time() < end:
        try:
            r = subprocess.run([str(REDIS_CLI), "-p", str(port), "PING"],
                               capture_output=True, text=True, timeout=2)
            if "PONG" in r.stdout:
                return True
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        time.sleep(0.3)
    return False


def run_one(workdir, mode, prob, n_ops, payload_bytes, port, timeout):
    # Start server in background
    server_proc = subprocess.Popen(
        [GRAMINE_CMD, "redis-server"],
        cwd=workdir, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )

    try:
        if not wait_server_ready(port, deadline_sec=60 if IS_SGX else 15):
            raise RuntimeError("redis-server did not respond to PING within deadline")

        # Drive workload via redis-benchmark, -P 1 disables pipelining so each
        # SET issues its own AOF fsync, mirroring durable per-op behavior
        bench_t0 = time.time()
        bench = subprocess.run(
            [str(REDIS_BENCH), "-h", "127.0.0.1", "-p", str(port),
             "-t", "SET", "-n", str(n_ops), "-c", "1", "-P", "1",
             "-d", str(payload_bytes), "-q"],
            capture_output=True, text=True, timeout=timeout,
        )
        bench_elapsed = time.time() - bench_t0
        bench_out = bench.stdout + bench.stderr

        m = BENCH_RE.search(bench_out)
        if not m:
            raise RuntimeError(f"no 'requests per second' in bench output:\n{bench_out[-500:]}")
        ops_per_sec = float(m.group(1))

        # Shutdown server gracefully via SIGTERM so crisp_on_exit fires + dumps profile
        server_proc.terminate()
        try:
            server_out, _ = server_proc.communicate(timeout=60)
        except subprocess.TimeoutExpired:
            server_proc.kill()
            server_out, _ = server_proc.communicate()

        csv_rows = CSV_LINE_RE.findall(server_out)
        return int(bench_elapsed * 1e6), ops_per_sec, csv_rows

    finally:
        if server_proc.poll() is None:
            server_proc.kill()
            server_proc.communicate()


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--out", default="redis_results.csv")
    p.add_argument("--profile-out", default="redis_profile.csv")
    p.add_argument("--modes", default="disabled,synchronous,optimistic,checker")
    p.add_argument("--prob-sweep", default=None)
    p.add_argument("--n-ops", type=int, default=1000)
    p.add_argument("--payload", type=int, default=32, help="SET value payload bytes")
    p.add_argument("--iter", type=int, default=1)
    p.add_argument("--checker-prob", type=int, default=0)
    p.add_argument("--timeout", type=int, default=600)
    args = p.parse_args()

    # Sanity checks for prerequisites
    if not REDIS_SERVER_SRC.exists():
        print(f"ERROR: {REDIS_SERVER_SRC} not found. Run 'make SGX=1' in CI-Examples/redis first.",
              file=sys.stderr)
        sys.exit(1)
    if not REDIS_CLI.exists() or not REDIS_BENCH.exists():
        print(f"ERROR: redis-cli or redis-benchmark missing under {REDIS_DIR}/src/src/",
              file=sys.stderr)
        sys.exit(1)

    modes = args.modes.split(",")
    prob_sweep = [int(x) for x in args.prob_sweep.split(",")] if args.prob_sweep else None

    print(f"# modes={modes} n_ops={args.n_ops} payload={args.payload} iter={args.iter} "
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
                with tempfile.TemporaryDirectory(prefix="redis_bench_") as td:
                    workdir = Path(td)
                    port = find_free_port(16500 + iteration * 10)
                    mc_path = f"/tmp/crisp_mc_redis_{os.getpid()}_{iteration}.dat"
                    Path(mc_path).unlink(missing_ok=True)
                    Path(mc_path + ".tmp").unlink(missing_ok=True)
                    setup_workdir(workdir, mode, mc_path, port,
                                  prob if mode == "checker" else None)
                    label = f"mode={mode} prob={prob} iter={iteration} port={port}"
                    try:
                        elapsed_us, ops, csv_lines = run_one(workdir, mode, prob,
                                                             args.n_ops, args.payload,
                                                             port, args.timeout)
                    except Exception as exc:
                        print(f"FAIL {label}: {exc}", file=sys.stderr)
                        continue
                    print(f"OK {label} -> {ops:.2f} ops/s in {elapsed_us / 1000:.1f} ms")
                    bench_rows.append({
                        "mode": mode, "checker_prob": prob, "iteration": iteration,
                        "n_ops": args.n_ops, "payload_bytes": args.payload,
                        "elapsed_us": elapsed_us, "ops_per_sec": ops,
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
                                               "n_ops", "payload_bytes",
                                               "elapsed_us", "ops_per_sec"])
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
