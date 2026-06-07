#!/usr/bin/env python3
# CRISP fail-stop detection tests
#   python3 docs/crisp_fail_stop.py            run all
#   python3 docs/crisp_fail_stop.py NAME ...   run only the named cases
# Each case simulates a corruption or attack against a previously-good CRISP state,
# then verifies that the runtime refuses to start the application (PalProcessExit(1)).
# One documented limitation case passes by NOT being detected: a full-storage-snapshot
# rollback is outside the reach of the simulated host-file MC, and a hardware-anchored
# counter would be needed to catch it. Needs the gramine runtime installed,
# gramine-manifest is run with --no-check

import os
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RT = "{{ gramine.runtimedir() }}"

GRAMINE_CMD = os.environ.get("GRAMINE_CMD", "gramine-direct")
IS_SGX = GRAMINE_CMD == "gramine-sgx"
VERBOSE = os.environ.get("VERBOSE") == "1"

APP = r'''
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
int main(void){
  int a=open("/cr/a.dat",O_WRONLY|O_CREAT|O_TRUNC,0600); write(a,"alpha",5); fsync(a); close(a);
  int b=open("/cr/b.dat",O_WRONLY|O_CREAT|O_TRUNC,0600); write(b,"beta",4);  fsync(b); close(b);
  printf("APP_RAN\n"); return 0;
}'''


def manifest(crisp, loglevel="debug"):
    max_threads = 'sgx.max_threads = 16\n' if IS_SGX else ''
    return (
        'libos.entrypoint = "/main"\n'
        f'loader.log_level = "{loglevel}"\n'
        'loader.env.LD_LIBRARY_PATH = "/lib"\n'
        'fs.insecure__keys.default = "ffeeddccbbaa99887766554433221100"\n'
        'fs.mounts = [\n'
        f'  {{ path = "/lib", uri = "file:{RT}" }},\n'
        '  { path = "/main", uri = "file:main" },\n'
        '  { type = "encrypted", path = "/cr", uri = "file:pf_dir" },\n'
        ']\n'
        f'{crisp}'
        'sgx.debug = true\n'
        'sgx.enclave_size = "256M"\n'
        f'{max_threads}'
        f'sgx.trusted_files = [\n  "file:main",\n  "file:{RT}/",\n]\n'
    )


def good_crisp(mcp, port=0):
    s = "sgx.crisp.enabled = true\n"
    s += 'sgx.crisp.vault_path = "/cr/vault.dat"\n'
    s += f'sgx.crisp.mc_path = "{mcp}"\n'
    s += 'sgx.crisp.tracked_pfs = ["/cr/a.dat", "/cr/b.dat"]\n'
    if port:
        s += f"sgx.crisp.checker_api_port = {port}\n"
    return s


def setup(d, mani):
    Path(d, "main.c").write_text(APP)
    Path(d, "main.manifest.template").write_text(mani)
    os.makedirs(Path(d, "pf_dir"), exist_ok=True)
    subprocess.run(
        ["gcc", "-O1", "-o", "main", "main.c"],
        cwd=d, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    subprocess.run(
        ["gramine-manifest", "--no-check", "main.manifest.template", "main.manifest"],
        cwd=d, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    if IS_SGX:
        subprocess.run(
            ["gramine-sgx-sign", "--manifest", "main.manifest",
             "--output", "main.manifest.sgx"],
            cwd=d, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )


def run(d, t=25):
    if not VERBOSE:
        p = subprocess.run(
            [GRAMINE_CMD, "main"],
            cwd=d, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, timeout=t,
        )
        return p.returncode, p.stdout

    proc = subprocess.Popen(
        [GRAMINE_CMD, "main"],
        cwd=d, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    buf = []
    try:
        for line in iter(proc.stdout.readline, ''):
            sys.stdout.write(line)
            sys.stdout.flush()
            buf.append(line)
        proc.wait(timeout=t)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
    return proc.returncode, ''.join(buf)


def mc_read(path):
    try:
        b = Path(path).read_bytes()
    except FileNotFoundError:
        return None
    if len(b) != 8:
        return None
    return struct.unpack("<Q", b)[0]


def mc_write(path, val):
    Path(path).write_bytes(struct.pack("<Q", val))


def clean(*paths):
    for p in paths:
        for suffix in ("", ".tmp"):
            Path(str(p) + suffix).unlink(missing_ok=True)


def fail_stopped(rc, out, marker=None):
    # Refusal means nonzero exit, no APP_RAN line, and the named reason in the log if given
    if rc == 0 or "APP_RAN" in out:
        return False
    if marker is None:
        return True
    return marker in out


# ----- cases ------------------------------------------------------------------

def case_rollback_mc_gt_l(d, mcp):
    # Bump the on-disk MC above the vault's promised L, then restart
    setup(d, manifest(good_crisp(mcp)))
    run(d)
    l = mc_read(mcp)
    mc_write(mcp, l + 1000)
    rc, out = run(d)
    ok = fail_stopped(rc, out, "ROLLBACK DETECTED")
    return ok, dict(rc=rc, vault_L=l, mc_set_to=l + 1000)


def case_crash_mc_lt_l(d, mcp):
    # Drop the on-disk MC below the vault's promised L, then restart
    setup(d, manifest(good_crisp(mcp)))
    run(d)
    l = mc_read(mcp)
    mc_write(mcp, max(0, l - 2))
    rc, out = run(d)
    ok = fail_stopped(rc, out, "UNRECOVERABLE CRASH")
    return ok, dict(rc=rc, vault_L=l, mc_set_to=max(0, l - 2))


def case_tag_mismatch_pf_deleted(d, mcp):
    # Remove a tracked Protected File between runs, the recomputed tag will not match the vault
    setup(d, manifest(good_crisp(mcp)))
    run(d)
    Path(d, "pf_dir", "a.dat").unlink()
    rc, out = run(d)
    ok = fail_stopped(rc, out, "TAG MISMATCH")
    return ok, dict(rc=rc)


def case_tampered_pf_unreadable(d, mcp):
    # Overwrite a tracked PF with random bytes, the PF layer will refuse to decrypt
    setup(d, manifest(good_crisp(mcp)))
    run(d)
    Path(d, "pf_dir", "a.dat").write_bytes(os.urandom(256))
    rc, out = run(d)
    ok = fail_stopped(rc, out, "exists but is unreadable as a Protected File")
    ok = ok and "normal startup" not in out
    return ok, dict(rc=rc, normal_startup="normal startup" in out)


def case_vault_deleted_mc_present(d, mcp):
    # Remove the vault file while the MC is still nonzero
    setup(d, manifest(good_crisp(mcp)))
    run(d)
    Path(d, "pf_dir", "vault.dat").unlink()
    rc, out = run(d)
    ok = fail_stopped(rc, out, "vault missing but MC > 0")
    return ok, dict(rc=rc, mc=mc_read(mcp))


def case_vault_corrupt(d, mcp):
    # Flip a byte inside the vault, the checksum will not verify
    setup(d, manifest(good_crisp(mcp)))
    run(d)
    v = Path(d, "pf_dir", "vault.dat")
    b = bytearray(v.read_bytes())
    b[2000] ^= 0xFF
    v.write_bytes(bytes(b))
    rc, out = run(d)
    ok = fail_stopped(rc, out, "vault file corrupted")
    return ok, dict(rc=rc)


def case_full_state_rollback_NOT_detected(d, mcp):
    # Documented simulated-MC limitation, a snapshot of {vault, PFs, MC} restored together
    # passes every check because each component is internally consistent at the snapshot time
    # A hardware RPMB or TPM-NV counter would catch this by being unrollable
    setup(d, manifest(good_crisp(mcp)))
    run(d)
    snap = tempfile.mkdtemp(prefix="crisp_fs_snap_")
    shutil.copytree(Path(d, "pf_dir"), Path(snap, "pf_dir"))
    shutil.copy(mcp, Path(snap, "mc.dat"))
    mc_at_snap = mc_read(mcp)
    run(d)
    shutil.rmtree(Path(d, "pf_dir"))
    shutil.copytree(Path(snap, "pf_dir"), Path(d, "pf_dir"))
    shutil.copy(Path(snap, "mc.dat"), mcp)
    rc, out = run(d)
    shutil.rmtree(snap, ignore_errors=True)
    ok = rc == 0 and "APP_RAN" in out and "normal startup" in out and "FAIL-STOP" not in out
    return ok, dict(
        rc=rc,
        mc_at_snapshot=mc_at_snap,
        mc_after_advance_then_restore=mc_read(mcp),
        note="EXPECTED not-detected, simulated MC is rollbackable, a hardware MC would catch this",
    )


def case_cfg_enabled_not_bool(d, mcp):
    # The enabled key must be a TOML boolean
    cfg = (
        'sgx.crisp.enabled = "true"\n'
        'sgx.crisp.vault_path = "/cr/vault.dat"\n'
        f'sgx.crisp.mc_path = "{mcp}"\n'
        'sgx.crisp.tracked_pfs = ["/cr/a.dat"]\n'
    )
    setup(d, manifest(cfg))
    rc, out = run(d)
    ok = fail_stopped(rc, out, "not a valid boolean")
    return ok, dict(rc=rc, cfg_invalid="config invalid" in out)


def case_cfg_port_out_of_range(d, mcp):
    # Port number above the valid TCP range
    setup(d, manifest(good_crisp(mcp) + "sgx.crisp.checker_api_port = 99999\n"))
    rc, out = run(d)
    ok = fail_stopped(rc, out, "checker_api_port must be an integer in [0, 65535]")
    return ok, dict(rc=rc)


def case_cfg_tracked_pfs_not_array(d, mcp):
    # tracked_pfs must be a TOML array, not a scalar string
    cfg = (
        'sgx.crisp.enabled = true\n'
        'sgx.crisp.vault_path = "/cr/vault.dat"\n'
        f'sgx.crisp.mc_path = "{mcp}"\n'
        'sgx.crisp.tracked_pfs = "/cr/a.dat"\n'
    )
    setup(d, manifest(cfg))
    rc, out = run(d)
    ok = fail_stopped(rc, out, "tracked_pfs is required and must be a non-empty array")
    return ok, dict(rc=rc)


def case_cfg_tracked_pfs_missing(d, mcp):
    # tracked_pfs is a required key, omitting it must refuse to start
    cfg = (
        'sgx.crisp.enabled = true\n'
        'sgx.crisp.vault_path = "/cr/vault.dat"\n'
        f'sgx.crisp.mc_path = "{mcp}"\n'
    )
    setup(d, manifest(cfg))
    rc, out = run(d)
    ok = fail_stopped(rc, out, "tracked_pfs is required")
    return ok, dict(rc=rc)


def case_cfg_vault_collides_tracked(d, mcp):
    # The vault path must not appear in the tracked PF list
    cfg = (
        'sgx.crisp.enabled = true\n'
        'sgx.crisp.vault_path = "/cr/a.dat"\n'
        f'sgx.crisp.mc_path = "{mcp}"\n'
        'sgx.crisp.tracked_pfs = ["/cr/a.dat"]\n'
    )
    setup(d, manifest(cfg))
    rc, out = run(d)
    ok = fail_stopped(rc, out, "collides with tracked PF")
    return ok, dict(rc=rc)


def case_checker_bind_failure(d, mcp):
    # Holding the Checker API port from the host side must cause CRISP to fail-stop at startup
    port = 19401
    code = (
        "import socket, time\n"
        "s = socket.socket()\n"
        "s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n"
        f"s.bind(('127.0.0.1', {port}))\n"
        "s.listen(1)\n"
        "time.sleep(20)\n"
    )
    holder = subprocess.Popen([sys.executable, "-c", code])
    time.sleep(1.0)
    setup(d, manifest(good_crisp(mcp, port=port)))
    try:
        rc, out = run(d)
    finally:
        holder.terminate()
        try:
            holder.wait(timeout=5)
        except subprocess.TimeoutExpired:
            holder.kill()
    ok = fail_stopped(rc, out, "bind/listen failed")
    return ok, dict(rc=rc, bind_err="PalSocketBind" in out)


CASES = [
    ("rollback_mc_gt_l", case_rollback_mc_gt_l),
    ("crash_mc_lt_l", case_crash_mc_lt_l),
    ("tag_mismatch_pf_deleted", case_tag_mismatch_pf_deleted),
    ("tampered_pf_unreadable", case_tampered_pf_unreadable),
    ("vault_deleted_mc_present", case_vault_deleted_mc_present),
    ("vault_corrupt", case_vault_corrupt),
    ("full_state_rollback_NOT_detected", case_full_state_rollback_NOT_detected),
    ("cfg_enabled_not_bool", case_cfg_enabled_not_bool),
    ("cfg_port_out_of_range", case_cfg_port_out_of_range),
    ("cfg_tracked_pfs_not_array", case_cfg_tracked_pfs_not_array),
    ("cfg_tracked_pfs_missing", case_cfg_tracked_pfs_missing),
    ("cfg_vault_collides_tracked", case_cfg_vault_collides_tracked),
    ("checker_bind_failure", case_checker_bind_failure),
]


def cleanup_mc():
    for f in Path("/tmp").glob("crisp_fs_*"):
        try:
            if f.is_file():
                f.unlink()
            else:
                shutil.rmtree(f, ignore_errors=True)
        except OSError:
            pass


class Tee:
    # Mirror writes to multiple streams so stdout still prints while a log file accumulates
    def __init__(self, *streams):
        self.streams = streams

    def write(self, s):
        for stream in self.streams:
            stream.write(s)
            stream.flush()

    def flush(self):
        for stream in self.streams:
            stream.flush()


def log_path_for(script):
    mode_suffix = "sgx" if IS_SGX else "direct"
    log_dir = Path(__file__).resolve().parent
    log_dir.mkdir(parents=True, exist_ok=True)
    override = os.environ.get("LOG_FILE")
    if override:
        return Path(override)
    return log_dir / f"{script}_{mode_suffix}.log"


def main():
    want = set(sys.argv[1:])
    cases = [(n, fn) for n, fn in CASES if not want or n in want]
    cleanup_mc()

    log_file = log_path_for("crisp_fail_stop").open("w")
    real_stdout = sys.stdout
    sys.stdout = Tee(real_stdout, log_file)
    try:
        npass = 0
        nfail = 0
        for i, (name, fn) in enumerate(cases):
            mcp = f"/tmp/crisp_fs_{i}.dat"
            clean(mcp)
            d = tempfile.mkdtemp(prefix="crisp_fs_")
            try:
                ok, info = fn(d, mcp)
            except Exception as e:
                ok, info = False, dict(error=repr(e))
            print(f"{'PASS' if ok else 'FAIL'}  {name}")
            for k, v in info.items():
                print(f"    {k} = {v}")
            if ok:
                npass += 1
            else:
                nfail += 1
            shutil.rmtree(d, ignore_errors=True)
        cleanup_mc()
        print(f"summary pass={npass} fail={nfail}")
    finally:
        sys.stdout = real_stdout
        log_file.close()
    sys.exit(0 if nfail == 0 else 1)


if __name__ == "__main__":
    main()
