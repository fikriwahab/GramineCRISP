#!/usr/bin/env python3
# CRISP functional behavior tests
#   python3 docs/crisp_functional.py            run all
#   python3 docs/crisp_functional.py NAME ...   run only the named cases
# Each case builds a tiny C application and a CRISP manifest under a per-case temp
# directory, runs it under gramine-direct or gramine-sgx, then inspects the on-disk
# monotonic counter file, the vault file, the Checker API socket, and the exit code
# against the expected behavior. Set GRAMINE_CMD=gramine-sgx to run under a real
# SGX enclave (the helper signs the manifest and bumps sgx.max_threads)

import os
import re
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


def manifest(crisp, extra_mounts="", extra_trusted="", loglevel="debug"):
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
        f'{extra_mounts}]\n'
        f'{crisp}'
        'sgx.debug = true\n'
        'sgx.enclave_size = "256M"\n'
        f'{max_threads}'
        'sgx.trusted_files = [\n  "file:main",\n'
        f'{extra_trusted}  "file:{RT}/",\n]\n'
    )


def crisp_keys(mcpath, port=0, tracked='["/cr/a.dat", "/cr/b.dat"]', enabled=True,
               latency=0, prob=0, qtimeout=0, mode=None, gate=None, gate_timeout=0,
               extra=""):
    if not enabled:
        return "sgx.crisp.enabled = false\n"
    s = "sgx.crisp.enabled = true\n"
    s += 'sgx.crisp.vault_path = "/cr/vault.dat"\n'
    s += f'sgx.crisp.mc_path = "{mcpath}"\n'
    s += f"sgx.crisp.tracked_pfs = {tracked}\n"
    if port:
        s += f"sgx.crisp.checker_api_port = {port}\n"
    if latency:
        s += f"sgx.crisp.mc_latency_ms = {latency}\n"
    if prob:
        s += f"sgx.crisp.checker_prob = {prob}\n"
    if qtimeout:
        s += f"sgx.crisp.queue_timeout_ms = {qtimeout}\n"
    if mode:
        s += f'sgx.crisp.mode = "{mode}"\n'
    if gate:
        s += "sgx.crisp.network_gate = true\n"
        s += f'sgx.crisp.gate_policy = "{gate}"\n'
        if gate_timeout:
            s += f"sgx.crisp.gate_timeout_ms = {gate_timeout}\n"
    return s + extra


def write(p, txt):
    Path(p).write_text(txt)


def setup(d, app_c, mani, child_c=None):
    write(Path(d) / "main.c", app_c)
    write(Path(d) / "main.manifest.template", mani)
    os.makedirs(Path(d) / "pf_dir", exist_ok=True)
    subprocess.run(
        ["gcc", "-O1", "-pthread", "-o", "main", "main.c"],
        cwd=d, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    if child_c is not None:
        write(Path(d) / "child.c", child_c)
        subprocess.run(
            ["gcc", "-O1", "-o", "child", "child.c"],
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


def run_bg(d):
    return subprocess.Popen(
        [GRAMINE_CMD, "main"],
        cwd=d, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )


def mc(path):
    try:
        b = Path(path).read_bytes()
    except FileNotFoundError:
        return None
    if len(b) == 8:
        return struct.unpack("<Q", b)[0]
    return (len(b), b)


def checker(port, deadline=8.0, expected_min=0):
    # Wire format, client sends 8-byte expected_min, server blocks until S >= expected_min,
    # then replies with 8-byte S
    end = time.time() + deadline
    while time.time() < end:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=4) as s:
                s.sendall(struct.pack("<Q", expected_min))
                data = b""
                while len(data) < 8:
                    chunk = s.recv(8 - len(data))
                    if not chunk:
                        break
                    data += chunk
            if len(data) == 8:
                return struct.unpack("<Q", data)[0]
            return None
        except (ConnectionRefusedError, OSError, socket.timeout):
            time.sleep(0.1)
    return None


def n_batches(out):
    return out.count("mc-thread: batch committed") + out.count("crisp_commit_now: committed")


def has_covered_gt1(out):
    return any(int(m) > 1 for m in re.findall(r"covered (\d+)", out))


def gate_listener(port=19500):
    # Host-side TCP listener that the enclaved app connects to
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", port))
    s.listen(1)
    s.settimeout(15.0)
    return s


def gate_observe(listener, recv_timeout=12.0):
    # Accept the app's connection, time how long until bytes arrive,
    # return (accept_s, recv_s, data)
    t0 = time.time()
    conn, _ = listener.accept()
    t_accept = time.time() - t0
    conn.settimeout(recv_timeout)
    data = b""
    t1 = time.time()
    try:
        while len(data) < 5:
            chunk = conn.recv(64)
            if not chunk:
                break
            data += chunk
    except (socket.timeout, ConnectionResetError):
        pass
    t_recv = time.time() - t1
    conn.close()
    return t_accept, t_recv, data


# ----- C apps -----------------------------------------------------------------

APP_TWO = r'''
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
int main(void){
  int a=open("/cr/a.dat",O_WRONLY|O_CREAT|O_TRUNC,0600); write(a,"alpha",5); fsync(a); close(a);
  int b=open("/cr/b.dat",O_WRONLY|O_CREAT|O_TRUNC,0600); write(b,"beta",4);  fsync(b); close(b);
  printf("APP_RAN\n"); return 0;
}'''

APP_ONE_FSYNC = r'''
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
int main(void){
  int a=open("/cr/a.dat",O_WRONLY|O_CREAT|O_TRUNC,0600); write(a,"x",1); fsync(a); close(a);
  printf("APP_RAN\n"); return 0;
}'''

APP_ONE_FDATASYNC = r'''
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
int main(void){
  int a=open("/cr/a.dat",O_WRONLY|O_CREAT|O_TRUNC,0600); write(a,"x",1); fdatasync(a); close(a);
  printf("APP_RAN\n"); return 0;
}'''

APP_CLOSE_TIMED = r'''
#include <fcntl.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
static long ms(void){struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return t.tv_sec*1000+t.tv_nsec/1000000;}
int main(void){
  long t0=ms();
  int a=open("/cr/a.dat",O_WRONLY|O_CREAT|O_TRUNC,0600); write(a,"x",1); fsync(a);
  long t1=ms(); close(a); long t2=ms();
  printf("FSYNC_MS=%ld CLOSE_MS=%ld\n", t1-t0, t2-t1); return 0;
}'''

APP_CLOSE_RANGE = r'''
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>
int main(void){
  int a=open("/cr/a.dat",O_WRONLY|O_CREAT|O_TRUNC,0600); write(a,"x",1);
  long r=syscall(SYS_close_range,(unsigned)a,(unsigned)a,0u);
  printf("CLOSE_RANGE_RC=%ld\n", r); sleep(6); return 0;
}'''

APP_DUP2 = r'''
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
int main(void){
  int a=open("/cr/a.dat",O_WRONLY|O_CREAT|O_TRUNC,0600); write(a,"x",1);
  int b=open("/cr/b.dat",O_WRONLY|O_CREAT|O_TRUNC,0600); write(b,"y",1);
  dup2(b,a);                       /* closes a.dat's handle -> CRISP commit */
  close(a); close(b); printf("APP_RAN\n"); return 0;
}'''

APP_EXECVE = r'''
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
int main(void){
  int a=open("/cr/a.dat",O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC,0600); write(a,"cloexec",7);
  printf("ABOUT_TO_EXEC\n"); fflush(stdout);
  char* av[]={"child",0}; char* ev[]={"LD_LIBRARY_PATH=/lib",0};
  execve("/child",av,ev); printf("EXECVE_FAIL\n"); return 2;
}'''

CHILD_SLEEP = r'''
#include <stdio.h>
#include <unistd.h>
int main(void){ printf("CHILD_STARTED\n"); fflush(stdout); sleep(6); return 0; }'''

APP_EXIT_NOCLOSE = r'''
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
int main(void){
  int a=open("/cr/a.dat",O_WRONLY|O_CREAT|O_TRUNC,0600); write(a,"viaexit",7);
  printf("APP_RAN\n"); return 0;       /* no fsync, no close, exit hook must commit */
}'''

APP_UNLINK_DIRFSYNC = r'''
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
int main(void){
  unlink("/cr/a.dat");
  int d=open("/cr",O_RDONLY); int r=fsync(d); printf("DIR_FSYNC_RC=%d\n", r);
  sleep(6); return 0;
}'''

APP_NONPF_FSYNC = r'''
#include <stdio.h>
#include <unistd.h>
int main(void){ int r=fsync(1); printf("FSYNC_STDOUT_RC=%d APP_RAN\n", r); return 0; }'''

APP_BURST = r'''
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
int main(void){
  int a=open("/cr/a.dat",O_WRONLY|O_CREAT|O_TRUNC,0600);
  for(int i=0;i<30;i++){ char c='0'+(i%10); pwrite(a,&c,1,0); fsync(a); }
  close(a); printf("APP_RAN\n"); return 0;
}'''

APP_CHECKER_SLEEP = r'''
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
int main(void){
  int a=open("/cr/a.dat",O_WRONLY|O_CREAT|O_TRUNC,0600); write(a,"alpha",5); fsync(a); close(a);
  printf("APP_RAN\n"); fflush(stdout); sleep(6); return 0;
}'''

APP_CHECKER_SLOW = r'''
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
int main(void){
  int a=open("/cr/a.dat",O_WRONLY|O_CREAT|O_TRUNC,0600); write(a,"alpha",5); fsync(a);
  printf("FSYNC_QUEUED\n"); fflush(stdout); close(a); sleep(6); return 0;
}'''

APP_PROB = r'''
#include <fcntl.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
static long ms(void){struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return t.tv_sec*1000+t.tv_nsec/1000000;}
int main(void){
  int a=open("/cr/a.dat",O_WRONLY|O_CREAT|O_TRUNC,0600); write(a,"x",1);
  long t0=ms(); fsync(a); long t1=ms(); close(a);
  printf("FSYNC_MS=%ld\n", t1-t0); return 0;
}'''

APP_GATE_TEST = r'''
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
static long ms(void){struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return t.tv_sec*1000+t.tv_nsec/1000000;}
int main(void){
  int a=open("/cr/a.dat",O_WRONLY|O_CREAT|O_TRUNC,0600);
  write(a,"data",4); fsync(a);
  printf("FSYNC_QUEUED\n"); fflush(stdout);

  int sock=socket(AF_INET,SOCK_STREAM,0);
  if(sock<0){ printf("SOCK_FAILED\n"); return 1; }
  struct sockaddr_in addr={0};
  addr.sin_family=AF_INET; addr.sin_port=htons(19500);
  addr.sin_addr.s_addr=htonl(0x7f000001);
  if(connect(sock,(struct sockaddr*)&addr,sizeof(addr))<0){
    printf("CONNECT_FAILED errno=%d\n", errno); return 2;
  }
  printf("CONNECTED\n"); fflush(stdout);

  long t0=ms();
  int n=send(sock,"PING\n",5,0);
  long t1=ms(); int se=errno;
  printf("SEND_RC=%d ELAPSED_MS=%ld ERRNO=%d\n", n, t1-t0, se); fflush(stdout);

  close(sock); close(a);
  printf("APP_RAN\n"); return 0;
}'''

# The queue-timeout case reuses the two-file writer, the manifest sets the slow MC and small queue timeout
APP_TWO_QT = APP_TWO


# ----- cases ------------------------------------------------------------------

def case_fresh_install(d, mcp):
    setup(d, APP_TWO, manifest(crisp_keys(mcp)))
    rc, out = run(d)
    nb = n_batches(out)
    m = mc(mcp)
    v = (Path(d) / "pf_dir" / "vault.dat").exists()
    ok = (
        rc == 0
        and "APP_RAN" in out
        and "fresh install" in out
        and m == nb
        and m and m > 0
        and v
    )
    return ok, dict(rc=rc, batches=nb, mc=m, vault=v)


def case_clean_restart(d, mcp):
    setup(d, APP_TWO, manifest(crisp_keys(mcp)))
    run(d)
    rc, out = run(d)
    ok = (
        rc == 0
        and "APP_RAN" in out
        and "tag verified" in out
        and "FAIL-STOP" not in out
    )
    return ok, dict(rc=rc, verified="tag verified" in out, mc=mc(mcp))


def case_fsync_commits(d, mcp):
    setup(d, APP_ONE_FSYNC, manifest(crisp_keys(mcp, tracked='["/cr/a.dat"]')))
    rc, out = run(d)
    m = mc(mcp)
    ok = rc == 0 and "APP_RAN" in out and n_batches(out) >= 1 and m and m > 0
    return ok, dict(rc=rc, batches=n_batches(out), mc=m)


def case_fdatasync_forwards(d, mcp):
    setup(d, APP_ONE_FDATASYNC, manifest(crisp_keys(mcp, tracked='["/cr/a.dat"]')))
    rc, out = run(d)
    m = mc(mcp)
    ok = rc == 0 and "APP_RAN" in out and n_batches(out) >= 1 and m and m > 0
    return ok, dict(rc=rc, batches=n_batches(out), mc=m)


def case_close_synchronous(d, mcp):
    # close on a tracked PF must block until the in-flight commit drains
    setup(d, APP_CLOSE_TIMED,
          manifest(crisp_keys(mcp, tracked='["/cr/a.dat"]', latency=2000)))
    rc, out = run(d, t=40)
    m1 = re.search(r"CLOSE_MS=(\d+)", out)
    close_ms = int(m1.group(1)) if m1 else -1
    ok = rc == 0 and close_ms >= 1500
    return ok, dict(rc=rc, close_ms=close_ms)


def case_close_range_commits(d, mcp):
    setup(d, APP_CLOSE_RANGE,
          manifest(crisp_keys(mcp, port=19310, tracked='["/cr/a.dat"]')))
    p = run_bg(d)
    time.sleep(3.5)
    cm = checker(19310)
    m = mc(mcp)
    v = (Path(d) / "pf_dir" / "vault.dat").exists()
    p.wait(timeout=20)
    ok = m and m > 0 and v and cm == m
    return ok, dict(mc=m, checker=cm, vault=v)


def case_dup2_overwrite_commits(d, mcp):
    setup(d, APP_DUP2, manifest(crisp_keys(mcp)))
    rc, out = run(d)
    m = mc(mcp)
    v = (Path(d) / "pf_dir" / "vault.dat").exists()
    ok = rc == 0 and "APP_RAN" in out and m and m > 0 and v
    return ok, dict(rc=rc, mc=m, vault=v)


def case_execve_cloexec_commits(d, mcp):
    setup(
        d,
        APP_EXECVE,
        manifest(
            crisp_keys(mcp, port=19311, tracked='["/cr/a.dat"]'),
            extra_mounts='  { path = "/child", uri = "file:child" },\n',
            extra_trusted='  "file:child",\n',
        ),
        child_c=CHILD_SLEEP,
    )
    p = run_bg(d)
    time.sleep(3.5)
    cm = checker(19311)
    m = mc(mcp)
    v = (Path(d) / "pf_dir" / "vault.dat").exists()
    out = p.stdout.read() if p.stdout else ""
    p.wait(timeout=20)
    ok = m and m > 0 and v and cm == m
    return ok, dict(mc=m, checker=cm, vault=v, child="CHILD_STARTED" in out)


def case_exit_commits(d, mcp):
    setup(d, APP_EXIT_NOCLOSE, manifest(crisp_keys(mcp, tracked='["/cr/a.dat"]')))
    rc, out = run(d)
    m = mc(mcp)
    v = (Path(d) / "pf_dir" / "vault.dat").exists()
    rc2, out2 = run(d)
    ok = (
        rc == 0
        and "APP_RAN" in out
        and m and m > 0
        and v
        and rc2 == 0
        and "tag verified" in out2
    )
    return ok, dict(rc=rc, mc=m, vault=v,
                    restart_ok=rc2 == 0 and "tag verified" in out2)


def case_dir_fsync_unlink_committed(d, mcp):
    # First a writer establishes a.dat on disk
    # Then an unlink+dirfsync run removes it, the deletion must commit
    # A restart after that must verify cleanly because the vault tag was re-bound
    # to the a.dat-absent state
    setup(d, APP_TWO, manifest(crisp_keys(mcp)))
    run(d)
    before = mc(mcp)
    setup(d, APP_UNLINK_DIRFSYNC, manifest(crisp_keys(mcp, port=19312)))
    p = run_bg(d)
    time.sleep(3.5)
    cm = checker(19312)
    p.wait(timeout=20)
    after = mc(mcp)
    setup(d, APP_TWO, manifest(crisp_keys(mcp)))
    rc, out = run(d)
    ok = (
        isinstance(before, int)
        and isinstance(after, int)
        and isinstance(cm, int)
        and cm > before
        and after > before
        and rc == 0
        and "tag verified" in out
    )
    return ok, dict(before=before, after=after, checker_during=cm,
                    restart_ok=rc == 0 and "tag verified" in out)


def case_non_pf_fsync_noop(d, mcp):
    # fsync on a non-PF handle (stdout via stdio) must not enqueue a CRISP batch
    # so the only commit is the exit hook one, MC == n_batches == 1
    setup(d, APP_NONPF_FSYNC, manifest(crisp_keys(mcp, tracked='["/cr/a.dat"]')))
    rc, out = run(d)
    m = mc(mcp)
    line = next((l for l in out.splitlines() if "FSYNC_STDOUT_RC" in l), "")
    ok = (
        rc == 0
        and "APP_RAN" in out
        and "FSYNC_STDOUT_RC=" in out
        and m == n_batches(out) == 1
    )
    return ok, dict(rc=rc, fsync_stdout=line.strip(), mc=m, batches=n_batches(out))


def case_tag_path_order_independent(d, mcp):
    setup(d, APP_TWO,
          manifest(crisp_keys(mcp, tracked='["/cr/a.dat", "/cr/b.dat"]')))
    run(d)
    setup(d, APP_TWO,
          manifest(crisp_keys(mcp, tracked='["/cr/b.dat", "/cr/a.dat"]')))
    rc, out = run(d)
    ok = rc == 0 and "tag verified" in out and "FAIL-STOP" not in out
    return ok, dict(rc=rc, verified="tag verified" in out)


def case_vault_is_encrypted(d, mcp):
    setup(d, APP_TWO, manifest(crisp_keys(mcp)))
    run(d)
    vb = (Path(d) / "pf_dir" / "vault.dat").read_bytes()
    ok = (b"CRSP" not in vb) and len(vb) > 0
    return ok, dict(vault_bytes=len(vb), plaintext_magic_present=b"CRSP" in vb)


def case_batch_squash(d, mcp):
    # Batching only happens in optimistic mode, the default is now synchronous
    # so the test opts in explicitly. APP_BURST does 30 fsyncs, the squash means
    # the final MC is well below 30
    setup(d, APP_BURST,
          manifest(crisp_keys(mcp, tracked='["/cr/a.dat"]', mode="optimistic")))
    rc, out = run(d, t=40)
    m = mc(mcp)
    ok = rc == 0 and m and m < 30 and has_covered_gt1(out)
    return ok, dict(rc=rc, mc=m, n_fsyncs=30,
                    batches=n_batches(out), squashed=has_covered_gt1(out))


def case_checker_returns_mc(d, mcp):
    setup(d, APP_CHECKER_SLEEP,
          manifest(crisp_keys(mcp, port=19313, tracked='["/cr/a.dat"]')))
    p = run_bg(d)
    time.sleep(3.0)
    cm = checker(19313)
    m = mc(mcp)
    p.wait(timeout=20)
    ok = cm is not None and m is not None and cm == m
    return ok, dict(checker=cm, mc=m)


def case_checker_blocks_on_pending(d, mcp):
    # An in-flight batch requires async commit, the default is now synchronous
    # so the test opts in to optimistic
    setup(d, APP_CHECKER_SLOW,
          manifest(crisp_keys(mcp, port=19314, tracked='["/cr/a.dat"]',
                              latency=2500, mode="optimistic")))
    p = run_bg(d)
    time.sleep(0.6)
    # The app queues one fsync so the promised L = 1, the probe requests
    # expected_min=1 and must block until S catches up
    t0 = time.time()
    cm = checker(19314, deadline=12.0, expected_min=1)
    blocked_ms = int((time.time() - t0) * 1000)
    p.wait(timeout=20)
    m = mc(mcp)
    ok = (
        isinstance(cm, int)
        and isinstance(m, int)
        and cm >= 1
        and cm <= m
        and blocked_ms >= 1200
    )
    return ok, dict(checker_returned=cm, mc_final=m, blocked_ms=blocked_ms)


def case_probabilistic_p100_vs_p0(d, mcp):
    # At prob=0 the fsync returns immediately (async L2), at prob=100 it must
    # block close to mc_latency_ms (every roll fires the drain)
    def go(prob, suf):
        for s in ("", ".tmp"):
            Path(mcp + suf + s).unlink(missing_ok=True)
        shutil.rmtree(Path(d) / "pf_dir", ignore_errors=True)
        setup(d, APP_PROB,
              manifest(crisp_keys(mcp + suf, tracked='["/cr/a.dat"]',
                                  latency=1200, prob=prob, mode="optimistic")))
        rc, out = run(d, t=30)
        mm = re.search(r"FSYNC_MS=(\d+)", out)
        return rc, (int(mm.group(1)) if mm else None)

    rc0, g0 = go(0, ".p0")
    rc1, g1 = go(100, ".p100")
    ok = (
        rc0 == 0
        and rc1 == 0
        and isinstance(g0, int)
        and isinstance(g1, int)
        and g1 >= 800
        and g0 < 400
    )
    return ok, dict(fsync_ms_p0=g0, fsync_ms_p100=g1, rc0=rc0, rc1=rc1)


def case_disabled_noop(d, mcp):
    # With CRISP disabled, the runtime must behave as stock Gramine
    # No crisp_init line, no mc-thread, no Checker port, no vault
    setup(d, APP_TWO, manifest(crisp_keys(mcp, port=19315, enabled=False)))
    rc, out = run(d)
    cm = checker(19315, deadline=1.5)
    v = (Path(d) / "pf_dir" / "vault.dat").exists()
    m = mc(mcp)
    ok = (
        rc == 0
        and "APP_RAN" in out
        and "crisp_init" not in out
        and "mc-thread: started" not in out
        and "checker: listening" not in out
        and cm is None
        and not v
        and m is None
    )
    return ok, dict(rc=rc,
                    crisp_logs=("crisp_init" in out or "mc-thread" in out),
                    checker_open=cm is not None,
                    vault=v, mc=m)


def case_queue_timeout_fires(d, mcp):
    # Queue timeout is meaningful only in optimistic mode where requests
    # sit in the mc-thread queue, the synchronous path commits inline
    setup(d, APP_TWO_QT,
          manifest(crisp_keys(mcp, latency=3000, qtimeout=200, mode="optimistic")))
    rc, out = run(d, t=30)
    ok = rc == 1 and "queue timeout exceeded" in out and "APP_RAN" not in out
    return ok, dict(rc=rc,
                    queue_timeout="queue timeout exceeded" in out,
                    app_ran="APP_RAN" in out)


def case_mode_synchronous_explicit(d, mcp):
    # Explicit L1 synchronous, every fsync commits inline so 30 fsyncs produce
    # at least 30 MC increments and no batch shows covered > 1
    setup(d, APP_BURST,
          manifest(crisp_keys(mcp, tracked='["/cr/a.dat"]', mode="synchronous")))
    rc, out = run(d, t=40)
    m = mc(mcp)
    ok = (
        rc == 0
        and "APP_RAN" in out
        and m is not None
        and m >= 30
        and not has_covered_gt1(out)
    )
    return ok, dict(rc=rc, mc=m, n_fsyncs=30,
                    batches=n_batches(out), squashed=has_covered_gt1(out))


def case_mode_checker_explicit(d, mcp):
    # Explicit L3 mode value parses and runs, currently behaves like optimistic
    # plus the probabilistic dial, this test guards against regressions
    setup(d, APP_TWO,
          manifest(crisp_keys(mcp, port=19316, tracked='["/cr/a.dat"]',
                              mode="checker")))
    rc, out = run(d, t=20)
    m = mc(mcp)
    v = (Path(d) / "pf_dir" / "vault.dat").exists()
    ok = (
        rc == 0
        and "APP_RAN" in out
        and m is not None
        and m > 0
        and v
        and "FAIL-STOP" not in out
    )
    return ok, dict(rc=rc, mc=m, vault=v, app_ran="APP_RAN" in out)


def case_mc_monotone_across_runs(d, mcp):
    setup(d, APP_TWO, manifest(crisp_keys(mcp)))
    vals = []
    for _ in range(3):
        run(d)
        vals.append(mc(mcp))
    ok = all(isinstance(v, int) for v in vals) and vals == sorted(vals)
    return ok, dict(mc_values=vals)


def case_gate_none_passthrough(d, mcp):
    # Gate disabled, the send proceeds immediately even with mc_latency=2000ms
    listener = gate_listener(19500)
    try:
        setup(d, APP_GATE_TEST,
              manifest(crisp_keys(mcp, tracked='["/cr/a.dat"]',
                                  latency=2000, mode="optimistic")))
        p = run_bg(d)
        accept_s, recv_s, data = gate_observe(listener)
        p.wait(timeout=20)
    finally:
        listener.close()
    ok = data == b"PING\n" and recv_s < 0.8
    return ok, dict(data=data, recv_s=round(recv_s, 3),
                    accept_s=round(accept_s, 3))


def case_gate_block_drains(d, mcp):
    # Gate=block holds the send until the commit drains, then releases
    # mc_latency=2000ms forces a sustained pending state
    listener = gate_listener(19500)
    try:
        setup(d, APP_GATE_TEST,
              manifest(crisp_keys(mcp, tracked='["/cr/a.dat"]',
                                  latency=2000, mode="optimistic",
                                  gate="block")))
        p = run_bg(d)
        accept_s, recv_s, data = gate_observe(listener)
        p.wait(timeout=20)
    finally:
        listener.close()
    ok = data == b"PING\n" and 1.5 <= recv_s <= 4.0
    return ok, dict(data=data, recv_s=round(recv_s, 3))


def case_gate_drop_returns_econnrefused(d, mcp):
    # Gate=drop on a pending state returns negative rc and closes the socket,
    # the payload never reaches the host listener
    listener = gate_listener(19500)
    try:
        setup(d, APP_GATE_TEST,
              manifest(crisp_keys(mcp, tracked='["/cr/a.dat"]',
                                  latency=2000, mode="optimistic",
                                  gate="drop")))
        p = run_bg(d)
        accept_s, recv_s, data = gate_observe(listener, recv_timeout=4.0)
        p.wait(timeout=20)
        out = p.stdout.read() if p.stdout else ""
    finally:
        listener.close()
    send_failed = "SEND_RC=-1" in out
    ok = send_failed or data == b"" or data is None
    return ok, dict(data=data, send_failed=send_failed,
                    app_out_tail=out[-200:])


def case_gate_warn_passes_and_logs(d, mcp):
    # Gate=warn lets the send through without blocking and emits a warning log line
    listener = gate_listener(19500)
    try:
        setup(d, APP_GATE_TEST,
              manifest(crisp_keys(mcp, tracked='["/cr/a.dat"]',
                                  latency=2000, mode="optimistic",
                                  gate="warn")))
        p = run_bg(d)
        accept_s, recv_s, data = gate_observe(listener)
        p.wait(timeout=20)
        out = p.stdout.read() if p.stdout else ""
    finally:
        listener.close()
    has_warn = "gate=warn" in out or ("warn" in out.lower() and "pending" in out.lower())
    ok = data == b"PING\n" and recv_s < 0.8 and has_warn
    return ok, dict(data=data, recv_s=round(recv_s, 3),
                    has_warn_log=has_warn)


def case_gate_l3_composition(d, mcp):
    # Gate=block composed with checker_prob=50 must not deadlock and the total
    # wait stays bounded, latency is small so the joint cost is reasonable
    listener = gate_listener(19500)
    try:
        setup(d, APP_GATE_TEST,
              manifest(crisp_keys(mcp, tracked='["/cr/a.dat"]',
                                  latency=800, prob=50, mode="checker",
                                  gate="block")))
        p = run_bg(d)
        accept_s, recv_s, data = gate_observe(listener)
        p.wait(timeout=20)
    finally:
        listener.close()
    ok = data == b"PING\n" and recv_s < 5.0
    return ok, dict(data=data, recv_s=round(recv_s, 3))


CASES = [
    ("fresh_install", case_fresh_install),
    ("clean_restart", case_clean_restart),
    ("fsync_commits", case_fsync_commits),
    ("fdatasync_forwards", case_fdatasync_forwards),
    ("close_synchronous", case_close_synchronous),
    ("close_range_commits", case_close_range_commits),
    ("dup2_overwrite_commits", case_dup2_overwrite_commits),
    ("execve_cloexec_commits", case_execve_cloexec_commits),
    ("exit_commits", case_exit_commits),
    ("dir_fsync_unlink_committed", case_dir_fsync_unlink_committed),
    ("non_pf_fsync_noop", case_non_pf_fsync_noop),
    ("tag_path_order_independent", case_tag_path_order_independent),
    ("vault_is_encrypted", case_vault_is_encrypted),
    ("batch_squash", case_batch_squash),
    ("checker_returns_mc", case_checker_returns_mc),
    ("checker_blocks_on_pending", case_checker_blocks_on_pending),
    ("probabilistic_p100_vs_p0", case_probabilistic_p100_vs_p0),
    ("disabled_noop", case_disabled_noop),
    ("queue_timeout_fires", case_queue_timeout_fires),
    ("mc_monotone_across_runs", case_mc_monotone_across_runs),
    ("mode_synchronous_explicit", case_mode_synchronous_explicit),
    ("mode_checker_explicit", case_mode_checker_explicit),
    ("gate_none_passthrough", case_gate_none_passthrough),
    ("gate_block_drains", case_gate_block_drains),
    ("gate_drop_returns_econnrefused", case_gate_drop_returns_econnrefused),
    ("gate_warn_passes_and_logs", case_gate_warn_passes_and_logs),
    ("gate_l3_composition", case_gate_l3_composition),
]


def cleanup_mc():
    for f in Path("/tmp").glob("crisp_st_*"):
        try:
            f.unlink()
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

    log_file = log_path_for("crisp_functional").open("w")
    real_stdout = sys.stdout
    sys.stdout = Tee(real_stdout, log_file)
    try:
        npass = 0
        nfail = 0
        for i, (name, fn) in enumerate(cases):
            mcp = f"/tmp/crisp_st_{i}.dat"
            for suffix in ("", ".0", ".100", ".tmp"):
                Path(mcp + suffix).unlink(missing_ok=True)
            d = tempfile.mkdtemp(prefix="crisp_st_")
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
