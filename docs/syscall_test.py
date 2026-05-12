#!/usr/bin/env python3
# Builds tiny C apps and manifests under /tmp, runs them under gramine-direct, and
# checks the on-disk MC file / vault file / Checker socket / exit codes
# and gramine-manifest run with --no-check (the schema does not know sgx.crisp.* yet)

import os, shutil, socket, struct, subprocess, sys, tempfile, time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RT = "{{ gramine.runtimedir() }}"

def manifest(crisp, extra_mounts="", extra_trusted="", loglevel="debug"):
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
        'sgx.trusted_files = [\n  "file:main",\n'
        f'{extra_trusted}  "file:{RT}/",\n]\n'
    )

def crisp_keys(mcpath, port=0, tracked='["/cr/a.dat", "/cr/b.dat"]', enabled=True,
               latency=0, prob=0, qtimeout=0, extra=""):
    if not enabled:
        return "sgx.crisp.enabled = false\n"
    s = "sgx.crisp.enabled = true\n"
    s += f'sgx.crisp.vault_path = "/cr/vault.dat"\n'
    s += f'sgx.crisp.mc_path = "{mcpath}"\n'
    s += f"sgx.crisp.tracked_pfs = {tracked}\n"
    if port:     s += f"sgx.crisp.checker_api_port = {port}\n"
    if latency:  s += f"sgx.crisp.mc_latency_ms = {latency}\n"
    if prob:     s += f"sgx.crisp.checker_prob = {prob}\n"
    if qtimeout: s += f"sgx.crisp.queue_timeout_ms = {qtimeout}\n"
    return s + extra

def write(p, txt):
    Path(p).write_text(txt)

def setup(d, app_c, mani, child_c=None):
    write(Path(d) / "main.c", app_c)
    write(Path(d) / "main.manifest.template", mani)
    os.makedirs(Path(d) / "pf_dir", exist_ok=True)
    subprocess.run(["gcc", "-O1", "-pthread", "-o", "main", "main.c"], cwd=d, check=True,
                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if child_c is not None:
        write(Path(d) / "child.c", child_c)
        subprocess.run(["gcc", "-O1", "-o", "child", "child.c"], cwd=d, check=True,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    subprocess.run(["gramine-manifest", "--no-check", "main.manifest.template", "main.manifest"],
                   cwd=d, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

def run(d, t=25):
    p = subprocess.run(["gramine-direct", "main"], cwd=d, stdout=subprocess.PIPE,
                       stderr=subprocess.STDOUT, text=True, timeout=t)
    return p.returncode, p.stdout

def run_bg(d):
    return subprocess.Popen(["gramine-direct", "main"], cwd=d, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True)

def mc(path):
    try:
        b = Path(path).read_bytes()
    except FileNotFoundError:
        return None
    return struct.unpack("<Q", b)[0] if len(b) == 8 else (len(b), b)

def checker(port, deadline=8.0):
    end = time.time() + deadline
    while time.time() < end:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=4) as s:
                data = b""
                while len(data) < 8:
                    c = s.recv(8 - len(data))
                    if not c: break
                    data += c
            return struct.unpack("<Q", data)[0] if len(data) == 8 else None
        except (ConnectionRefusedError, OSError, socket.timeout):
            time.sleep(0.1)
    return None

def n_batches(out):  return out.count("mc-thread: batch committed")
def has_covered_gt1(out):
    import re
    return any(int(m) > 1 for m in re.findall(r"covered (\d+)", out))

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
  printf("APP_RAN\n"); return 0;       /* no fsync, no close -> exit hook must commit */
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
APP_TWO_QT = APP_TWO   # same app, the manifest sets the slow MC + small queue timeout

# ----- cases ------------------------------------------------------------------
def case_fresh_install(d, mcp):
    setup(d, APP_TWO, manifest(crisp_keys(mcp)))
    rc, out = run(d)
    nb = n_batches(out); m = mc(mcp); v = (Path(d)/"pf_dir"/"vault.dat").exists()
    ok = rc == 0 and "APP_RAN" in out and "fresh install" in out and m == nb and m and m > 0 and v
    return ok, dict(rc=rc, batches=nb, mc=m, vault=v)

def case_clean_restart(d, mcp):
    setup(d, APP_TWO, manifest(crisp_keys(mcp)))
    run(d); rc, out = run(d)
    ok = rc == 0 and "APP_RAN" in out and "tag verified" in out and "FAIL-STOP" not in out
    return ok, dict(rc=rc, verified="tag verified" in out, mc=mc(mcp))

def case_fsync_commits(d, mcp):
    setup(d, APP_ONE_FSYNC, manifest(crisp_keys(mcp, tracked='["/cr/a.dat"]')))
    rc, out = run(d); m = mc(mcp)
    ok = rc == 0 and "APP_RAN" in out and n_batches(out) >= 1 and m and m > 0
    return ok, dict(rc=rc, batches=n_batches(out), mc=m)

def case_fdatasync_forwards(d, mcp):
    setup(d, APP_ONE_FDATASYNC, manifest(crisp_keys(mcp, tracked='["/cr/a.dat"]')))
    rc, out = run(d); m = mc(mcp)
    ok = rc == 0 and "APP_RAN" in out and n_batches(out) >= 1 and m and m > 0
    return ok, dict(rc=rc, batches=n_batches(out), mc=m)

def case_close_synchronous(d, mcp):
    setup(d, APP_CLOSE_TIMED, manifest(crisp_keys(mcp, tracked='["/cr/a.dat"]', latency=2000)))
    rc, out = run(d, t=40)
    close_ms = next((int(x.split("=")[1].split()[0]) for x in [out] if False), None)
    import re
    m1 = re.search(r"CLOSE_MS=(\d+)", out)
    close_ms = int(m1.group(1)) if m1 else -1
    ok = rc == 0 and close_ms >= 1500   # close blocked ~2s for its batch
    return ok, dict(rc=rc, close_ms=close_ms)

def case_close_range_commits(d, mcp):
    setup(d, APP_CLOSE_RANGE, manifest(crisp_keys(mcp, port=19310, tracked='["/cr/a.dat"]')))
    p = run_bg(d); time.sleep(3.5)
    cm = checker(19310); m = mc(mcp); v = (Path(d)/"pf_dir"/"vault.dat").exists()
    p.wait(timeout=20)
    ok = m and m > 0 and v and cm == m
    return ok, dict(mc=m, checker=cm, vault=v)

def case_dup2_overwrite_commits(d, mcp):
    setup(d, APP_DUP2, manifest(crisp_keys(mcp)))
    rc, out = run(d); m = mc(mcp); v = (Path(d)/"pf_dir"/"vault.dat").exists()
    ok = rc == 0 and "APP_RAN" in out and m and m > 0 and v
    return ok, dict(rc=rc, mc=m, vault=v)

def case_execve_cloexec_commits(d, mcp):
    setup(d, APP_EXECVE,
          manifest(crisp_keys(mcp, port=19311, tracked='["/cr/a.dat"]'),
                   extra_mounts='  { path = "/child", uri = "file:child" },\n',
                   extra_trusted='  "file:child",\n'),
          child_c=CHILD_SLEEP)
    p = run_bg(d); time.sleep(3.5)
    cm = checker(19311); m = mc(mcp); v = (Path(d)/"pf_dir"/"vault.dat").exists()
    out = p.stdout.read() if p.stdout else ""; p.wait(timeout=20)
    ok = m and m > 0 and v and cm == m
    return ok, dict(mc=m, checker=cm, vault=v, child="CHILD_STARTED" in out)

def case_exit_commits(d, mcp):
    setup(d, APP_EXIT_NOCLOSE, manifest(crisp_keys(mcp, tracked='["/cr/a.dat"]')))
    rc, out = run(d); m = mc(mcp); v = (Path(d)/"pf_dir"/"vault.dat").exists()
    rc2, out2 = run(d)
    ok = rc == 0 and "APP_RAN" in out and m and m > 0 and v and rc2 == 0 and "tag verified" in out2
    return ok, dict(rc=rc, mc=m, vault=v, restart_ok=rc2 == 0 and "tag verified" in out2)

def case_dir_fsync_unlink_committed(d, mcp):
    # establish a.dat present, then unlink + dir-fsync (the deletion must commit), then restart must
    # verify (no false fail-stop, because the vault tag was re-bound to the a.dat-absent state)
    setup(d, APP_TWO, manifest(crisp_keys(mcp)))
    run(d); before = mc(mcp)
    setup(d, APP_UNLINK_DIRFSYNC, manifest(crisp_keys(mcp, port=19312)))
    p = run_bg(d); time.sleep(3.5); cm = checker(19312); p.wait(timeout=20)
    after = mc(mcp)
    setup(d, APP_TWO, manifest(crisp_keys(mcp)))   # back to the writer app, restart
    rc, out = run(d)
    ok = (isinstance(before, int) and isinstance(after, int) and isinstance(cm, int)
          and cm > before and after > before and rc == 0 and "tag verified" in out)
    return ok, dict(before=before, after=after, checker_during=cm, restart_ok=rc == 0 and "tag verified" in out)

def case_non_pf_fsync_noop(d, mcp):
    # fsync of a non-PF handle (stdout: a pipe -> returns -EINVAL) must not enqueue a CRISP batch,
    # so the only batch is the exit-hook one: MC == n_batches == 1
    setup(d, APP_NONPF_FSYNC, manifest(crisp_keys(mcp, tracked='["/cr/a.dat"]')))
    rc, out = run(d); m = mc(mcp)
    line = next((l for l in out.splitlines() if "FSYNC_STDOUT_RC" in l), "")
    ok = rc == 0 and "APP_RAN" in out and "FSYNC_STDOUT_RC=" in out and m == n_batches(out) == 1
    return ok, dict(rc=rc, fsync_stdout=line.strip(), mc=m, batches=n_batches(out))

def case_tag_path_order_independent(d, mcp):
    setup(d, APP_TWO, manifest(crisp_keys(mcp, tracked='["/cr/a.dat", "/cr/b.dat"]')))
    run(d)
    setup(d, APP_TWO, manifest(crisp_keys(mcp, tracked='["/cr/b.dat", "/cr/a.dat"]')))  # reordered
    rc, out = run(d)
    ok = rc == 0 and "tag verified" in out and "FAIL-STOP" not in out
    return ok, dict(rc=rc, verified="tag verified" in out)

def case_vault_is_encrypted(d, mcp):
    setup(d, APP_TWO, manifest(crisp_keys(mcp)))
    run(d)
    vb = (Path(d)/"pf_dir"/"vault.dat").read_bytes()
    ok = (b"CRSP" not in vb) and len(vb) > 0
    return ok, dict(vault_bytes=len(vb), plaintext_magic_present=b"CRSP" in vb)

def case_batch_squash(d, mcp):
    setup(d, APP_BURST, manifest(crisp_keys(mcp, tracked='["/cr/a.dat"]')))
    rc, out = run(d, t=40); m = mc(mcp)
    ok = rc == 0 and m and m < 30 and has_covered_gt1(out)
    return ok, dict(rc=rc, mc=m, n_fsyncs=30, batches=n_batches(out), squashed=has_covered_gt1(out))

def case_checker_returns_mc(d, mcp):
    setup(d, APP_CHECKER_SLEEP, manifest(crisp_keys(mcp, port=19313, tracked='["/cr/a.dat"]')))
    p = run_bg(d); time.sleep(3.0)
    cm = checker(19313); m = mc(mcp)
    p.wait(timeout=20)
    ok = cm is not None and m is not None and cm == m
    return ok, dict(checker=cm, mc=m)

def case_checker_blocks_on_pending(d, mcp):
    setup(d, APP_CHECKER_SLOW, manifest(crisp_keys(mcp, port=19314, tracked='["/cr/a.dat"]', latency=2500)))
    p = run_bg(d); time.sleep(0.6)               # connect while the 2.5s batch is in flight
    t0 = time.time(); cm = checker(19314, deadline=12.0); blocked_ms = int((time.time()-t0)*1000)
    p.wait(timeout=20); m = mc(mcp)              # m = final MC (incl. the exit-hook batch), cm = MC seen by the probe
    ok = isinstance(cm, int) and isinstance(m, int) and cm >= 1 and cm <= m and blocked_ms >= 1200
    return ok, dict(checker_returned=cm, mc_final=m, blocked_ms=blocked_ms)

def case_probabilistic_p100_vs_p0(d, mcp):
    import re
    def go(prob, suf):
        for s in ("", ".tmp"):
            Path(mcp + suf + s).unlink(missing_ok=True)
        shutil.rmtree(Path(d) / "pf_dir", ignore_errors=True)   # fresh state per run
        setup(d, APP_PROB, manifest(crisp_keys(mcp+suf, tracked='["/cr/a.dat"]', latency=1200, prob=prob)))
        rc, out = run(d, t=30)
        mm = re.search(r"FSYNC_MS=(\d+)", out)
        return rc, (int(mm.group(1)) if mm else None)
    rc0, g0 = go(0, ".p0")
    rc1, g1 = go(100, ".p100")
    ok = rc0 == 0 and rc1 == 0 and isinstance(g0, int) and isinstance(g1, int) and g1 >= 800 and g0 < 400
    return ok, dict(fsync_ms_p0=g0, fsync_ms_p100=g1, rc0=rc0, rc1=rc1)

def case_disabled_noop(d, mcp):
    setup(d, APP_TWO, manifest(crisp_keys(mcp, port=19315, enabled=False)))
    rc, out = run(d)
    cm = checker(19315, deadline=1.5)            # should be refused
    v = (Path(d)/"pf_dir"/"vault.dat").exists(); m = mc(mcp)
    ok = (rc == 0 and "APP_RAN" in out and "crisp_init" not in out and "mc-thread: started" not in out
          and "checker: listening" not in out and cm is None and not v and m is None)
    return ok, dict(rc=rc, crisp_logs=("crisp_init" in out or "mc-thread" in out), checker_open=cm is not None,
                    vault=v, mc=m)

def case_queue_timeout_fires(d, mcp):
    setup(d, APP_TWO_QT, manifest(crisp_keys(mcp, latency=3000, qtimeout=200)))
    rc, out = run(d, t=30)
    ok = rc == 1 and "queue timeout exceeded" in out and "APP_RAN" not in out
    return ok, dict(rc=rc, queue_timeout="queue timeout exceeded" in out, app_ran="APP_RAN" in out)

def case_mc_monotone_across_runs(d, mcp):
    setup(d, APP_TWO, manifest(crisp_keys(mcp)))
    vals = []
    for _ in range(3):
        run(d); vals.append(mc(mcp))
    ok = all(isinstance(v, int) for v in vals) and vals == sorted(vals)
    return ok, dict(mc_values=vals)

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
]

def cleanup_mc():
    for f in Path("/tmp").glob("crisp_st_*"):
        try: f.unlink()
        except OSError: pass

def main():
    want = set(sys.argv[1:])
    cases = [(n, f) for n, f in CASES if not want or n in want]
    cleanup_mc()
    npass = nfail = 0
    for i, (name, fn) in enumerate(cases):
        mcp = f"/tmp/crisp_st_{i}.dat"
        for suf in ("", ".0", ".100", ".tmp"):
            Path(mcp + suf).unlink(missing_ok=True)
        d = tempfile.mkdtemp(prefix="crisp_st_")
        try:
            ok, info = fn(d, mcp)
        except Exception as e:
            ok, info = False, dict(error=repr(e))
        print(f"{'PASS' if ok else 'FAIL'}  {name}")
        for k, v in info.items():
            print(f"    {k} = {v}")
        npass += ok; nfail += not ok
        shutil.rmtree(d, ignore_errors=True)
    cleanup_mc()
    print(f"summary pass={npass} fail={nfail}")
    sys.exit(0 if nfail == 0 else 1)

if __name__ == "__main__":
    main()
