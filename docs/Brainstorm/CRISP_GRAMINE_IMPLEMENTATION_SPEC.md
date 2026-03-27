# CRISP Implementation Specification for Gramine (v3.10)

## Project: Checker-Gated Network Shields for Gramine
### Mirroring CRISP (SCONE) → Gramine 1:1 at the Runtime Level

---

# TABLE OF CONTENTS

1. [Project Overview](#1-project-overview)
2. [Architecture: SCONE Runtime → Gramine LibOS](#2-architecture-scone-runtime--gramine-libos)
3. [Core Mechanisms (from Paper)](#3-core-mechanisms-from-paper)
4. [Phase 1: Gramine LibOS Modifications (C)](#4-phase-1-gramine-libos-modifications-c)
5. [Phase 2: Network Gate Extension (Go) — Thesis Contribution](#5-phase-2-network-gate-extension-go--thesis-contribution)
6. [Implementation Timeline](#6-implementation-timeline)
7. [File Structure](#7-file-structure)
8. [Testing Procedures](#8-testing-procedures)
9. [Metrics & Evaluation](#9-metrics--evaluation)

---

# 1. PROJECT OVERVIEW

## 1.1 Objective

Mirror CRISP from SCONE to Gramine **at the runtime level**, then extend with network gating.

- **Phase 1 (CRISP Mirror):** Modify Gramine's LibOS (C) to intercept fsync/close/exit, add mc-thread, vault, Checker API — exactly as CRISP does in SCONE.
- **Phase 2 (Thesis Extension):** Add gRPC network gate that calls Checker API before sending responses.

## 1.2 Key Principle: Runtime-Level, Not Application-Level

From the paper:
> "CRISP is implemented entirely within the SCONE runtime without modifying application source code."

| CRISP on SCONE | Our Port on Gramine |
|---|---|
| Modified SCONE runtime (C, closed-source) | Modify Gramine LibOS (C, open-source) |
| Intercepts fsync/close/exit in runtime | Intercepts fsync/close/exit in LibOS |
| mc-thread inside enclave | mc-thread (LibOS thread) inside enclave |
| Checker API via TCP server | Checker API via TCP server |
| App unchanged (MariaDB) | App unchanged (or our gRPC service) |

## 1.3 Feature Comparison

| Feature | Gramine | SCONE | CRISP adds |
|---|---|---|---|
| Open Source | Yes (LGPL) | Commercial | — |
| Protected/Encrypted Files | Yes | Yes (FSPF) | — |
| Rollback Protection (after close) | No | Via CAS | MC binding |
| Network Shield (TLS) | Via RA-TLS | Built-in | — |
| Rollback-Safe Network Gate | No | No | **Future work** |
| Monotonic Counter | No | No | **CRISP core** |
| L/S Counter Model | No | No | **CRISP core** |

Note: Neither SCONE nor Gramine has rollback protection natively.
CRISP adds it. Our thesis ports CRISP to Gramine + extends with network gate.

## 1.4 Threat Model (from Paper Section II-C)

**Trusted:**
- CPU (Intel SGX hardware)
- Monotonic Counter (RPMB device / simulated)
- Cryptographic algorithms

**Untrusted:**
- Operating System, Hypervisor, Cloud Operator
- Kubernetes Control Plane
- Storage (disk, volumes)
- Network infrastructure
- All other software

**Adversary can:** Replace files with older versions, reboot system, full admin access.
**Adversary cannot:** Break SGX, decrement MC, modify enclave memory, break crypto.

### 1.4.1 Simulated MC Limitation (Phase 1 Development Adaptation)

The CRISP paper assumes a **hardware-backed monotonic counter** (e.g., eMMC-RPMB) that the adversary physically cannot decrement or reset. Gramine and Linux SGX do **not** provide a built-in hardware MC backend — Intel removed Platform Services (which included trusted monotonic counters) from the Linux SGX SDK starting version 2.9+.

Phase 1 uses a **simulated monotonic counter** (file-based with configurable latency) to validate CRISP runtime integration, batching, gating, and startup verification logic in Gramine. This preserves **functional behavior** (correct L/S logic, batch ordering, fail-stop semantics) but does **not** provide full hardware-backed freshness guarantees under the original CRISP threat model — an OS-level attacker who controls the filesystem could roll back both the MC file and vault file to a consistent older state.

**Alternatives for trusted MC backend (future work):**
1. **TPM2 NV counter** — most realistic local hardware option on x86; requires host-side proxy with attestation binding
2. **Remote trusted counter service** — practical for cloud/SGX; enclave authenticates via RA-TLS
3. **RPMB / secure element** — closest to CRISP paper, but rarely available on SGX servers

Security equivalence to CRISP's hardware-backed freshness guarantee requires a trusted monotonic counter backend in a later stage. The MC interface (`crisp_mc_init`/`crisp_mc_read`/`crisp_mc_increment`) is designed to be backend-pluggable so switching from simulated to trusted requires no architectural changes.

---

# 2. ARCHITECTURE: SCONE RUNTIME → GRAMINE LIBOS

## 2.1 Where CRISP Lives (Paper Section IV)

From the paper:
> "The runtime modifications include: Interception of fsync, fdatasync, close, exit system calls. The mc-thread for asynchronous batching. The Checker API TCP server. Vault file management with MC value binding."

In SCONE: these live inside the SCONE runtime (mediator layer).
In Gramine: these live inside Gramine's LibOS (library OS layer).

Both are **userspace code inside the enclave** — NOT kernel code.

## 2.2 Gramine LibOS Architecture

```
┌────────────────────────────────────────────────────────────────┐
│ Gramine SGX Enclave │
│ │
│ ┌─────────────────────────────────────────────────────────┐ │
│ │ Application (UNMODIFIED) │ │
│ │ e.g., MariaDB, or gRPC service │ │
│ │ │ │ │
│ │ fsync / fdatasync / close / exit │ │
│ │ │ │ │
│ └────────────────────────┼─────────────────────────────────┘ │
│ │ │
│ ▼ │
│ ┌─────────────────────────────────────────────────────────┐ │
│ │ Gramine LibOS — MODIFIED BY US (C code) │ │
│ │ │ │
│ │ ┌─────────────────────────────────────────────────────┐ │ │
│ │ │ fsync/fdatasync handler (HOOKED): │ │ │
│ │ │ 1. Write encrypted data (Protected Files) │ │ │
│ │ │ 2. Compute tag (Merkle root hash) │ │ │
│ │ │ 3. Queue (tag) to mc-thread │ │ │
│ │ │ 4. Return immediately (optimistic) │ │ │
│ │ │ │ │ │
│ │ │ [Probabilistic: with prob P, call Checker API │ │ │
│ │ │ → reads L from vault → polls S until S >= L] │ │ │
│ │ └─────────────────────────────────────────────────────┘ │ │
│ │ │ │
│ │ ┌─────────────────────────────────────────────────────┐ │ │
│ │ │ close/exit handler (HOOKED): │ │ │
│ │ │ 1. Enqueue (like fsync — capture flush state) │ │ │
│ │ │ 2. Signal mc-thread to process queue │ │ │
│ │ │ 3. BLOCK until queue empty AND S >= L │ │ │
│ │ │ 4. Proceed with actual close/exit │ │ │
│ │ └─────────────────────────────────────────────────────┘ │ │
│ │ │ │
│ │ ┌─────────────────────────────────────────────────────┐ │ │
│ │ │ mc-thread (background LibOS thread): │ │ │
│ │ │ loop: │ │ │
│ │ │ 1. Collect pending batch requests │ │ │
│ │ │ 2. Consolidate tags → single tag │ │ │
│ │ │ 3. L++ (promise new MC value for this batch) │ │ │
│ │ │ 4. Write (consolidated_tag, L) to vault file │ │ │
│ │ │ 5. Enforce rate limit (sleep if needed) │ │ │
│ │ │ 6. MC hardware increment (slow: ~20ms) │ │ │
│ │ │ 7. S = MC hardware value (now S == L) │ │ │
│ │ │ 8. Signal waiters (condvar broadcast) │ │ │
│ │ │ 9. Check queue timeout (exit if exceeded) │ │ │
│ │ └─────────────────────────────────────────────────────┘ │ │
│ │ │ │
│ │ ┌─────────────────────────────────────────────────────┐ │ │
│ │ │ Checker API (TCP server, port configurable): │ │ │
│ │ │ On connection (single listener, sequential): │ │ │
│ │ │ 1. Read current L from g_crisp.L (in-memory) │ │ │
│ │ │ 2. Poll S periodically (PalEventWait loop) │ │ │
│ │ │ 3. Block until S >= L │ │ │
│ │ │ 4. Return MC value, close connection │ │ │
│ │ └─────────────────────────────────────────────────────┘ │ │
│ │ │ │
│ │ ┌─────────────────────────────────────────────────────┐ │ │
│ │ │ Vault File (Protected File): │ │ │
│ │ │ Stores: tag (Merkle root) + L (promised MC) │ │ │
│ │ │ Updated per batch by mc-thread (new tag + L) │ │ │
│ │ │ Read by Checker API to get current L │ │ │
│ │ └─────────────────────────────────────────────────────┘ │ │
│ │ │ │
│ │ ┌─────────────────────────────────────────────────────┐ │ │
│ │ │ Simulated MC (file-based): │ │ │
│ │ │ Stores: S (actual counter value) │ │ │
│ │ │ Increment: sleep(latency) + S++ + persist │ │ │
│ │ │ Read: return S from file │ │ │
│ │ └─────────────────────────────────────────────────────┘ │ │
│ │ │ │
│ └───────────────────────────────────────────────────────────┘ │
│ │
│ ┌───────────────────────────────────────────────────────────┐ │
│ │ gRPC Network Gate (Go) — THESIS EXTENSION (Phase 2) │ │
│ │ Before sending response: │ │
│ │ connect to Checker API TCP → blocks until S >= L │ │
│ │ Then send response │ │
│ └───────────────────────────────────────────────────────────┘ │
│ │
└────────────────────────────────────────────────────────────────┘
 │ │ │
 ▼ ▼ ▼
 ┌──────────┐ ┌──────────┐ ┌──────────┐
 │ Disk │ │Simulated │ │ Network │
 │(Protected│ │ MC │ │ │
 │ Files) │ │(file+ │ │ │
 │ │ │ latency) │ │ │
 └──────────┘ └──────────┘ └──────────┘
```

## 2.3 L and S — Where They Live

From the paper:
> "latest value written to the vault file and represents the promised MC value" (= L)
> "latest MC value" (= S, from hardware)

| Value | Name | Where stored | Updated when |
|---|---|---|---|
| **L** (Local) | Promised MC | **Vault file** | On each **batch** (mc-thread writes L++ to vault) |
| **S** (Stable) | Actual MC | **MC hardware** (simulated file) | After mc-thread commits MC increment |

**Key:** L increments once per **batch**, NOT per fsync. Multiple fsyncs in one batch share one L value.

**Checker API** reads L from vault, polls S from MC hardware, returns when S >= L.

**On startup:** Compare vault L vs hardware S:
- S > L → **ROLLBACK DETECTED** (vault replaced with older version)
- S < L → **CRASH** (system crashed between vault write and MC commit; cannot safely restart)
- S == L → **NORMAL** (all commits completed)

---

# 3. CORE MECHANISMS (from Paper)

## 3.1 Three Levels of Involvement (Paper Section III)

```
Level 1: Transparent Protection (no code changes)
 fsync → MC increment (synchronous, slow)
 Performance: HIGH overhead

Level 2: Optimistic Batching (no code changes, config only)
 fsync → acknowledge immediately → queue to mc-thread
 mc-thread batches multiple fsyncs → single MC increment
 Performance: LOW overhead
 Tradeoff: vulnerability window (up to 2x MC write latency = ~40ms)

Level 3: Checker API (minimal code changes or library integration)
 Application/middleware calls check at critical points
 Blocks until S >= L
 Performance: MEDIUM overhead
 Tradeoff: eliminates effective vulnerability window at those points
```

## 3.2 Optimistic Batching Flow (Paper Figure 1)

```
 Batch 6 Batch 7
App Thread: s1 ──► s2 ──► s3 ──►
 │ │ │
fsync handler: queue queue queue
 (return immediately) (return immediately)
 │ │
mc-thread: collect s1,s2 collect s3
 consolidate tags consolidate tags
 L++ (L=6) L++ (L=7)
 vault: [tag,L=6] vault: [tag,L=7]
 inc_mc → S=6 inc_mc → S=7
 │ │
 COMMITTED COMMITTED

Vulnerability window: between vault write (L=6) and MC commit (S=6)
Duration: up to MC write latency = ~20ms (RPMB)
Total window per batch: up to 2x MC write latency = ~40ms (including read)
```

## 3.3 Checker API Flow (Paper Figure 2, Section III-C)

From the paper:
> "spawns a new thread for each check request that is received through a TCP connection"
> "check the latest promised MC value that has been written to the vault file, named as local"
> "It will then check the value on the MC periodically until the condition is satisfied"

```
Client (app or gRPC gate):
 connect("tcp", checker_api_address)
 write(...) // blocks until MC commits
 read(...) // returns MC value
 close

Checker API server (inside runtime):
 On connection → spawn thread:
 L = read_vault_local // read L from vault file
 loop:
 S = mc_read_value // read S from MC hardware
 if S >= L: break
 sleep(poll_interval)
 send(S) // return MC value
 close connection
```

## 3.4 close/exit are SYNCHRONOUS (Paper Section III-B)

From the paper:
> "close and exit system calls are not treated optimistically and instead remain synchronous"
> "blocked until all outstanding asynchronous requests are committed"

## 3.5 Probabilistic Checking (Paper Section IV-A)

From the paper:
> "all fsync-related calls will be intercepted, and the blocking Checker API call will be triggered according to the chosen probability"

Configuration parameter `checker_probability` (0-100%):
- 0% = no automatic checking (default)
- 1% = ~1 in 100 fsyncs triggers blocking check
- 10% = ~1 in 10 fsyncs triggers blocking check
- 20% = ~1 in 5 fsyncs triggers blocking check

Results from paper (Table II):

| Check % | Avg fsync/batch | Avg batch duration |
|---|---|---|
| 0% | 205.97 | 63.49 ms |
| 1% | 46.99 | 33.53 ms |
| 10% | 7.30 | 34.16 ms |
| 20% | 3.92 | 35.27 ms |

## 3.6 MC Rate Limit (Paper Section IV-B)

From the paper:
> "Setting the MC rate limit to a value higher than its write latency leads to increased batch sizes"

- Min time between MC increments
- Higher = larger batches = fewer MC writes = longer MC hardware lifetime
- Tradeoff: larger vulnerability window

## 3.7 Queue Timeout (Paper Section IV-B)

From the paper:
> "regulates the tolerance for MC increment latencies. When a request waits in the queue longer than the timeout, the runtime will exit prematurely"

- Security mechanism: prevents attacker from slowing MC to extend vulnerability window
- If any queued request exceeds timeout → runtime halts

---

# 4. PHASE 1: GRAMINE LIBOS MODIFICATIONS (C)

These files are added to the Gramine source tree. This mirrors exactly what CRISP does inside the SCONE runtime.

## 4.1 Gramine Source Locations

**Actual Gramine source structure** (verified from repository):
- fsync, fdatasync, AND close are ALL in `libos/src/sys/libos_open.c`
- fdatasync is literally a 1-line wrapper around fsync
- exit/exit_group are in `libos/src/sys/libos_exit.c`
- New sources must be added to `libos/src/meson.build` to be compiled

```
gramine/ # Cloned Gramine repository
├── common/
│ ├── include/
│ │ ├── crypto.h # lib_SHA256Init/Update/Final (use this)
│ │ └── spinlock.h # spinlock_t, spinlock_lock/unlock
│ └── src/
│ └── protected_files/
│ └── protected_files.h # PF internal API (no tag extraction)
│
├── libos/
│ ├── include/
│ │ ├── libos_lock.h # struct libos_lock (Gramine mutex)
│ │ ├── libos_thread.h # thread_wait/thread_wakeup
│ │ └── crisp.h # NEW: public header for hooks
│ │
│ ├── src/
│ │ ├── sys/
│ │ │ ├── libos_open.c # HOOK: fsync, fdatasync, AND close
│ │ │ └── libos_exit.c # HOOK: exit, exit_group
│ │ │
│ │ ├── fs/chroot/
│ │ │ └── encrypted.c # PF flush chain (chroot_encrypted_flush)
│ │ │
│ │ ├── crisp/ # NEW: our CRISP implementation
│ │ │ ├── crisp.h # Internal header (full struct defs)
│ │ │ ├── crisp_init.c # Initialization + startup verification
│ │ │ ├── crisp_fsync.c # fsync hook + optimistic batching + drain_and_wait
│ │ │ ├── crisp_close.c # close/exit hooks (separated from fsync)
│ │ │ ├── crisp_vault.c # Vault file (tag + L)
│ │ │ ├── crisp_mc.c # Simulated monotonic counter
│ │ │ ├── crisp_mcthread.c # Background mc-thread (L++, vault, MC)
│ │ │ ├── crisp_checker_api.c # TCP server for Checker API
│ │ │ ├── crisp_tag.c # PF tag extraction + global digest + flush_pf_by_path
│ │ │ └── crisp_config.c # Configuration parameters
│ │ │
│ │ └── meson.build # ADD our crisp/*.c sources here
```

**Flush call chain** (how fsync reaches Protected Files):
```
libos_syscall_fsync(fd)
 → hdl->fs->fs_ops->flush(hdl)
 → chroot_encrypted_flush(hdl) [fs/chroot/encrypted.c]
 → encrypted_file_flush(enc)
 → pf_flush(pf) [protected_files.c]
```

## 4.2 Main Header

**IMPORTANT:** Gramine LibOS does NOT use pthreads internally. It has its own primitives:
- **Mutex:** `struct libos_lock` with `create_lock`, `lock`, `unlock` (from `libos_lock.h`)
- **Spinlock:** `spinlock_t` with `spinlock_lock`, `spinlock_unlock` (from `spinlock.h`)
- **Thread wait/wake:** `thread_prepare_wait`, `thread_wait`, `thread_wakeup` (from `libos_thread.h`)
- **No condition variables** — use `thread_wait`/`thread_wakeup` pattern instead

```c
/* libos/src/crisp/crisp.h */

#ifndef _CRISP_H_
#define _CRISP_H_

#include <stdint.h>
#include <stdbool.h>

/* Gramine primitives — NOT pthread */
#include "libos_lock.h" /* struct libos_lock, lock, unlock */
#include "libos_thread.h" /* struct libos_thread, get_cur_thread */
#include "spinlock.h" /* spinlock_t for low-contention cases */
#include "pal.h" /* PalEventCreate/Wait/Set, PalSystemTimeQuery */
#include "libos_fs_encrypted.h" /* struct libos_encrypted_file */

/* ============================================================
 * VAULT FILE — stores tag + L (promised MC value)
 * Paper: "latest value written to the vault file"
 * ============================================================ */

#define CRISP_VAULT_MAGIC "CRSP"
#define CRISP_TAG_SIZE 32

typedef struct {
 char magic[4]; /* "CRSP" */
 uint8_t tag[CRISP_TAG_SIZE]; /* Merkle root hash (FSPF/Protected Files) */
 uint64_t local_mc; /* L: promised MC value */
 uint8_t checksum[32]; /* SHA-256 of above fields */
} crisp_vault_t;

/* ============================================================
 * LOCK ORDERING — always acquire in this order:
 * 1. queue_mu — protects pending_count, batch_in_flight,
 * queue_has_work, oldest_enqueue_us
 * 2. mu — protects L, halted
 * 3. waiter_lock (spinlock) — protects waiter list
 * 4. mc_mu — protects MC value (in crisp_mc.c)
 * Never hold a higher-numbered lock while acquiring a lower one.
 * ============================================================ */

/* ============================================================
 * CRISP GLOBAL STATE
 * ============================================================ */

typedef struct {
 /* Feature gate — CRISP is default-OFF.
 * Set to true only if Gramine manifest has: sgx.crisp.enable = true
 * When false, all hooks (fsync/close/exit) skip CRISP entirely,
 * and crisp_init is never called. Zero overhead for non-CRISP workloads. */
 bool enabled;

 /* L/S counters */
 uint64_t L; /* Local: promised MC (also in vault) */
 /* S is always read from MC hardware, not stored here */

 /* Synchronization — Gramine primitives */
 struct libos_lock mu; /* Main lock (protects L, halted) */
 bool halted; /* True if rollback detected */

 /* mc-thread (uses get_new_internal_thread + PalThreadCreate).
 * Internal threads (tid=0) CANNOT use thread_wait/thread_prepare_wait
 * (those assert !is_internal). Uses PAL events directly instead. */
 struct libos_thread* mc_thread_handle; /* Internal thread struct */
 bool mc_thread_running;
 PAL_HANDLE mc_wakeup_event; /* PAL event for mc-thread
 * sleep/wakeup. Auto-clear.
 * DEDICATED to mc-thread only.
 * No other thread waits on this.
 * Prevents signal-stealing bug where
 * Checker API polling consumed the
 * wakeup intended for mc-thread. */
 PAL_HANDLE checker_poll_event; /* separate auto-clear event
 * for internal-thread waiters
 * (Checker API) in drain_and_wait.
 * Set by crisp_wake_all_waiters
 * after batch commit. */

 /* Batch queue (protected by queue_mu)
 * Queue is a simple counter — no per-file tags stored.
 * The mc-thread computes a global digest over ALL PFs per batch
 * (mirrors SCONE's volume-level Merkle root). */
 int pending_count; /* Number of pending fsyncs */
 struct libos_lock queue_mu; /* Protects queue fields */
 bool queue_has_work; /* Flag for thread_wait/wakeup */
 bool batch_in_flight; /* true while mc-thread
 * processes a batch (between
 * queue clear and MC commit).
 * Prevents waiters from exiting
 * early during the gap. */
 uint64_t oldest_enqueue_us; /* timestamp of first
 * pending request in queue.
 * Paper: "request waits in
 * the queue longer than timeout"
 * — per-request, not global. */

 /* Waiter list — threads waiting for S >= L */
 /* Since Gramine has no condvar, we track waiting threads */
 struct libos_thread* waiters[64]; /* Max concurrent waiters */
 int waiter_count;
 spinlock_t waiter_lock; /* Protects waiter list */

 /* Protected File registry (for global digest computation)
 * Paths of all PFs being tracked. Pre-sorted at init time.
 * The mc-thread iterates these to compute the global tag
 * (= SHA-256 of all PF metadata MACs, sorted by path). */
 char** pf_paths; /* Sorted array of PF file paths */
 int pf_count; /* Number of registered PF paths */

 /* Configuration (from paper Section IV-B) */
 char vault_path[256];
 char mc_path[256];
 uint64_t mc_latency_ms; /* Simulated RPMB latency */
 uint64_t rate_limit_ms; /* Min time between MC increments */
 uint64_t queue_timeout_ms;/* Max time in queue before halt */
 int checker_prob; /* Probabilistic checking 0-100 */
 int checker_api_port;/* TCP port for Checker API */
} crisp_state_t;

/* Global singleton */
extern crisp_state_t g_crisp;

/* Recursion guard for vault VFS I/O.
 * Plain global bool, NOT __thread. Gramine LibOS links with
 * -nostdlib --no-undefined, so __thread (TLSGD model) fails at link
 * time with undefined __tls_get_addr. Zero __thread usage exists in
 * Gramine LibOS. Safe as plain global: only mc-thread sets it, and
 * reads occur on the same thread during vault VFS I/O (no race).
 * Checked by crisp_on_fsync and crisp_on_close to skip
 * re-entering CRISP queue logic during vault writes.
 * Defined in crisp_vault.c. */
extern bool g_in_crisp_io;

/* ============================================================
 * FAIL-STOP — Paper: "the runtime will exit prematurely"
 *
 * All critical failures route through crisp_fail_stop.
 * This is a ONE-WAY state transition: once halted, the process
 * terminates. No code path should continue after halt.
 *
 * Previously was fail-open (set halted=true but the app continued
 * running without rollback protection). This violates the paper's
 * requirement that the runtime exits on unrecoverable errors.
 * ============================================================ */

/* Central fail-stop handler. Logs reason, sets halted, wakes all
 * waiters (so they see halted=true and propagate), then terminates.
 * The __attribute__((noreturn)) ensures compiler enforces no
 * continuation after a call to this function. */
noreturn void crisp_fail_stop(const char* reason);

/* ============================================================
 * API FUNCTIONS — called from Gramine syscall hooks
 * ============================================================ */

/* Initialization (called once at startup) */
int crisp_init(const char* vault_path, const char* mc_path);

/* fsync/fdatasync hook: signal pending work, return immediately.
 * no per-file tag parameter — global tag computed by mc-thread.
 * returns -ENOTRECOVERABLE if halted (fail-stop propagation). */
int crisp_on_fsync(void);

/* close/exit hook: synchronous wait
 * Both propagate errors. On failure, close returns error code;
 * exit calls crisp_fail_stop (terminates process). */
int crisp_on_close(void);
void crisp_on_exit(void);

/* Drain queue + wait for S >= L (factored-out helper)
 * Used by: close, exit, probabilistic check, Checker API.
 * Paper: "blocked until all outstanding asynchronous requests
 * are committed"
 * returns -1 if halted, 0 on success. */
int crisp_drain_and_wait(void);

/* Global tag computation (mirrors SCONE volume tag)
 * SHA-256 over all PF metadata MACs, sorted by path.
 * Paper: "Merkle tree root hash for the relevant part of
 * the filesystem" */
int crisp_compute_global_tag(uint8_t* tag_out);

/* Vault operations */
int crisp_vault_load(crisp_vault_t* out);
int crisp_vault_save(const uint8_t* tag, uint64_t local_mc);

/* MC operations (simulated) */
int crisp_mc_init(void);
int crisp_mc_read(uint64_t* value);
int crisp_mc_increment(uint64_t* new_value);

/* mc-thread */
noreturn void crisp_mc_thread_func(void* arg);

/* Checker API TCP server */
noreturn void crisp_checker_api_func(void* arg);

/* Wake all threads waiting on S advancement */
void crisp_wake_all_waiters(void);

/* Flush a PF by path (force metadata MAC update).
 * Used by crisp_on_exit to flush all tracked PFs before
 * enqueuing, since the close chain hasn't run yet at exit time. */
int crisp_flush_pf_by_path(const char* path);

#endif /* _CRISP_H_ */
```

## 4.3 Initialization + Startup Verification

From the paper (Section III-A):
> "loads the vault file, verifies integrity by comparing the stored FSPF tag against the Merkle tree root hash, and compares the vault file's MC value against the hardware MC"

```c
/* libos/src/crisp/crisp_init.c */

#include "crisp.h"
#include <string.h>

/* Gramine logging */
#include "libos_utils.h" /* log_error, log_warning */

crisp_state_t g_crisp;

/* ================================================================
 * crisp_fail_stop — Central fail-stop handler
 *
 * Paper: "When a request waits in the queue longer than the timeout,
 * the runtime will exit prematurely."
 * This generalizes to ALL unrecoverable CRISP failures.
 *
 * ONE-WAY state transition: halted is set, all waiters are woken
 * (so they see halted=true and can propagate errors), then the
 * process terminates via PalProcessExit(1).
 * ================================================================ */
noreturn void crisp_fail_stop(const char* reason) {
 /* One-way transition — atomic to prevent races */
 __atomic_store_n(&g_crisp.halted, true, __ATOMIC_RELEASE);

 log_error("CRISP FAIL-STOP: %s", reason);

 /* Wake all waiters so they see halted=true and stop blocking */
 crisp_wake_all_waiters;

 /* Terminate the entire enclave process.
 * PalProcessExit is the PAL-level process termination.
 * exit code 1 = abnormal termination. */
 PalProcessExit(1);
 __builtin_unreachable;
}

/* Called from libos_init.c ONLY if manifest has sgx.crisp.enable = true:
 * if (crisp_is_enabled_in_manifest) {
 * int crisp_ret = crisp_init("/path/to/vault", "/path/to/mc");
 * if (crisp_ret < 0)
 * PalProcessExit(1); // or use Gramine's RUN_INIT(...) pattern
 * }
 * When not called, g_crisp.enabled remains false (zero-initialized),
 * and all hooks (fsync/close/exit) are no-ops. */
int crisp_init(const char* vault_path, const char* mc_path) {
 memset(&g_crisp, 0, sizeof(g_crisp));
 strncpy(g_crisp.vault_path, vault_path, sizeof(g_crisp.vault_path) - 1);
 strncpy(g_crisp.mc_path, mc_path, sizeof(g_crisp.mc_path) - 1);

 /* Initialize Gramine locks (NOT pthread) */
 if (!create_lock(&g_crisp.mu)) return -1;
 if (!create_lock(&g_crisp.queue_mu)) return -1;
 spinlock_init(&g_crisp.waiter_lock);

 /* No pending_tags buffer needed — queue is a simple counter.
 * Global tag is computed fresh by mc-thread from all PFs. */

 /* 0. Register Protected File paths (from config/manifest)
 * These are the files CRISP protects. Must be pre-sorted by path
 * so crisp_compute_global_tag produces deterministic output.
 * In production, these come from Gramine manifest parsing. */
 /* g_crisp.pf_paths = crisp_config_load_pf_paths(&g_crisp.pf_count); */

 /* 1. Initialize MC from storage */
 if (crisp_mc_init != 0) return -1;

 /* 2. Load vault file */
 crisp_vault_t vault;
 int vault_ret = crisp_vault_load(&vault);

 /* 3. Read actual MC value (= S) */
 uint64_t actual_mc;
 if (crisp_mc_read(&actual_mc) != 0) return -1;

 if (vault_ret == -2) {
 /* No vault file — fresh installation.
 * Only ENOENT means "no vault" (fresh install).
 * All other open errors (EACCES, EIO, etc.) return -1, which
 * routes to the fail-stop below.
 *
 * CRITICAL: Must check actual_mc == 0 here!
 * If vault is missing but MC > 0, an attacker deleted the vault
 * to bypass rollback detection. Without this check:
 * - Vault missing → L = 0
 * - MC = 7 (from previous runs)
 * - S(7) >= L(0) trivially true → Checker API passes
 * - ROLLBACK UNDETECTED
 *
 * The rollback check (actual_mc > stored_L) only runs in the
 * normal startup path (vault loaded OK). It does NOT run here.
 * This was incorrectly claimed as "MC safety net catches it"
 * in an earlier revision — that analysis was WRONG because
 * the check was inside the else block, unreachable from here.
 *
 * On legitimate first-ever boot: MC=0, no vault → both zero → OK.
 * On vault deletion attack: MC>0, no vault → caught here. */
 if (actual_mc != 0) {
 crisp_fail_stop("vault missing but MC > 0: rollback attack");
 /* unreachable */
 }
 g_crisp.L = 0;
 } else if (vault_ret != 0) {
 /* Vault corrupted or I/O error — fail-stop.
 * This now catches all non-ENOENT open errors
 * (permission denied, disk error, etc.) in addition to
 * corruption (bad magic, bad checksum). */
 crisp_fail_stop("vault file corrupted or I/O error");
 /* unreachable */
 } else {
 /* 4. ROLLBACK DETECTION (Paper Section III-A) */
 uint64_t stored_L = vault.local_mc;

 if (actual_mc > stored_L) {
 /* MC went forward but vault is old = ROLLBACK ATTACK
 * fail-stop — terminates process */
 crisp_fail_stop("ROLLBACK DETECTED: MC > vault L");
 /* unreachable */
 }

 if (actual_mc < stored_L) {
 /* Vault claims higher MC than hardware
 * Paper: "Crashes between tag writes and MC increments
 * also prevent restart"
 * fail-stop — terminates process */
 crisp_fail_stop("UNRECOVERABLE CRASH: MC < vault L");
 /* unreachable */
 }

 /* actual_mc == stored_L → Normal startup */
 g_crisp.L = stored_L;

 /* 5. TAG VERIFICATION (Paper Section III-A)
 * Paper: "the latest volume tag will be loaded from the vault
 * file and matched with a Merkle tree root hash for
 * the relevant part of the filesystem"
 *
 * Recompute global tag from current PF state and compare to
 * the tag stored in the vault. This detects the case where
 * an attacker rolls back only PF files (not vault/MC):
 * - vault.L == MC → passes MC check
 * - BUT vault.tag != current PF state → DETECTED here
 *
 * Without this check, file-only rollback goes undetected. */
 uint8_t current_tag[CRISP_TAG_SIZE];
 if (crisp_compute_global_tag(current_tag) != 0) {
 log_error("CRISP: failed to compute global tag at startup");
 return -1;
 }
 if (memcmp(vault.tag, current_tag, CRISP_TAG_SIZE) != 0) {
 /* fail-stop — terminates process */
 crisp_fail_stop("TAG MISMATCH: PF files rolled back independently");
 /* unreachable */
 }
 }

 /* 6. Create PAL events
 * Internal threads cannot use thread_wait/thread_prepare_wait
 * (those assert !is_internal). We use dedicated PAL events.
 *
 * TWO separate events to prevent signal-stealing bug.
 * mc_wakeup_event: ONLY mc-thread waits on it (auto-clear OK).
 * checker_poll_event: ONLY internal-thread waiters (Checker API)
 * poll on it. Set by crisp_wake_all_waiters after batch commit.
 * Without separation, Checker API's timed PalEventWait could
 * consume the signal meant for mc-thread (auto-clear wakes only 1
 * waiter with FUTEX_WAKE(1)), leaving mc-thread asleep. */
 int pal_ret = PalEventCreate(&g_crisp.mc_wakeup_event,
 /*init_signaled=*/false,
 /*auto_clear=*/true);
 if (pal_ret < 0) return -1;

 pal_ret = PalEventCreate(&g_crisp.checker_poll_event,
 /*init_signaled=*/false,
 /*auto_clear=*/true);
 if (pal_ret < 0) return -1;

 /* 7. Start mc-thread (verified against actual Gramine pattern)
 * Pattern from IPC worker (libos_ipc_worker.c) and async worker
 * (libos_async.c): get_new_internal_thread + PalThreadCreate.
 * Internal threads have tid=0 (is_internal returns true). */
 g_crisp.mc_thread_running = true;
 g_crisp.mc_thread_handle = get_new_internal_thread;
 if (!g_crisp.mc_thread_handle) return -1;

 PAL_HANDLE mc_pal_handle = NULL;
 pal_ret = PalThreadCreate(crisp_mc_thread_wrapper, NULL, &mc_pal_handle);
 if (pal_ret < 0) {
 put_thread(g_crisp.mc_thread_handle);
 g_crisp.mc_thread_handle = NULL;
 return -1;
 }
 g_crisp.mc_thread_handle->pal_handle = mc_pal_handle;

 /* 8. Start Checker API TCP server (same pattern) */
 /* if (g_crisp.checker_api_port > 0) {
 *... same get_new_internal_thread + PalThreadCreate pattern...
 * } */

 /* Enable CRISP only after all init steps succeed (fail-closed startup). */
 g_crisp.enabled = true;
 return 0;
}
```

**Thread creation pattern:** Gramine internal threads (IPC worker, async worker) are created via `get_new_internal_thread` (allocates `struct libos_thread` with tid=0) + `PalThreadCreate(wrapper, arg, &handle)` (creates actual PAL-level thread). The wrapper function MUST call `libos_tcb_init` + `set_cur_thread(thread)` + `log_setprefix` before entering the main loop. See `libos/src/ipc/libos_ipc_worker.c:363` and `libos/src/libos_async.c:114` for reference.

**Critical constraint:** Internal threads (`is_internal == true`) CANNOT use `thread_wait` or `thread_prepare_wait` — both have `assert(!is_internal(cur_thread))`. The mc-thread and Checker API thread must use PAL events (`PalEventWait`/`PalEventSet`) directly instead. App threads (fsync/close/exit callers) CAN use `thread_wait` since they are regular threads.

## 4.4 fsync/fdatasync Hook (Optimistic Batching)

From the paper (Section III-B):
> "acknowledges flush requests immediately without waiting for counter confirmation"
> "placing them in a time-aware queue"
> "fsync, although other invocations (e.g., sync, fdatasync) are also included"

**IMPORTANT:** L is NOT incremented here. L increments per BATCH in the mc-thread.
The vault is NOT written here. Vault is written per BATCH in the mc-thread.
fsync only queues the tag and returns immediately.

```c
/* libos/src/crisp/crisp_fsync.c */

#include "crisp.h"
#include <string.h>
#include "libos_thread.h"
#include "libos_utils.h" /* log_error */
#include "pal.h" /* PalSystemTimeQuery, PalEventWait/Set */

/* Thread-safe counter for probabilistic checking. */
static uint32_t fsync_counter = 0;

/* ================================================================
 * crisp_drain_and_wait — factored-out helper
 *
 * Signal mc-thread, then block until:
 * (1) queue is empty, AND
 * (2) no batch is in-flight, AND
 * (3) S >= L (all committed)
 *
 * Used by: close, exit, probabilistic check, Checker API.
 * Paper: "blocked until all outstanding asynchronous requests
 * are committed"
 *
 * Handles both app threads and internal threads.
 * App threads (fsync/close/exit) use thread_prepare_wait/thread_wait.
 * Internal threads (Checker API) use PalEventWait with polling,
 * because thread_wait asserts !is_internal(cur_thread).
 * ================================================================ */
int crisp_drain_and_wait(void) {
 /* Returns 0 on success, -1 if halted (fail-stop). */
 if (__atomic_load_n(&g_crisp.halted, __ATOMIC_ACQUIRE)) return -1;

 /* Signal mc-thread to process any pending work */
 lock(&g_crisp.queue_mu);
 g_crisp.queue_has_work = true;
 unlock(&g_crisp.queue_mu);
 PalEventSet(g_crisp.mc_wakeup_event); /* PAL event, not thread_wakeup */

 struct libos_thread* self = get_cur_thread;
 bool internal = is_internal(self);

 while (!__atomic_load_n(&g_crisp.halted, __ATOMIC_ACQUIRE)) {
 if (internal) {
 /* Internal threads (Checker API) cannot use
 * thread_prepare_wait (asserts !is_internal).
 * Poll with 1ms timeout via PAL event.
 * Uses checker_poll_event (NOT mc_wakeup_event).
 * This path is NOT vulnerable to lost-wakeup because
 * PalEventWait with timeout acts as a bounded poll. */

 /* Check condition first (polling — no lost-wakeup risk) */
 lock(&g_crisp.queue_mu);
 bool queue_empty = (g_crisp.pending_count == 0);
 bool in_flight = g_crisp.batch_in_flight;
 unlock(&g_crisp.queue_mu);

 uint64_t S;
 crisp_mc_read(&S);
 lock(&g_crisp.mu);
 uint64_t current_L = g_crisp.L;
 unlock(&g_crisp.mu);

 if (queue_empty && !in_flight && S >= current_L) break;

 uint64_t poll_us = 1000; /* 1ms */
 PalEventWait(g_crisp.checker_poll_event, &poll_us);
 } else {
 /* App threads: canonical Gramine wait pattern.
 * Ordering: prepare → COMPILER_BARRIER → check → wait.
 *
 * The check→prepare→wait ordering is vulnerable to
 * lost-wakeup: thread_wakeup can fire between the
 * condition check and thread_prepare_wait, and the
 * signal is lost (prepare clears the event).
 *
 * The canonical pattern (from libos_wait.c:190-199):
 * thread_prepare_wait // Step 1: clear event
 * COMPILER_BARRIER // Step 2: prevent reorder
 * if (condition_met) break // Step 3: check AFTER prepare
 * thread_wait // Step 4: sleep
 *
 * After prepare, any thread_wakeup will set the event
 * AFTER it was cleared, so thread_wait sees it. */

 /* Register as waiter first (dedup to prevent overflow).
 *
 * Takes a thread reference (get_thread) when
 * enqueuing. Without it, the thread could exit before mc-thread
 * calls thread_wakeup → stale pointer → UAF crash.
 * Gramine convention: add_thread_to_queue calls get_thread,
 * wake_queue calls put_thread after wakeup. We mirror that. */
 bool registered = false;
 spinlock_lock(&g_crisp.waiter_lock);
 bool already = false;
 for (int i = 0; i < g_crisp.waiter_count; i++) {
 if (g_crisp.waiters[i] == self) { already = true; registered = true; break; }
 }
 if (!already) {
 if (g_crisp.waiter_count < 64) {
 get_thread(self); /* hold reference while in waiter list */
 g_crisp.waiters[g_crisp.waiter_count++] = self;
 registered = true;
 }
 /* If array full, registered stays false → use timeout below */
 }
 spinlock_unlock(&g_crisp.waiter_lock);

 /* Step 1: Prepare — clears the thread's scheduler event */
 thread_prepare_wait;

 /* Step 2: Compiler barrier — prevents reordering of the
 * prepare (event clear) with the condition check below */
 COMPILER_BARRIER;

 /* Step 3: Re-check condition AFTER prepare.
 * If mc-thread calls thread_wakeup between prepare and
 * this check, the event is now set, so thread_wait below
 * will return immediately — no lost wakeup. */
 lock(&g_crisp.queue_mu);
 bool queue_empty = (g_crisp.pending_count == 0);
 bool in_flight = g_crisp.batch_in_flight;
 unlock(&g_crisp.queue_mu);

 uint64_t S;
 crisp_mc_read(&S);
 lock(&g_crisp.mu);
 uint64_t current_L = g_crisp.L;
 unlock(&g_crisp.mu);

 if (queue_empty && !in_flight && S >= current_L) {
 /* If we registered in waiters[] (possibly on a prior loop
 * iteration via dedup path), remove our entry and release
 * the held ref before leaving. Otherwise the waiter entry/ref
 * can leak until a later mc-thread wakeup. */
 if (registered) {
 bool removed_waiter = false;
 spinlock_lock(&g_crisp.waiter_lock);
 for (int i = 0; i < g_crisp.waiter_count; i++) {
 if (g_crisp.waiters[i] == self) {
 g_crisp.waiters[i] = g_crisp.waiters[g_crisp.waiter_count - 1];
 g_crisp.waiters[g_crisp.waiter_count - 1] = NULL;
 g_crisp.waiter_count--;
 removed_waiter = true;
 break;
 }
 }
 spinlock_unlock(&g_crisp.waiter_lock);
 if (removed_waiter) put_thread(self);
 }
 break;
 }

 /* Step 4: Sleep — will wake on thread_wakeup or signal.
 * Overflow waiters (not registered) use a 5ms timeout
 * to poll, since they won't receive thread_wakeup signals.
 * Registered waiters can sleep indefinitely (woken by mc-thread). */
 if (registered) {
 thread_wait(/*timeout_us=*/NULL, /*ignore_pending_signals=*/false);
 } else {
 uint64_t poll_timeout_us = 5000; /* 5ms polling for overflow */
 thread_wait(&poll_timeout_us, /*ignore_pending_signals=*/false);
 }
 }
 }

 /* Return error if we exited because of halt */
 return __atomic_load_n(&g_crisp.halted, __ATOMIC_ACQUIRE) ? -1 : 0;
}

/* Called from Gramine's fsync/fdatasync handler (libos_open.c)
 * No tag parameter — queue is a counter, not a tag buffer.
 * The mc-thread computes the global tag from all PFs per batch. */
int crisp_on_fsync(void) {
 /* Recursion guard — skip CRISP for vault's own I/O.
 * When mc-thread writes the vault through LibOS VFS, the write
 * triggers fsync hooks. Without this check, we'd re-enter the
 * CRISP queue logic, causing infinite recursion. */
 if (g_in_crisp_io) return 0;

 /* fail-stop propagation. If halted, return error so the
 * syscall handler can propagate it to the application.
 * -ENOTRECOVERABLE signals an unrecoverable state error. */
 if (__atomic_load_n(&g_crisp.halted, __ATOMIC_ACQUIRE))
 return -ENOTRECOVERABLE;

 /* Increment pending count — NO L++, NO vault write, NO tag */
 /* Paper: "acknowledges immediately but puts each request into */
 /* a time-aware queue" */
 lock(&g_crisp.queue_mu);

 /* Track enqueue time for oldest pending request.
 * Paper: "When a request waits in the queue longer than
 * the timeout, the runtime will exit prematurely" */
 if (g_crisp.pending_count == 0) {
 PalSystemTimeQuery(&g_crisp.oldest_enqueue_us); }

 g_crisp.pending_count++;
 g_crisp.queue_has_work = true;
 unlock(&g_crisp.queue_mu);

 /* Wake mc-thread via PAL event (not thread_wakeup —
 * mc-thread is internal, scheduler_event not initialized) */
 PalEventSet(g_crisp.mc_wakeup_event);

 /* Probabilistic checking (Paper Section IV-A)
 * "all fsync-related calls will be intercepted, and the blocking
 * Checker API call will be triggered according to the chosen
 * probability"
 *
 * Uses crisp_drain_and_wait to block until the current
 * batch commits, which is what limits batch sizes
 * (paper Table II). */
 if (g_crisp.checker_prob > 0) {
 uint32_t count = __atomic_fetch_add(&fsync_counter, 1,
 __ATOMIC_RELAXED);
 if ((count % 100) < (uint32_t)g_crisp.checker_prob) {
 crisp_drain_and_wait;
 }
 }

 /* Return immediately — optimistic acknowledgment */
 return 0;
}

/* Paper Section III-A: "we update the FSPF tag in three situations:
 * disk flush, file close, and program exit"
 * Paper Section III-B: "close and exit system calls are not treated
 * optimistically and instead remain synchronous...blocked until
 * all outstanding asynchronous requests are committed"
 *
 * Close/exit must ENQUEUE before waiting, and
 * the hook must run AFTER PF flush, not before.
 * Gramine's close call chain:
 * libos_syscall_close(fd)
 * → detach_fd_handle(fd)
 * → put_handle(hdl) ← refcount--
 * → (refcount==0) fs_ops->close(hdl) ← chroot_encrypted_close
 * → encrypted_file_put(enc)
 * → (use_count==0) encrypted_file_internal_close(enc)
 * → pf_close(pf) → ipf_close(pf)
 * → ipf_internal_flush(pf)
 * → ipf_update_metadata_node ← MAC UPDATED HERE
 *
 * NOTE: The hook must NOT be placed before put_handle. If crisp_on_fsync
 * enqueues before the PF close-flush, the mc-thread computes the global
 * tag from the OLD metadata MAC → vault stores stale tag → startup tag
 * verification detects mismatch → false-positive halt (liveness bug).
 *
 * The syscall hook calls put_handle FIRST (triggering
 * the PF flush + MAC update), THEN calls crisp_on_close. The hook
 * runs OUTSIDE any inode locks (put_handle releases all locks before
 * returning). See Section 4.9 for the updated hook placement.
 *
 * For exit: crisp_on_exit runs before process_exit/thread_exit
 * which will close all FDs. We must explicitly flush all tracked PFs
 * before enqueuing, since after exit we can't rely on the close chain. */
int crisp_on_close(void) {
 /* Recursion guard — skip CRISP for vault's own I/O */
 if (g_in_crisp_io) return 0;

 /* Called AFTER put_handle completes — MAC is already fresh.
 * Enqueue to bind close-flush state to next MC batch.
 * Returns -ENOTRECOVERABLE if halted. */
 int ret = crisp_on_fsync;
 if (ret < 0) return ret;
 ret = crisp_drain_and_wait;
 if (ret < 0) return -ENOTRECOVERABLE;
 return 0;
}

void crisp_on_exit(void) {
 /* Exit path: must flush ALL tracked PFs explicitly.
 * The close chain hasn't run yet (process_exit does FD cleanup later).
 * Force-flush each tracked PF to update its metadata MAC,
 * then enqueue and wait for MC commitment.
 *
 * If any step fails, call crisp_fail_stop (terminates).
 * On success, returns normally so Gramine can do its exit cleanup. */
 /* Check flush return value per file.
 * If any flush fails, the MAC is stale and the global tag
 * will be wrong — violates binding guarantee. Fail-stop. */
 for (int i = 0; i < g_crisp.pf_count; i++) {
 if (crisp_flush_pf_by_path(g_crisp.pf_paths[i]) < 0) {
 crisp_fail_stop("PF flush failed during exit");
 /* unreachable */
 }
 }

 if (crisp_on_fsync < 0) {
 crisp_fail_stop("fsync enqueue failed during exit");
 /* unreachable */
 }
 if (crisp_drain_and_wait < 0) {
 crisp_fail_stop("drain_and_wait failed during exit");
 /* unreachable */
 }
 /* Success: all state committed to MC. Normal exit proceeds. */
}

/* Wake all threads waiting on S advancement */
/* Called by mc-thread after MC commit (replaces pthread_cond_broadcast) */
void crisp_wake_all_waiters(void) {
 /* Wake app threads via scheduler_event (thread_wakeup).
 * Releases thread references after wakeup.
 * Mirrors Gramine's wake_queue pattern: thread_wakeup + put_thread. */
 struct libos_thread* local_waiters[64];
 int local_waiter_count = 0;

 /* Snapshot + clear under spinlock, then wake/release refs outside it.
 * Avoids holding waiter_lock across thread_wakeup/put_thread. */
 spinlock_lock(&g_crisp.waiter_lock);
 local_waiter_count = g_crisp.waiter_count;
 for (int i = 0; i < local_waiter_count; i++) {
 local_waiters[i] = g_crisp.waiters[i];
 g_crisp.waiters[i] = NULL;
 }
 g_crisp.waiter_count = 0;
 spinlock_unlock(&g_crisp.waiter_lock);

 for (int i = 0; i < local_waiter_count; i++) {
 thread_wakeup(local_waiters[i]);
 put_thread(local_waiters[i]);
 }

 /* Also wake internal-thread pollers (Checker API).
 * Uses separate event to prevent signal-stealing from mc-thread. */
 PalEventSet(g_crisp.checker_poll_event);
}
```

## 4.5 mc-thread (Background Processing)

From the paper (Section III-B):
> "separate loop thread...process the accumulated operations, update the tag once, and increment the MC once"

**This is where L++ and vault write happen — per BATCH, not per fsync.**

```c
/* libos/src/crisp/crisp_mcthread.c */

#include "crisp.h"
#include <string.h>
#include "libos_thread.h"
#include "libos_utils.h" /* log_error, log_debug */
#include "pal.h" /* PalSystemTimeQuery, PalEventWait/Set/Clear */

/* Thread wrapper — required for all Gramine internal threads.
 * Pattern from libos_ipc_worker.c:363 and libos_async.c:114.
 * Must initialize TCB before entering the main loop. */
static int crisp_mc_thread_wrapper(void* arg) {
 (void)arg;
 libos_tcb_init;
 set_cur_thread(g_crisp.mc_thread_handle);
 log_setprefix(libos_get_tcb);
 log_debug("CRISP mc-thread started");
 crisp_mc_thread_func(NULL);
 /* Unreachable — crisp_mc_thread_func is noreturn */
 return 0;
}

noreturn void crisp_mc_thread_func(void* arg) {
 (void)arg;
 uint64_t last_commit_us = 0;

 while (g_crisp.mc_thread_running) {
 /* Wait for pending requests.
 * Internal threads CANNOT use thread_wait
 * (asserts !is_internal). Use PalEventWait on dedicated event.
 * Pattern follows IPC/async workers. */
 lock(&g_crisp.queue_mu);
 while (g_crisp.pending_count == 0 && g_crisp.mc_thread_running) {
 g_crisp.queue_has_work = false;
 unlock(&g_crisp.queue_mu);

 PalEventWait(g_crisp.mc_wakeup_event, /*timeout=*/NULL);

 lock(&g_crisp.queue_mu);
 }
 if (!g_crisp.mc_thread_running) {
 unlock(&g_crisp.queue_mu);
 break;
 }

 /* Set batch_in_flight BEFORE clearing the queue.
 * This prevents waiters (close/exit/Checker) from seeing
 * queue_empty=true but L/S still at old values — the race
 * race condition where waiters could exit early while
 * a batch was being processed. */
 g_crisp.batch_in_flight = true;

 /* 1. Collect batch — record size, clear queue */
 int batch_size = g_crisp.pending_count;
 g_crisp.pending_count = 0;

 /* Check queue timeout — per-request time.
 * Paper: "When a request waits in the queue longer than
 * the timeout, the runtime will exit prematurely"
 * Must check BEFORE resetting oldest_enqueue_us. */
 if (g_crisp.queue_timeout_ms > 0 && g_crisp.oldest_enqueue_us > 0) {
 uint64_t now_us = 0;
 PalSystemTimeQuery(&now_us); uint64_t waited_ms = (now_us - g_crisp.oldest_enqueue_us) / 1000;
 if (waited_ms > g_crisp.queue_timeout_ms) {
 g_crisp.batch_in_flight = false;
 unlock(&g_crisp.queue_mu);
 /* fail-stop — terminates process */
 crisp_fail_stop("queue timeout exceeded");
 /* unreachable */
 }
 }

 g_crisp.oldest_enqueue_us = 0; /* Reset after timeout check */

 unlock(&g_crisp.queue_mu);

 /* 2. Compute global tag from ALL Protected Files.
 * Mirrors SCONE's volume-level Merkle root: one tag that
 * represents the current state of ALL encrypted files.
 * Paper: "consolidates multiple requests, generating a
 * single tag and one MC value" */
 uint8_t global_tag[CRISP_TAG_SIZE];
 if (crisp_compute_global_tag(global_tag) != 0) {
 lock(&g_crisp.queue_mu);
 g_crisp.batch_in_flight = false;
 unlock(&g_crisp.queue_mu);
 /* fail-stop — terminates process */
 crisp_fail_stop("global tag computation failed");
 /* unreachable */
 }

 /* 3. L++ — promise new MC value for this batch */
 /* Paper: "For every batch, a new MC value is promised, */
 /* referred to as local (L)" */
 lock(&g_crisp.mu);
 g_crisp.L++;
 uint64_t current_L = g_crisp.L;
 unlock(&g_crisp.mu);

 /* 4. Write (global_tag, L) to vault file */
 /* Paper: "After confirming the writes to the FSPF volume */
 /* and vault file, the runtime issues MC increments" */
 /* Check return value — halt if write fails */
 if (crisp_vault_save(global_tag, current_L) != 0) {
 lock(&g_crisp.queue_mu);
 g_crisp.batch_in_flight = false;
 unlock(&g_crisp.queue_mu);
 /* fail-stop — terminates process */
 crisp_fail_stop("vault write failed after L++");
 /* unreachable */
 }

 /* 5. Rate limiting (Paper Section IV-B) */
 if (g_crisp.rate_limit_ms > 0 && last_commit_us > 0) {
 uint64_t now_us = 0;
 PalSystemTimeQuery(&now_us); uint64_t elapsed_ms = (now_us - last_commit_us) / 1000;
 if (elapsed_ms < g_crisp.rate_limit_ms) {
 uint64_t sleep_us = (g_crisp.rate_limit_ms - elapsed_ms) * 1000;
 /* Internal thread — use PalEventWait for timed sleep.
 * Using mc_wakeup_event means early wakeup is possible if
 * new work arrives, but that's fine — we recheck the loop. */
 PalEventWait(g_crisp.mc_wakeup_event, &sleep_us);
 }
 }

 /* 6. Increment MC hardware (THE SLOW OPERATION: ~20ms for RPMB) */
 uint64_t new_mc;
 if (crisp_mc_increment(&new_mc) != 0) {
 lock(&g_crisp.queue_mu);
 g_crisp.batch_in_flight = false;
 unlock(&g_crisp.queue_mu);
 /* fail-stop — terminates process */
 crisp_fail_stop("MC increment failed");
 /* unreachable */
 }

 /* Invariant 2 hardening — verify S == L after increment.
 * After MC increment, new_mc must equal current_L (the value we
 * promised). If they diverge, the MC is corrupted or another
 * entity incremented it — either way, the binding is broken. */
 if (new_mc != current_L) {
 lock(&g_crisp.queue_mu);
 g_crisp.batch_in_flight = false;
 unlock(&g_crisp.queue_mu);
 crisp_fail_stop("MC value mismatch after increment: "
 "invariant S==L violated");
 /* unreachable */
 }

 /* 7. Batch fully committed: S == current_L.
 * Clear in_flight flag and wake all waiters. */
 lock(&g_crisp.queue_mu);
 g_crisp.batch_in_flight = false;
 unlock(&g_crisp.queue_mu);
 crisp_wake_all_waiters;

 PalSystemTimeQuery(&last_commit_us); }

 /* Thread exit — internal threads use PalThreadExit, NOT thread_exit.
 * thread_exit is for app threads (calls detach_all_fds etc).
 * Internal threads exit via PalThreadExit (see libos_ipc_worker.c). */
 static int g_mc_thread_clear_on_exit = 1;
 PalThreadExit(&g_mc_thread_clear_on_exit);
 __builtin_unreachable;
}
```

## 4.6 Simulated Monotonic Counter

**Development adaptation (not from the CRISP paper's production design):** The CRISP paper assumes a real hardware MC (RPMB). We use a simulated MC because Gramine/Linux SGX has no built-in hardware MC support (Intel removed SGX Platform Services from Linux SDK 2.9+). This is a Phase 1 adaptation for runtime logic validation — full security requires a trusted backend (see §1.4.1). The MC interface (`init`/`read`/`increment`) is backend-pluggable by design.

From the paper (Section IV):
> "simulates the MC on the same machine using the latency characteristics from Table I"

```c
/* libos/src/crisp/crisp_mc.c */

#include "crisp.h"
#include "libos_thread.h"
#include "pal.h" /* PalSystemTimeQuery, PalEventWait, PalStreamOpen/Read/Write */

static uint64_t mc_value = 0;
static struct libos_lock mc_mu;
static bool mc_mu_initialized = false;

/* Helper to build PAL URI from path */
static void mc_path_to_uri(const char* path, char* uri, size_t uri_size) {
 snprintf(uri, uri_size, "file:%s", path);
}

int crisp_mc_init(void) {
 if (!mc_mu_initialized) {
 if (!create_lock(&mc_mu)) return -1;
 mc_mu_initialized = true;
 }

 lock(&mc_mu);

 /* Try to read existing MC value from file.
 * Uses PAL-level I/O (not stdio — unavailable in LibOS).
 * The simulated MC file is on an UNENCRYPTED path since the MC
 * simulates external hardware that is NOT inside the enclave. */
 char uri[300];
 mc_path_to_uri(g_crisp.mc_path, uri, sizeof(uri));

 PAL_HANDLE hdl = NULL;
 int ret = PalStreamOpen(uri, PAL_ACCESS_RDONLY, /*share_flags=*/0,
 PAL_CREATE_NEVER, /*options=*/0, &hdl);
 if (ret < 0) {
 /* Distinguish ENOENT (new MC) from other errors.
 * Permission errors, corruption, etc. should NOT silently create a fresh MC. */
 if (ret != PAL_ERROR_STREAMNOTEXIST) {
 log_error("CRISP: MC file open failed: %d (not ENOENT)", ret);
 unlock(&mc_mu);
 return -1; /* Fatal — propagate to crisp_init → fail-stop */
 }

 /* New MC — start at 0 */
 mc_value = 0;
 ret = PalStreamOpen(uri, PAL_ACCESS_RDWR, /*share_flags=*/0600,
 PAL_CREATE_ALWAYS, /*options=*/0, &hdl);
 if (ret < 0) {
 log_error("CRISP: MC file create failed: %d", ret);
 unlock(&mc_mu);
 return -1;
 }
 size_t count = sizeof(mc_value);
 ret = PalStreamWrite(hdl, /*offset=*/0, &count, &mc_value);
 PalObjectDestroy(hdl);
 if (ret < 0 || count != sizeof(mc_value)) {
 log_error("CRISP: MC file initial write failed");
 unlock(&mc_mu);
 return -1;
 }
 unlock(&mc_mu);
 return 0;
 }

 size_t count = sizeof(mc_value);
 ret = PalStreamRead(hdl, /*offset=*/0, &count, &mc_value);
 PalObjectDestroy(hdl);
 if (ret < 0 || count != sizeof(mc_value)) {
 log_error("CRISP: MC file read failed (short read or error)");
 unlock(&mc_mu);
 return -1;
 }
 unlock(&mc_mu);
 return 0;
}

int crisp_mc_read(uint64_t* value) {
 lock(&mc_mu);
 *value = mc_value;
 unlock(&mc_mu);
 return 0;
}

int crisp_mc_increment(uint64_t* new_value) {
 /* Simulate RPMB hardware latency BEFORE acquiring lock.
 * Real RPMB hardware delay precedes the atomic counter write.
 * Moving sleep outside lock prevents blocking crisp_mc_read callers
 * (e.g., drain_and_wait in app threads) during the ~20ms sleep.
 * This gives more accurate latency measurements vs. real hardware.
 * (Paper Table I: 19.97ms write)
 * Called from mc-thread (internal), can't use thread_wait.
 * Use PalEventWait on mc_wakeup_event with timeout for sleep. */
 if (g_crisp.mc_latency_ms > 0) {
 uint64_t sleep_us = g_crisp.mc_latency_ms * 1000;
 PalEventWait(g_crisp.mc_wakeup_event, &sleep_us);
 }

 lock(&mc_mu);
 mc_value++;
 *new_value = mc_value;

 /* Persist to file (unencrypted — simulates external hardware) */
 /* Atomic write-then-rename, same as vault.
 * Uses PAL-level I/O (PalStreamOpen/Write/ChangeName). */
 char tmp_path[260];
 snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", g_crisp.mc_path);

 char tmp_uri[300], mc_uri[300];
 mc_path_to_uri(tmp_path, tmp_uri, sizeof(tmp_uri));
 mc_path_to_uri(g_crisp.mc_path, mc_uri, sizeof(mc_uri));

 PAL_HANDLE hdl = NULL;
 int ret = PalStreamOpen(tmp_uri, PAL_ACCESS_RDWR, /*share_flags=*/0600,
 PAL_CREATE_ALWAYS, /*options=*/0, &hdl);
 if (ret < 0) {
 unlock(&mc_mu);
 return -1;
 }
 /* Check ALL PAL return values and byte counts.
 * If any step fails, the on-disk MC is stale — return error so
 * mc-thread calls fail-stop (in-memory MC already advanced). */
 size_t count = sizeof(mc_value);
 ret = PalStreamWrite(hdl, /*offset=*/0, &count, &mc_value);
 if (ret < 0 || count != sizeof(mc_value)) {
 PalObjectDestroy(hdl);
 unlock(&mc_mu);
 return -1;
 }
 ret = PalStreamFlush(hdl);
 PalObjectDestroy(hdl);
 if (ret < 0) {
 unlock(&mc_mu);
 return -1;
 }

 /* Atomic rename: tmp → mc */
 ret = PalStreamOpen(tmp_uri, PAL_ACCESS_RDWR, /*share_flags=*/0,
 PAL_CREATE_NEVER, /*options=*/0, &hdl);
 if (ret < 0) {
 unlock(&mc_mu);
 return -1;
 }
 ret = PalStreamChangeName(hdl, mc_uri);
 PalObjectDestroy(hdl);
 if (ret < 0) {
 unlock(&mc_mu);
 return -1;
 }

 unlock(&mc_mu);
 return 0;
}
```

## 4.7 Vault File

From the paper:
> "bind each tag update to an MC value, all saved in the local vault file"
> L (local) is "latest value written to the vault file"

**Note:** `crisp_vault_save` is called from mc-thread (per batch), not from fsync.

**SECURITY: The vault file MUST be a Protected File (encrypted).**
In SCONE, the vault is inside the FSPF volume — integrity-protected by the enclave key.
A plain SHA-256 checksum does NOT prevent attacker forgery (the attacker can recompute it).
Place the vault on an `encrypted` mount in the Gramine manifest so the PF layer provides
AES-GCM integrity protection. The SHA-256 checksum is kept as defense-in-depth.

**Vault I/O uses LibOS VFS, NOT PAL-level I/O.**
PAL-level I/O (`PalStreamOpen`/`PalStreamWrite`) goes directly to the host filesystem, bypassing the encrypted FS layer entirely. Using PAL I/O for the vault writes it as plaintext on disk, defeating the requirement that the vault must be a Protected File.

The correct approach: vault I/O goes through LibOS VFS (internal `open_namei`/`do_handle_read`/
`do_handle_write`) which routes through `chroot_encrypted` → `pf_open` → PF encryption.
This way the vault gets the same AES-GCM integrity protection as any other Protected File.

**Re-entrancy safety:** Since the vault goes through LibOS VFS, its write path will
trigger the fsync/close hooks. We use a recursion guard (plain global bool) to prevent infinite
recursion:

```c
bool g_in_crisp_io = false;
```

The CRISP hooks check this flag and skip processing when set:
- `crisp_on_fsync`: if `g_in_crisp_io`, return 0 immediately
- `crisp_on_close`: if `g_in_crisp_io`, return 0 immediately

The mc-thread sets `g_in_crisp_io = true` around vault I/O calls, ensuring vault writes
flow through the PF encryption layer but don't re-enter CRISP's queue logic.

**MC file stays on PAL I/O.** The MC simulates external hardware (trusted, outside enclave).
PAL I/O is correct for MC — it should NOT be encrypted. Same threat model as the paper.

**No stdio (FILE*/fopen/fwrite) in LibOS code.** Gramine's LibOS is kernel-equivalent
userspace code — it does NOT have access to the C standard library's buffered I/O.
LibOS provides the syscall layer TO stdio, not uses it. All file I/O must use LibOS VFS
internals or PAL-level primitives (for unencrypted paths like MC).

```c
/* libos/src/crisp/crisp_vault.c */

#include "crisp.h"
#include <string.h>
/* Gramine's crypto wrapper (NOT raw mbedtls) */
/* common/include/crypto.h wraps mbedtls with lib_SHA256* API */
#include "crypto.h"
#include "libos_fs.h" /* open_namei, g_dcache_lock, put_inode, path_lookupat */
#include "libos_handle.h" /* get_new_handle, put_handle, do_handle_read, do_handle_write */

/* Vault I/O uses LibOS VFS, NOT PAL-level I/O.
 * This ensures the vault goes through Gramine's encrypted FS layer
 * (chroot_encrypted → PF encryption/integrity), so it's protected
 * by AES-GCM just like any other Protected File.
 *
 * PAL-level I/O (PalStreamOpen/PalStreamWrite) bypasses the encrypted
 * FS layer, so vault must use LibOS VFS to get PF encryption.
 *
 * API pattern (verified from libos_syscall_openat in libos_open.c):
 * 1. hdl = get_new_handle // allocate empty handle
 * 2. open_namei(hdl, NULL, path, flags, mode, NULL) // lookup + connect
 * 3. do_handle_read/write(hdl, buf, count) // actual I/O
 * 4. put_handle(hdl) // release
 *
 * open_namei signature (6 params, NOT 7):
 * int open_namei(struct libos_handle* hdl, struct libos_dentry* start,
 * const char* path, int flags, int mode,
 * struct libos_dentry** found);
 */

/* Recursion guard (plain global bool, single-writer safe).
 * When the mc-thread writes the vault through LibOS VFS, the write
 * path triggers fsync/close hooks. Without this guard, those hooks
 * would re-enter CRISP (enqueue → mc-thread → vault write → enqueue...).
 * The guard is checked in crisp_on_fsync and crisp_on_close.
 * NOT __thread: Gramine LibOS -nostdlib link model has no __tls_get_addr.
 * Safe as plain global: only mc-thread writes, reads on same thread. */
bool g_in_crisp_io = false;

static void compute_checksum(const uint8_t* tag, uint64_t local_mc,
 uint8_t* out) {
 LIB_SHA256_CONTEXT ctx;
 lib_SHA256Init(&ctx);
 lib_SHA256Update(&ctx, (const uint8_t*)CRISP_VAULT_MAGIC, 4);
 lib_SHA256Update(&ctx, tag, CRISP_TAG_SIZE);
 lib_SHA256Update(&ctx, (const uint8_t*)&local_mc, sizeof(local_mc));
 lib_SHA256Final(&ctx, out);
}

int crisp_vault_load(crisp_vault_t* out) {
 /* Open vault via LibOS VFS — goes through encrypted FS layer.
 * The vault file is on an encrypted mount, so open_namei routes
 * through chroot_encrypted → pf_open → PF decryption.
 *
 * Correct open_namei usage:
 * 1. get_new_handle to allocate empty handle
 * 2. open_namei(hdl, start, path, flags, mode, found) — 6 params
 * 3. do_handle_read(hdl, buf, count) — returns ssize_t */
 g_in_crisp_io = true;

 struct libos_handle* hdl = get_new_handle;
 if (!hdl) {
 g_in_crisp_io = false;
 return -1;
 }

 int ret = open_namei(hdl, /*start=*/NULL, g_crisp.vault_path,
 O_RDONLY, /*mode=*/0, /*found=*/NULL);
 if (ret < 0) {
 put_handle(hdl);
 g_in_crisp_io = false;
 /* Distinguish ENOENT from other errors */
 if (ret == -ENOENT) return -2; /* No vault = fresh install */
 return -1; /* Other error = halt */
 }

 ssize_t nread = do_handle_read(hdl, out, sizeof(crisp_vault_t));
 put_handle(hdl);
 g_in_crisp_io = false;

 if (nread < (ssize_t)sizeof(crisp_vault_t)) return -1;

 /* Verify magic */
 if (memcmp(out->magic, CRISP_VAULT_MAGIC, 4) != 0) return -1;

 /* Verify checksum (defense-in-depth — PF provides AES-GCM) */
 uint8_t expected[32];
 compute_checksum(out->tag, out->local_mc, expected);
 if (memcmp(out->checksum, expected, 32) != 0) return -1;

 return 0;
}

int crisp_vault_save(const uint8_t* tag, uint64_t local_mc) {
 crisp_vault_t v;
 memcpy(v.magic, CRISP_VAULT_MAGIC, 4);
 memcpy(v.tag, tag, CRISP_TAG_SIZE);
 v.local_mc = local_mc;
 compute_checksum(tag, local_mc, v.checksum);

 /* Write vault through LibOS VFS with recursion guard.
 * Write-then-rename for atomicity.
 *
 * The vault file is on an encrypted PF mount, so all I/O goes
 * through chroot_encrypted → PF encryption. The recursion guard
 * (g_in_crisp_io) prevents the fsync/close hooks from re-entering
 * CRISP logic during vault writes.
 *
 * Correct open_namei usage — 6 params, needs
 * get_new_handle first.
 * NOT libos_syscall_renameat (rejects LibOS memory pointers).
 * NOT do_rename either (static, asserts g_dcache_lock).
 * Instead: inline d_ops->rename + inode fixup under g_dcache_lock. */
 g_in_crisp_io = true;

 char tmp_path[260];
 snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", g_crisp.vault_path);

 /* Open tmp file for writing via LibOS VFS */
 struct libos_handle* hdl = get_new_handle;
 if (!hdl) {
 g_in_crisp_io = false;
 return -1;
 }

 int ret = open_namei(hdl, /*start=*/NULL, tmp_path,
 O_WRONLY | O_CREAT | O_TRUNC, /*mode=*/0600,
 /*found=*/NULL);
 if (ret < 0) {
 put_handle(hdl);
 g_in_crisp_io = false;
 return -1;
 }

 /* Write vault struct */
 ssize_t written = do_handle_write(hdl, &v, sizeof(v));
 if (written < (ssize_t)sizeof(v)) {
 put_handle(hdl);
 g_in_crisp_io = false;
 return -1;
 }

 /* Flush to ensure PF metadata is written to disk.
 * Check return value — if flush fails, the tmp file
 * has corrupt/incomplete PF metadata. Renaming it over the real
 * vault would destroy the last known-good state. */
 if (hdl->fs && hdl->fs->fs_ops && hdl->fs->fs_ops->flush) {
 ret = hdl->fs->fs_ops->flush(hdl);
 if (ret < 0) {
 put_handle(hdl);
 g_in_crisp_io = false;
 return -1;
 }
 }
 put_handle(hdl);

 /* Atomic rename: tmp → vault.
 *
 * CANNOT use libos_syscall_renameat from mc-thread: that syscall
 * wrapper calls is_user_string_readable which rejects LibOS-internal
 * memory (stack/global buffers) when g_check_invalid_ptrs=true
 * (default). Every call would return -EFAULT.
 *
 * do_rename is static in libos_file.c and asserts
 * g_dcache_lock is held. Instead, replicate its logic inline:
 * acquire g_dcache_lock, path_lookupat both dentries, call
 * d_ops->rename directly, fix up inodes, release lock.
 * This mirrors what libos_syscall_renameat does internally
 * but without the is_user_string_readable check. */
 lock(&g_dcache_lock);

 struct libos_dentry* old_dent = NULL;
 struct libos_dentry* new_dent = NULL;

 /* Lookup tmp file dentry (under g_dcache_lock) */
 ret = path_lookupat(/*start=*/NULL, tmp_path, LOOKUP_NO_FOLLOW, &old_dent);
 if (ret < 0 || !old_dent->inode) {
 if (old_dent) put_dentry(old_dent);
 unlock(&g_dcache_lock);
 g_in_crisp_io = false;
 return -1;
 }

 /* Lookup or create vault file dentry (parent must exist) */
 ret = path_lookupat(/*start=*/NULL, g_crisp.vault_path,
 LOOKUP_NO_FOLLOW | LOOKUP_CREATE, &new_dent);
 if (ret < 0) {
 put_dentry(old_dent);
 unlock(&g_dcache_lock);
 g_in_crisp_io = false;
 return -1;
 }

 /* Inline do_rename logic: call fs d_ops->rename, then fix up inodes.
 * do_rename is static in libos_file.c, so we replicate its core. */
 struct libos_fs* fs = old_dent->inode->fs;
 if (!fs || !fs->d_ops || !fs->d_ops->rename) {
 ret = -EPERM;
 } else {
 ret = fs->d_ops->rename(old_dent, new_dent);
 if (ret == 0) {
 if (new_dent->inode)
 put_inode(new_dent->inode);
 new_dent->inode = old_dent->inode;
 old_dent->inode = NULL;
 }
 }

 put_dentry(old_dent);
 put_dentry(new_dent);
 unlock(&g_dcache_lock);
 g_in_crisp_io = false;

 return (ret < 0) ? -1 : 0;
}
```

## 4.8 Checker API TCP Server

From the paper (Section IV-A):
> "spawns a new thread for each check request that is received through a TCP connection"
> "check the latest promised MC value that has been written to the vault file"
> "check the value on the MC periodically until the condition is satisfied"

```c
/* libos/src/crisp/crisp_checker_api.c */

#include "crisp.h"
#include "pal.h" /* PAL socket APIs — libc sockets don't exist in LibOS */
#include "libos_thread.h"
#include "libos_utils.h"

/* Handler for each TCP connection (Paper Listing 1 server-side) */
/*
 * INTENTIONAL SIMPLIFICATION:
 *
 * The paper says "spawns a new thread for each check request" (Section IV-A).
 * Our implementation uses a SINGLE internal listener thread handling
 * connections sequentially (option b below).
 *
 * Rationale:
 * - Thread-per-connection in Gramine is expensive: each thread requires
 * get_new_internal_thread + PalThreadCreate + TCB initialization.
 * - For the thesis's network gate use case, there is ONE gate calling
 * the Checker API at a time (sequential by design).
 * - Sequential handling is functionally identical for single-client use.
 *
 * For paper-faithful evaluation (if reviewer requires it):
 * - Option (a): Spawn a thread via clone for each connection.
 * This can be added as a config flag (CRISP_CHECKER_THREAD_PER_CONN).
 * The current sequential mode would be the default.
 *
 * Two options:
 * (a) Spawn a thread via clone for each connection (mirrors paper)
 * (b) Handle sequentially in accept loop (simpler, works for low concurrency)
 * We use option (b); option (a) available as future config option.
 */
static void handle_check_request(PAL_HANDLE client_hdl) {
 /* Use crisp_drain_and_wait — same helper as close/exit.
 *
 * The paper's Checker API: "if the queue is empty and there is no
 * pending increment, the Checker API will return immediately."
 * This confirms the Checker checks queue state, not just vault L.
 *
 * Our "hard gate" mode (for network gate, thesis extension):
 * Signal mc-thread, wait for queue drain + !batch_in_flight + S >= L.
 * Guarantees window = 0 for the network gate.
 *
 * Note: This is an intentional strengthening over the paper's
 * passive polling approach. For evaluation that reproduces paper
 * measurements exactly, a "paper mode" checker (read vault L,
 * poll S) can be added as a config option. */

 int ret = crisp_drain_and_wait;

 if (ret < 0) {
 /* fail-stop — close connection without responding.
 * The network gate will see the disconnect and refuse the response.
 * The crisp_fail_stop was already called by whoever set halted. */
 PalObjectDestroy(client_hdl);
 return;
 }

 /* Return MC value to caller (PAL socket send) */
 uint64_t S;
 crisp_mc_read(&S);
 struct iovec iov = {.iov_base = &S,.iov_len = sizeof(S) };
 size_t out_size = 0;
 int send_ret = PalSocketSend(client_hdl, &iov, 1, &out_size, /*addr=*/NULL,
 /*force_nonblocking=*/false);
 if (send_ret < 0 || out_size != sizeof(S)) {
 log_warning("CRISP: Checker API send failed: %d (sent %zu/%zu)",
 send_ret, out_size, sizeof(S));
 /* Not fatal — client (network gate) will see disconnect and refuse.
 * The gate's fail-safe is to reject on any communication error. */
 }
 PalObjectDestroy(client_hdl);
}

/* TCP server main loop */
noreturn void crisp_checker_api_func(void* arg) {
 (void)arg;

 /* Use PAL socket APIs, NOT libc socket.
 * LibOS code doesn't link against libc. Internal threads (like IPC worker)
 * use PAL-level APIs exclusively. Verified: PalSocketCreate/Bind/Listen/Accept
 * exist in pal/src/pal_sockets.c; PalStreamWaitForClient is pipe-only. */
 PAL_HANDLE server_hdl = NULL;
 int ret = PalSocketCreate(PAL_IPV4, PAL_SOCKET_TCP, /*options=*/0, &server_hdl);
 if (ret < 0) {
 log_error("CRISP: Checker API socket creation failed: %d", ret);
 /* Internal threads must use PalThreadExit, not
 * thread_exit (which is for app threads and calls
 * detach_all_fds etc — see libos_ipc_worker.c). */
 static int g_checker_clear_on_exit = 1;
 PalThreadExit(&g_checker_clear_on_exit);
 __builtin_unreachable;
 }

 /* pal_socket_addr expects network byte order
 * for both addr and port. pal_to_linux_sockaddr copies directly
 * to sin_addr/sin_port without conversion. Regression test
 * send_handle.c:112 confirms: htons(PORT) before PalSocketBind. */
 struct pal_socket_addr addr = {.domain = PAL_IPV4,.ipv4 = {.addr = __builtin_bswap32(0x7F000001), /* 127.0.0.1 in network order */.port = __builtin_bswap16(g_crisp.checker_api_port), /* network order */
 },
 };
 ret = PalSocketBind(server_hdl, &addr);
 if (ret < 0) {
 log_error("CRISP: Checker API bind failed: %d", ret);
 PalObjectDestroy(server_hdl);
 static int g_checker_clear_on_exit3 = 1;
 PalThreadExit(&g_checker_clear_on_exit3);
 __builtin_unreachable;
 }
 ret = PalSocketListen(server_hdl, 128);
 if (ret < 0) {
 log_error("CRISP: Checker API listen failed: %d", ret);
 PalObjectDestroy(server_hdl);
 static int g_checker_clear_on_exit4 = 1;
 PalThreadExit(&g_checker_clear_on_exit4);
 __builtin_unreachable;
 }

 while (!__atomic_load_n(&g_crisp.halted, __ATOMIC_ACQUIRE)) {
 PAL_HANDLE client_hdl = NULL;
 ret = PalSocketAccept(server_hdl, /*options=*/0, &client_hdl,
 /*out_client_addr=*/NULL, /*out_local_addr=*/NULL);
 if (ret < 0) continue;

 /* Handle check request (sequential for simplicity) */
 /* Paper says "spawns a new thread" but sequential handling */
 /* is acceptable since check requests are fast (only polls */
 /* until S >= L, typically < 1 batch cycle = ~20-40ms) */
 handle_check_request(client_hdl);
 }

 PalObjectDestroy(server_hdl);
 /* Internal thread exit (same pattern as mc-thread) */
 static int g_checker_clear_on_exit2 = 1;
 PalThreadExit(&g_checker_clear_on_exit2);
 __builtin_unreachable;
}
```

## 4.9 Gramine Syscall Hooks

These are the modifications to existing Gramine LibOS files.

From the paper:
> "fsync, although other invocations (e.g., sync, fdatasync) are also included"

**Key finding from Gramine source:** fsync, fdatasync, AND close are ALL in the same file: `libos/src/sys/libos_open.c`. There is no separate `libos_sync.c` or `libos_file.c`.

**Scope note:** The paper says "fsync, although other invocations (e.g., sync, fdatasync)
are also included." We hook **fsync** and **fdatasync** (which wraps fsync). We do NOT hook:
- `sync` — global filesystem flush (rarely used by DB workloads)
- `syncfs` — per-filesystem flush (uncommon)
- `msync` — mmap flush (only relevant for mmap'd files)

These are out of scope for the thesis. Target workloads (SQLite, Redis) use fsync/fdatasync
exclusively. Listed as future work.

**Actual Gramine function signatures:**
```c
/* All in libos/src/sys/libos_open.c: */
long libos_syscall_fsync(int fd); /* dispatches to fs_ops->flush */
long libos_syscall_fdatasync(int fd); /* literally: return libos_syscall_fsync(fd); */
long libos_syscall_close(int fd); /* detach_fd_handle → put_handle */

/* In libos/src/sys/libos_exit.c: */
long libos_syscall_exit(int error_code); /* calls thread_exit */
long libos_syscall_exit_group(int error_code); /* calls process_exit */
```

```c
/* ===== In gramine/libos/src/sys/libos_open.c ===== */
/* Modify libos_syscall_fsync — hook AFTER flush completes */

#include "crisp.h"

long libos_syscall_fsync(int fd) {
 /* Matches actual Gramine goto structure (libos_open.c:496-524).
 * Single put_handle at out: label — CRISP hook inserted before it. */
 struct libos_handle* hdl = get_fd_handle(fd, NULL, NULL);
 if (!hdl)
 return -EBADF;

 int ret;
 struct libos_fs* fs = hdl->fs;

 if (!fs || !fs->fs_ops) {
 ret = -EACCES;
 goto out;
 }

 if (hdl->is_dir) {
 ret = 0;
 goto out;
 }

 if (!fs->fs_ops->flush) {
 ret = -EINVAL;
 goto out;
 }

 ret = fs->fs_ops->flush(hdl);

 /* >>> CRISP HOOK: after PF flush completes <<< */
 /* Only hook Protected Files (encrypted).
 * No tag parameter — mc-thread computes global tag
 * from all PFs. fsync just signals "work pending."
 * Propagate CRISP errors to application.
 * Placed before out: label to match goto pattern. */
 if (ret == 0 && g_crisp.enabled && hdl->type == TYPE_CHROOT_ENCRYPTED) {
 ret = crisp_on_fsync;
 /* ret may be -ENOTRECOVERABLE if halted */
 }

out:
 put_handle(hdl);
 return ret;
}

/* fdatasync wraps fsync — no separate hook needed */
long libos_syscall_fdatasync(int fd) {
 return libos_syscall_fsync(fd); /* Already has CRISP hook */
}

/* Modify libos_syscall_close — hook AFTER PF flush completes
 *
 * The CRISP hook MUST run after put_handle triggers the
 * PF close chain (encrypted_file_put → encrypted_file_internal_close
 * → pf_close → ipf_close → ipf_internal_flush
 * → ipf_update_metadata_node → metadata MAC updated).
 *
 * The hook must NOT be placed before put_handle: the mc-thread would
 * compute the global tag from the OLD MAC (before close-flush),
 * causing false-positive rollback detection at startup.
 *
 * Correct ordering: detach → check type → put_handle (flushes PF, updates
 * MAC) → crisp_on_close (enqueue + drain). The hook runs OUTSIDE
 * inode locks because put_handle releases everything before returning.
 *
 * Note: After put_handle, `handle` may be freed (refcount→0).
 * We save the type BEFORE calling put_handle. */
long libos_syscall_close(int fd) {
 struct libos_handle* handle = detach_fd_handle(fd, NULL, NULL);
 if (!handle) return -EBADF;

 /* Save type BEFORE put_handle — handle may be freed after */
 int handle_type = handle->type;

 /* Release handle — triggers PF flush if refcount reaches 0.
 * This is where the metadata MAC gets updated.
 *
 * For dup'd fds, non-last close decrements refcount
 * without flushing PF. The CRISP hook below fires on every close,
 * not just last-reference close — so it may enqueue with unchanged
 * MACs. This is safe: the global tag is idempotent (same sorted
 * MACs → same digest → same tag). We accept the extra MC increment
 * as conservative-by-default rather than risk missing the last
 * close by gating on refcount (which is not exposed by put_handle). */
 put_handle(handle);

 /* >>> CRISP HOOK: AFTER PF flush completes <<< */
 /* Only hook Protected Files (encrypted).
 * Moved AFTER put_handle so MAC is fresh.
 * Propagate CRISP errors to application. */
 if (g_crisp.enabled && handle_type == TYPE_CHROOT_ENCRYPTED) {
 int crisp_ret = crisp_on_close;
 if (crisp_ret < 0) return crisp_ret;
 }

 return 0;
}


/* ===== In gramine/libos/src/sys/libos_exit.c ===== */
/* Modify thread_exit or process_exit — hook BEFORE actual exit */

#include "crisp.h"

/* Inside thread_exit or process_exit, before cleanup: */
{
 /* >>> CRISP HOOK: block until all batches committed <<< */
 if (g_crisp.enabled)
 crisp_on_exit;
}

/* Actual signatures: */
/* long libos_syscall_exit(int error_code) { */
/* error_code &= 0xFF; */
/* if (g_crisp.enabled) */
/* crisp_on_exit; // <-- ADD HERE */
/* thread_exit(error_code, 0); */
/* } */
/* long libos_syscall_exit_group(int error_code) { */
/* error_code &= 0xFF; */
/* if (g_crisp.enabled) */
/* crisp_on_exit; // <-- ADD HERE */
/* process_exit(error_code, 0); */
/* } */
```

**Build system:** Add CRISP sources to `libos/src/meson.build`:
```meson
# In libos/src/meson.build, add to libos_sources:
libos_sources += files(
 'crisp/crisp_init.c',
 'crisp/crisp_fsync.c',
 'crisp/crisp_close.c', # close/exit hooks
 'crisp/crisp_vault.c',
 'crisp/crisp_mc.c',
 'crisp/crisp_mcthread.c',
 'crisp/crisp_checker_api.c',
 'crisp/crisp_tag.c', # Also contains crisp_flush_pf_by_path
 'crisp/crisp_config.c',
)
```

## 4.10 Protected Files Tag Extraction + Global Digest

The CRISP paper says:
> "bind each tag update to an MC value" where "tag" = Merkle root hash of the FSPF volume

### 4.10.1 Architectural Difference: SCONE vs Gramine

In SCONE, the FSPF is a **single encrypted volume** with **one Merkle tree**. The "tag" is the Merkle root — a single value that represents ALL files. The mc-thread reads this root once per batch.

In Gramine, Protected Files are **individual files** with **separate integrity trees**. Each PF has its own `metadata_mac` (16-byte AES-GCM tag). There is no built-in volume-level root hash.

**Our solution:** Define a **global digest** that mirrors SCONE's volume tag:
```
global_tag = SHA-256( concat( pf_mac(path_1), pf_mac(path_2),... ) )
```
Where `path_1 < path_2 <...` (sorted lexicographically for determinism).

This global_tag changes whenever ANY protected file changes — exactly like SCONE's Merkle root. It is:
- Computed by mc-thread per batch (Section 4.5)
- Stored in vault with L (Section 4.7)
- Verified against current PF state at startup (Section 4.3)

**PF set assumption:** We target a **fixed PF set** — all protected file paths are
known at deployment time from the Gramine manifest (encrypted mounts). This mirrors SCONE's
FSPF, which is also a fixed volume defined at deployment. For dynamic workloads that
create/rename/delete files at runtime (e.g., MariaDB with InnoDB tablespace management),
the PF registry would need dynamic enumeration of the encrypted mount. This is listed as
future work — the thesis evaluation uses SQLite (single-file DB) where the PF set is
fixed by construction. An unregistered PF file would NOT be covered by rollback detection.

### 4.10.2 PF Metadata MAC Extraction (OPEN PROBLEM)

**Problem:** Gramine's PF implementation does NOT expose a public API to extract the metadata MAC. The `metadata_mac` field exists internally in `pf_context->metadata_node` (see `common/src/protected_files/protected_files.c`), but there is no function like `pf_get_metadata_mac`.

**Required change to Gramine PF code:**
```c
/* Add to common/src/protected_files/protected_files.h */
pf_status_t pf_get_metadata_mac(pf_context_t* pf, uint8_t* mac_out);

/* Implementation (in protected_files.c): */
pf_status_t pf_get_metadata_mac(pf_context_t* pf, uint8_t* mac_out) {
 if (!pf || !mac_out) return PF_STATUS_INVALID_PARAMETER;
 /* metadata_node is EMBEDDED in pf_context (not a pointer).
 * Struct layout (from protected_files_internal.h):
 * pf->metadata_node — metadata_node_t (4096 bytes, embedded)
 * pf->metadata_node.plaintext_part — metadata_plaintext_t
 * pf->metadata_node.plaintext_part.metadata_mac — pf_mac_t (16 bytes)
 *
 * The MAC is the AES-GCM tag over metadata_decrypted_t (3392 bytes).
 * Any change to any data node propagates through the Merkle tree
 * to this MAC — it serves as the per-file "root hash." */
 memcpy(mac_out, &pf->metadata_node.plaintext_part.metadata_mac, PF_MAC_SIZE);
 return PF_STATUS_SUCCESS;
}
```
This is a minimal change: one new function, ~5 lines, well-contained.

### 4.10.3 Global Tag Computation

```c
/* libos/src/crisp/crisp_tag.c */

#include "crisp.h"
#include "crypto.h"
#include <string.h>

/* Helper: extract metadata MAC from a PF by path.
 * Opens the file, calls pf_get_metadata_mac, closes.
 * The file must have been flushed already (fsync completed).
 *
 * PF context access path (verified from Gramine source):
 * hdl->inode->data → (struct libos_encrypted_file*)
 * enc->pf → pf_context_t*
 *
 * See: libos/src/fs/chroot/encrypted.c (chroot_encrypted_flush)
 * libos/src/fs/libos_fs_encrypted.c (struct libos_encrypted_file)
 * libos/include/libos_fs_encrypted.h:49-62 */
static int crisp_extract_pf_mac(const char* path, uint8_t* mac_out) {
 /* Open file via LibOS VFS to get a handle.
 * NOTE: This open is internal (from mc-thread). The file should
 * already be open by the app; we just need the PF context.
 * Alternative: maintain a handle cache in g_crisp to avoid
 * repeated open/close. For now, open fresh each time.
 *
 * Correct open_namei usage — 6 params.
 * Must call get_new_handle first, then pass to open_namei. */
 struct libos_handle* hdl = get_new_handle;
 if (!hdl) return -1;

 int ret = open_namei(hdl, /*start=*/NULL, path,
 O_RDONLY, /*mode=*/0, /*found=*/NULL);
 if (ret < 0) {
 put_handle(hdl);
 return -1;
 }

 /* Extract PF context: hdl->inode->data is struct libos_encrypted_file*.
 *
 * MUST acquire hdl->inode->lock before accessing
 * enc->pf. libos_fs_encrypted.h:46-47 explicitly states:
 * "Operations on a single libos_encrypted_file are NOT thread-safe,
 * it is intended to be protected by a lock."
 * All existing callers (chroot_encrypted_read/write/flush) lock inode. */
 if (!hdl->inode || !hdl->inode->data) {
 put_handle(hdl);
 return -1;
 }

 lock(&hdl->inode->lock);
 struct libos_encrypted_file* enc =
 (struct libos_encrypted_file*)hdl->inode->data;
 if (!enc->pf) {
 unlock(&hdl->inode->lock);
 put_handle(hdl);
 return -1;
 }

 pf_status_t status = pf_get_metadata_mac(enc->pf, mac_out);
 unlock(&hdl->inode->lock);
 put_handle(hdl);
 return (status == PF_STATUS_SUCCESS) ? 0 : -1;
}

/* Compute global tag over ALL registered Protected Files.
 * Mirrors SCONE's volume-level Merkle root.
 * Called by: mc-thread (per batch), crisp_init (startup verification).
 *
 * The PF paths in g_crisp.pf_paths are pre-sorted at init time,
 * ensuring deterministic output regardless of enumeration order. */
int crisp_compute_global_tag(uint8_t* tag_out) {
 LIB_SHA256_CONTEXT ctx;
 lib_SHA256Init(&ctx);

 for (int i = 0; i < g_crisp.pf_count; i++) {
 uint8_t mac[16]; /* PF metadata MAC is 16 bytes (AES-GCM tag) */
 if (crisp_extract_pf_mac(g_crisp.pf_paths[i], mac) != 0) {
 return -1;
 }
 lib_SHA256Update(&ctx, mac, 16);
 }

 lib_SHA256Final(&ctx, tag_out);
 return 0;
}

/* Force-flush a PF by path to update its metadata MAC.
 * Used by crisp_on_exit to flush all tracked PFs before enqueuing,
 * since the close chain hasn't run yet at exit time.
 *
 * Opens the file via LibOS VFS, calls fs_ops->flush to trigger
 * pf_flush → ipf_internal_flush → ipf_update_metadata_node,
 * then releases the handle. */
int crisp_flush_pf_by_path(const char* path) {
 g_in_crisp_io = true;

 struct libos_handle* hdl = get_new_handle;
 if (!hdl) {
 g_in_crisp_io = false;
 return -1;
 }

 int ret = open_namei(hdl, /*start=*/NULL, path,
 O_RDONLY, /*mode=*/0, /*found=*/NULL);
 if (ret < 0) {
 put_handle(hdl);
 g_in_crisp_io = false;
 return -1;
 }

 /* Trigger PF flush to update metadata MAC */
 if (hdl->fs && hdl->fs->fs_ops && hdl->fs->fs_ops->flush) {
 ret = hdl->fs->fs_ops->flush(hdl);
 }

 put_handle(hdl);
 g_in_crisp_io = false;
 return ret;
}
```

---

# 5. PHASE 2: NETWORK GATE EXTENSION (Go) — THESIS CONTRIBUTION

After CRISP is fully mirrored (Phase 1), we add a network-level gate as our thesis extension.

The CRISP paper's Checker API is already implemented in Phase 1 (TCP server inside the runtime). Here we add a **gRPC interceptor** that calls that Checker API before sending responses — ensuring no response leaves until the MC has committed.

## 5.1 gRPC Interceptor (Calls Checker API via TCP)

```go
// internal/interceptor/gate.go

package interceptor

import (
 "context"
 "encoding/binary"
 "net"
 "time"

 "google.golang.org/grpc"
 "google.golang.org/grpc/codes"
 "google.golang.org/grpc/status"
)

type GateOptions struct {
 CheckerAPIAddr string // "localhost:7777"
 Timeout time.Duration
 SkipMethods []string
}

// callCheckerAPI connects to the CRISP Checker API TCP server
// and blocks until S >= L (exactly like Paper Listing 1)
func callCheckerAPI(addr string, timeout time.Duration) (uint64, error) {
 conn, err := net.DialTimeout("tcp", addr, timeout)
 if err != nil {
 return 0, err
 }
 defer conn.Close

 // Write triggers the check (server reads L, polls S)
 conn.Write([]byte{1}) // Any byte triggers the check

 // Read blocks until S >= L, returns MC value
 var mc uint64
 err = binary.Read(conn, binary.LittleEndian, &mc)
 return mc, err
}

// UnaryServerInterceptor gates gRPC responses until MC commits
func UnaryServerInterceptor(opts GateOptions) grpc.UnaryServerInterceptor {
 skipMap := make(map[string]bool)
 for _, m := range opts.SkipMethods {
 skipMap[m] = true
 }

 return func(
 ctx context.Context,
 req interface{},
 info *grpc.UnaryServerInfo,
 handler grpc.UnaryHandler,
 ) (interface{}, error) {

 if skipMap[info.FullMethod] {
 return handler(ctx, req)
 }

 // Execute the handler (may trigger fsyncs → L increments)
 resp, err := handler(ctx, req)
 if err != nil {
 return nil, err
 }

 // GATE: Call Checker API — blocks until S >= L
 // This is the thesis contribution: network-level gating
 _, checkErr := callCheckerAPI(opts.CheckerAPIAddr, opts.Timeout)
 if checkErr != nil {
 return nil, status.Error(codes.Unavailable,
 "CRISP check failed: "+checkErr.Error)
 }

 return resp, nil
 }
}
```

## 5.2 Sample gRPC Service (Test Application)

```go
// cmd/server/main.go

package main

import (
 "log"
 "net"

 "google.golang.org/grpc"
 "crisp-gramine/internal/interceptor"
 pb "crisp-gramine/api/proto"
)

func main {
 gate := interceptor.GateOptions{
 CheckerAPIAddr: "localhost:7777",
 Timeout: 5 * time.Second,
 }

 server := grpc.NewServer(
 grpc.UnaryInterceptor(interceptor.UnaryServerInterceptor(gate)),
 )

 // Register your service...
 pb.RegisterKVServiceServer(server, &kvServer{})

 lis, _ := net.Listen("tcp", ":50051")
 log.Fatal(server.Serve(lis))
}
```

---

# 6. IMPLEMENTATION TIMELINE

## Phase 1: CRISP Core in Gramine LibOS (Weeks 1-4)
**Goal: 1:1 mirror of CRISP paper in Gramine**

```
Week 1: Setup + Vault + Simulated MC
□ Clone Gramine, build from source
□ Implement crisp_vault.c (tag + L storage)
□ Implement crisp_mc.c (simulated with configurable latency)
□ Unit tests for vault and MC

Week 2: mc-thread + L/S Logic
□ Implement crisp_mcthread.c (background pthread)
□ Implement crisp_on_fsync (optimistic batching, L++)
□ Implement crisp_on_close/exit (synchronous blocking)
□ Implement crisp_wait_until_stable
□ Unit tests for L/S counters and batching

Week 3: Checker API + Probabilistic Checking
□ Implement crisp_checker_api.c (TCP server)
□ Implement probabilistic checking in fsync hook
□ Implement rate limit + queue timeout
□ Integration test: Checker API via TCP

Week 4: Gramine Integration + Startup Verification
□ Hook into Gramine's fsync/close/exit handlers
□ Implement crisp_init.c (startup verification)
□ Test rollback detection
□ Build and test with gramine-direct
```

## Phase 2: Network Gate (Weeks 5-6)
**Goal: Implement thesis extension (network-level gating)**

```
Week 5: gRPC Service + Interceptor
□ Create sample gRPC key-value service (Go)
□ Implement UnaryServerInterceptor (calls Checker API TCP)
□ Integration test: request → fsync → gate → response

Week 6: Full Integration
□ Run Go gRPC service inside Gramine
□ End-to-end test with Protected Files
□ Verify vulnerability window = 0
```

## Phase 3: Evaluation (Weeks 7-9)
**Goal: Reproduce CRISP paper evaluations + thesis-specific metrics**

```
Week 7-8: Benchmarks
□ 4 configurations (Native, SGX, SGX+PF, SGX+PF+Gate)
□ Throughput, latency, vulnerability window
□ Sensitivity analysis (vary MC latency: 5, 10, 20, 50ms)

Week 9: Analysis + Writing
□ Compare results to CRISP paper
□ Document thesis evaluation chapter
```

---

# 7. FILE STRUCTURE

```
VM/
├── WSL-gramine/ # Cloned + modified Gramine
│ ├── libos/src/crisp/ # OUR CRISP IMPLEMENTATION (C)
│ │ ├── crisp.h # Internal header (structs, Gramine includes)
│ │ ├── crisp_init.c # Initialization + startup verification
│ │ ├── crisp_fsync.c # fsync/close/exit hooks + wait logic
│ │ ├── crisp_vault.c # Vault file (tag + L)
│ │ ├── crisp_mc.c # Simulated monotonic counter
│ │ ├── crisp_mcthread.c # Background mc-thread (L++, vault, MC)
│ │ ├── crisp_checker_api.c # TCP server for Checker API
│ │ ├── crisp_tag.c # PF tag extraction (Section 4.10)
│ │ └── crisp_config.c # Configuration parameters
│ │
│ ├── libos/src/sys/libos_open.c # MODIFIED: fsync/fdatasync/close hooks
│ ├── libos/src/sys/libos_exit.c # MODIFIED: exit/exit_group hooks
│ └── libos/src/meson.build # MODIFIED: add crisp/*.c sources
│
├── checker-gated-shield/ # THESIS EXTENSION (Go)
│ ├── cmd/
│ │ ├── server/main.go # gRPC server with network gate
│ │ └── client/main.go # Test client
│ ├── internal/
│ │ └── interceptor/gate.go # gRPC interceptor → Checker API TCP
│ ├── api/proto/service.proto # gRPC service definition
│ ├── gramine/
│ │ ├── manifest.template # Gramine config for Go binary
│ │ └── Makefile
│ ├── test/
│ │ ├── integration/
│ │ └── benchmark/
│ ├── go.mod
│ └── Makefile
```

---

# 8. TESTING PROCEDURES

## 8.0 Mandatory Debugging Protocol (All Phases)

Testing is not only "expected output matches." For CRISP, each session must use a layered debugging stack and produce evidence for edge cases.

### 8.0.1 Required Tool Stack

| Layer | Tooling | Why required | Typical edge cases |
|---|---|---|---|
| Orchestration | Bash scripts (`bash`, `timeout`, loop runner) | Deterministic and stress scenario execution | flaky race, queue timeout, restart drift |
| Invariant assertions | Python scripts | Parse logs and assert security invariants (`S <= L`, gating correctness, fail-stop reason) | silent logic regression |
| Memory/UB checks | ASAN + UBSAN debug build | Detect memory corruption and UB under stress | UAF/OOB/undefined behavior |
| Crash/hang triage | gdb + core dumps | Root-cause deadlock/crash and validate hook/wait order | lock inversion, stuck waits |
| Syscall/timing visibility | strace/perf (or equivalent system tracing) | Validate blocking path and latency claims | wrong syscall path, unexpected blocking |

### 8.0.2 Minimum Execution Flow Per Session

1. Run targeted functional scenarios using Bash harness
2. Run stress loop (`N >= 100`) for touched code paths
3. Run Python invariant checker on generated logs
4. Run sanitizer build for touched code paths
5. Run at least one relevant fault-injection scenario
6. If crash/hang happens, collect gdb evidence before declaring fixed
7. Collect syscall/timing trace for sessions touching sync/wait/network paths

### 8.0.3 Mandatory Debugging Checklist

- [ ] Bash scenario run completed with captured exit codes
- [ ] Bash stress loop completed and summarized (pass/fail count)
- [ ] Python invariant checker report stored
- [ ] ASAN/UBSAN run completed (clean or issues documented)
- [ ] Fault injection executed (delay/crash/rollback/timeout as relevant)
- [ ] gdb backtrace (`thread apply all bt`) captured for any crash/hang
- [ ] Syscall/timing trace captured for critical path changes

## 8.1 Phase 1 Tests (C — CRISP Core)

### Vault Tests
```
test_vault_create_new — Create vault, verify on disk
test_vault_load_existing — Save then load, verify contents
test_vault_corrupted — Modify bytes, verify detection
test_vault_stores_L — Verify vault.local_mc == L after fsync
```

### MC Tests
```
test_mc_initial_value — New MC starts at 0
test_mc_increment — Increment, verify value
test_mc_persistence — Increment, reload, verify persisted
test_mc_latency — Verify simulated delay matches config
```

### L/S Counter Tests
```
test_ls_initial — L=0, S=0 at start
test_ls_fsync_increments_L — After fsync, L > S
test_ls_mcthread_catches_up — After mc-thread processes, S == L
test_ls_multiple_batches — Multiple fsyncs batched, single MC increment
test_ls_close_blocks — close blocks until S >= L
```

### Startup Verification
```
test_startup_normal — vault.L == MC.S → OK
test_startup_rollback — MC.S > vault.L → HALT (rollback)
test_startup_crash — MC.S < vault.L → HALT (unrecoverable crash)
test_startup_fresh — No vault file → Initialize L=0, S=0
```

### Checker API Tests
```
test_checker_api_immediate — S >= L → returns immediately
test_checker_api_waits — S < L → blocks until mc-thread commits
test_checker_api_returns_mc — Returns correct MC value
test_checker_api_sequential_stress — Repeated client requests under sequential accept loop
test_checker_api_concurrent — Optional: only for future thread-per-request mode
```

## 8.2 Phase 2 Tests (Go — Network Gate)

### Interceptor Tests
```
test_gate_blocks_response — Response delayed until Checker API returns
test_gate_vulnerability_window — With gate: window = 0
test_gate_without_gate — Without gate: window > 0
test_gate_skip_methods — Health check bypasses gate
```

### End-to-End
```
1. Start Gramine with CRISP-enabled LibOS
2. Start gRPC service with network gate
3. Client: Put(key, value)
4. Verify: response only after MC commit (window = 0)
5. Kill server, restore old vault → restart → rollback detected
```

### Phase 2 Debugging Checklist
```
□ Gate interceptor tested under concurrent requests (load + partial failures)
□ Checker API timeout/failure propagation verified (no fail-open response path)
□ Retry/fallback behavior validated against stale-state externalization risk
□ p50/p99 latency impact measured with and without gate
□ At least one gdb/core or trace-based triage performed for induced failure
```

---

# 9. METRICS & EVALUATION

## 9.1 Configurations (mirrors Paper Section V)

| Config | SGX | Protected Files | CRISP (MC) | Network Gate | Description |
|---|---|---|---|---|---|
| A | No | No | No | No | Native baseline |
| B | Yes | No | No | No | SGX overhead only |
| C | Yes | Yes | Yes | No | CRISP without gate |
| D | Yes | Yes | Yes | Yes | Full solution (thesis) |

## 9.2 Metrics

| Metric | Description | Target |
|---|---|---|
| Throughput | Requests/sec | D >= 80% of C |
| Latency p50/p99 | Median/tail latency | Characterize |
| Vulnerability Window | Time between response and MC commit | **C > 0, D = 0** |
| Gating Frequency | % of requests that actually block | Characterize |
| MC Rate | Increments/sec | Shows batching efficiency |
| Batch Size | Avg fsyncs per MC increment | Compare to paper Table II |

## 9.3 Sensitivity Analysis

Vary MC latency: 5ms, 10ms, 20ms, 50ms
- Show: window = 0 for Config D regardless of MC speed
- Show tradeoff: faster MC = lower overhead

Vary checker probability (for Config C): 0%, 1%, 10%, 20%
- Compare batch sizes to Paper Table II
- Show vulnerability window reduction

---

# 10. REFERENCES

## Papers
1. **CRISP (2024)** — Hartono, Brito, Fetzer — IEEE CLOUD 2024
 https://arxiv.org/html/2408.06822v1
2. **ROTE (2017)** — Matetic et al. — USENIX Security
3. **Gramine (2024)** — ACM CCS

## Documentation
1. Gramine Docs — https://gramine.readthedocs.io/
2. Gramine Protected Files — https://gramine.readthedocs.io/en/stable/manifest-syntax.html#protected-files
3. Gramine Source — https://github.com/gramineproject/gramine
4. gRPC Go — https://grpc.io/docs/languages/go/

## Code
1. Gramine Examples — https://github.com/gramineproject/examples
2. Gramine LibOS syscall handlers — `gramine/libos/src/sys/`

---