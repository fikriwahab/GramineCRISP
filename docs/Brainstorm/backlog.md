# CRISP-Gramine Phase 1 — Implementation Guide

> **Spec:** `CRISP_GRAMINE_IMPLEMENTATION_SPEC.md` v3.10
> **Paper:** https://arxiv.org/html/2408.06822v1 (IEEE CLOUD 2024)
> **Gramine source:** `VM/WSL-gramine/` (Gramine v1.9)
> **Build location:** `~/gramine/` (Linux native filesystem — do NOT build on /mnt/c/)

---

## Overview

13 implementation sessions, executed in order. Each session produces one CRISP component inside Gramine's LibOS.

### Session Map

| # | Component | File | Depends on |
|---|-----------|------|------------|
| 1 | Header + skeleton | `crisp.h` + stubs | — |
| 2 | Simulated monotonic counter | `crisp_mc.c` | 1 |
| 3 | Vault file I/O | `crisp_vault.c` | 1 |
| 4 | Tag computation (global digest) | `crisp_tag.c` | 1 |
| 5 | Fail-stop handler | `crisp_init.c` (partial) | 1 |
| 6 | fsync hook + queue + drain | `crisp_fsync.c` | 1, 4, 5 |
| 7 | mc-thread batch processor | `crisp_mcthread.c` | 1–5 |
| 8 | Close/exit hooks | `crisp_close.c` | 1, 4–6 |
| 9 | Init + startup verification | `crisp_init.c` (complete) | 1–5, 7 |
| 10 | Checker API TCP server | `crisp_checker_api.c` | 1, 5, 6 |
| 11 | Syscall hook integration | 3 existing Gramine files | 6, 8, 9 |
| 12 | Build integration | `meson.build` | 1–11 |
| 13 | End-to-end testing | test app + manifest | All |

### Critical Path

```
1 → 5 → 6 → 7 → 9 → 11 → 12 → 13
```

---

## Key Concepts from CRISP Paper

| Concept | Summary |
|---------|---------|
| L (promised MC) | Counter in vault, incremented per batch by mc-thread |
| S (actual MC) | Counter from MC hardware, incremented after vault write |
| Optimistic batching | fsync returns immediately, mc-thread batches commits |
| Synchronous close/exit | Block until S >= L before returning |
| Checker API | TCP server: drain queue, wait S >= L, return S |
| Startup verification | Load vault, compare tag + L vs current PF state + MC |
| Fail-stop | Unrecoverable error → halt process, never continue silently |

### Five Invariants

| # | Invariant | Enforced by |
|---|-----------|-------------|
| 1 | Tag reflects ALL PF state at commit time | mc-thread (global digest) |
| 2 | L++ before MC increment, new_mc == L after | mc-thread |
| 3 | Externalize only when S >= L | Checker API, close, exit |
| 4 | Startup: tag + MC vs current PF state | crisp_init |
| 5 | MC value only increases | crisp_mc.c |

---

## Gramine Primitives (NOT pthread)

CRISP is **default-OFF**. Enabled via manifest: `sgx.crisp.enable = true`.

| Need | Gramine API | Header |
|------|-------------|--------|
| Mutex | `struct libos_lock` / `create_lock` / `lock` / `unlock` | `libos_lock.h` |
| Spinlock | `spinlock_t` / `spinlock_init` / `spinlock_lock` / `spinlock_unlock` | `spinlock.h` |
| Thread sleep/wake | `thread_prepare_wait` / `thread_wait` / `thread_wakeup` | `libos_thread.h` |
| PAL event | `PalEventCreate` / `PalEventWait` / `PalEventSet` | `pal.h` |
| SHA-256 | `lib_SHA256Init` / `lib_SHA256Update` / `lib_SHA256Final` | `crypto.h` |
| File open (VFS) | `get_new_handle()` + `open_namei(hdl, start, path, flags, mode, found)` | `libos_fs.h` |
| File read/write | `do_handle_read` / `do_handle_write` | `libos_handle.h` |
| File close | `put_handle(hdl)` | `libos_handle.h` |
| Process exit | `PalProcessExit(exit_code)` | `pal.h` |
| Internal thread | `get_new_internal_thread()` + `PalThreadCreate(wrapper, arg, &handle)` | `libos_thread.h`, `pal.h` |

**Important constraints:**
- `thread_prepare_wait()` / `thread_wait()` have `assert(!is_internal)` — internal threads (mc-thread, checker) must use `PalEventWait` instead
- Internal thread wrapper must call `libos_tcb_init()` + `set_cur_thread()` before any LibOS API
- `g_in_crisp_io` is a plain global bool (NOT `__thread` — Gramine's `-nostdlib` linker has no `__tls_get_addr`)

---

## File Structure

```
VM/WSL-gramine/libos/
├── include/
│   └── libos_crisp.h              # Public header (prototypes for syscall hooks)
└── src/
    ├── crisp/
    │   ├── crisp.h                # Internal header (structs, all prototypes)
    │   ├── crisp_init.c           # Init + startup verification + fail-stop
    │   ├── crisp_fsync.c          # fsync hook + drain_and_wait
    │   ├── crisp_close.c          # close/exit hooks
    │   ├── crisp_vault.c          # Vault I/O via LibOS VFS
    │   ├── crisp_mc.c             # Simulated MC via PAL I/O
    │   ├── crisp_mcthread.c       # mc-thread batch processor
    │   ├── crisp_tag.c            # Global digest + PF MAC extraction
    │   ├── crisp_checker_api.c    # Checker API TCP server
    │   └── crisp_config.c         # Configuration parameters
    ├── sys/libos_open.c           # MODIFIED: +fsync/close hooks (~15 lines)
    ├── sys/libos_exit.c           # MODIFIED: +exit hook (~3 lines)
    ├── libos_init.c               # MODIFIED: +crisp_init() call (~2 lines)
    └── meson.build                # MODIFIED: +crisp sources (~10 lines)
```

---

## Session 1: Header + Skeleton

**What:** Create `crisp.h` with all structs, constants, and function prototypes. Create empty `.c` stubs.

**Key items:**
- `crisp_state_t` struct with all fields (enabled, L, locks, halted, queue, waiters, config)
- `crisp_vault_t` struct (magic[4] + tag[32] + local_mc + checksum[32])
- `extern bool g_in_crisp_io` — recursion guard (plain global)
- `noreturn void crisp_fail_stop(const char* reason)`
- Lock ordering: `queue_mu → mu → waiter_lock → mc_mu`
- `halted` accessed via `__atomic_store_n` / `__atomic_load_n`

---

## Session 2: Simulated Monotonic Counter (`crisp_mc.c`)

**What:** MC file via PAL I/O. Read, increment with write-to-tmp + rename.

**Key items:**
- `crisp_mc_init()` — read or create MC file. Only `PAL_ERROR_STREAMNOTEXIST` = new; other errors → fail-stop
- `crisp_mc_read()` — return value under lock
- `crisp_mc_increment()` — simulate latency, increment, atomic write, check all PAL return values
- MC is NOT encrypted (simulates trusted external hardware) — uses PAL I/O, not LibOS VFS
- The simulated MC is a development placeholder; real deployment needs RPMB/TPM2

---

## Session 3: Vault File (`crisp_vault.c`)

**What:** Vault stores tag + L as a Protected File. Uses LibOS VFS (NOT PAL I/O).

**Key items:**
- `g_in_crisp_io = false` defined here
- `crisp_vault_load()` — open via `open_namei`, verify magic + SHA-256 checksum. Returns: 0=OK, -2=ENOENT, -1=error
- `crisp_vault_save()` — set guard → write tmp → flush PF → rename under `g_dcache_lock` (inline `d_ops->rename`) → clear guard
- Vault MUST go through PF encryption layer — PAL I/O bypasses encryption entirely
- `g_in_crisp_io` must be reset on ALL error paths (goto cleanup)
- Rename: can't use `libos_syscall_renameat` (rejects LibOS memory) or `do_rename()` (static). Inline `d_ops->rename` under `g_dcache_lock`

---

## Session 4: Tag Computation (`crisp_tag.c`)

**What:** Extract per-file PF MACs, compute global SHA-256 digest.

**Key items:**
- Add `pf_get_metadata_mac()` to Gramine PF code (~6 lines)
- `crisp_extract_pf_mac(path, mac_out)` — open PF, get MAC under `hdl->inode->lock`
- `crisp_compute_global_tag(tag_out)` — iterate `pf_paths[]` (pre-sorted), SHA-256 of concatenated MACs
- `crisp_flush_pf_by_path(path)` — for exit hook, ensure MACs are fresh
- `metadata_node` is EMBEDDED in `pf_context` (not a pointer)

---

## Session 5: Fail-Stop (`crisp_fail_stop`)

**What:** Central failure handler — terminate on any invariant violation.

**Key items:**
- Set `halted` atomically (`__ATOMIC_RELEASE`)
- Log reason, wake all waiters
- `PalProcessExit(1)` + `__builtin_unreachable()`
- One-way transition: `halted` only goes false → true
- Define `crisp_state_t g_crisp` here

---

## Session 6: fsync Hook + Queue (`crisp_fsync.c`)

**What:** Enqueue fsync requests, drain queue when needed.

**`crisp_on_fsync()`:**
1. Skip if `g_in_crisp_io` or `halted`
2. Increment `pending_count`, wake mc-thread
3. Probabilistic check: maybe call `drain_and_wait()`
4. Return 0 (optimistic)

**`crisp_drain_and_wait()` — app threads:**
- Pattern: `prepare_wait → COMPILER_BARRIER → check → wait`
- Condition: `queue_empty && !batch_in_flight && S >= L`
- Register in waiters[] with `get_thread()` refcount
- Overflow (>64): poll with 5ms timeout

**`crisp_drain_and_wait()` — internal threads:**
- `PalEventWait` polling loop (can't use `thread_wait`)

---

## Session 7: mc-thread Batch Processor (`crisp_mcthread.c`)

**What:** Background thread that batches fsyncs.

**Thread wrapper:** `libos_tcb_init()` → `set_cur_thread()` → `log_setprefix()` → main loop

**Main loop:**
1. Wait for work (`PalEventWait`)
2. Set `batch_in_flight = true`, take pending count
3. Check queue timeout → fail-stop if exceeded
4. Compute global tag
5. L++, save vault
6. Rate limit, increment MC
7. Verify `new_mc == L` → fail-stop if not
8. Clear `batch_in_flight`, wake waiters

**Critical ordering:** tag → L++ → vault → MC → verify

---

## Session 8: Close/Exit Hooks (`crisp_close.c`)

**What:** Synchronous blocking on close() and exit().

**`crisp_on_close()`:** Skip if guard → enqueue → drain (block until committed)

**`crisp_on_exit()`:** Flush ALL PFs → enqueue → drain → fail-stop on any error

**Important:** Close hook runs AFTER `put_handle()` (MAC must be fresh). Exit must flush explicitly.

---

## Session 9: Init + Startup Verification (`crisp_init.c`)

**What:** Initialize CRISP, verify no rollback.

**Flow:**
1. Zero state, create locks
2. Init MC
3. Load vault:
   - **ENOENT + MC > 0** → fail-stop (rollback attack)
   - **ENOENT + MC == 0** → fresh install
   - **OK** → compare MC vs L, verify tag
4. Create events + threads
5. Set `enabled = true` only at the end (fail-closed init)

---

## Session 10: Checker API (`crisp_checker_api.c`)

**What:** TCP server for external network gate queries.

**Deviation:** Single listener instead of thread-per-request. Document in thesis.

**Per connection:** Accept → drain queue → read MC → send S → close client

Uses PAL socket APIs. Port in network byte order (`__builtin_bswap16`).

---

## Session 11: Syscall Hook Integration

Minimal changes to 3 existing files:

- **`libos_open.c` fsync:** Hook after `fs_ops->flush()`, gated on `g_crisp.enabled` + `TYPE_CHROOT_ENCRYPTED`
- **`libos_open.c` close:** Save `handle->type` BEFORE `put_handle()`, hook AFTER
- **`libos_exit.c`:** Hook before `thread_exit()` / `process_exit()`
- **`libos_init.c`:** Manifest-gated, fail-closed `crisp_init()` call

---

## Session 12: Build Integration

Add 9 CRISP `.c` files to `meson.build`. Build must succeed: `ninja -C build` exits 0.

---

## Session 13: End-to-End Testing

| # | Scenario | Expected |
|---|----------|----------|
| 1 | Happy path: write → fsync → close → restart | Startup passes |
| 2 | Tamper PF file between runs | FAIL-STOP: TAG MISMATCH |
| 3 | Delete vault, MC > 0 | FAIL-STOP: vault missing but MC > 0 |
| 4 | Replace vault with older copy | FAIL-STOP: MC > vault L |
| 5 | Connect to Checker API | Receive MC value after drain |
| 6 | Concurrent fsyncs | All committed, no hang |
| 7 | Delay MC beyond timeout | FAIL-STOP: queue timeout |
| 8 | CRISP disabled | Normal operation, zero overhead |
| 9 | Non-PF fsync/close with CRISP on | No hooks fire |

**Thesis proof:** Same tamper scenarios, CRISP off vs on. Off = accepted silently. On = detected + halted. This shows: Gramine has confidentiality + integrity. CRISP adds **freshness**.

---

## Common Pitfalls

1. Don't increment L in fsync — only mc-thread does L++
2. Don't write vault in fsync — only mc-thread writes vault
3. Don't use PAL I/O for vault — bypasses encryption
4. Don't use pthread — Gramine has its own primitives
5. Don't use stdio — LibOS provides libc, doesn't use it
6. Don't use `thread_wait` in internal threads — asserts `!is_internal`
7. Don't use `thread_exit` in internal threads — use `PalThreadExit`
8. Don't use check→prepare→wait — use prepare→barrier→check→wait
9. Don't hash only last tag — must hash ALL PF MACs
10. Don't continue after halt — must call `PalProcessExit(1)`
11. Don't ignore vault errors — only ENOENT = fresh install
12. Don't forget `g_in_crisp_io` cleanup on error paths
13. Don't call close hook before `put_handle` — must be AFTER

---

## Dependency Graph

```
Session 1 (crisp.h)
├── Session 2 (crisp_mc.c)
├── Session 3 (crisp_vault.c)
├── Session 4 (crisp_tag.c)
├── Session 5 (crisp_fail_stop)
│   ├── Session 6 (crisp_fsync.c)
│   │   ├── Session 8 (crisp_close.c)
│   │   └── Session 10 (crisp_checker_api.c)
│   └── Session 7 (crisp_mcthread.c)
│       └── Session 9 (crisp_init.c)
│           └── Session 11 (syscall hooks)
│               └── Session 12 (meson.build)
│                   └── Session 13 (E2E test)
```