/* SPDX-License-Identifier: LGPL-3.0-or-later */

// Lock ordering:
//   tag_lock                       taken alone; outermost vs g_dcache_lock and inode->lock
//                                  (serializes a PF flush against the global-tag computation)
//   queue_mu -> mu -> waiter_lock  queue/state path
//   mc_mu                          file-scope in crisp_mc.c; taken alone

#ifndef _CRISP_H_
#define _CRISP_H_

#include <stdbool.h>
#include <stdint.h>
#include <stdnoreturn.h>

#include "libos_lock.h"
#include "libos_thread.h"
#include "spinlock.h"
#include "pal.h"
#include "libos_fs_encrypted.h"

struct libos_handle;

#define CRISP_VAULT_MAGIC "CRSP"
#define CRISP_TAG_SIZE    32
#define CRISP_QUEUE_CAP   64
#define CRISP_MAX_WAITERS 64

// Profiling slots for sgx.crisp.profile instrumentation, off by default
enum {
    CRISP_PROF_COMPUTE_TAG = 0,
    CRISP_PROF_VAULT_SAVE,
    CRISP_PROF_MC_INCREMENT,
    CRISP_PROF_COMMIT_NOW,
    CRISP_PROF_BATCH_LATENCY,
    CRISP_PROF_FSYNC_HOOK,
    CRISP_PROF_CLOSE_HOOK,
    CRISP_PROF_EXIT_HOOK,
    CRISP_PROF_GATE_HOOK,
    CRISP_PROF_NUM_SLOTS,
};

// Network egress gating policy values for sgx.crisp.gate_policy
enum {
    CRISP_GATE_NONE = 0,   // default, gating disabled, passthrough
    CRISP_GATE_BLOCK,      // block sendto until commit done (S >= L, queue empty)
    CRISP_GATE_WARN,       // log warning on pending state, allow send (audit mode)
    CRISP_GATE_DROP,       // return -ECONNREFUSED if pending state (paranoid mode)
};

// On-disk vault format. Stored as a Protected File.
typedef struct {
    char     magic[4];                  // "CRSP"
    uint8_t  tag[CRISP_TAG_SIZE];       // SHA-256 over sorted PF metadata MACs
    uint64_t local_mc;                  // L: promised MC value
    uint8_t  checksum[32];              // SHA-256(magic || tag || L)
} crisp_vault_t;

typedef struct {
    bool enabled;                       // set true at the end of crisp_init (fail-closed); default false (BSS)
    bool manifest_enabled;              // sgx.crisp.enabled = true in the manifest
    uint64_t L;                         // promised MC; S read on demand from MC

    struct libos_lock mu;               // protects L, halted
    bool halted;                        // accessed atomically (ACQUIRE/RELEASE)

    // serializes PF flushes (the fsync, close, and exit hooks) against the global-tag
    // computation so the tag is a consistent point-in-time snapshot
    struct libos_lock tag_lock;

    // mc-thread is internal (tid==0); cannot use thread_wait, uses PalEventWait.
    struct libos_thread* mc_thread_handle;
    bool mc_thread_running;

    // Checker API TCP server thread (internal).
    struct libos_thread* checker_thread_handle;
    PAL_HANDLE checker_listener;        // bound and listening before the thread spawns; fail-stop on bind error

    // Two separate events to avoid signal-stealing between mc-thread and checker.
    PAL_HANDLE mc_wakeup_event;         // set by fsync hooks
    PAL_HANDLE checker_poll_event;      // set by wake_all_waiters
    PAL_HANDLE mc_sleep_event;          // never signaled, used only for the MC latency sleep

    // Queue is just a counter; the global tag is computed across all PFs.
    int                pending_count;
    struct libos_lock  queue_mu;
    bool               queue_has_work;
    bool               batch_in_flight; // true while mc-thread is committing
    uint64_t           oldest_enqueue_us;
    uint64_t           last_increment_us; // mc-thread only, for the optional rate limit

    // Manual waiter list (no condvar in Gramine).
    struct libos_thread* waiters[CRISP_MAX_WAITERS];
    int                  waiter_count;
    spinlock_t           waiter_lock;

    // Tracked PFs, pre-sorted at init for deterministic tag.
    char** pf_paths;
    int    pf_count;

    // Loaded from manifest.
    char     vault_path[256];
    char     mc_path[256];
    uint64_t mc_latency_ms;
    uint64_t rate_limit_ms;
    uint64_t queue_timeout_ms;
    int      checker_prob;
    int      checker_api_port;
    int      mode;  // sgx.crisp.mode value, 0 optimistic, 1 synchronous default, 2 explicit checker

    // Network egress gating, default off so existing apps unaffected
    bool     network_gate;          // sgx.crisp.network_gate, master switch
    int      gate_policy;           // CRISP_GATE_NONE/BLOCK/WARN/DROP
    uint64_t gate_timeout_ms;       // sgx.crisp.gate_timeout_ms, max block duration before fail-stop

    // Profiling, gated by sgx.crisp.profile manifest flag, default off so the macros expand to a single branch
    bool     profile_enabled;
    uint64_t profile_total_us[CRISP_PROF_NUM_SLOTS];
    uint64_t profile_count[CRISP_PROF_NUM_SLOTS];
} crisp_state_t;

extern crisp_state_t g_crisp;

// Profiling helpers, expand to a single runtime branch when profile is off
// Usage:
//   CRISP_PROF_BEGIN(COMPUTE_TAG);
//   ... code under measurement ...
//   CRISP_PROF_END(COMPUTE_TAG);
// Slot must be a bare identifier matching one of the CRISP_PROF_* enum values
#define CRISP_PROF_BEGIN(slot_name)                                                  \
    uint64_t __crisp_prof_t0_##slot_name = 0;                                        \
    if (g_crisp.profile_enabled)                                                     \
        PalSystemTimeQuery(&__crisp_prof_t0_##slot_name)

#define CRISP_PROF_END(slot_name)                                                    \
    do {                                                                             \
        if (g_crisp.profile_enabled) {                                               \
            uint64_t __crisp_prof_t1 = 0;                                            \
            PalSystemTimeQuery(&__crisp_prof_t1);                                    \
            uint64_t __crisp_prof_dt = __crisp_prof_t1 - __crisp_prof_t0_##slot_name;\
            __atomic_fetch_add(&g_crisp.profile_total_us[CRISP_PROF_##slot_name],    \
                               __crisp_prof_dt, __ATOMIC_RELAXED);                   \
            __atomic_fetch_add(&g_crisp.profile_count[CRISP_PROF_##slot_name],       \
                               1, __ATOMIC_RELAXED);                                 \
        }                                                                            \
    } while (0)

noreturn void crisp_fail_stop(const char* reason);

int  crisp_init(const char* vault_path, const char* mc_path);
int  crisp_init_sync(void);
int  crisp_spawn_mc_thread(void);
int  crisp_spawn_checker_thread(void);
int  crisp_checker_listen(void);
int  crisp_config_load(void);
int  crisp_on_fsync(void);
int  crisp_commit_now(void);  // inline commit cycle for synchronous mode and mc-thread
int  crisp_on_close(void);
int  crisp_close_handle(struct libos_handle* handle);
void crisp_on_exit(void);
int  crisp_drain_and_wait(void);
void crisp_wake_all_waiters(void);
int  crisp_compute_global_tag(uint8_t* tag_out);
int  crisp_vault_load(crisp_vault_t* out);
int  crisp_vault_save(const uint8_t* tag, uint64_t local_mc);
int  crisp_mc_init(void);
int  crisp_mc_read(uint64_t* value);
int  crisp_mc_increment(uint64_t* new_value);
int  crisp_flush_pf_by_path(const char* path);

int crisp_mc_thread_func(void* arg);
int crisp_checker_api_func(void* arg);
void crisp_profile_dump(void);

// Network egress gating, called from socket send syscalls
// Returns 0 if send may proceed, negative errno to fail the syscall
int crisp_gate_check(void);

#endif
