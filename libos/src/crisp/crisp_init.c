/* SPDX-License-Identifier: LGPL-3.0-or-later */
// Init + fail-stop + startup verify, owns the g_crisp singleton

#include <errno.h>
#include <string.h>

#include "api.h"
#include "libos_internal.h"
#include "libos_thread.h"
#include "pal.h"
#include "spinlock.h"

#include "crisp.h"

crisp_state_t g_crisp = {0};

noreturn void crisp_fail_stop(const char* reason) {
    __atomic_store_n(&g_crisp.halted, true, __ATOMIC_RELEASE);
    log_error("CRISP FAIL-STOP: %s", reason);
    crisp_wake_all_waiters();
    PalProcessExit(1);
    __builtin_unreachable();
}

// Allocate sync primitives needed by fsync hook + drain barrier
// Idempotent: safe to call multiple times during init/test
int crisp_init_sync(void) {
    if (!lock_created(&g_crisp.mu) && !create_lock(&g_crisp.mu))
        return -1;
    if (!lock_created(&g_crisp.queue_mu) && !create_lock(&g_crisp.queue_mu))
        return -1;

    spinlock_init(&g_crisp.waiter_lock);

    if (!g_crisp.mc_wakeup_event &&
        PalEventCreate(&g_crisp.mc_wakeup_event, /*init_signaled=*/false,
                       /*auto_clear=*/true) < 0)
        return -1;

    if (!g_crisp.checker_poll_event &&
        PalEventCreate(&g_crisp.checker_poll_event, /*init_signaled=*/false,
                       /*auto_clear=*/false) < 0)
        return -1;

    return 0;
}

// Spawn the background mc-thread (internal, tid==0), idempotent
int crisp_spawn_mc_thread(void) {
    if (g_crisp.mc_thread_handle)
        return 0;

    struct libos_thread* t = get_new_internal_thread();
    if (!t)
        return -ENOMEM;

    PAL_HANDLE handle = NULL;
    int ret = PalThreadCreate(crisp_mc_thread_func, t, &handle);
    if (ret < 0) {
        put_thread(t);
        return -1;
    }

    t->pal_handle = handle;
    g_crisp.mc_thread_handle = t;
    return 0;
}

// Spawn the checker API TCP server thread (internal), idempotent
// Checker logic itself is stubbed until the checker API session
int crisp_spawn_checker_thread(void) {
    if (g_crisp.checker_thread_handle)
        return 0;

    struct libos_thread* t = get_new_internal_thread();
    if (!t)
        return -ENOMEM;

    PAL_HANDLE handle = NULL;
    int ret = PalThreadCreate(crisp_checker_api_func, t, &handle);
    if (ret < 0) {
        put_thread(t);
        return -1;
    }

    t->pal_handle = handle;
    g_crisp.checker_thread_handle = t;
    return 0;
}

// Insertion sort g_crisp.pf_paths lexicographically for deterministic global tag
// pf_count is small; insertion sort is adequate and avoids needing qsort
static void sort_pf_paths(void) {
    for (int i = 1; i < g_crisp.pf_count; i++) {
        char* key = g_crisp.pf_paths[i];
        int j = i - 1;
        while (j >= 0 && strcmp(g_crisp.pf_paths[j], key) > 0) {
            g_crisp.pf_paths[j + 1] = g_crisp.pf_paths[j];
            j--;
        }
        g_crisp.pf_paths[j + 1] = key;
    }
}

// Startup initialization + rollback verification
// Caller must populate g_crisp.pf_paths / pf_count beforehand (crisp_config_load
// or directly). On rollback / corruption / crash-inconsistency -> fail-stop
int crisp_init(const char* vault_path, const char* mc_path) {
    log_always("crisp_init(vault=%s, mc=%s)", vault_path, mc_path);

    if (crisp_init_sync() < 0)
        return -1;

    snprintf(g_crisp.vault_path, sizeof(g_crisp.vault_path), "%s", vault_path);
    snprintf(g_crisp.mc_path, sizeof(g_crisp.mc_path), "%s", mc_path);

    sort_pf_paths();

    if (crisp_mc_init() != 0)
        return -1;

    uint64_t actual_mc = 0;
    if (crisp_mc_read(&actual_mc) != 0)
        return -1;

    crisp_vault_t vault;
    int vault_ret = crisp_vault_load(&vault);

    if (vault_ret == -2) {
        // No vault file = fresh install; MC must be 0, else vault-deletion attack
        if (actual_mc != 0)
            crisp_fail_stop("vault missing but MC > 0: rollback attack");
        lock(&g_crisp.mu);
        g_crisp.L = 0;
        unlock(&g_crisp.mu);
        log_always("crisp_init: fresh install (MC=0, no vault)");
    } else if (vault_ret != 0) {
        crisp_fail_stop("vault file corrupted or I/O error");
    } else {
        uint64_t stored_L = vault.local_mc;

        if (actual_mc > stored_L)
            crisp_fail_stop("ROLLBACK DETECTED: MC > vault L");
        if (actual_mc < stored_L)
            crisp_fail_stop("UNRECOVERABLE CRASH: MC < vault L");

        // actual_mc == stored_L -> normal startup
        lock(&g_crisp.mu);
        g_crisp.L = stored_L;
        unlock(&g_crisp.mu);

        // Tag verification: recompute from current PF state, compare to vault
        uint8_t current_tag[CRISP_TAG_SIZE];
        if (crisp_compute_global_tag(current_tag) != 0) {
            log_error("crisp_init: failed to compute global tag");
            return -1;
        }
        if (memcmp(vault.tag, current_tag, CRISP_TAG_SIZE) != 0)
            crisp_fail_stop("TAG MISMATCH: PF files rolled back independently");

        log_always("crisp_init: normal startup (L=%lu, tag verified)", stored_L);
    }

    if (crisp_spawn_mc_thread() < 0)
        return -1;

    if (g_crisp.checker_api_port > 0 && crisp_spawn_checker_thread() < 0)
        return -1;

    // Enable CRISP only after all init steps succeed (fail-closed)
    g_crisp.enabled = true;
    return 0;
}
