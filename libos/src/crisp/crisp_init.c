/* SPDX-License-Identifier: LGPL-3.0-or-later */
// Init + fail-stop. Owns the g_crisp singleton.

#include "libos_internal.h"
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

// Allocate sync primitives needed by fsync hook + drain barrier.
// Idempotent: safe to call multiple times during init/test.
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

// TODO startup verify: load vault, verify MC vs L, spawn mc-thread + checker.
int crisp_init(const char* vault_path, const char* mc_path) {
    log_always("crisp_init(vault=%s, mc=%s)", vault_path, mc_path);
    return crisp_init_sync();
}
