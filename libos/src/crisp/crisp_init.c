/* SPDX-License-Identifier: LGPL-3.0-or-later */
// Init + fail-stop. Owns the g_crisp singleton.

#include "libos_internal.h"
#include "crisp.h"

crisp_state_t g_crisp = {0};

noreturn void crisp_fail_stop(const char* reason) {
    __atomic_store_n(&g_crisp.halted, true, __ATOMIC_RELEASE);
    log_error("CRISP FAIL-STOP: %s", reason);
    crisp_wake_all_waiters();
    PalProcessExit(1);
    __builtin_unreachable();
}

// TODO Session 9: load vault, verify MC vs L, spawn mc-thread + checker.
int crisp_init(const char* vault_path, const char* mc_path) {
    log_always("crisp_init(vault=%s, mc=%s)", vault_path, mc_path);
    return 0;
}
