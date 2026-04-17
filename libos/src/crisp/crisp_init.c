/* SPDX-License-Identifier: LGPL-3.0-or-later */
// Init + fail-stop. Owns the g_crisp singleton.

#include "libos_internal.h"
#include "crisp.h"

crisp_state_t g_crisp = {0};

// TODO Session 5: implement halt + wake waiters before exit.
noreturn void crisp_fail_stop(const char* reason) {
    log_always("crisp_fail_stop: %s", reason);
    PalProcessExit(1);
    __builtin_unreachable();
}

// TODO Session 9: load vault, verify MC vs L, spawn mc-thread + checker.
int crisp_init(const char* vault_path, const char* mc_path) {
    log_always("crisp_init(vault=%s, mc=%s)", vault_path, mc_path);
    return 0;
}
