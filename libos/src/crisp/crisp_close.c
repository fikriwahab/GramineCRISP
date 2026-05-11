/* SPDX-License-Identifier: LGPL-3.0-or-later */
// Synchronous close + exit hooks, block until committed

#include <errno.h>

#include "api.h"
#include "libos_internal.h"

#include "crisp.h"

// Close hook: enqueue the post-close-flush state, then block until committed
// Called from libos_syscall_close AFTER put_handle (PF flush + MAC update done)
int crisp_on_close(void) {
    if (g_in_crisp_io)
        return 0;

    if (!g_crisp.enabled)
        return 0;

    if (__atomic_load_n(&g_crisp.halted, __ATOMIC_ACQUIRE))
        return -ENOTRECOVERABLE;

    int ret = crisp_on_fsync();
    if (ret < 0)
        return ret;

    ret = crisp_drain_and_wait();
    if (ret < 0) {
        char msg[128];
        snprintf(msg, sizeof(msg), "crisp_on_close: drain_and_wait failed: %d", ret);
        crisp_fail_stop(msg);
    }
    return 0;
}

// Exit hook: force-flush all tracked PFs (MAC fresh), enqueue, block until committed
// Called before process exit cleanup; the close chain has not run yet
void crisp_on_exit(void) {
    if (g_in_crisp_io)
        return;

    if (!g_crisp.enabled)
        return;

    if (__atomic_load_n(&g_crisp.halted, __ATOMIC_ACQUIRE))
        return;

    for (int i = 0; i < g_crisp.pf_count; i++) {
        if (crisp_flush_pf_by_path(g_crisp.pf_paths[i]) < 0) {
            char msg[256];
            snprintf(msg, sizeof(msg), "crisp_on_exit: flush failed for %s",
                     g_crisp.pf_paths[i]);
            crisp_fail_stop(msg);
        }
    }

    int ret = crisp_on_fsync();
    if (ret < 0)
        crisp_fail_stop("crisp_on_exit: enqueue failed");

    ret = crisp_drain_and_wait();
    if (ret < 0) {
        char msg[128];
        snprintf(msg, sizeof(msg), "crisp_on_exit: drain_and_wait failed: %d", ret);
        crisp_fail_stop(msg);
    }
}
