/* SPDX-License-Identifier: LGPL-3.0-or-later */
// Synchronous close + exit hooks (block until committed).

#include "libos_internal.h"
#include "crisp.h"

// TODO close hook: enqueue + drain.
int crisp_on_close(void) {
    if (!g_crisp.enabled) {
        return 0;
    }
    int ret = crisp_drain_and_wait();
    if (ret < 0) {
        char msg[128];
        snprintf(msg, sizeof(msg), "crisp_on_close: drain_and_wait failed: %d", ret);
        crisp_fail_stop(msg);
    }
    return 0;
}

// TODO exit hook: flush all tracked PFs, then enqueue + drain.
void crisp_on_exit(void) {
    if (!g_crisp.enabled) {
        return;
    }

    for (int i = 0; i < g_crisp.pf_count; i++) {
        if (crisp_flush_pf_by_path(g_crisp.pf_paths[i]) < 0) {
            char msg[256];
            snprintf(msg, sizeof(msg), "crisp_on_exit: flush_pf_by_path failed for %s", g_crisp.pf_paths[i]);
            crisp_fail_stop(msg);
        }
    }
    
    int ret = crisp_drain_and_wait();
    if (ret < 0) {
        char msg[128];
        snprintf(msg, sizeof(msg), "crisp_on_exit: drain_and_wait failed: %d", ret);
        crisp_fail_stop(msg);
    }
}

