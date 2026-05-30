/* SPDX-License-Identifier: LGPL-3.0-or-later */
// Profile stats dump on process exit, emits both human-readable log lines
// and CSV-tagged lines so the test harness can grep and feed pandas

#include <stdint.h>

#include "api.h"
#include "libos_internal.h"

#include "crisp.h"

static const char* const slot_names[CRISP_PROF_NUM_SLOTS] = {
    "compute_tag",
    "vault_save",
    "mc_increment",
    "commit_now",
    "batch_latency",
    "fsync_hook",
    "close_hook",
    "exit_hook",
    "gate_hook",
};

// Emit per-slot stats, called from crisp_on_exit after the final commit completes
// CSV-tagged lines are stable for downstream parsing, log lines are for humans
void crisp_profile_dump(void) {
    if (!g_crisp.profile_enabled)
        return;

    log_always("[CRISP PROFILE] dumping per-slot stats");
    log_always("[CRISP CSV] slot,count,total_us,avg_us");

    for (int i = 0; i < CRISP_PROF_NUM_SLOTS; i++) {
        uint64_t cnt = __atomic_load_n(&g_crisp.profile_count[i], __ATOMIC_RELAXED);
        uint64_t tot = __atomic_load_n(&g_crisp.profile_total_us[i], __ATOMIC_RELAXED);
        uint64_t avg = cnt > 0 ? tot / cnt : 0;
        log_always("[CRISP PROFILE] slot=%-14s count=%-6lu total_us=%-10lu avg_us=%lu",
                   slot_names[i], cnt, tot, avg);
        log_always("[CRISP CSV] %s,%lu,%lu,%lu", slot_names[i], cnt, tot, avg);
    }
}
