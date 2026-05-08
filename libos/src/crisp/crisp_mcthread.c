/* SPDX-License-Identifier: LGPL-3.0-or-later */
// Background batch processor (internal thread)

#include <errno.h>

#include "api.h"
#include "libos_internal.h"
#include "libos_thread.h"
#include "pal.h"

#include "crisp.h"

// Internal thread main loop: wait on mc_wakeup_event, drain queue once,
// commit (compute tag, ++L, vault_save, mc++, verify invariant), wake waiters
// Returns int (signature required by PalThreadCreate) but never returns
// in practice (exits via PalThreadExit on halt)
int crisp_mc_thread_func(void* arg) {
    struct libos_thread* self = (struct libos_thread*)arg;
    libos_tcb_init();
    set_cur_thread(self);
    log_setprefix(libos_get_tcb());

    log_always("mc-thread: started");
    g_crisp.mc_thread_running = true;

    while (1) {
        PalEventWait(g_crisp.mc_wakeup_event, /*timeout=*/NULL);

        if (__atomic_load_n(&g_crisp.halted, __ATOMIC_ACQUIRE))
            break;

        lock(&g_crisp.queue_mu);
        bool has_work = (g_crisp.pending_count > 0);
        uint64_t enqueue_time = g_crisp.oldest_enqueue_us;
        if (has_work)
            g_crisp.batch_in_flight = true;
        unlock(&g_crisp.queue_mu);

        if (!has_work)
            continue;

        if (g_crisp.queue_timeout_ms > 0 && enqueue_time > 0) {
            uint64_t now;
            PalSystemTimeQuery(&now);
            uint64_t elapsed_ms = (now - enqueue_time) / 1000;
            if (elapsed_ms > g_crisp.queue_timeout_ms)
                crisp_fail_stop("queue timeout exceeded");
        }

        uint8_t tag[CRISP_TAG_SIZE];
        if (crisp_compute_global_tag(tag) < 0)
            crisp_fail_stop("compute_global_tag failed");

        lock(&g_crisp.mu);
        uint64_t new_L = ++g_crisp.L;
        unlock(&g_crisp.mu);

        if (crisp_vault_save(tag, new_L) < 0)
            crisp_fail_stop("vault_save failed");

        uint64_t new_mc = 0;
        if (crisp_mc_increment(&new_mc) < 0)
            crisp_fail_stop("mc_increment failed");

        if (new_mc != new_L)
            crisp_fail_stop("mc drift: new_mc != L");

        lock(&g_crisp.queue_mu);
        g_crisp.pending_count = 0;
        g_crisp.queue_has_work = false;
        g_crisp.batch_in_flight = false;
        g_crisp.oldest_enqueue_us = 0;
        unlock(&g_crisp.queue_mu);

        crisp_wake_all_waiters();
        log_debug("mc-thread: batch committed L=%lu", new_L);
    }

    log_always("mc-thread: exiting (halted)");
    g_crisp.mc_thread_running = false;
    PalThreadExit(NULL);
    return 0;
}
