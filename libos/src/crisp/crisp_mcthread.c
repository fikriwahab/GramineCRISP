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
        if (__atomic_load_n(&g_crisp.halted, __ATOMIC_ACQUIRE))
            break;

        lock(&g_crisp.queue_mu);
        uint64_t batch_count = (uint64_t)g_crisp.pending_count;
        uint64_t enqueue_time = g_crisp.oldest_enqueue_us;
        if (batch_count > 0) {
            g_crisp.oldest_enqueue_us = 0;  // this batch's requests are about to commit
        }
        unlock(&g_crisp.queue_mu);

        if (batch_count == 0) {
            PalEventWait(g_crisp.mc_wakeup_event, /*timeout=*/NULL);
            continue;
        }

        // timeout check, effective threshold = queue_timeout + rate_limit (the rate limit
        // deliberately throttles increments so it shouldn't itself trip the timeout)
        uint64_t timeout_ms = g_crisp.queue_timeout_ms + g_crisp.rate_limit_ms;
        if (timeout_ms > 0 && enqueue_time > 0) {
            uint64_t now;
            PalSystemTimeQuery(&now);
            if ((now - enqueue_time) / 1000 > timeout_ms)
                crisp_fail_stop("queue timeout exceeded");
        }

        // optional MC rate limit: keep MC increments at least rate_limit_ms apart
        if (g_crisp.rate_limit_ms > 0 && g_crisp.last_increment_us > 0) {
            uint64_t now;
            PalSystemTimeQuery(&now);
            uint64_t earliest = g_crisp.last_increment_us + g_crisp.rate_limit_ms * 1000;
            if (now < earliest) {
                uint64_t sleep_us = earliest - now;
                PalEventWait(g_crisp.mc_sleep_event, &sleep_us);
            }
        }

        int r = crisp_commit_now();
        if (r < 0)
            crisp_fail_stop("commit cycle failed");

        // subtract only what this batch covered so fsyncs that arrived mid-commit
        // stay counted, and the next iteration picks them up without waiting
        lock(&g_crisp.queue_mu);
        g_crisp.pending_count -= (int)batch_count;
        g_crisp.queue_has_work = (g_crisp.pending_count > 0);
        unlock(&g_crisp.queue_mu);

        crisp_wake_all_waiters();
        log_debug("mc-thread: batch committed (covered %lu)", batch_count);
    }

    log_always("mc-thread: exiting (halted)");
    g_crisp.mc_thread_running = false;
    PalThreadExit(NULL);
    return 0;
}
