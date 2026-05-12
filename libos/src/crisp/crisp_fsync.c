/* SPDX-License-Identifier: LGPL-3.0-or-later */
// fsync hook + drain/wait + waiter wakeup

#include <errno.h>
#include <stdint.h>

#include "api.h"
#include "libos_internal.h"
#include "libos_thread.h"
#include "pal.h"

#include "crisp.h"

// App thread enqueues fsync request, signals mc-thread, returns immediately
// Optimistic: caller does not wait for MC commit
// Probabilistic checker: checker_prob% of fsyncs block until committed, which
// bounds batch size
int crisp_on_fsync(void) {
    if (__atomic_load_n(&g_crisp.halted, __ATOMIC_ACQUIRE))
        return -ENOTRECOVERABLE;

    lock(&g_crisp.queue_mu);
    if (g_crisp.oldest_enqueue_us == 0)
        PalSystemTimeQuery(&g_crisp.oldest_enqueue_us);  // age of the oldest uncommitted request
    g_crisp.pending_count++;
    g_crisp.queue_has_work = true;
    unlock(&g_crisp.queue_mu);

    if (g_crisp.mc_wakeup_event)
        PalEventSet(g_crisp.mc_wakeup_event);

    if (g_crisp.checker_prob > 0) {
        static uint32_t fsync_counter = 0;
        uint32_t c = __atomic_fetch_add(&fsync_counter, 1, __ATOMIC_RELAXED);
        if ((c % 100) < (uint32_t)g_crisp.checker_prob)
            crisp_drain_and_wait();
    }

    return 0;
}

// App thread blocks until queue drained AND S >= L (or halted)
// Canonical wait pattern: register -> prepare -> barrier -> check -> wait
int crisp_drain_and_wait(void) {
    struct libos_thread* self = get_cur_thread();
    if (!self || is_internal(self))
        return -EINVAL;

    bool registered = false;
    spinlock_lock(&g_crisp.waiter_lock);
    for (int i = 0; i < g_crisp.waiter_count; i++) {
        if (g_crisp.waiters[i] == self) {
            registered = true;
            break;
        }
    }
    if (!registered && g_crisp.waiter_count < CRISP_MAX_WAITERS) {
        get_thread(self);
        g_crisp.waiters[g_crisp.waiter_count++] = self;
        registered = true;
    }
    spinlock_unlock(&g_crisp.waiter_lock);

    while (1) {
        if (__atomic_load_n(&g_crisp.halted, __ATOMIC_ACQUIRE))
            break;

        thread_prepare_wait();
        COMPILER_BARRIER();

        lock(&g_crisp.queue_mu);
        bool queue_empty = (g_crisp.pending_count == 0);
        bool in_flight = g_crisp.batch_in_flight;
        unlock(&g_crisp.queue_mu);

        uint64_t S = 0;
        crisp_mc_read(&S);
        lock(&g_crisp.mu);
        uint64_t current_L = g_crisp.L;
        unlock(&g_crisp.mu);

        if (queue_empty && !in_flight && S >= current_L)
            break;

        uint64_t timeout_us = 5000;
        thread_wait(registered ? NULL : &timeout_us, /*ignore_pending_signals=*/false);
    }

    if (registered) {
        spinlock_lock(&g_crisp.waiter_lock);
        for (int i = 0; i < g_crisp.waiter_count; i++) {
            if (g_crisp.waiters[i] == self) {
                g_crisp.waiters[i] = g_crisp.waiters[g_crisp.waiter_count - 1];
                g_crisp.waiters[g_crisp.waiter_count - 1] = NULL;
                g_crisp.waiter_count--;
                spinlock_unlock(&g_crisp.waiter_lock);
                put_thread(self);
                goto check_halted;
            }
        }
        spinlock_unlock(&g_crisp.waiter_lock);
    }

check_halted:
    return __atomic_load_n(&g_crisp.halted, __ATOMIC_ACQUIRE) ? -ENOTRECOVERABLE : 0;
}

// mc-thread (or fail_stop) wakes all blocked app threads
// Also signals checker poll event for periodic check thread
void crisp_wake_all_waiters(void) {
    spinlock_lock(&g_crisp.waiter_lock);
    for (int i = 0; i < g_crisp.waiter_count; i++) {
        if (g_crisp.waiters[i])
            thread_wakeup(g_crisp.waiters[i]);
    }
    spinlock_unlock(&g_crisp.waiter_lock);

    if (g_crisp.checker_poll_event)
        PalEventSet(g_crisp.checker_poll_event);
}
