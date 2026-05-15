/* SPDX-License-Identifier: LGPL-3.0-or-later */
// fsync hook + drain/wait + waiter wakeup

#include <errno.h>
#include <stdint.h>

#include "api.h"
#include "libos_internal.h"
#include "libos_thread.h"
#include "pal.h"

#include "crisp.h"

// Synchronous (pessimistic) commit: tag -> ++L -> vault_save -> mc_increment -> verify
// Safe to call from app thread or mc-thread.
// Returns 0 on success, negative errno on failure — caller is responsible for fail-stop.
int crisp_commit_now(void) {
    uint8_t tag[CRISP_TAG_SIZE];
    uint64_t new_L  = 0;
    uint64_t new_mc = 0;
    int ret = -EIO;

    if (__atomic_load_n(&g_crisp.halted, __ATOMIC_ACQUIRE))
        return -ENOTRECOVERABLE;

    // Signal to drain_and_wait() that a commit is in progress
    lock(&g_crisp.queue_mu);
    g_crisp.batch_in_flight = true;
    unlock(&g_crisp.queue_mu);

    if (crisp_compute_global_tag(tag) < 0)
        goto out;

    lock(&g_crisp.mu);
    new_L = ++g_crisp.L;
    unlock(&g_crisp.mu);

    if (crisp_vault_save(tag, new_L) < 0)
        goto out;

    if (crisp_mc_increment(&new_mc) < 0)
        goto out;
    PalSystemTimeQuery(&g_crisp.last_increment_us);

    if (new_mc != new_L)
        goto out;

    ret = 0;
    log_debug("crisp_commit_now: committed L=%lu", new_L);

out:
    lock(&g_crisp.queue_mu);
    g_crisp.batch_in_flight = false;
    g_crisp.queue_has_work = (g_crisp.pending_count > 0);
    unlock(&g_crisp.queue_mu);

    crisp_wake_all_waiters();
    return ret;
}

// App thread enqueues fsync request, signals mc-thread, returns immediately
// Optimistic: caller does not wait for MC commit
// Probabilistic checker: checker_prob% of fsyncs block until committed, which
// bounds batch size
int crisp_on_fsync(void) {
    if (__atomic_load_n(&g_crisp.halted, __ATOMIC_ACQUIRE))
        return -ENOTRECOVERABLE;

    // L1: synchronous mode — commit inline, skip enqueue
    if (g_crisp.mode == 1) {
        int r = crisp_commit_now();
        if (r < 0)
            crisp_fail_stop("synchronous fsync commit failed");
        return 0;
    }

    lock(&g_crisp.queue_mu);
    if (g_crisp.oldest_enqueue_us == 0)
        PalSystemTimeQuery(&g_crisp.oldest_enqueue_us);  // age of the oldest uncommitted request
    g_crisp.pending_count++;
    g_crisp.queue_has_work = true;
    unlock(&g_crisp.queue_mu);

    if (g_crisp.mc_wakeup_event)
        PalEventSet(g_crisp.mc_wakeup_event);

    // L3: deterministic periodic checker — block every (100/checker_prob)-th fsync
    // e.g. prob=25 -> every 4th call; prob=50 -> every 2nd; prob=100 -> every call
    if (g_crisp.checker_prob > 0) {
        static uint32_t fsync_counter = 0;
        uint32_t c = __atomic_fetch_add(&fsync_counter, 1, __ATOMIC_RELAXED);
        uint32_t period = (uint32_t)(100 / (uint32_t)g_crisp.checker_prob);
        if (period == 0)
            period = 1;
        if ((c % period) == 0)
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
