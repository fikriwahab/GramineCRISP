/* SPDX-License-Identifier: LGPL-3.0-or-later */
// Network egress gating, called before socket send syscalls externalize state
// Reuses crisp_drain_and_wait to block until in-flight commits complete

#include <errno.h>

#include "api.h"
#include "libos_internal.h"

#include "crisp.h"

// Entry point invoked from libos_syscall_sendto / sendmsg / sendmmsg before do_sendmsg
// returns 0 if send may proceed, negative errno otherwise
int crisp_gate_check(void) {
    CRISP_PROF_BEGIN(GATE_HOOK);

    if (!g_crisp.enabled || !g_crisp.network_gate ||
        g_crisp.gate_policy == CRISP_GATE_NONE) {
        CRISP_PROF_END(GATE_HOOK);
        return 0;
    }

    if (__atomic_load_n(&g_crisp.halted, __ATOMIC_ACQUIRE)) {
        CRISP_PROF_END(GATE_HOOK);
        return -ENOTRECOVERABLE;
    }

    // Snapshot pending state under queue_mu to make the policy decision
    lock(&g_crisp.queue_mu);
    bool queue_empty = (g_crisp.pending_count == 0);
    bool in_flight = g_crisp.batch_in_flight;
    unlock(&g_crisp.queue_mu);

    uint64_t S = 0;
    crisp_mc_read(&S);
    lock(&g_crisp.mu);
    uint64_t current_L = g_crisp.L;
    unlock(&g_crisp.mu);

    bool pending = !queue_empty || in_flight || S < current_L;

    if (!pending) {
        CRISP_PROF_END(GATE_HOOK);
        return 0;
    }

    switch (g_crisp.gate_policy) {
        case CRISP_GATE_WARN:
            log_warning("crisp_gate: pending state at send, allowing (warn mode): "
                        "pending=%d in_flight=%d S=%lu L=%lu",
                        g_crisp.pending_count, in_flight, S, current_L);
            CRISP_PROF_END(GATE_HOOK);
            return 0;

        case CRISP_GATE_DROP:
            log_warning("crisp_gate: pending state at send, dropping (drop mode): "
                        "pending=%d in_flight=%d S=%lu L=%lu",
                        g_crisp.pending_count, in_flight, S, current_L);
            CRISP_PROF_END(GATE_HOOK);
            return -ECONNREFUSED;

        case CRISP_GATE_BLOCK: {
            // Block until queue drained and S >= L (all pending commits are done)
            int ret = crisp_drain_and_wait();
            CRISP_PROF_END(GATE_HOOK);
            if (ret < 0) {
                log_error("crisp_gate: drain_and_wait failed: %d", ret);
                return ret;
            }
            return 0;
        }

        default:
            log_error("crisp_gate: unknown gate_policy %d, defaulting to block",
                      g_crisp.gate_policy);
            int ret = crisp_drain_and_wait();
            CRISP_PROF_END(GATE_HOOK);
            return ret;
    }
}
