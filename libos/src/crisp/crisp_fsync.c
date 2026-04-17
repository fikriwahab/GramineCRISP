/* SPDX-License-Identifier: LGPL-3.0-or-later */
// fsync hook + drain/wait + waiter wakeup.

#include "libos_internal.h"
#include "crisp.h"

// TODO Session 6: enqueue + signal mc-thread; probabilistic check.
int crisp_on_fsync(void) {
    log_always("crisp_on_fsync");
    return 0;
}

// TODO Session 6: block until queue drained and S >= L (or halted).
int crisp_drain_and_wait(void) {
    log_always("crisp_drain_and_wait");
    return 0;
}

// TODO Session 6: wake app threads + checker poll event.
void crisp_wake_all_waiters(void) {
    log_always("crisp_wake_all_waiters");
}
