/* SPDX-License-Identifier: LGPL-3.0-or-later */
// Background batch processor (internal thread).

#include "libos_internal.h"
#include "crisp.h"

// TODO Session 7: wait on mc_wakeup_event, drain queue, compute tag,
//                 ++L, save vault, increment MC, wake waiters.
noreturn void crisp_mc_thread_func(void* arg) {
    (void)arg;
    log_always("crisp_mc_thread_func");
    PalThreadExit(NULL);
    __builtin_unreachable();
}
