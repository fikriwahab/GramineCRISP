/* SPDX-License-Identifier: LGPL-3.0-or-later */
// Synchronous close + exit hooks (block until committed).

#include "libos_internal.h"
#include "crisp.h"

// TODO close hook: enqueue + drain.
int crisp_on_close(void) {
    log_always("crisp_on_close");
    return 0;
}

// TODO exit hook: flush all tracked PFs, then enqueue + drain.
void crisp_on_exit(void) {
    log_always("crisp_on_exit");
}
