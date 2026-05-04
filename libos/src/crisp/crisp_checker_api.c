/* SPDX-License-Identifier: LGPL-3.0-or-later */
// Checker API TCP server (single listener, sequential).
// Uses PAL socket APIs because internal threads can't use libc sockets.

#include "libos_internal.h"
#include "crisp.h"

// TODO checker API: listen on checker_api_port; per-connection: drain, return MC.
noreturn void crisp_checker_api_func(void* arg) {
    (void)arg;
    log_always("crisp_checker_api_func");
    PalThreadExit(NULL);
    __builtin_unreachable();
}
