/* SPDX-License-Identifier: LGPL-3.0-or-later */
// Checker API TCP server (single listener, sequential)
// Uses PAL socket APIs because internal threads can't use libc sockets

#include "libos_internal.h"
#include "libos_thread.h"

#include "crisp.h"

// TODO checker API: listen on checker_api_port; per-connection: drain, return MC
// Returns int (PalThreadCreate signature); exits via PalThreadExit in practice
int crisp_checker_api_func(void* arg) {
    struct libos_thread* self = (struct libos_thread*)arg;
    if (self) {
        libos_tcb_init();
        set_cur_thread(self);
        log_setprefix(libos_get_tcb());
    }
    log_always("crisp_checker_api_func: stub (listen impl pending)");
    PalThreadExit(NULL);
    return 0;
}
