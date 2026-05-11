/* SPDX-License-Identifier: LGPL-3.0-or-later */
// Checker API TCP server (single listener, sequential)
// Uses PAL socket APIs because internal threads can't use libc sockets

#include <stdint.h>

#include "api.h"
#include "iovec.h"
#include "libos_internal.h"
#include "libos_thread.h"
#include "pal.h"
#include "socket_utils.h"

#include "crisp.h"

// Block until queue drained AND S >= L, or halted
// Internal-thread-safe: crisp_drain_and_wait asserts !is_internal, so the checker
// uses this local poll loop on checker_poll_event instead
static void checker_drain(void) {
    while (1) {
        if (__atomic_load_n(&g_crisp.halted, __ATOMIC_ACQUIRE))
            return;

        lock(&g_crisp.queue_mu);
        bool queue_empty = (g_crisp.pending_count == 0);
        bool in_flight = g_crisp.batch_in_flight;
        unlock(&g_crisp.queue_mu);

        uint64_t S = 0;
        crisp_mc_read(&S);
        lock(&g_crisp.mu);
        uint64_t L = g_crisp.L;
        unlock(&g_crisp.mu);

        if (queue_empty && !in_flight && S >= L)
            return;

        uint64_t timeout_us = 5000;
        PalEventWait(g_crisp.checker_poll_event, &timeout_us);
    }
}

// TCP server loop: accept connection, drain until S >= L, send MC value, close
// Returns int (PalThreadCreate signature); exits via PalThreadExit in practice
int crisp_checker_api_func(void* arg) {
    struct libos_thread* self = (struct libos_thread*)arg;
    if (self) {
        libos_tcb_init();
        set_cur_thread(self);
        log_setprefix(libos_get_tcb());
    }

    if (g_crisp.checker_api_port <= 0) {
        log_always("checker: no port configured, exiting");
        g_crisp.checker_thread_handle = NULL;
        PalThreadExit(NULL);
        return 0;
    }

    PAL_HANDLE listener = NULL;
    int ret = PalSocketCreate(PAL_IPV4, PAL_SOCKET_TCP, /*options=*/0, &listener);
    if (ret < 0) {
        log_error("checker: PalSocketCreate failed: %d", ret);
        g_crisp.checker_thread_handle = NULL;
        PalThreadExit(NULL);
        return 0;
    }

    struct pal_socket_addr addr = {0};
    addr.domain = PAL_IPV4;
    addr.ipv4.addr = 0;  // 0.0.0.0 (INADDR_ANY); htonl(0) == 0
    addr.ipv4.port = htons((uint16_t)g_crisp.checker_api_port);  // pal addr port is network byte order

    ret = PalSocketBind(listener, &addr);
    if (ret < 0) {
        log_error("checker: PalSocketBind(port=%d) failed: %d", g_crisp.checker_api_port, ret);
        PalObjectDestroy(listener);
        g_crisp.checker_thread_handle = NULL;
        PalThreadExit(NULL);
        return 0;
    }

    ret = PalSocketListen(listener, /*backlog=*/4);
    if (ret < 0) {
        log_error("checker: PalSocketListen failed: %d", ret);
        PalObjectDestroy(listener);
        g_crisp.checker_thread_handle = NULL;
        PalThreadExit(NULL);
        return 0;
    }

    log_always("checker: listening on 0.0.0.0:%d", g_crisp.checker_api_port);

    while (!__atomic_load_n(&g_crisp.halted, __ATOMIC_ACQUIRE)) {
        PAL_HANDLE client = NULL;
        ret = PalSocketAccept(listener, /*options=*/0, &client, /*out_client_addr=*/NULL,
                              /*out_local_addr=*/NULL);
        if (ret < 0)
            continue;  // transient (EINTR etc.); halt is caught by loop condition

        // Block until all pending MC commits done (S >= L)
        checker_drain();

        // Reply with current MC value (8 bytes, host byte order)
        uint64_t S = 0;
        crisp_mc_read(&S);
        struct iovec iov = { .iov_base = &S, .iov_len = sizeof(S) };
        size_t sent = 0;
        PalSocketSend(client, &iov, /*iov_len=*/1, &sent, /*addr=*/NULL,
                      /*force_nonblocking=*/false);

        PalObjectDestroy(client);
    }

    log_always("checker: exiting (halted)");
    PalObjectDestroy(listener);
    g_crisp.checker_thread_handle = NULL;
    PalThreadExit(NULL);
    return 0;
}
