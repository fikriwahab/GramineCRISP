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

// Create + bind + listen on the configured port, store the listener into g_crisp.checker_listener
// Called synchronously from crisp_init so a bind/listen failure is detected at init time and
// fail-stops there, rather than fail-opening inside the thread (the operator asked for the L3
// Checker, so it must be available). Returns 0 on success, -1 on failure.
int crisp_checker_listen(void) {
    PAL_HANDLE listener = NULL;
    int ret = PalSocketCreate(PAL_IPV4, PAL_SOCKET_TCP, /*options=*/0, &listener);
    if (ret < 0) {
        log_error("checker: PalSocketCreate failed: %d", ret);
        return -1;
    }

    // SO_REUSEADDR so a quick restart isn't blocked by the previous listener's TIME_WAIT (best-effort)
    PAL_STREAM_ATTR attr;
    if (PalStreamAttributesQueryByHandle(listener, &attr) == 0) {
        attr.socket.reuseaddr = true;
        PalStreamAttributesSetByHandle(listener, &attr);
    }

    struct pal_socket_addr addr = {0};
    addr.domain = PAL_IPV4;
    addr.ipv4.addr = htonl(0x7f000001u);  // 127.0.0.1, the Checker is a local-only endpoint
    addr.ipv4.port = htons((uint16_t)g_crisp.checker_api_port);  // pal addr port is network byte order
    ret = PalSocketBind(listener, &addr);
    if (ret < 0) {
        log_error("checker: PalSocketBind(port=%d) failed: %d", g_crisp.checker_api_port, ret);
        PalObjectDestroy(listener);
        return -1;
    }
    ret = PalSocketListen(listener, /*backlog=*/4);
    if (ret < 0) {
        log_error("checker: PalSocketListen failed: %d", ret);
        PalObjectDestroy(listener);
        return -1;
    }
    g_crisp.checker_listener = listener;
    return 0;
}

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

// TCP server loop: accept on the pre-bound listener, drain until S >= L, send the MC value, close
// Returns int (PalThreadCreate signature), exits via PalThreadExit in practice
int crisp_checker_api_func(void* arg) {
    struct libos_thread* self = (struct libos_thread*)arg;
    if (self) {
        libos_tcb_init();
        set_cur_thread(self);
        log_setprefix(libos_get_tcb());
    }

    log_always("checker: listening on 127.0.0.1:%d", g_crisp.checker_api_port);

    // TODO: L3, read an expected min MC from the client and block until S >= it, not just drain + reply current MC
    // TODO: L3, single sequential listener, concurrent connections serialize, fine for a prototype
    // TODO: L3, network egress gating, a proxy/caller that queries this Checker before externalizing
    while (!__atomic_load_n(&g_crisp.halted, __ATOMIC_ACQUIRE)) {
        PAL_HANDLE client = NULL;
        int ret = PalSocketAccept(g_crisp.checker_listener, /*options=*/0, &client,
                                  /*out_client_addr=*/NULL, /*out_local_addr=*/NULL);
        if (ret < 0)
            continue;  // transient (EINTR etc.), the halt flag is caught by the loop condition

        // Block until all pending MC commits are done (S >= L)
        checker_drain();

        // Reply with the current MC value (8 bytes, host byte order)
        uint64_t S = 0;
        crisp_mc_read(&S);
        struct iovec iov = { .iov_base = &S, .iov_len = sizeof(S) };
        size_t sent = 0;
        PalSocketSend(client, &iov, /*iov_len=*/1, &sent, /*addr=*/NULL,
                      /*force_nonblocking=*/false);

        PalObjectDestroy(client);
    }

    log_always("checker: exiting (halted)");
    PalObjectDestroy(g_crisp.checker_listener);
    g_crisp.checker_thread_handle = NULL;
    PalThreadExit(NULL);
    return 0;
}
