/* SPDX-License-Identifier: LGPL-3.0-or-later */
// Simulated monotonic counter via PAL I/O (unencrypted, models external MC hardware).

#include "api.h"
#include "libos_internal.h"
#include "crisp.h"

static uint64_t mc_value = 0;
static struct libos_lock mc_mu;
static bool mc_mu_initialized = false;

static void mc_uri(const char* path, char* out, size_t out_size) {
    snprintf(out, out_size, "file:%s", path);
}

// Open existing MC file or create new one with value 0.
// Returns 0 on success, -1 on error (caller fail-stops).
int crisp_mc_init(void) {
    if (!mc_mu_initialized) {
        if (!create_lock(&mc_mu)) return -1;
        mc_mu_initialized = true;
    }

    lock(&mc_mu);

    char uri[300];
    mc_uri(g_crisp.mc_path, uri, sizeof(uri));

    PAL_HANDLE hdl = NULL;
    int ret = PalStreamOpen(uri, PAL_ACCESS_RDONLY, /*share_flags=*/0,
                            PAL_CREATE_NEVER, /*options=*/0, &hdl);
    if (ret < 0) {
        // Only ENOENT means fresh install; other errors are fatal.
        if (ret != PAL_ERROR_STREAMNOTEXIST) {
            log_error("crisp_mc_init: open failed: %d", ret);
            unlock(&mc_mu);
            return -1;
        }

        mc_value = 0;
        ret = PalStreamOpen(uri, PAL_ACCESS_RDWR, /*share_flags=*/0600,
                            PAL_CREATE_ALWAYS, /*options=*/0, &hdl);
        if (ret < 0) {
            log_error("crisp_mc_init: create failed: %d", ret);
            unlock(&mc_mu);
            return -1;
        }
        size_t count = sizeof(mc_value);
        ret = PalStreamWrite(hdl, /*offset=*/0, &count, &mc_value);
        PalObjectDestroy(hdl);
        if (ret < 0 || count != sizeof(mc_value)) {
            log_error("crisp_mc_init: initial write failed");
            unlock(&mc_mu);
            return -1;
        }
        log_debug("crisp_mc_init: fresh, value=0");
        unlock(&mc_mu);
        return 0;
    }

    size_t count = sizeof(mc_value);
    ret = PalStreamRead(hdl, /*offset=*/0, &count, &mc_value);
    PalObjectDestroy(hdl);
    if (ret < 0 || count != sizeof(mc_value)) {
        log_error("crisp_mc_init: read failed (ret=%d, count=%lu)", ret, count);
        unlock(&mc_mu);
        return -1;
    }
    log_debug("crisp_mc_init: loaded, value=%lu", mc_value);
    unlock(&mc_mu);
    return 0;
}

int crisp_mc_read(uint64_t* value) {
    if (!mc_mu_initialized) {
        *value = 0;
        return 0;
    }
    lock(&mc_mu);
    *value = mc_value;
    unlock(&mc_mu);
    return 0;
}

// Simulate hardware latency, increment, atomic write+rename.
int crisp_mc_increment(uint64_t* new_value) {
    // Sleep before lock so concurrent crisp_mc_read calls aren't blocked.
    if (g_crisp.mc_latency_ms > 0) {
        uint64_t sleep_us = g_crisp.mc_latency_ms * 1000;
        PalEventWait(g_crisp.mc_wakeup_event, &sleep_us);
    }

    lock(&mc_mu);
    mc_value++;
    *new_value = mc_value;
    uint64_t snapshot = mc_value;

    char tmp_path[260];
    snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", g_crisp.mc_path);

    char tmp_uri_s[300], mc_uri_s[300];
    mc_uri(tmp_path, tmp_uri_s, sizeof(tmp_uri_s));
    mc_uri(g_crisp.mc_path, mc_uri_s, sizeof(mc_uri_s));

    PAL_HANDLE hdl = NULL;
    int ret = PalStreamOpen(tmp_uri_s, PAL_ACCESS_RDWR, /*share_flags=*/0600,
                            PAL_CREATE_ALWAYS, /*options=*/0, &hdl);
    if (ret < 0) {
        log_error("crisp_mc_increment: tmp open failed: %d", ret);
        unlock(&mc_mu);
        return -1;
    }

    size_t count = sizeof(snapshot);
    ret = PalStreamWrite(hdl, /*offset=*/0, &count, &snapshot);
    if (ret < 0 || count != sizeof(snapshot)) {
        log_error("crisp_mc_increment: write failed (ret=%d, count=%lu)", ret, count);
        PalObjectDestroy(hdl);
        unlock(&mc_mu);
        return -1;
    }
    ret = PalStreamFlush(hdl);
    PalObjectDestroy(hdl);
    if (ret < 0) {
        log_error("crisp_mc_increment: flush failed: %d", ret);
        unlock(&mc_mu);
        return -1;
    }

    // Atomic rename tmp -> mc.
    ret = PalStreamOpen(tmp_uri_s, PAL_ACCESS_RDWR, /*share_flags=*/0,
                       PAL_CREATE_NEVER, /*options=*/0, &hdl);
    if (ret < 0) {
        log_error("crisp_mc_increment: reopen for rename failed: %d", ret);
        unlock(&mc_mu);
        return -1;
    }
    ret = PalStreamChangeName(hdl, mc_uri_s);
    PalObjectDestroy(hdl);
    if (ret < 0) {
        log_error("crisp_mc_increment: rename failed: %d", ret);
        unlock(&mc_mu);
        return -1;
    }

    log_debug("crisp_mc_increment: %lu -> %lu", snapshot - 1, snapshot);
    unlock(&mc_mu);
    return 0;
}
