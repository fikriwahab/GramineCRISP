/* SPDX-License-Identifier: LGPL-3.0-or-later */
// CRISP-aware handle close + the synchronous close and exit hooks (block until committed)

#include <errno.h>

#include "api.h"
#include "libos_fs.h"
#include "libos_handle.h"
#include "libos_internal.h"

#include "crisp.h"

// CRISP-aware handle close used by every user-facing fd close (close, close_range, dup2/dup3 overwrite)
// for a tracked PF with CRISP on it flushes under tag_lock then synchronously commits via crisp_on_close,
// otherwise it just put_handles, returning a flush error, -ENOTRECOVERABLE if halted, or 0
int crisp_close_handle(struct libos_handle* handle) {
    bool is_pf = (g_crisp.enabled && handle->type == TYPE_CHROOT_ENCRYPTED);
    int fr = 0;
    if (is_pf && handle->fs && handle->fs->fs_ops && handle->fs->fs_ops->flush) {
        lock(&g_crisp.tag_lock);
        fr = handle->fs->fs_ops->flush(handle);
        unlock(&g_crisp.tag_lock);
    }
    put_handle(handle);
    if (fr < 0)
        return fr;
    if (is_pf)
        return crisp_on_close();
    return 0;
}

// Close hook: enqueue the post-close-flush state, then block until committed
int crisp_on_close(void) {
    if (!g_crisp.enabled)
        return 0;

    if (__atomic_load_n(&g_crisp.halted, __ATOMIC_ACQUIRE))
        return -ENOTRECOVERABLE;

    if (g_crisp.mode == 1)
        return crisp_commit_now();

    int ret = crisp_on_fsync();
    if (ret < 0)
        return ret;

    ret = crisp_drain_and_wait();
    if (ret < 0) {
        char msg[128];
        snprintf(msg, sizeof(msg), "crisp_on_close: drain_and_wait failed: %d", ret);
        crisp_fail_stop(msg);
    }
    return 0;
}

// Exit hook: force-flush every tracked PF that exists (MAC fresh), enqueue, block until committed
// Called before process exit cleanup, the close chain has not run yet
void crisp_on_exit(void) {
    if (!g_crisp.enabled)
        return;

    if (__atomic_load_n(&g_crisp.halted, __ATOMIC_ACQUIRE))
        return;

    for (int i = 0; i < g_crisp.pf_count; i++) {
        if (crisp_flush_pf_by_path(g_crisp.pf_paths[i]) < 0) {
            char msg[256];
            snprintf(msg, sizeof(msg), "crisp_on_exit: flush failed for %s",
                     g_crisp.pf_paths[i]);
            crisp_fail_stop(msg);
        }
    }

    int ret = crisp_on_fsync();
    if (ret < 0)
        crisp_fail_stop("crisp_on_exit: enqueue failed");

    ret = crisp_drain_and_wait();
    if (ret < 0) {
        char msg[128];
        snprintf(msg, sizeof(msg), "crisp_on_exit: drain_and_wait failed: %d", ret);
        crisp_fail_stop(msg);
    }
}
