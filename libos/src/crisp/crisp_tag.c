/* SPDX-License-Identifier: LGPL-3.0-or-later */
// Global tag = SHA-256(sorted concat of per-PF metadata MACs).

#include <errno.h>
#include <string.h>

#include "crypto.h"
#include "libos_fs.h"
#include "libos_fs_encrypted.h"
#include "libos_handle.h"
#include "libos_internal.h"
#include "linux_abi/fs.h"

#include "protected_files.h"

#include "crisp.h"

// open PF, extract metadata_mac, close (inode-locked, PF not thread-safe)
// returns 0 (mac_out filled), -ENOENT if the file does not exist, or another negative
// error if it exists but cannot be read as a Protected File (tampered / unreadable)
static int extract_pf_mac(const char* path, uint8_t* mac_out) {
    struct libos_handle* hdl = get_new_handle();
    int r = open_namei(hdl, NULL, path, O_RDONLY, 0, NULL);
    if (r < 0) {
        put_handle(hdl);
        return r;
    }

    int ret = -EIO;
    if (hdl->inode && hdl->inode->data) {
        lock(&hdl->inode->lock);
        struct libos_encrypted_file* enc = (struct libos_encrypted_file*)hdl->inode->data;
        if (enc->pf && pf_get_metadata_mac(enc->pf, mac_out) == PF_STATUS_SUCCESS)
            ret = 0;
        unlock(&hdl->inode->lock);
    }
    put_handle(hdl);
    return ret;
}

// SHA-256 over the sorted concat of all tracked PFs' metadata_macs (a not-yet-created tracked PF
// contributes a zero MAC, an existing-but-unreadable one is an integrity failure that aborts)
// tag_lock keeps the loop a consistent snapshot even while PFs are flushed concurrently
int crisp_compute_global_tag(uint8_t* tag_out) {
    CRISP_PROF_BEGIN(COMPUTE_TAG);
    LIB_SHA256_CONTEXT ctx;
    lib_SHA256Init(&ctx);

    lock(&g_crisp.tag_lock);
    for (int i = 0; i < g_crisp.pf_count; i++) {
        uint8_t mac[PF_MAC_SIZE];
        int r = extract_pf_mac(g_crisp.pf_paths[i], mac);
        if (r == -ENOENT) {
            // truly not present yet, contribute a zero MAC, a later mismatch catches a real deletion
            memset(mac, 0, sizeof(mac));
            log_debug("tag: %s not present, using zero MAC", g_crisp.pf_paths[i]);
        } else if (r < 0) {
            // exists but cannot be read as a Protected File (tampered / unreadable): integrity failure
            unlock(&g_crisp.tag_lock);
            log_error("tag: %s exists but is unreadable as a Protected File", g_crisp.pf_paths[i]);
            return -1;
        }
        lib_SHA256Update(&ctx, mac, PF_MAC_SIZE);
    }
    unlock(&g_crisp.tag_lock);

    lib_SHA256Final(&ctx, tag_out);
    log_debug("tag: computed over %d PFs", g_crisp.pf_count);
    CRISP_PROF_END(COMPUTE_TAG);
    return 0;
}

// force flush a PF to refresh its metadata_mac (used by the exit hook)
// a not-yet-created tracked PF is fine (returns 0), consistent with the zero-MAC
// rule in crisp_compute_global_tag, so a partial-tracked-set first run still exits cleanly
// the flush itself runs under tag_lock so it can't tear a concurrent global-tag snapshot
int crisp_flush_pf_by_path(const char* path) {
    struct libos_handle* hdl = get_new_handle();
    int r = open_namei(hdl, NULL, path, O_RDONLY, 0, NULL);
    if (r == -ENOENT) {
        put_handle(hdl);
        return 0;
    }
    if (r < 0) {
        put_handle(hdl);
        return r;
    }

    int ret = 0;
    if (hdl->fs && hdl->fs->fs_ops && hdl->fs->fs_ops->flush) {
        lock(&g_crisp.tag_lock);
        ret = hdl->fs->fs_ops->flush(hdl);
        unlock(&g_crisp.tag_lock);
    }
    put_handle(hdl);
    return ret;
}
