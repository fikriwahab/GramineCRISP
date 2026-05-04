/* SPDX-License-Identifier: LGPL-3.0-or-later */
// Global tag = SHA-256(sorted concat of per-PF metadata MACs).

#include <string.h>

#include "crypto.h"
#include "libos_fs.h"
#include "libos_fs_encrypted.h"
#include "libos_handle.h"
#include "libos_internal.h"
#include "linux_abi/fs.h"

#include "protected_files.h"

#include "crisp.h"

// Open PF, extract metadata_mac, close. Inode-locked (PF not thread-safe).
static int extract_pf_mac(const char* path, uint8_t* mac_out) {
    struct libos_handle* hdl = get_new_handle();
    int ret = -1;

    if (open_namei(hdl, NULL, path, O_RDONLY, 0, NULL) < 0)
        goto done;
    if (!hdl->inode || !hdl->inode->data)
        goto done;

    lock(&hdl->inode->lock);
    struct libos_encrypted_file* enc = (struct libos_encrypted_file*)hdl->inode->data;
    if (enc->pf) {
        pf_status_t s = pf_get_metadata_mac(enc->pf, mac_out);
        if (s == PF_STATUS_SUCCESS)
            ret = 0;
    }
    unlock(&hdl->inode->lock);

done:
    put_handle(hdl);
    return ret;
}

// SHA-256 over concatenated metadata_macs of all tracked PFs (sorted).
int crisp_compute_global_tag(uint8_t* tag_out) {
    LIB_SHA256_CONTEXT ctx;
    lib_SHA256Init(&ctx);
    // TODO: tidak ada lock, ada kemungkinan di tengah2 count, dan kalau tiba2 tambahan file baru, jadi gimana handlenya.
    // Ketika ada write request, maka impement lock dan waiter (e.g. mutex)
    // SOLUTION:
    // Scenario or assumption is that fsync/write onto one of the PF in the middle of the loop, MAC will change when read
    // So we can use global mutex. Writer take lock when it is about to flush, and  compute_tag take lock when iterate
    // Implement soon when we have the write hook and fsync hook.
    for (int i = 0; i < g_crisp.pf_count; i++) {
        uint8_t mac[PF_MAC_SIZE];
        if (extract_pf_mac(g_crisp.pf_paths[i], mac) < 0) {
            log_error("tag: extract failed for %s", g_crisp.pf_paths[i]);
            return -1;
        }
        lib_SHA256Update(&ctx, mac, PF_MAC_SIZE);
    }

    lib_SHA256Final(&ctx, tag_out);
    log_debug("tag: computed over %d PFs", g_crisp.pf_count);
    return 0;
}

// Force flush a PF to refresh its metadata_mac. Used by exit hook.
int crisp_flush_pf_by_path(const char* path) {
    g_in_crisp_io = true;
    int ret = -1;

    struct libos_handle* hdl = get_new_handle();
    if (open_namei(hdl, NULL, path, O_RDONLY, 0, NULL) < 0)
        goto done;

    if (hdl->fs && hdl->fs->fs_ops && hdl->fs->fs_ops->flush)
        ret = hdl->fs->fs_ops->flush(hdl);

done:
    put_handle(hdl);
    g_in_crisp_io = false;
    return ret;
}
