/* SPDX-License-Identifier: LGPL-3.0-or-later */
// Global tag = SHA-256(sorted concat of per-PF metadata MACs).

#include "libos_internal.h"
#include "crisp.h"

// TODO Session 4: iterate g_crisp.pf_paths, read each metadata_mac, hash.
int crisp_compute_global_tag(uint8_t* tag_out) {
    log_always("crisp_compute_global_tag");
    if (tag_out) {
        for (int i = 0; i < CRISP_TAG_SIZE; i++) tag_out[i] = 0;
    }
    return 0;
}

// TODO Session 4: open PF, fs_ops->flush, close (used by exit hook).
int crisp_flush_pf_by_path(const char* path) {
    log_always("crisp_flush_pf_by_path(%s)", path);
    return 0;
}
