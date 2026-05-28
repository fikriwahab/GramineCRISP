/* SPDX-License-Identifier: LGPL-3.0-or-later */
// Vault I/O via LibOS VFS (goes through PF encryption).
// Save = write tmp file, flush, then rename tmp -> vault (atomic).

#include <string.h>

#include "api.h"
#include "crypto.h"
#include "libos_fs.h"
#include "libos_handle.h"
#include "libos_internal.h"
#include "linux_abi/errors.h"
#include "linux_abi/fs.h"

#include "crisp.h"

// SHA-256(magic || tag || L). Extra integrity layer on top of PF encryption.
static void compute_checksum(const uint8_t* tag, uint64_t local_mc, uint8_t* out) {
    LIB_SHA256_CONTEXT ctx;
    lib_SHA256Init(&ctx);
    lib_SHA256Update(&ctx, (const uint8_t*)CRISP_VAULT_MAGIC, 4);
    lib_SHA256Update(&ctx, tag, CRISP_TAG_SIZE);
    lib_SHA256Update(&ctx, (const uint8_t*)&local_mc, sizeof(local_mc));
    lib_SHA256Final(&ctx, out);
}

// Load vault from disk.
// Returns: 0 = OK, -2 = fresh install (no file yet), -1 = error.
int crisp_vault_load(crisp_vault_t* out) {
    int ret = -1;

    struct libos_handle* hdl = get_new_handle();
    int r = open_namei(hdl, NULL, g_crisp.vault_path, O_RDONLY, 0, NULL);

    if (r == -ENOENT) {
        ret = -2;
        goto done;
    }
    if (r < 0)
        goto done;

    // Read 76 bytes into caller's buffer.
    if (do_handle_read(hdl, out, sizeof(*out)) != (ssize_t)sizeof(*out))
        goto done;

    // Check magic "CRSP".
    if (memcmp(out->magic, CRISP_VAULT_MAGIC, 4) != 0)
        goto done;

    // Recompute checksum and compare.
    uint8_t expected[32];
    compute_checksum(out->tag, out->local_mc, expected);
    if (memcmp(out->checksum, expected, 32) != 0)
        goto done;

    ret = 0;
    log_debug("vault_load: OK, L=%lu", out->local_mc);

done:
    put_handle(hdl);
    if (ret == -1) log_error("vault_load: failed (r=%d)", r);
    return ret;
}

// Save vault atomically.
// Returns: 0 = OK, -1 = error.
int crisp_vault_save(const uint8_t* tag, uint64_t local_mc) {
    CRISP_PROF_BEGIN(VAULT_SAVE);
    // Build struct on stack.
    crisp_vault_t v;
    memcpy(v.magic, CRISP_VAULT_MAGIC, 4);
    memcpy(v.tag, tag, CRISP_TAG_SIZE);
    v.local_mc = local_mc;
    compute_checksum(tag, local_mc, v.checksum);

    int ret = -1;

    char tmp_path[300];
    snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", g_crisp.vault_path);

    // Step 1: Write vault to tmp (encrypted by PF layer).
    struct libos_handle* hdl = get_new_handle();
    if (open_namei(hdl, NULL, tmp_path, O_WRONLY | O_CREAT | O_TRUNC, 0600, NULL) < 0)
        goto out;
    if (do_handle_write(hdl, &v, sizeof(v)) != (ssize_t)sizeof(v)) {
        put_handle(hdl);
        goto out;
    }
    if (hdl->fs->fs_ops->flush(hdl) < 0) {
        put_handle(hdl);
        goto out;
    }
    put_handle(hdl);

    // Step 2: atomic rename tmp -> vault (inline under the dcache lock)
    // libos_syscall_renameat rejects LibOS pointers and do_rename is static, so
    // replicate the core: look up both dentries, call d_ops->rename, move the inode
    // every lookup and pointer is checked, a failure leaves ret == -1 so the
    // mc-thread fail-stops cleanly instead of dereferencing a NULL dentry
    lock(&g_dcache_lock);
    struct libos_dentry *old_d = NULL, *new_d = NULL;
    int lr1 = path_lookupat(NULL, tmp_path, LOOKUP_NO_FOLLOW, &old_d);
    int lr2 = path_lookupat(NULL, g_crisp.vault_path, LOOKUP_NO_FOLLOW | LOOKUP_CREATE, &new_d);
    if (lr1 == 0 && lr2 == 0 && old_d && old_d->inode && new_d &&
        old_d->inode->fs && old_d->inode->fs->d_ops && old_d->inode->fs->d_ops->rename) {
        int r = old_d->inode->fs->d_ops->rename(old_d, new_d);
        if (r == 0) {
            if (new_d->inode) put_inode(new_d->inode);
            new_d->inode = old_d->inode;
            old_d->inode = NULL;
            ret = 0;
        }
    }
    if (old_d) put_dentry(old_d);
    if (new_d) put_dentry(new_d);
    unlock(&g_dcache_lock);

out:
    if (ret == 0) log_debug("vault_save: OK, L=%lu", local_mc);
    else          log_error("vault_save: failed");
    CRISP_PROF_END(VAULT_SAVE);
    return ret;
}
