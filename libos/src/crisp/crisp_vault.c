/* SPDX-License-Identifier: LGPL-3.0-or-later */
// Vault I/O via LibOS VFS so it goes through PF encryption.
// Atomic write-tmp + inline rename under g_dcache_lock (libos_syscall_renameat
// rejects LibOS-internal pointers; do_rename is static).

#include <string.h>

#include "api.h"
#include "crypto.h"
#include "libos_fs.h"
#include "libos_handle.h"
#include "libos_internal.h"
#include "linux_abi/errors.h"
#include "linux_abi/fs.h"

#include "crisp.h"

bool g_in_crisp_io = false;

static void compute_checksum(const uint8_t* tag, uint64_t local_mc, uint8_t* out) {
    LIB_SHA256_CONTEXT ctx;
    lib_SHA256Init(&ctx);
    lib_SHA256Update(&ctx, (const uint8_t*)CRISP_VAULT_MAGIC, 4);
    lib_SHA256Update(&ctx, tag, CRISP_TAG_SIZE);
    lib_SHA256Update(&ctx, (const uint8_t*)&local_mc, sizeof(local_mc));
    lib_SHA256Final(&ctx, out);
}

// Open via LibOS VFS (-> chroot_encrypted -> PF), read+verify magic+checksum.
// Returns 0 on OK, -2 on ENOENT (fresh install), -1 on other errors.
int crisp_vault_load(crisp_vault_t* out) {
    g_in_crisp_io = true;

    struct libos_handle* hdl = get_new_handle();
    if (!hdl) {
        g_in_crisp_io = false;
        return -1;
    }

    int ret = open_namei(hdl, /*start=*/NULL, g_crisp.vault_path,
                         O_RDONLY, /*mode=*/0, /*found=*/NULL);
    if (ret < 0) {
        put_handle(hdl);
        g_in_crisp_io = false;
        if (ret == -ENOENT) {
            log_debug("crisp_vault_load: no vault (fresh install)");
            return -2;
        }
        log_error("crisp_vault_load: open failed: %d", ret);
        return -1;
    }

    ssize_t nread = do_handle_read(hdl, out, sizeof(crisp_vault_t));
    put_handle(hdl);
    g_in_crisp_io = false;

    if (nread < (ssize_t)sizeof(crisp_vault_t)) {
        log_error("crisp_vault_load: short read (%ld bytes)", nread);
        return -1;
    }

    if (memcmp(out->magic, CRISP_VAULT_MAGIC, 4) != 0) {
        log_error("crisp_vault_load: bad magic");
        return -1;
    }

    uint8_t expected[32];
    compute_checksum(out->tag, out->local_mc, expected);
    if (memcmp(out->checksum, expected, 32) != 0) {
        log_error("crisp_vault_load: checksum mismatch");
        return -1;
    }

    log_debug("crisp_vault_load: OK, L=%lu", out->local_mc);
    return 0;
}

// Build vault struct, write to .tmp via LibOS VFS, flush PF, atomic rename.
int crisp_vault_save(const uint8_t* tag, uint64_t local_mc) {
    crisp_vault_t v;
    memcpy(v.magic, CRISP_VAULT_MAGIC, 4);
    memcpy(v.tag, tag, CRISP_TAG_SIZE);
    v.local_mc = local_mc;
    compute_checksum(tag, local_mc, v.checksum);

    g_in_crisp_io = true;

    char tmp_path[260];
    snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", g_crisp.vault_path);

    struct libos_handle* hdl = get_new_handle();
    if (!hdl) {
        g_in_crisp_io = false;
        return -1;
    }

    int ret = open_namei(hdl, /*start=*/NULL, tmp_path,
                         O_WRONLY | O_CREAT | O_TRUNC, /*mode=*/0600,
                         /*found=*/NULL);
    if (ret < 0) {
        put_handle(hdl);
        g_in_crisp_io = false;
        log_error("crisp_vault_save: tmp open failed: %d", ret);
        return -1;
    }

    ssize_t written = do_handle_write(hdl, &v, sizeof(v));
    if (written < (ssize_t)sizeof(v)) {
        put_handle(hdl);
        g_in_crisp_io = false;
        log_error("crisp_vault_save: short write (%ld)", written);
        return -1;
    }

    // Force PF metadata to disk; if flush fails, do not rename over real vault.
    if (hdl->fs && hdl->fs->fs_ops && hdl->fs->fs_ops->flush) {
        ret = hdl->fs->fs_ops->flush(hdl);
        if (ret < 0) {
            put_handle(hdl);
            g_in_crisp_io = false;
            log_error("crisp_vault_save: flush failed: %d", ret);
            return -1;
        }
    }
    put_handle(hdl);

    // Inline rename: replicate do_rename without going through libos_syscall_renameat.
    lock(&g_dcache_lock);

    struct libos_dentry* old_dent = NULL;
    struct libos_dentry* new_dent = NULL;

    ret = path_lookupat(/*start=*/NULL, tmp_path, LOOKUP_NO_FOLLOW, &old_dent);
    if (ret < 0 || !old_dent || !old_dent->inode) {
        if (old_dent) put_dentry(old_dent);
        unlock(&g_dcache_lock);
        g_in_crisp_io = false;
        log_error("crisp_vault_save: tmp lookup failed: %d", ret);
        return -1;
    }

    ret = path_lookupat(/*start=*/NULL, g_crisp.vault_path,
                       LOOKUP_NO_FOLLOW | LOOKUP_CREATE, &new_dent);
    if (ret < 0) {
        put_dentry(old_dent);
        unlock(&g_dcache_lock);
        g_in_crisp_io = false;
        log_error("crisp_vault_save: vault lookup failed: %d", ret);
        return -1;
    }

    struct libos_fs* fs = old_dent->inode->fs;
    if (!fs || !fs->d_ops || !fs->d_ops->rename) {
        ret = -EPERM;
    } else {
        ret = fs->d_ops->rename(old_dent, new_dent);
        if (ret == 0) {
            if (new_dent->inode)
                put_inode(new_dent->inode);
            new_dent->inode = old_dent->inode;
            old_dent->inode = NULL;
        }
    }

    put_dentry(old_dent);
    put_dentry(new_dent);
    unlock(&g_dcache_lock);
    g_in_crisp_io = false;

    if (ret < 0) {
        log_error("crisp_vault_save: rename failed: %d", ret);
        return -1;
    }

    log_debug("crisp_vault_save: OK, L=%lu", local_mc);
    return 0;
}
