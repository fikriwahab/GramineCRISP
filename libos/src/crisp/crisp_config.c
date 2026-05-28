/* SPDX-License-Identifier: LGPL-3.0-or-later */
// Manifest config loader (sgx.crisp.* keys), fail-closed: any parse or range error when
// sgx.crisp.enabled = true aborts CRISP init rather than silently disabling protection

#include <stdint.h>
#include <string.h>

#include "api.h"
#include "libos_internal.h"
#include "libos_utils.h"
#include "toml.h"
#include "toml_utils.h"

#include "crisp.h"

// generous overflow-safe ceiling for the *_ms tuning fields (one week in ms, so the * 1000 to us is safe)
#define CRISP_MS_MAX (7LL * 24 * 3600 * 1000)

// parse an integer key into [0, max], returns 0 (an absent key gives *out = def), -1 on a bad or out-of-range value
static int load_int(const char* key, int64_t def, int64_t max, int64_t* out) {
    if (toml_int_in(g_manifest_root, key, def, out) < 0 || *out < 0 || *out > max) {
        log_error("crisp_config: %s must be an integer in [0, %ld]", key, max);
        return -1;
    }
    return 0;
}

// copy a string key into a fixed buffer, returns -1 on a bad value or truncation, 0 otherwise (incl. absent)
static int load_str(const char* key, char* dst, size_t dstsz) {
    char* s = NULL;
    if (toml_string_in(g_manifest_root, key, &s) < 0) {
        log_error("crisp_config: %s is not a valid string", key);
        return -1;
    }
    if (s) {
        int wr = snprintf(dst, dstsz, "%s", s);
        free(s);
        if (wr < 0 || (size_t)wr >= dstsz) {
            log_error("crisp_config: %s is too long", key);
            return -1;
        }
    }
    return 0;
}

// parse the required sgx.crisp.tracked_pfs array (non-empty, each entry a non-empty path string) into g_crisp
// called only when CRISP is enabled, so the list is mandatory, returns 0 on success, -1 on any problem
static int load_tracked_pfs(void) {
    // CRISP is enabled here, so tracked_pfs is mandatory; toml_array_in returns NULL for both
    // an absent key and a wrong-typed value, and either one is a config error
    toml_table_t* sgx = toml_table_in(g_manifest_root, "sgx");
    toml_table_t* crisp = sgx ? toml_table_in(sgx, "crisp") : NULL;
    toml_array_t* arr = crisp ? toml_array_in(crisp, "tracked_pfs") : NULL;
    if (!arr) {
        log_error("crisp_config: sgx.crisp.tracked_pfs is required and must be a non-empty array of path strings");
        return -1;
    }
    int n = toml_array_nelem(arr);
    if (n <= 0) {
        log_error("crisp_config: sgx.crisp.tracked_pfs must be a non-empty array");
        return -1;
    }
    char** paths = malloc((size_t)n * sizeof(char*));
    if (!paths)
        return -1;
    for (int i = 0; i < n; i++) {
        toml_datum_t d = toml_string_at(arr, i);
        const char* err = NULL;
        if (!d.ok)
            err = "is not a string";
        else if (d.u.s[0] == '\0')
            err = "is an empty string";
        if (err) {
            log_error("crisp_config: sgx.crisp.tracked_pfs[%d] %s", i, err);
            if (d.ok)
                free(d.u.s);
            for (int j = 0; j < i; j++)
                free(paths[j]);
            free(paths);
            return -1;
        }
        paths[i] = d.u.s;  // tomlc99 mallocs this, ownership passes to g_crisp
    }
    g_crisp.pf_paths = paths;
    g_crisp.pf_count = n;
    return 0;
}

// load CRISP config from the manifest's sgx.crisp.* keys
// returns 1 if sgx.crisp.enabled = true (CRISP should run), 0 if not enabled, -1 on a parse/range error
int crisp_config_load(void) {
    if (!g_manifest_root)
        return 0;

    bool enabled = false;
    if (toml_bool_in(g_manifest_root, "sgx.crisp.enabled", false, &enabled) < 0) {
        log_error("crisp_config: sgx.crisp.enabled is not a valid boolean");
        return -1;
    }
    g_crisp.manifest_enabled = enabled;
    if (!enabled)
        return 0;

    int64_t v;
    if (load_int("sgx.crisp.mc_latency_ms", 0, CRISP_MS_MAX, &v) < 0)
        return -1;
    g_crisp.mc_latency_ms = (uint64_t)v;
    if (load_int("sgx.crisp.rate_limit_ms", 0, CRISP_MS_MAX, &v) < 0)
        return -1;
    g_crisp.rate_limit_ms = (uint64_t)v;
    if (load_int("sgx.crisp.queue_timeout_ms", 0, CRISP_MS_MAX, &v) < 0)  // disabled by default
        return -1;
    g_crisp.queue_timeout_ms = (uint64_t)v;
    if (load_int("sgx.crisp.checker_prob", 0, 100, &v) < 0)
        return -1;
    g_crisp.checker_prob = (int)v;
    if (load_int("sgx.crisp.checker_api_port", 0, 65535, &v) < 0)
        return -1;
    g_crisp.checker_api_port = (int)v;

    bool profile = false;
    if (toml_bool_in(g_manifest_root, "sgx.crisp.profile", false, &profile) < 0) {
        log_error("crisp_config: sgx.crisp.profile is not a valid boolean");
        return -1;
    }
    g_crisp.profile_enabled = profile;
// TODO: replace numeric mode values with named constants (CRISP_MODE_*) once defined.    
    char* mode = NULL;
    if (toml_string_in(g_manifest_root, "sgx.crisp.mode", &mode) < 0) {
        log_error("crisp_config: sgx.crisp.mode is not a valid string");
        return -1;
    }

    if (mode) {
        if (strcmp(mode, "optimistic") == 0)
            g_crisp.mode = 0;
        else if (strcmp(mode, "synchronous") == 0)
            g_crisp.mode = 1;
        else if (strcmp(mode, "checker") == 0)
            g_crisp.mode = 2;
        else {
            log_error("crisp_config: sgx.crisp.mode must be one of optimistic|synchronous|checker");
            free(mode);
            return -1;
        }
        free(mode);
    } else {
        g_crisp.mode = 1;  // default to synchronous, the more pessimistic and security-first choice
    }

    if (load_str("sgx.crisp.vault_path", g_crisp.vault_path, sizeof(g_crisp.vault_path)) < 0)
        return -1;
    if (g_crisp.vault_path[0] == '\0') {
        log_error("crisp_config: sgx.crisp.vault_path is required when sgx.crisp.enabled = true");
        return -1;
    }
    if (load_str("sgx.crisp.mc_path", g_crisp.mc_path, sizeof(g_crisp.mc_path)) < 0)
        return -1;
    if (g_crisp.mc_path[0] == '\0') {
        log_error("crisp_config: sgx.crisp.mc_path is required when sgx.crisp.enabled = true");
        return -1;
    }

    if (load_tracked_pfs() < 0)
        return -1;

    // the vault must not sit on (or share a .tmp name with) a tracked PF, otherwise CRISP clobbers
    // the app's data when it writes the vault, then fail-stops on a tag mismatch at the next restart
    char vault_tmp[300];
    snprintf(vault_tmp, sizeof(vault_tmp), "%s.tmp", g_crisp.vault_path);
    for (int i = 0; i < g_crisp.pf_count; i++) {
        if (strcmp(g_crisp.pf_paths[i], g_crisp.vault_path) == 0 ||
            strcmp(g_crisp.pf_paths[i], vault_tmp) == 0) {
            log_error("crisp_config: sgx.crisp.vault_path (or its .tmp) collides with tracked PF %s",
                      g_crisp.pf_paths[i]);
            return -1;
        }
    }

    return 1;
}
