/* SPDX-License-Identifier: LGPL-3.0-or-later */
// Manifest config loader (sgx.crisp.* fields)

#include <stdint.h>
#include <string.h>

#include "api.h"
#include "libos_internal.h"
#include "libos_utils.h"
#include "toml.h"
#include "toml_utils.h"

#include "crisp.h"

// Load CRISP config from manifest sgx.crisp.* into g_crisp
// Scalar fields only; sgx.crisp.tracked_pfs array parse is TODO (caller sets
// g_crisp.pf_paths / pf_count directly until then)
// Returns 0 always: missing keys fall back to defaults
int crisp_config_load(void) {
    if (!g_manifest_root)
        return 0;

    int64_t v;

    toml_int_in(g_manifest_root, "sgx.crisp.mc_latency_ms", 0, &v);
    g_crisp.mc_latency_ms = (uint64_t)v;

    toml_int_in(g_manifest_root, "sgx.crisp.rate_limit_ms", 0, &v);
    g_crisp.rate_limit_ms = (uint64_t)v;

    toml_int_in(g_manifest_root, "sgx.crisp.queue_timeout_ms", 5000, &v);
    g_crisp.queue_timeout_ms = (uint64_t)v;

    toml_int_in(g_manifest_root, "sgx.crisp.checker_prob", 0, &v);
    g_crisp.checker_prob = (int)v;

    toml_int_in(g_manifest_root, "sgx.crisp.checker_api_port", 0, &v);
    g_crisp.checker_api_port = (int)v;

    char* s = NULL;
    if (toml_string_in(g_manifest_root, "sgx.crisp.vault_path", &s) == 0 && s) {
        snprintf(g_crisp.vault_path, sizeof(g_crisp.vault_path), "%s", s);
        free(s);
    }
    s = NULL;
    if (toml_string_in(g_manifest_root, "sgx.crisp.mc_path", &s) == 0 && s) {
        snprintf(g_crisp.mc_path, sizeof(g_crisp.mc_path), "%s", s);
        free(s);
    }

    // TODO sgx.crisp.tracked_pfs array parse (toml_array_in + toml_string_at + sort)

    return 0;
}
