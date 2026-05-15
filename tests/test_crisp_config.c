/* SPDX-License-Identifier: LGPL-3.0-or-later */
// unit tests for CRISP config parsing (sgx.crisp.mode)

#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "api.h"
#include "crisp/crisp.h"
#include "toml.h"

crisp_state_t g_crisp = {0};
const toml_table_t* g_manifest_root = NULL;

bool g_in_crisp_io = false;
int g_log_level = 0;

static char last_log_message[256];

void libos_log(int level, const char* file, const char* func, uint64_t line, const char* fmt, ...) {
    (void)level;
    (void)file;
    (void)func;
    (void)line;

    va_list ap;
    va_start(ap, fmt);
    vsnprintf(last_log_message, sizeof(last_log_message), fmt, ap);
    va_end(ap);
}

noreturn void libos_abort(void) {
    exit(101);
}

int parse_size_str(const char* str, uint64_t* out) {
    (void)str;
    (void)out;
    return -1;
}

static void reset_state(void) {
    memset(&g_crisp, 0, sizeof(g_crisp));
    memset(last_log_message, 0, sizeof(last_log_message));
    g_manifest_root = NULL;
}

static int load_with_mode(const char* mode_str, int* out_mode) {
    reset_state();

    char manifest[512];
    const char* base =
        "sgx.crisp.enabled = true\n"
        "sgx.crisp.vault_path = \"/cr/vault.dat\"\n"
        "sgx.crisp.mc_path = \"/tmp/mc\"\n"
        "sgx.crisp.tracked_pfs = [\"/cr/a.dat\"]\n"
        "sgx.crisp.checker_api_port = 1234\n";

    if (mode_str) {
        snprintf(manifest, sizeof(manifest), "%s%s%s%s",
                 base, "sgx.crisp.mode = \"", mode_str, "\"\n");
    } else {
        snprintf(manifest, sizeof(manifest), "%s", base);
    }

    char errbuf[200];
    toml_table_t* root = toml_parse(manifest, errbuf, sizeof(errbuf));
    if (!root) {
        fprintf(stderr, "toml_parse failed: %s\n", errbuf);
        return 1;
    }

    g_manifest_root = root;
    int ret = crisp_config_load();
    if (ret >= 0 && out_mode)
        *out_mode = g_crisp.mode;

    toml_free(root);
    g_manifest_root = NULL;
    return ret;
}

static int test_mode_default(void) {
    int mode = -1;
    int ret = load_with_mode(NULL, &mode);
    if (ret != 1 || mode != 0)
        return 1;
    return 0;
}

static int test_mode_optimistic(void) {
    int mode = -1;
    int ret = load_with_mode("optimistic", &mode);
    if (ret != 1 || mode != 0)
        return 1;
    return 0;
}

static int test_mode_synchronous(void) {
    int mode = -1;
    int ret = load_with_mode("synchronous", &mode);
    if (ret != 1 || mode != 1)
        return 1;
    return 0;
}

static int test_mode_checker(void) {
    int mode = -1;
    int ret = load_with_mode("checker", &mode);
    if (ret != 1 || mode != 2)
        return 1;
    return 0;
}

static int test_mode_invalid(void) {
    int mode = -1;
    int ret = load_with_mode("badvalue", &mode);
    if (ret != -1)
        return 1;
    return 0;
}

#define RUN_CASE(name) \
    do { \
        int rc = test_##name(); \
        if (rc == 0) { \
            printf("PASS %s\n", #name); \
            passed++; \
        } else { \
            printf("FAIL %s\n", #name); \
            failed++; \
        } \
    } while (0)

int main(int argc, char** argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <test-name|all>\n", argv[0]);
        return 1;
    }

    int passed = 0;
    int failed = 0;

    if (!strcmp(argv[1], "all") || !strcmp(argv[1], "mode_default"))
        RUN_CASE(mode_default);
    if (!strcmp(argv[1], "all") || !strcmp(argv[1], "mode_optimistic"))
        RUN_CASE(mode_optimistic);
    if (!strcmp(argv[1], "all") || !strcmp(argv[1], "mode_synchronous"))
        RUN_CASE(mode_synchronous);
    if (!strcmp(argv[1], "all") || !strcmp(argv[1], "mode_checker"))
        RUN_CASE(mode_checker);
    if (!strcmp(argv[1], "all") || !strcmp(argv[1], "mode_invalid"))
        RUN_CASE(mode_invalid);

    if (!strcmp(argv[1], "all") || !strcmp(argv[1], "--summary"))
        printf("\nSUMMARY PASSED=%d FAILED=%d\n", passed, failed);

    return failed ? 1 : 0;
}
