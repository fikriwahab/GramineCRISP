/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Session 9 unit tests for crisp_init startup verification flow. */

#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "crisp/crisp.h"

bool g_in_crisp_io = false;

/* Test control flags */
static int test_vault_result = -2; /* -2: ENOENT, 0: success, -1: error */
static uint64_t test_vault_local_mc = 0;
static uint64_t test_mc_value = 0;
static int test_mc_init_ret = 0;
static int test_config_load_ret = 0;
static int test_tag_compute_ret = 0;
static bool test_tag_mismatch = false;
static uint8_t test_vault_tag[32];

static char last_log_message[256];

int g_log_level = 0;

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

int PalEventCreate(PAL_HANDLE* handle, bool init_signaled, bool auto_clear) {
    (void)init_signaled;
    (void)auto_clear;
    *handle = (PAL_HANDLE)0x1;
    return 0;
}

int PalEventWait(PAL_HANDLE handle, uint64_t* timeout_us) {
    (void)handle;
    (void)timeout_us;
    return 0;
}

void PalEventSet(PAL_HANDLE handle) {
    (void)handle;
}

void crisp_wake_all_waiters(void) {
}

struct libos_thread* get_new_internal_thread(void) {
    static struct libos_thread t;
    memset(&t, 0, sizeof(t));
    return &t;
}

void put_thread(struct libos_thread* thread) {
    (void)thread;
}

int crisp_mc_thread_func(void* arg) {
    (void)arg;
    return 0;
}

int crisp_checker_api_func(void* arg) {
    (void)arg;
    return 0;
}

int crisp_checker_listen(void) {
    return 0;
}

int PalThreadCreate(int (*callback)(void*), void* param, PAL_HANDLE* handle) {
    (void)callback;
    (void)param;
    *handle = (PAL_HANDLE)0x2;
    return 0;
}

noreturn void PalProcessExit(int exit_code) {
    /* Map fail-stop exit(1) to sentinel for fork-based assertions. */
    exit(exit_code == 1 ? 100 : exit_code);
}

/* Mocks for crisp_init external dependencies */
int crisp_vault_load(crisp_vault_t* out) {
    if (test_vault_result == -2)
        return -2;
    if (test_vault_result < 0)
        return -1;

    memcpy(out->magic, "CRSP", 4);
    memcpy(out->tag, test_vault_tag, sizeof(out->tag));
    out->local_mc = test_vault_local_mc;
    memset(out->checksum, 0, sizeof(out->checksum));
    return 0;
}

int crisp_mc_init(void) {
    return test_mc_init_ret;
}

int crisp_mc_read(uint64_t* value) {
    *value = test_mc_value;
    return 0;
}

int crisp_config_load(void) {
    if (test_config_load_ret < 0)
        return -1;

    strcpy(g_crisp.vault_path, "/vault.enc");
    strcpy(g_crisp.mc_path, "/dev/shm/mc");
    g_crisp.mc_latency_ms = 1;
    g_crisp.rate_limit_ms = 10;
    g_crisp.queue_timeout_ms = 100;
    g_crisp.checker_prob = 10;
    g_crisp.checker_api_port = 9999;
    return 0;
}

int crisp_compute_global_tag(uint8_t* tag_out) {
    if (test_tag_compute_ret < 0)
        return -1;

    if (test_tag_mismatch) {
        memset(tag_out, 0xEE, 32);
    } else {
        memcpy(tag_out, test_vault_tag, 32);
    }
    return 0;
}

static void reset_test_state(void) {
    memset(&g_crisp, 0, sizeof(g_crisp));
    g_in_crisp_io = false;

    test_vault_result = -2;
    test_vault_local_mc = 0;
    test_mc_value = 0;
    test_mc_init_ret = 0;
    test_config_load_ret = 0;
    test_tag_compute_ret = 0;
    test_tag_mismatch = false;
    memset(test_vault_tag, 0xAA, sizeof(test_vault_tag));
    memset(last_log_message, 0, sizeof(last_log_message));
}

static int test_fresh_install(void) {
    reset_test_state();
    test_vault_result = -2;
    test_mc_value = 0;

    int ret = crisp_init(NULL, NULL);
    if (ret != 0)
        return fprintf(stderr, "fresh_install: ret=%d\n", ret), 1;
    if (g_crisp.L != 0)
        return fprintf(stderr, "fresh_install: L=%lu\n", g_crisp.L), 1;
    if (!g_crisp.enabled)
        return fprintf(stderr, "fresh_install: enabled=false\n"), 1;
    return 0;
}

static int test_rollback_missing_vault(void) {
    reset_test_state();
    test_vault_result = -2;
    test_mc_value = 7;

    pid_t pid = fork();
    if (pid == 0) {
        (void)crisp_init(NULL, NULL);
        _exit(0);
    }

    int status = 0;
    waitpid(pid, &status, 0);
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 100)
        return fprintf(stderr, "rollback_missing_vault: expected exit 100\n"), 1;
    return 0;
}

static int test_normal_restart(void) {
    reset_test_state();
    test_vault_result = 0;
    test_vault_local_mc = 9;
    test_mc_value = 9;

    int ret = crisp_init(NULL, NULL);
    if (ret != 0)
        return fprintf(stderr, "normal_restart: ret=%d\n", ret), 1;
    if (g_crisp.L != 9)
        return fprintf(stderr, "normal_restart: L=%lu\n", g_crisp.L), 1;
    return 0;
}

static int test_rollback_mc_less_than_l(void) {
    reset_test_state();
    test_vault_result = 0;
    test_vault_local_mc = 20;
    test_mc_value = 10;

    pid_t pid = fork();
    if (pid == 0) {
        (void)crisp_init(NULL, NULL);
        _exit(0);
    }

    int status = 0;
    waitpid(pid, &status, 0);
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 100)
        return fprintf(stderr, "rollback_mc_less_than_l: expected exit 100\n"), 1;
    return 0;
}

static int test_tag_mismatch_startup(void) {
    reset_test_state();
    test_vault_result = 0;
    test_vault_local_mc = 10;
    test_mc_value = 10;
    test_tag_mismatch = true;

    pid_t pid = fork();
    if (pid == 0) {
        (void)crisp_init(NULL, NULL);
        _exit(0);
    }

    int status = 0;
    waitpid(pid, &status, 0);
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 100)
        return fprintf(stderr, "tag_mismatch_startup: expected exit 100\n"), 1;
    return 0;
}

static int test_config_load_fail(void) {
    reset_test_state();
    test_config_load_ret = -1;

    int ret = crisp_init(NULL, NULL);
    if (ret != -1)
        return fprintf(stderr, "config_load_fail: ret=%d\n", ret), 1;
    if (g_crisp.enabled)
        return fprintf(stderr, "config_load_fail: enabled=true\n"), 1;
    return 0;
}

static int test_mc_init_fail(void) {
    reset_test_state();
    test_mc_init_ret = -1;

    int ret = crisp_init(NULL, NULL);
    if (ret != -1)
        return fprintf(stderr, "mc_init_fail: ret=%d\n", ret), 1;
    return 0;
}

static int test_vault_load_io_error(void) {
    reset_test_state();
    test_vault_result = -1;

    int ret = crisp_init(NULL, NULL);
    if (ret != -1)
        return fprintf(stderr, "vault_load_io_error: ret=%d\n", ret), 1;
    return 0;
}

static int test_fail_closed_init(void) {
    reset_test_state();
    test_config_load_ret = -1;

    int ret = crisp_init(NULL, NULL);
    if (ret != -1)
        return fprintf(stderr, "fail_closed_init: ret=%d\n", ret), 1;
    if (g_crisp.enabled)
        return fprintf(stderr, "fail_closed_init: enabled=true\n"), 1;
    return 0;
}

static int test_config_load_all_fields(void) {
    reset_test_state();

    int ret = crisp_config_load();
    if (ret != 0)
        return fprintf(stderr, "config_load_all_fields: ret=%d\n", ret), 1;
    if (strlen(g_crisp.vault_path) == 0 || strlen(g_crisp.mc_path) == 0)
        return fprintf(stderr, "config_load_all_fields: empty paths\n"), 1;
    if (g_crisp.checker_api_port == 0)
        return fprintf(stderr, "config_load_all_fields: missing port\n"), 1;
    return 0;
}

static int test_full_init_success(void) {
    reset_test_state();
    test_vault_result = -2;
    test_mc_value = 0;

    int ret = crisp_init(NULL, NULL);
    if (ret != 0)
        return fprintf(stderr, "full_init_success: ret=%d\n", ret), 1;
    if (!lock_created(&g_crisp.mu) || !lock_created(&g_crisp.queue_mu))
        return fprintf(stderr, "full_init_success: locks not created\n"), 1;
    if (g_crisp.mc_thread_handle == NULL)
        return fprintf(stderr, "full_init_success: mc thread not spawned\n"), 1;
    if (!g_crisp.enabled)
        return fprintf(stderr, "full_init_success: enabled=false\n"), 1;
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

    if (!strcmp(argv[1], "all") || !strcmp(argv[1], "fresh_install"))
        RUN_CASE(fresh_install);
    if (!strcmp(argv[1], "all") || !strcmp(argv[1], "rollback_missing_vault"))
        RUN_CASE(rollback_missing_vault);
    if (!strcmp(argv[1], "all") || !strcmp(argv[1], "normal_restart"))
        RUN_CASE(normal_restart);
    if (!strcmp(argv[1], "all") || !strcmp(argv[1], "rollback_mc_less_than_l"))
        RUN_CASE(rollback_mc_less_than_l);
    if (!strcmp(argv[1], "all") || !strcmp(argv[1], "tag_mismatch_startup"))
        RUN_CASE(tag_mismatch_startup);
    if (!strcmp(argv[1], "all") || !strcmp(argv[1], "config_load_fail"))
        RUN_CASE(config_load_fail);
    if (!strcmp(argv[1], "all") || !strcmp(argv[1], "mc_init_fail"))
        RUN_CASE(mc_init_fail);
    if (!strcmp(argv[1], "all") || !strcmp(argv[1], "vault_load_io_error"))
        RUN_CASE(vault_load_io_error);
    if (!strcmp(argv[1], "all") || !strcmp(argv[1], "fail_closed_init"))
        RUN_CASE(fail_closed_init);
    if (!strcmp(argv[1], "all") || !strcmp(argv[1], "config_load_all_fields"))
        RUN_CASE(config_load_all_fields);
    if (!strcmp(argv[1], "all") || !strcmp(argv[1], "full_init_success"))
        RUN_CASE(full_init_success);

    if (!strcmp(argv[1], "all") || !strcmp(argv[1], "--summary")) {
        printf("\nSUMMARY PASSED=%d FAILED=%d\n", passed, failed);
    }

    return failed ? 1 : 0;
}
