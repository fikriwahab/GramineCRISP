#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

#include "crisp/crisp.h"

// Provide the global state used by crisp_close.c 
crisp_state_t g_crisp = {0};
bool g_in_crisp_io = false;

static int drain_ret = 0;
static int flush_ret = 0;
static int failstop_called = 0;
static int failstop_exit_code = 100;

int crisp_drain_and_wait(void) {
    return drain_ret;
}

int crisp_flush_pf_by_path(const char* path) {
    (void)path;
    return flush_ret;
}

// terminate process with deterministic code.
noreturn void crisp_fail_stop(const char* reason) {
    fprintf(stderr, "CRISP_FAIL_STOP: %s\n", reason);
    failstop_called = 1;
    exit(failstop_exit_code);
}

int main(int argc, char** argv) {
    if (argc != 2) {
        fprintf(stderr,
                "usage: %s <disabled_close|enabled_close_ok|enabled_close_fail|exit_ok|exit_drain_fail|exit_flush_fail>\n",
                argv[0]);
        return 2;
    }

    if (strcmp(argv[1], "disabled_close") == 0) {
        g_crisp.enabled = false;
        drain_ret = -1;
        crisp_on_close();
        return 0;
    }

    if (strcmp(argv[1], "enabled_close_ok") == 0) {
        g_crisp.enabled = true;
        drain_ret = 0;
        crisp_on_close();
        return 0;
    }

    if (strcmp(argv[1], "enabled_close_fail") == 0) {
        g_crisp.enabled = true;
        drain_ret = -1;
        crisp_on_close();
        return 0;
    }

    if (strcmp(argv[1], "exit_flush_fail") == 0) {
        g_crisp.enabled = true;
        g_crisp.pf_count = 1;
        g_crisp.pf_paths = malloc(sizeof(char*));
        g_crisp.pf_paths[0] = malloc(16);
        strcpy(g_crisp.pf_paths[0], "dummy_pf");

        flush_ret = -1;
        drain_ret = 0;
        crisp_on_exit();

        free(g_crisp.pf_paths[0]);
        free(g_crisp.pf_paths);
        return 0;
    }

    if (strcmp(argv[1], "exit_ok") == 0) {
        g_crisp.enabled = true;
        g_crisp.pf_count = 1;
        g_crisp.pf_paths = malloc(sizeof(char*));
        g_crisp.pf_paths[0] = malloc(16);
        strcpy(g_crisp.pf_paths[0], "dummy_pf");

        flush_ret = 0;
        drain_ret = 0;
        crisp_on_exit();

        free(g_crisp.pf_paths[0]);
        free(g_crisp.pf_paths);
        return 0;
    }

    if (strcmp(argv[1], "exit_drain_fail") == 0) {
        g_crisp.enabled = true;
        g_crisp.pf_count = 1;
        g_crisp.pf_paths = malloc(sizeof(char*));
        g_crisp.pf_paths[0] = malloc(16);
        strcpy(g_crisp.pf_paths[0], "dummy_pf");

        flush_ret = 0;
        drain_ret = -1;
        crisp_on_exit();

        free(g_crisp.pf_paths[0]);
        free(g_crisp.pf_paths);
        return 0;
    }

    fprintf(stderr, "unknown case: %s\n", argv[1]);
    return 2;
}
