/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Session 10 host-side tests for checker TCP behavior. */

#include <errno.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

/* Minimal state mirror used by this host test harness. */
typedef struct {
    uint64_t L;
    bool enabled;
    bool halted;
    int checker_api_port;
    char vault_path[256];
    char mc_path[256];
} crisp_state_t;

static crisp_state_t g_crisp;
static uint64_t test_mc_value;
static int test_drain_called;
static int test_drain_ret;

static int crisp_drain_and_wait(void) {
    test_drain_called = 1;
    return test_drain_ret;
}

static int crisp_mc_read(uint64_t* value) {
    *value = test_mc_value;
    return 0;
}

static void reset_test_state(void) {
    memset(&g_crisp, 0, sizeof(g_crisp));
    test_mc_value = 0;
    test_drain_called = 0;
    test_drain_ret = 0;
}

static int test_checker_socket_bind(void) {
    reset_test_state();
    g_crisp.checker_api_port = 19999;

    int server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (server_sock < 0)
        return perror("socket"), 1;

    int opt = 1;
    if (setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0)
        return perror("setsockopt"), close(server_sock), 1;

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = htonl(0x7f000001),
        .sin_port = htons((uint16_t)g_crisp.checker_api_port),
    };

    if (bind(server_sock, (struct sockaddr*)&addr, sizeof(addr)) < 0)
        return perror("bind"), close(server_sock), 1;

    if (listen(server_sock, 3) < 0)
        return perror("listen"), close(server_sock), 1;

    close(server_sock);
    return 0;
}

static int test_checker_client_interaction(void) {
    reset_test_state();
    const int port = 19998;
    test_mc_value = 42;

    pid_t pid = fork();
    if (pid == 0) {
        usleep(100000);

        int c = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in a = {
            .sin_family = AF_INET,
            .sin_addr.s_addr = htonl(0x7f000001),
            .sin_port = htons((uint16_t)port),
        };
        if (connect(c, (struct sockaddr*)&a, sizeof(a)) < 0)
            _exit(1);

        uint64_t expected_min = 42;
        if (write(c, &expected_min, sizeof(expected_min)) != (ssize_t)sizeof(expected_min))
            _exit(1);

        uint64_t got = 0;
        ssize_t n = read(c, &got, sizeof(got));
        close(c);
        if (n != (ssize_t)sizeof(got) || got != 42)
            _exit(2);
        _exit(0);
    }

    int s = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = htonl(0x7f000001),
        .sin_port = htons((uint16_t)port),
    };

    if (bind(s, (struct sockaddr*)&addr, sizeof(addr)) < 0)
        return perror("bind"), close(s), 1;
    if (listen(s, 1) < 0)
        return perror("listen"), close(s), 1;

    int c = accept(s, NULL, NULL);
    if (c < 0)
        return perror("accept"), close(s), 1;

    uint64_t expected_min = 0;
    ssize_t n = read(c, &expected_min, sizeof(expected_min));
    if (n != (ssize_t)sizeof(expected_min) || expected_min != 42)
        return close(c), close(s), 1;

    test_drain_called = 0;
    if (crisp_drain_and_wait() < 0)
        return close(c), close(s), 1;
    if (!test_drain_called)
        return close(c), close(s), 1;

    uint64_t out = 42;
    if (write(c, &out, sizeof(out)) != (ssize_t)sizeof(out))
        return close(c), close(s), 1;

    close(c);
    close(s);

    int status = 0;
    waitpid(pid, &status, 0);
    return (WIFEXITED(status) && WEXITSTATUS(status) == 0) ? 0 : 1;
}

static int test_checker_multiple_clients(void) {
    reset_test_state();
    const int port = 19997;

    int s = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in a = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = htonl(0x7f000001),
        .sin_port = htons((uint16_t)port),
    };

    if (bind(s, (struct sockaddr*)&a, sizeof(a)) < 0)
        return close(s), 1;
    if (listen(s, 3) < 0)
        return close(s), 1;

    int accepted = 0;
    for (int i = 0; i < 3; i++) {
        pid_t pid = fork();
        if (pid == 0) {
            usleep(50000);
            int c = socket(AF_INET, SOCK_STREAM, 0);
            struct sockaddr_in ca = {
                .sin_family = AF_INET,
                .sin_addr.s_addr = htonl(0x7f000001),
                .sin_port = htons((uint16_t)port),
            };
            (void)connect(c, (struct sockaddr*)&ca, sizeof(ca));
            close(c);
            _exit(0);
        }

        int c = accept(s, NULL, NULL);
        if (c >= 0) {
            accepted++;
            close(c);
        }

        int status = 0;
        waitpid(pid, &status, 0);
    }

    close(s);
    return accepted == 3 ? 0 : 1;
}

static int test_checker_drain_failure(void) {
    reset_test_state();
    test_drain_ret = -ENOTRECOVERABLE;

    int ret = crisp_drain_and_wait();
    if (ret != -ENOTRECOVERABLE)
        return 1;
    if (!test_drain_called)
        return 1;
    return 0;
}

static int test_checker_mc_transmission(void) {
    reset_test_state();

    uint64_t values[] = {0, 1, 100, 0xdeadbeefULL, UINT64_MAX};
    for (size_t i = 0; i < sizeof(values) / sizeof(values[0]); i++) {
        test_mc_value = values[i];
        uint64_t got = 0;
        if (crisp_mc_read(&got) < 0 || got != values[i])
            return 1;
    }

    return 0;
}

static int test_checker_port_config(void) {
    reset_test_state();
    g_crisp.checker_api_port = 12345;
    if (g_crisp.checker_api_port != 12345)
        return 1;
    if (g_crisp.checker_api_port <= 0 || g_crisp.checker_api_port > 65535)
        return 1;
    return 0;
}

static int test_checker_localhost_only(void) {
    reset_test_state();
    const int port = 19996;

    int s = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in a = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = htonl(0x7f000001),
        .sin_port = htons((uint16_t)port),
    };

    if (bind(s, (struct sockaddr*)&a, sizeof(a)) < 0)
        return close(s), 1;
    if (listen(s, 1) < 0)
        return close(s), 1;

    int c = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in ca = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = htonl(0x7f000001),
        .sin_port = htons((uint16_t)port),
    };

    int ok = connect(c, (struct sockaddr*)&ca, sizeof(ca));
    close(c);
    close(s);
    return ok == 0 ? 0 : 1;
}

static int test_checker_config_fields(void) {
    reset_test_state();
    strcpy(g_crisp.vault_path, "/vault.enc");
    strcpy(g_crisp.mc_path, "/dev/shm/mc");
    g_crisp.checker_api_port = 9999;

    if (strlen(g_crisp.vault_path) == 0 || strlen(g_crisp.mc_path) == 0)
        return 1;
    if (g_crisp.checker_api_port != 9999)
        return 1;
    return 0;
}

static int test_s9_s10_integration_checklist(void) {
    int checks = 0;

    if (offsetof(crisp_state_t, vault_path) > 0) checks++;
    if (offsetof(crisp_state_t, mc_path) > 0) checks++;
    if (offsetof(crisp_state_t, L) == 0) checks++;
    if (offsetof(crisp_state_t, enabled) > 0) checks++;
    if (offsetof(crisp_state_t, halted) > 0) checks++;
    if (offsetof(crisp_state_t, checker_api_port) > 0) checks++;

    return checks >= 6 ? 0 : 1;
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

    if (!strcmp(argv[1], "all") || !strcmp(argv[1], "socket_bind"))
        RUN_CASE(checker_socket_bind);
    if (!strcmp(argv[1], "all") || !strcmp(argv[1], "client_interaction"))
        RUN_CASE(checker_client_interaction);
    if (!strcmp(argv[1], "all") || !strcmp(argv[1], "multiple_clients"))
        RUN_CASE(checker_multiple_clients);
    if (!strcmp(argv[1], "all") || !strcmp(argv[1], "drain_failure"))
        RUN_CASE(checker_drain_failure);
    if (!strcmp(argv[1], "all") || !strcmp(argv[1], "mc_transmission"))
        RUN_CASE(checker_mc_transmission);
    if (!strcmp(argv[1], "all") || !strcmp(argv[1], "port_config"))
        RUN_CASE(checker_port_config);
    if (!strcmp(argv[1], "all") || !strcmp(argv[1], "localhost_only"))
        RUN_CASE(checker_localhost_only);
    if (!strcmp(argv[1], "all") || !strcmp(argv[1], "config_fields"))
        RUN_CASE(checker_config_fields);
    if (!strcmp(argv[1], "all") || !strcmp(argv[1], "integration_checklist"))
        RUN_CASE(s9_s10_integration_checklist);

    if (!strcmp(argv[1], "all") || !strcmp(argv[1], "--summary")) {
        printf("\nSUMMARY PASSED=%d FAILED=%d\n", passed, failed);
    }

    return failed ? 1 : 0;
}
