/* QEaaS entropy pool validation + CoAP integration test
 * Copyright (C) 2024-2025 Javier Blanco-Romero @fj-blanco (UC3M, QURSA project)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zephyr/kernel.h>
#include <zephyr/device.h>
#include <zephyr/drivers/entropy.h>
#include <zephyr/net/socket.h>
#include <zephyr/posix/unistd.h>
#include <coap3/coap.h>
#include "wifi.h"

#ifdef CONFIG_SOC_ESP32
#include <esp_timer.h>
#endif

/* High-resolution time source */
static inline uint64_t get_time_us(void) {
#ifdef CONFIG_SOC_ESP32
    return esp_timer_get_time();
#else
    return (uint64_t)k_uptime_get() * 1000ULL;
#endif
}

/* CoAP configuration */
#ifndef COAP_SERVER_IP
#define COAP_SERVER_IP "134.102.218.18"
#endif
#ifndef COAP_SERVER_PATH
#define COAP_SERVER_PATH "/hello"
#endif
#ifndef COAP_SERVER_PORT
#define COAP_SERVER_PORT COAP_DEFAULT_PORT
#endif
#define COAP_CLIENT_URI "coap://" COAP_SERVER_IP COAP_SERVER_PATH

/* Test configuration */
#define TEST_BUFFER_SIZE     64
#define TEST_SMALL_BUFFER    16
#define TEST_LARGE_BUFFER    256
#define TEST_ITERATIONS      10
#define QUANTUM_ENTROPY_SIZE 32
#define LATENCY_ITERATIONS   100

#define COLOR_GREEN   "\033[32m"
#define COLOR_RED     "\033[31m"
#define COLOR_RESET   "\033[0m"

/* Statistics */
static struct {
    uint32_t tests_passed;
    uint32_t tests_failed;
    uint32_t total_bytes_extracted;
    uint32_t total_quantum_bytes_added;
} stats = {0};

static bool quantum_pass = false;
static bool continuous_pass = false;
static bool boundary_pass = false;
static int coap_have_response = 0;

static bool buffer_has_data(const uint8_t *buf, size_t len) {
    uint8_t accum = 0;
    for (size_t i = 0; i < len; i++) accum |= buf[i];
    return accum != 0;
}

/* Entropy Tests */
static void test_multiple_extractions(const struct device *dev) {
    uint8_t buffer[TEST_SMALL_BUFFER];
    int failures = 0;
    printf("\nT1 multiple extractions\n");
    for (int i = 0; i < TEST_ITERATIONS; i++) {
        memset(buffer, 0, sizeof(buffer));
        if (entropy_get_entropy(dev, buffer, sizeof(buffer)) == 0 &&
            buffer_has_data(buffer, sizeof(buffer))) {
            stats.total_bytes_extracted += sizeof(buffer);
        } else {
            failures++;
        }
        k_msleep(10);
    }
    if (failures == 0) stats.tests_passed++; else stats.tests_failed++;
    printf("Result: %s (failures=%d)\n", failures == 0 ? "PASS" : "FAIL", failures);
}

static void test_quantum_injection(const struct device *dev) {
    uint8_t quantum_entropy[QUANTUM_ENTROPY_SIZE];
    uint8_t mixed_output[TEST_BUFFER_SIZE];
    printf("\nT2 quantum entropy injection\n");
    for (size_t i = 0; i < sizeof(quantum_entropy); i++)
        quantum_entropy[i] = (uint8_t)(k_cycle_get_32() & 0xFF);
    int ret = entropy_add_entropy(dev, quantum_entropy, sizeof(quantum_entropy),
                                  sizeof(quantum_entropy) * 8);
    if (ret == 0) {
        stats.total_quantum_bytes_added += sizeof(quantum_entropy);
        printf(COLOR_GREEN "✓" COLOR_RESET " Quantum entropy added\n");
        k_msleep(50);
        ret = entropy_get_entropy(dev, mixed_output, sizeof(mixed_output));
        if (ret == 0 && buffer_has_data(mixed_output, sizeof(mixed_output))) {
            printf(COLOR_GREEN "PASS" COLOR_RESET "\n");
            stats.tests_passed++;
            quantum_pass = true;
            stats.total_bytes_extracted += sizeof(mixed_output);
        } else {
            printf(COLOR_RED "FAIL (post-mix)" COLOR_RESET "\n");
            stats.tests_failed++;
        }
    } else {
        printf(COLOR_RED "FAIL (add ret=%d)" COLOR_RESET "\n", ret);
        stats.tests_failed++;
    }
}

static void test_continuous_operation(const struct device *dev) {
    uint8_t buffer[TEST_SMALL_BUFFER];
    int failures = 0;
    uint32_t start = k_uptime_get_32();
    printf("\nT3 continuous operation\n");
    for (int i = 0; i < 100; i++) {
        memset(buffer, 0, sizeof(buffer));
        if (entropy_get_entropy(dev, buffer, sizeof(buffer)) != 0 ||
            !buffer_has_data(buffer, sizeof(buffer))) {
            failures++;
        } else {
            stats.total_bytes_extracted += sizeof(buffer);
        }
    }
    uint32_t duration = k_uptime_get_32() - start;
    printf("100 blocks in %u ms, failures=%d\n", duration, failures);
    if (failures == 0) { stats.tests_passed++; continuous_pass = true; }
    else stats.tests_failed++;
    printf("Result: %s\n", failures == 0 ? "PASS" : "FAIL");
}

static void test_boundary_conditions(const struct device *dev) {
    uint8_t tiny[1], large[TEST_LARGE_BUFFER], b1[TEST_SMALL_BUFFER], b2[TEST_SMALL_BUFFER];
    int failures = 0;
    printf("\nT4 boundary conditions\n");
    memset(tiny, 0, 1);
    if (entropy_get_entropy(dev, tiny, 1) == 0 && tiny[0] != 0) {
        printf(" single-byte: OK\n");
        stats.total_bytes_extracted++;
    } else failures++;
    memset(large, 0, sizeof(large));
    if (entropy_get_entropy(dev, large, sizeof(large)) == 0 &&
        buffer_has_data(large, sizeof(large))) {
        printf(" large buffer: OK (%d bytes)\n", TEST_LARGE_BUFFER);
        stats.total_bytes_extracted += sizeof(large);
    } else failures++;
    memset(b1, 0, sizeof(b1)); memset(b2, 0, sizeof(b2));
    if (entropy_get_entropy(dev, b1, sizeof(b1)) == 0 &&
        entropy_get_entropy(dev, b2, sizeof(b2)) == 0 &&
        buffer_has_data(b1, sizeof(b1)) && buffer_has_data(b2, sizeof(b2))) {
        printf(" back-to-back: OK\n");
        stats.total_bytes_extracted += sizeof(b1) + sizeof(b2);
    } else failures++;
    if (failures == 0) { stats.tests_passed++; boundary_pass = true; }
    else stats.tests_failed++;
    printf("Result: %s\n", failures == 0 ? "PASS" : "FAIL");
}

static void test_entropy_latency(const struct device *dev) {
    uint8_t buffer[TEST_SMALL_BUFFER];
    uint64_t total_us = 0;
    int failures = 0;
    printf("\nT5 extraction latency\n");
    for (int i = 0; i < LATENCY_ITERATIONS; i++) {
        memset(buffer, 0, sizeof(buffer));
        uint64_t t0 = get_time_us();
        int ret = entropy_get_entropy(dev, buffer, sizeof(buffer));
        total_us += get_time_us() - t0;
        if (ret != 0 || !buffer_has_data(buffer, sizeof(buffer))) failures++;
        else stats.total_bytes_extracted += sizeof(buffer);
    }
    printf(" avg_us=%llu failures=%d\n", (unsigned long long)(total_us/LATENCY_ITERATIONS), failures);
    if (failures == 0) stats.tests_passed++; else stats.tests_failed++;
}

static void test_injection_latency(const struct device *dev) {
    uint8_t quantum[QUANTUM_ENTROPY_SIZE];
    uint64_t total_us = 0;
    int failures = 0;
    printf("\nT6 injection latency\n");
    for (int i = 0; i < LATENCY_ITERATIONS; i++) {
        for (size_t j = 0; j < sizeof(quantum); j++)
            quantum[j] = (uint8_t)(k_cycle_get_32() & 0xFF);
        uint64_t t0 = get_time_us();
        int ret = entropy_add_entropy(dev, quantum, sizeof(quantum), sizeof(quantum)*8);
        total_us += get_time_us() - t0;
        if (ret != 0) failures++;
        else stats.total_quantum_bytes_added += sizeof(quantum);
    }
    printf(" avg_us=%llu failures=%d\n", (unsigned long long)(total_us/LATENCY_ITERATIONS), failures);
    if (failures == 0) stats.tests_passed++; else stats.tests_failed++;
}

/* CoAP Test */
static coap_response_t coap_response_handler(coap_session_t *session,
                                             const coap_pdu_t *sent,
                                             const coap_pdu_t *received,
                                             const int id) {
    (void)session; (void)sent; (void)id;
    coap_have_response = 1;
    size_t len;
    const uint8_t *data;
    printf("\n=== CoAP RESPONSE ===\n");
    coap_show_pdu(COAP_LOG_WARN, received);
    if (coap_get_data_large(received, &len, &data, NULL, NULL)) {
        printf("Data: %.*s\n", (int)len, data);
    }
    printf("=== END ===\n");
    return COAP_RESPONSE_OK;
}

static int setup_coap_address(coap_address_t *dst, const char *host, uint16_t port) {
    memset(dst, 0, sizeof(coap_address_t));
    struct sockaddr_in *sin = (struct sockaddr_in *)&dst->addr.sin;
    sin->sin_family = AF_INET;
    sin->sin_port = htons(port);
    if (inet_pton(AF_INET, host, &sin->sin_addr) <= 0) return 0;
    dst->size = sizeof(struct sockaddr_in);
    dst->addr.sa.sa_family = AF_INET;
    return 1;
}

static int run_coap_test(void) {
    coap_context_t *ctx = NULL;
    coap_session_t *session = NULL;
    coap_optlist_t *optlist = NULL;
    coap_address_t dst;
    coap_pdu_t *pdu = NULL;
    coap_uri_t uri;
    unsigned char scratch[100];
    int result = -1;
    const char *coap_uri = COAP_CLIENT_URI;

    printf("\n=== CoAP Test ===\nURI: %s\n", coap_uri);
    coap_startup();
    coap_set_log_level(COAP_LOG_WARN);

    if (coap_split_uri((const unsigned char *)coap_uri, strlen(coap_uri), &uri) != 0) {
        printf("URI parse failed\n");
        goto finish;
    }

    char host[64];
    if (uri.host.length < sizeof(host)) {
        memcpy(host, uri.host.s, uri.host.length);
        host[uri.host.length] = '\0';
    } else goto finish;

    if (!setup_coap_address(&dst, host, uri.port ? uri.port : COAP_SERVER_PORT)) {
        printf("Address setup failed\n");
        goto finish;
    }

    if (!(ctx = coap_new_context(NULL))) {
        printf("Context creation failed\n");
        goto finish;
    }
    coap_context_set_block_mode(ctx, COAP_BLOCK_USE_LIBCOAP | COAP_BLOCK_SINGLE_BODY);

    if (!(session = coap_new_client_session(ctx, NULL, &dst, COAP_PROTO_UDP))) {
        printf("Session creation failed\n");
        goto finish;
    }
    coap_register_response_handler(ctx, coap_response_handler);

    pdu = coap_pdu_init(COAP_MESSAGE_CON, COAP_REQUEST_CODE_GET,
                        coap_new_message_id(session), coap_session_max_pdu_size(session));
    if (!pdu) goto finish;

    if (coap_uri_into_options(&uri, &dst, &optlist, 1, scratch, sizeof(scratch)) ||
        (optlist && !coap_add_optlist_pdu(pdu, &optlist))) {
        printf("Options failed\n");
        goto finish;
    }

    coap_show_pdu(COAP_LOG_WARN, pdu);
    if (coap_send(session, pdu) == COAP_INVALID_MID) {
        printf("Send failed\n");
        goto finish;
    }
    printf("Request sent, waiting...\n");

    unsigned int wait_ms = 5000;
    while (!coap_have_response && wait_ms > 0) {
        int res = coap_io_process(ctx, 500);
        if (res >= 0) wait_ms -= (res < (int)wait_ms) ? res : wait_ms;
    }

    result = coap_have_response ? 0 : -1;
    printf("CoAP test: %s\n", result == 0 ? "SUCCESS" : "TIMEOUT");

finish:
    if (optlist) coap_delete_optlist(optlist);
    if (session) coap_session_release(session);
    if (ctx) coap_free_context(ctx);
    coap_cleanup();
    return result;
}

int main(void) {
    printf("\n=== QEaaS Entropy Pool + CoAP Test ===\n");

    /* Entropy tests */
    const struct device *entropy_dev = DEVICE_DT_GET(DT_CHOSEN(zephyr_entropy));
    if (!device_is_ready(entropy_dev)) {
        printf(COLOR_RED "FATAL: Entropy device not ready\n" COLOR_RESET);
        return EXIT_FAILURE;
    }
    printf(COLOR_GREEN "✓ Entropy device: %s" COLOR_RESET "\n", entropy_dev->name);
    k_msleep(500);

    test_multiple_extractions(entropy_dev);
    test_quantum_injection(entropy_dev);
    test_continuous_operation(entropy_dev);
    test_boundary_conditions(entropy_dev);
    test_entropy_latency(entropy_dev);
    test_injection_latency(entropy_dev);

    printf("\nEntropy Summary: passed=%u failed=%u bytes=%u quantum=%u\n",
           stats.tests_passed, stats.tests_failed,
           stats.total_bytes_extracted, stats.total_quantum_bytes_added);

    bool entropy_ok = quantum_pass && continuous_pass && boundary_pass;
    printf("Entropy core: %s\n", entropy_ok ? COLOR_GREEN "PASS" COLOR_RESET : COLOR_RED "FAIL" COLOR_RESET);

    /* CoAP test */
    wifi_init(NULL);
    int wifi_ok = 0;
    for (int i = 1; i <= 3 && !wifi_ok; i++) {
        if (i > 1) printf("WiFi retry %d/3\n", i);
        if (connect_to_wifi() >= 0 && wait_for_wifi_connection() >= 0) wifi_ok = 1;
        else { wifi_disconnect(); k_sleep(K_MSEC(2000)); }
    }
    if (!wifi_ok) {
        printf("WiFi failed\n");
        return EXIT_FAILURE;
    }
    k_sleep(K_MSEC(1000));

    int coap_result = run_coap_test();
    wifi_disconnect();

    printf("\n=== FINAL RESULT ===\n");
    printf("Entropy: %s, CoAP: %s\n",
           entropy_ok ? "PASS" : "FAIL",
           coap_result == 0 ? "PASS" : "FAIL");

    return (entropy_ok && coap_result == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
