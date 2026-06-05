/* QEaaS Benchmark Client
 *
 * Post-quantum CoAP client with structured benchmark output for
 * entropy pool operations and full-cycle quantum entropy distribution.
 *
 * Copyright (C) 2018-2024 Olaf Bergmann <bergmann@tzi.org>
 * Copyright (C) 2024-2025 Javier Blanco-Romero @fj-blanco (UC3M, QURSA project)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zephyr/init.h>
#include <zephyr/kernel.h>
#include <zephyr/device.h>
#include <zephyr/drivers/entropy.h>
#include <zephyr/net/socket.h>
#include <zephyr/posix/unistd.h>
#include <zephyr/sys/slist.h>
#include <coap3/coap.h>
#include "wifi.h"

/* Include wolfSSL settings for compile-time feature detection */
#include <wolfssl/wolfcrypt/settings.h>

/* Embedded CA certificates for server verification.
 * Generated automatically by scripts/generate_ca_header.sh from
 * PEM files in qeaas-server/coap2http-proxy/certs/.
 * Omitted when SKIP_PEER_VERIFY is set. */
#ifndef SKIP_PEER_VERIFY
#include "ca_certs.h"
#endif

/* Heap runtime statistics for memory tracking */
#ifdef CONFIG_SYS_HEAP_RUNTIME_STATS
#include <zephyr/sys/sys_heap.h>
#include <zephyr/sys/mem_stats.h>
extern struct k_heap _system_heap;
#endif

/* ======================== Configuration ======================== */

/* CoAP proxy address (where the ESP32 connects via DTLS) */
#ifndef COAP_SERVER_IP
#define COAP_SERVER_IP "192.168.1.136"
#endif

#ifndef COAP_SERVER_PORT
#ifdef USE_DTLS
#define COAP_SERVER_PORT COAPS_DEFAULT_PORT
#else
#define COAP_SERVER_PORT COAP_DEFAULT_PORT
#endif
#endif

/* The Proxy-URI: the HTTP backend URL the proxy will curl.
 * Since the proxy runs on the same host (host network), use 127.0.0.1. */
#ifndef PROXY_BACKEND_URI
#define PROXY_BACKEND_URI "http://127.0.0.1:6065/random_number/8"
#endif

/* URI used to connect to the proxy (no path needed — we use Proxy-URI) */
#ifdef USE_DTLS
#define COAP_CLIENT_URI "coaps://" COAP_SERVER_IP
#else
#define COAP_CLIENT_URI "coap://" COAP_SERVER_IP
#endif

/* Benchmark parameters */
#define BENCH_ITERATIONS       100
#define BENCH_WARMUP           5
#define BENCH_ENTROPY_SIZES    {16, 32, 64, 128, 256}
#define NUM_ENTROPY_SIZES      5
#define QUANTUM_ENTROPY_SIZE   32
#define FULL_CYCLE_ITERATIONS 100

/* ======================== Benchmark Output Macros ======================== */
/* Structured output format: [BENCH] test,param,iteration,value_us */

#define BENCH_HEADER()     printf("\n[BENCH_START]\n")
#define BENCH_FOOTER()     printf("[BENCH_END]\n\n")
#define BENCH_RESULT(test, param, iter, us) \
    printf("[BENCH] %s,%d,%d,%llu\n", (test), (param), (iter), (unsigned long long)(us))
#define BENCH_META(key, val) \
    printf("[BENCH_META] %s,%s\n", (key), (val))

/* ======================== Heap Stats Helper ======================== */

static void report_heap_stats(const char *label)
{
#ifdef CONFIG_SYS_HEAP_RUNTIME_STATS
    struct sys_memory_stats stats;
    if (sys_heap_runtime_stats_get(&_system_heap.heap, &stats) == 0) {
        char buf[32];
        char meta_key[48];

        snprintf(meta_key, sizeof(meta_key), "heap_free_%s", label);
        snprintf(buf, sizeof(buf), "%zu", stats.free_bytes);
        BENCH_META(meta_key, buf);

        snprintf(meta_key, sizeof(meta_key), "heap_used_%s", label);
        snprintf(buf, sizeof(buf), "%zu", stats.allocated_bytes);
        BENCH_META(meta_key, buf);

        snprintf(meta_key, sizeof(meta_key), "heap_peak_%s", label);
        snprintf(buf, sizeof(buf), "%zu", stats.max_allocated_bytes);
        BENCH_META(meta_key, buf);
    }
#else
    (void)label;
#endif
}

/* ======================== Globals ======================== */

static int have_response = 0;
static uint8_t response_data[512];
static size_t response_data_len = 0;
static uint32_t coap_response_cycles = 0;

/* ======================== High-resolution Timing ======================== */
/*
 * Use raw hardware cycle counter for sub-microsecond precision.
 * ESP32 runs at 240 MHz → ~4.17 ns per cycle.
 * k_cycle_get_32() wraps every ~17.9s; unsigned subtraction handles wrapping.
 */
static inline uint32_t get_cycles(void)
{
    return k_cycle_get_32();
}

static inline uint32_t cycles_to_us(uint32_t start, uint32_t end)
{
    return k_cyc_to_us_floor32(end - start);
}

int setup_destination_address(coap_address_t *dst, const char *host,
                              uint16_t port) {
    memset(dst, 0, sizeof(coap_address_t));

    struct sockaddr_in *sin = (struct sockaddr_in *)&dst->addr.sin;
    sin->sin_family = AF_INET;
    sin->sin_port = htons(port);

    if (inet_pton(AF_INET, host, &sin->sin_addr) <= 0) {
        printf("Failed to convert IP address: %s\n", host);
        return 0;
    }

    dst->size = sizeof(struct sockaddr_in);
    dst->addr.sa.sa_family = AF_INET;
    return 1;
}

/* ======================== CoAP Response Handler ======================== */

static coap_response_t response_handler(coap_session_t *session,
                                        const coap_pdu_t *sent,
                                        const coap_pdu_t *received,
                                        const int id) {
    size_t len;
    const uint8_t *databuf;
    size_t offset;
    size_t total;

    (void)session;
    (void)sent;
    (void)id;

    have_response = 1;
    coap_response_cycles = get_cycles();

    if (coap_get_data_large(received, &len, &databuf, &offset, &total)) {
        response_data_len = (len < sizeof(response_data)) ? len : sizeof(response_data);
        memcpy(response_data, databuf, response_data_len);
    }
    return COAP_RESPONSE_OK;
}

/* ======================== TLS Verification ======================== */

void verify_tls_backend(void) {
    printf("\n=== TLS Backend Verification ===\n");
    
    coap_tls_version_t *tls_version = coap_get_tls_library_version();
    if (!tls_version) {
        printf("Failed to get TLS library version\n");
        return;
    }
    
    switch (tls_version->type) {
        case COAP_TLS_LIBRARY_WOLFSSL:
            printf("TLS Backend: wolfSSL\n");
            break;
        default:
            printf("TLS Backend: type=%d\n", tls_version->type);
            break;
    }
    
    printf("DTLS: %s\n", coap_dtls_is_supported() ? "Yes" : "No");

#if defined(WOLFSSL_ALGO_MLKEM1024)
    printf("ML-KEM (PQC): ML-KEM-1024\n");
    BENCH_META("pqc_kem", "ML-KEM-1024");
#elif defined(WOLFSSL_ALGO_MLKEM768)
    printf("ML-KEM (PQC): ML-KEM-768\n");
    BENCH_META("pqc_kem", "ML-KEM-768");
#elif defined(WOLFSSL_ALGO_MLKEM512)
    printf("ML-KEM (PQC): ML-KEM-512\n");
    BENCH_META("pqc_kem", "ML-KEM-512");
#else
    printf("ML-KEM (PQC): Not available\n");
    BENCH_META("pqc_kem", "none");
#endif
#ifdef WOLFSSL_DTLS13
    printf("DTLS 1.3: Yes\n");
    BENCH_META("dtls_version", "1.3");
#else
    BENCH_META("dtls_version", "1.2");
#endif

#if defined(WOLFSSL_SIG_MLDSA44)
    printf("Signature: ML-DSA-44 (FIPS 204)\n");
    BENCH_META("signature", "ML-DSA-44");
#else
    printf("Signature: ECDSA P-256\n");
    BENCH_META("signature", "ECDSA-P256");
#endif
    
    printf("=== End TLS Verification ===\n\n");
}

#ifdef USE_DTLS
static coap_dtls_pki_t *setup_dtls_pki(void) {
    static coap_dtls_pki_t dtls_pki;
    memset(&dtls_pki, 0, sizeof(dtls_pki));
    dtls_pki.version = COAP_DTLS_PKI_SETUP_VERSION;
    dtls_pki.is_rpk_not_cert = 0;

#ifdef SKIP_PEER_VERIFY
    /* No verification — accept any server certificate (lab/benchmark mode) */
    dtls_pki.verify_peer_cert = 0;
#else
    /* Full verification against the embedded CA certificate.
     * allow_expired_certs covers "not yet valid" too — required because
     * ESP32 boots at epoch (Jan 1 1970) and certs are dated 2024+. */
    dtls_pki.verify_peer_cert = 1;
    dtls_pki.check_common_ca = 1;
    dtls_pki.allow_self_signed = 1;
    dtls_pki.allow_expired_certs = 1;
    dtls_pki.cert_chain_validation = 1;
    dtls_pki.cert_chain_verify_depth = 2;
    dtls_pki.allow_no_crl = 1;

    dtls_pki.pki_key.key_type = COAP_PKI_KEY_PEM_BUF;
#if defined(WOLFSSL_SIG_MLDSA44)
    dtls_pki.pki_key.key.pem_buf.ca_cert = (const uint8_t *)ca_cert_mldsa44_pem;
    dtls_pki.pki_key.key.pem_buf.ca_cert_len = sizeof(ca_cert_mldsa44_pem);
#else
    dtls_pki.pki_key.key.pem_buf.ca_cert = (const uint8_t *)ca_cert_ecc_pem;
    dtls_pki.pki_key.key.pem_buf.ca_cert_len = sizeof(ca_cert_ecc_pem);
#endif
#endif /* SKIP_PEER_VERIFY */

    return &dtls_pki;
}
#endif

/* ======================== Phase 1: Entropy Pool Benchmarks ======================== */

static void bench_entropy_extraction(const struct device *entropy_dev)
{
    int sizes[] = BENCH_ENTROPY_SIZES;
    uint8_t buffer[256];

    printf("\n--- Phase 1a: Entropy Extraction Latency ---\n");

    for (int s = 0; s < NUM_ENTROPY_SIZES; s++) {
        int size = sizes[s];

        /* Warmup */
        for (int w = 0; w < BENCH_WARMUP; w++) {
            entropy_get_entropy(entropy_dev, buffer, size);
        }

        /* Benchmark */
        for (int i = 0; i < BENCH_ITERATIONS; i++) {
            memset(buffer, 0, size);
            uint32_t c0 = get_cycles();
            int ret = entropy_get_entropy(entropy_dev, buffer, size);
            uint32_t c1 = get_cycles();

            if (ret == 0) {
                BENCH_RESULT("entropy_get", size, i, cycles_to_us(c0, c1));
            } else {
                printf("[BENCH_ERR] entropy_get,%d,%d,ret=%d\n", size, i, ret);
            }
        }
    }
}

static void bench_entropy_injection(const struct device *entropy_dev)
{
    int sizes[] = BENCH_ENTROPY_SIZES;
    uint8_t buffer[256];

    printf("\n--- Phase 1b: Entropy Injection Latency ---\n");

    for (int s = 0; s < NUM_ENTROPY_SIZES; s++) {
        int size = sizes[s];

        /* Warmup */
        for (int w = 0; w < BENCH_WARMUP; w++) {
            for (int j = 0; j < size; j++) {
                buffer[j] = (uint8_t)(k_cycle_get_32() & 0xFF);
            }
            entropy_add_entropy(entropy_dev, buffer, size, size * 8);
        }

        /* Benchmark */
        for (int i = 0; i < BENCH_ITERATIONS; i++) {
            /* Generate pseudo-random data to inject */
            for (int j = 0; j < size; j++) {
                buffer[j] = (uint8_t)(k_cycle_get_32() & 0xFF);
            }

            uint32_t c0 = get_cycles();
            int ret = entropy_add_entropy(entropy_dev, buffer, size, size * 8);
            uint32_t c1 = get_cycles();

            if (ret == 0) {
                BENCH_RESULT("entropy_add", size, i, cycles_to_us(c0, c1));
            } else {
                printf("[BENCH_ERR] entropy_add,%d,%d,ret=%d\n", size, i, ret);
            }
        }
    }
}

static void bench_entropy_roundtrip(const struct device *entropy_dev)
{
    uint8_t inject_buf[QUANTUM_ENTROPY_SIZE];
    uint8_t extract_buf[QUANTUM_ENTROPY_SIZE];

    printf("\n--- Phase 1c: Injection + Extraction Roundtrip ---\n");

    for (int w = 0; w < BENCH_WARMUP; w++) {
        for (int j = 0; j < QUANTUM_ENTROPY_SIZE; j++) {
            inject_buf[j] = (uint8_t)(k_cycle_get_32() & 0xFF);
        }
        entropy_add_entropy(entropy_dev, inject_buf, QUANTUM_ENTROPY_SIZE,
                            QUANTUM_ENTROPY_SIZE * 8);
        entropy_get_entropy(entropy_dev, extract_buf, QUANTUM_ENTROPY_SIZE);
    }

    for (int i = 0; i < BENCH_ITERATIONS; i++) {
        for (int j = 0; j < QUANTUM_ENTROPY_SIZE; j++) {
            inject_buf[j] = (uint8_t)(k_cycle_get_32() & 0xFF);
        }

        uint32_t c0 = get_cycles();
        int ret1 = entropy_add_entropy(entropy_dev, inject_buf, QUANTUM_ENTROPY_SIZE,
                                       QUANTUM_ENTROPY_SIZE * 8);
        int ret2 = entropy_get_entropy(entropy_dev, extract_buf, QUANTUM_ENTROPY_SIZE);
        uint32_t c1 = get_cycles();

        if (ret1 == 0 && ret2 == 0) {
            BENCH_RESULT("entropy_roundtrip", QUANTUM_ENTROPY_SIZE, i, cycles_to_us(c0, c1));
        } else {
            printf("[BENCH_ERR] entropy_roundtrip,%d,%d,ret1=%d,ret2=%d\n",
                   QUANTUM_ENTROPY_SIZE, i, ret1, ret2);
        }
    }
}

/* ======================== Phase 2: Full Cycle Benchmark ======================== */

/**
 * Performs a single CoAP request to the QEaaS server and returns the
 * response data. Measures: DTLS handshake (first request), CoAP RTT,
 * and entropy injection.
 */
static int do_coap_entropy_request(coap_context_t *ctx, coap_session_t *session)
{
    coap_pdu_t *pdu = NULL;
    coap_optlist_t *optlist = NULL;
    int res;
    unsigned int wait_ms;

    have_response = 0;
    response_data_len = 0;

    /* Construct CoAP GET request */
    pdu = coap_pdu_init(COAP_MESSAGE_CON, COAP_REQUEST_CODE_GET,
                        coap_new_message_id(session),
                        coap_session_max_pdu_size(session));
    if (!pdu) {
        return -1;
    }

    /* Add Proxy-URI option (option 35) — tells the proxy to forward
     * this request to the HTTP backend via libcurl. */
    const char *backend = PROXY_BACKEND_URI;
    coap_insert_optlist(&optlist,
                        coap_new_optlist(COAP_OPTION_PROXY_URI,
                                        strlen(backend),
                                        (const uint8_t *)backend));

    if (optlist) {
        res = coap_add_optlist_pdu(pdu, &optlist);
        coap_delete_optlist(optlist);
        if (res != 1) {
            return -1;
        }
    } else {
        return -1;
    }

    coap_mid_t mid = coap_send(session, pdu);
    if (mid == COAP_INVALID_MID) {
        return -1;
    }

    /* Wait for response — 10 s timeout.
     * ML-DSA-44 certificates (~5.6 KB) require multiple DTLS fragments;
     * lost fragments trigger retransmission with exponential back-off
     * (1 s, 2 s, 4 s, 8 s …).  30 s gives enough budget for full
     * retransmissions even over lossy WiFi. */
    wait_ms = 30000;
    while (have_response == 0) {
        res = coap_io_process(ctx, 500);
        if (res >= 0) {
            if (wait_ms > 0) {
                if ((unsigned)res >= wait_ms) {
                    return -2; /* timeout */
                }
                wait_ms -= res;
            }
        }
    }

    return (response_data_len > 0) ? 0 : -3;
}

static void bench_full_cycle(const struct device *entropy_dev)
{
    coap_address_t dst;
    coap_uri_t uri;
    const char *coap_uri = COAP_CLIENT_URI;

    (void)entropy_dev; /* Entropy pool already characterised in Phase 1 */

    printf("\n--- Phase 2: DTLS Handshake + CoAP Benchmarks ---\n");
    printf("Proxy: %s\n", coap_uri);
    printf("Backend: %s\n", PROXY_BACKEND_URI);

    BENCH_META("coap_uri", coap_uri);
    BENCH_META("proxy_backend", PROXY_BACKEND_URI);
    BENCH_META("server_ip", COAP_SERVER_IP);

    /* Initialize libcoap */
    coap_startup();
    verify_tls_backend();
    /* Use COAP_LOG_ERR to suppress WARN-level logs in coap_wolfssl.c.
     * WARN-level log macros evaluate coap_session_str(session) which calls
     * malloc on the ~5 KB libc heap (separate from Zephyr's sys_heap).
     * During PQC handshakes the libc heap is depleted and malloc crashes.
     * The coap_log() macro's runtime level check prevents argument
     * evaluation entirely when the log level is below WARN. */
    coap_set_log_level(COAP_LOG_ERR);

    /* Parse URI */
    int len = coap_split_uri((const unsigned char *)coap_uri, strlen(coap_uri), &uri);
    if (len != 0) {
        printf("[BENCH_ERR] Failed to parse URI\n");
        goto phase2_cleanup;
    }

    /* Connect WiFi */
    wifi_init(NULL);
    int wifi_connected = 0;
    for (int attempt = 1; attempt <= 3 && !wifi_connected; attempt++) {
        if (attempt > 1) {
            printf("WiFi retry %d/3...\n", attempt);
        }
        int ret = connect_to_wifi();
        if (ret >= 0 && wait_for_wifi_connection() >= 0) {
            wifi_connected = 1;
        } else {
            if (attempt < 3) {
                wifi_disconnect();
                k_sleep(K_MSEC(2000));
            }
        }
    }

    if (!wifi_connected) {
        printf("[BENCH_ERR] WiFi connection failed\n");
        goto phase2_cleanup;
    }

    k_sleep(K_MSEC(1000));

    /* Setup destination address */
    char host_str[64];
    if (uri.host.length < sizeof(host_str)) {
        memcpy(host_str, uri.host.s, uri.host.length);
        host_str[uri.host.length] = '\0';
    } else {
        printf("[BENCH_ERR] Host string too long\n");
        goto phase2_cleanup;
    }

    uint16_t port = uri.port ? uri.port : COAP_SERVER_PORT;
    if (!setup_destination_address(&dst, host_str, port)) {
        printf("[BENCH_ERR] Address setup failed\n");
        goto phase2_cleanup;
    }

    report_heap_stats("pre_handshake");

    /* ===== Phase 2a: Handshake + 1st Request (fresh context each iteration) ===== */
    /*
     * Phase 2a creates a fresh CoAP **context** and DTLS **session** per
     * iteration so the timer captures the full handshake + first CoAP
     * request.  A per-iteration context ensures complete DTLS state
     * isolation: shared contexts retain internal session-table entries that
     * cause the server to silently drop subsequent ClientHello messages
     * (observed as 1/N success with "unexpected_message" alerts).
     */
#ifdef USE_DTLS
    const char *phase2a_label = "Handshake + 1st Request";
    const char *bench_tag = "dtls_handshake_plus_first_req";
    const int teardown_delay_ms = 1000; /* let server tear down DTLS session */
#else
    const char *phase2a_label = "1st Request (plain CoAP)";
    const char *bench_tag = "dtls_handshake_plus_first_req"; /* keep label for parser compat */
    const int teardown_delay_ms = 100; /* no DTLS state to clean up */
#endif
    printf("\n--- Phase 2a: %s (%d iterations) ---\n",
           phase2a_label, FULL_CYCLE_ITERATIONS);

    int handshake_ok = 0;
    int handshake_fail = 0;

    for (int i = 0; i < FULL_CYCLE_ITERATIONS; i++) {

        /* Fresh context per iteration ensures full DTLS state isolation.
         * A shared context retains internal session-table state that can
         * cause the server to silently drop subsequent ClientHello messages
         * (seen as 1/N success pattern with "unexpected_message" alerts). */
        coap_context_t *ctx2a = coap_new_context(NULL);
        if (!ctx2a) {
            printf("[BENCH_ERR] Cannot create Phase 2a context (iter %d)\n", i);
            handshake_fail++;
            continue;
        }
        coap_context_set_block_mode(ctx2a,
            COAP_BLOCK_USE_LIBCOAP | COAP_BLOCK_SINGLE_BODY);
        coap_register_response_handler(ctx2a, response_handler);

        /* ---- START measurement ----
         * Timer includes session creation (sends ClientHello, triggers
         * DTLS handshake) and the first CoAP request driven by
         * coap_io_process() inside do_coap_entropy_request().
         */
        uint32_t c0 = get_cycles();

        coap_session_t *session = NULL;
        if (uri.scheme == COAP_URI_SCHEME_COAP) {
            session = coap_new_client_session(ctx2a, NULL, &dst,
                                              COAP_PROTO_UDP);
#ifdef USE_DTLS
        } else if (uri.scheme == COAP_URI_SCHEME_COAPS) {
            coap_dtls_pki_t *dtls_pki = setup_dtls_pki();
            session = coap_new_client_session_pki(ctx2a, NULL, &dst,
                                                  COAP_PROTO_DTLS,
                                                  dtls_pki);
#endif
        }

        int ret = -1;
        if (session) {
#ifdef USE_DTLS
            /* ML-DSA certs fragment into many DTLS records; the default
             * max_retransmit of 4 is shared across ALL handshake flights
             * and is easily exhausted over WiFi.  Raise it so the DTLS
             * layer keeps retrying until the app-level 30 s timeout. */
            coap_session_set_max_retransmit(session, 8);
#endif
            ret = do_coap_entropy_request(ctx2a, session);
        }

        uint32_t c1 = get_cycles();
        /* ---- END measurement ---- */

        if (ret == 0) {
            uint32_t us = cycles_to_us(c0, c1);
            BENCH_RESULT(bench_tag,
                         (int)response_data_len, i, us);
            handshake_ok++;
            if (i == 0 || (i + 1) % 25 == 0) {
                printf("  [%3d/%d] %u us (%u.%03u ms)\n",
                       i + 1, FULL_CYCLE_ITERATIONS,
                       us, us / 1000, us % 1000);
            }
        } else {
            printf("[BENCH_ERR] handshake_first_req,%d,ret=%d\n", i, ret);
            handshake_fail++;
        }

        /* Release session, drain close_notify, then destroy context.
         * Skip coap_io_process() after a failure — attempting to send
         * close_notify on a dead WiFi socket triggers a CPU exception
         * (coap_socket_send: Invalid argument → Zephyr FATAL ERROR). */
        if (session) {
            coap_session_release(session);
        }
        if (ret == 0) {
            coap_io_process(ctx2a, 500);
        }
        coap_free_context(ctx2a);

        /* Inter-iteration delay: let the server tear down session state */
        k_sleep(K_MSEC(teardown_delay_ms));

        /* If WiFi dropped, reconnect before the next iteration */
        if (!wifi_is_connected()) {
            printf("[BENCH_WARN] WiFi lost after iteration %d, reconnecting...\n", i);
            if (wifi_reconnect() != 0) {
                printf("[BENCH_ERR] WiFi reconnection failed, aborting\n");
                break;
            }
        }

        /* Periodic heap report for fragmentation detection */
        if ((i + 1) % 10 == 0) {
            report_heap_stats("mid_handshake");
        }
    }

    printf("Handshake results: %d OK, %d failed out of %d\n",
           handshake_ok, handshake_fail, FULL_CYCLE_ITERATIONS);
    {
        char meta_buf[16];
        snprintf(meta_buf, sizeof(meta_buf), "%d", handshake_ok);
        BENCH_META("handshake_ok", meta_buf);
        snprintf(meta_buf, sizeof(meta_buf), "%d", handshake_fail);
        BENCH_META("handshake_fail", meta_buf);
    }

    report_heap_stats("post_handshake");

    /* ===== Phase 2b: Subsequent RTT (single session, sanity baseline) ===== */
    /*
     * A single established session is reused for FULL_CYCLE_ITERATIONS
     * requests.  This measures the algorithm-independent symmetric-cipher
     * CoAP round-trip and serves as a reference baseline.
     */
    {
        coap_context_t *ctx = coap_new_context(NULL);
        if (!ctx) {
            printf("[BENCH_ERR] Cannot create context for RTT phase\n");
            goto phase2_cleanup;
        }
        coap_context_set_block_mode(ctx,
            COAP_BLOCK_USE_LIBCOAP | COAP_BLOCK_SINGLE_BODY);
        coap_register_response_handler(ctx, response_handler);

        coap_session_t *session = NULL;
        if (uri.scheme == COAP_URI_SCHEME_COAP) {
            session = coap_new_client_session(ctx, NULL, &dst,
                                              COAP_PROTO_UDP);
#ifdef USE_DTLS
        } else if (uri.scheme == COAP_URI_SCHEME_COAPS) {
            coap_dtls_pki_t *dtls_pki = setup_dtls_pki();
            session = coap_new_client_session_pki(ctx, NULL, &dst,
                                                  COAP_PROTO_DTLS,
                                                  dtls_pki);
#endif
        }

        if (!session) {
            printf("[BENCH_ERR] Cannot create session for RTT phase\n");
            coap_free_context(ctx);
            goto phase2_cleanup;
        }

        /* Prime the session: handshake + 1st request (not measured) */
        int prime = do_coap_entropy_request(ctx, session);
        if (prime != 0) {
            printf("[BENCH_ERR] Session priming failed: %d\n", prime);
            coap_session_release(session);
            coap_free_context(ctx);
            goto phase2_cleanup;
        }
        k_sleep(K_MSEC(200));

        printf("\n--- Phase 2b: Subsequent RTT (%d iterations, session reuse) ---\n",
               FULL_CYCLE_ITERATIONS);

        for (int i = 0; i < FULL_CYCLE_ITERATIONS; i++) {
            uint32_t c0 = get_cycles();
            int ret = do_coap_entropy_request(ctx, session);
            uint32_t c1 = get_cycles();

            if (ret == 0) {
                BENCH_RESULT("coap_rtt", (int)response_data_len, i,
                             cycles_to_us(c0, c1));
            } else {
                printf("[BENCH_ERR] coap_rtt,%d,ret=%d\n", i, ret);
                if (!wifi_is_connected()) {
                    printf("[BENCH_WARN] WiFi lost during Phase 2b, stopping\n");
                    break;
                }
            }

            k_sleep(K_MSEC(100));
        }

        coap_session_release(session);
        coap_free_context(ctx);
    }

    report_heap_stats("final");

phase2_cleanup:
    coap_cleanup();
    wifi_disconnect();
}

/* ======================== Main ======================== */

int main(void)
{
    const struct device *entropy_dev;
    char buf[32];

    printf("\n========================================\n");
    printf("QEaaS Benchmark Client\n");
    printf("========================================\n");

    /* Get entropy device */
    entropy_dev = DEVICE_DT_GET(DT_CHOSEN(zephyr_entropy));
    if (!device_is_ready(entropy_dev)) {
        printf("FATAL: Entropy device not ready\n");
        return EXIT_FAILURE;
    }

    printf("Entropy device: %s\n", entropy_dev->name);

    /* Wait for serial monitor to connect before starting benchmarks.
     * After flash+reset, the host needs ~2-3s to open the serial port.
     * Total boot time (ROM + bootloader + Zephyr) is ~2s, so 3s extra
     * ensures the monitor is ready before [BENCH_START]. */
    printf("Waiting for serial monitor...\n");
    k_msleep(5000);

    /* Emit metadata */
    BENCH_HEADER();
    BENCH_META("board", "esp32_devkitc_wroom");
    BENCH_META("entropy_driver", entropy_dev->name);
    snprintf(buf, sizeof(buf), "%d", BENCH_ITERATIONS);
    BENCH_META("bench_iterations", buf);
    snprintf(buf, sizeof(buf), "%d", FULL_CYCLE_ITERATIONS);
    BENCH_META("full_cycle_iterations", buf);
    snprintf(buf, sizeof(buf), "%d", CONFIG_HEAP_MEM_POOL_SIZE);
    BENCH_META("heap_pool_size", buf);
    snprintf(buf, sizeof(buf), "%d", CONFIG_MAIN_STACK_SIZE);
    BENCH_META("main_stack_size", buf);
#ifdef USE_DTLS
    BENCH_META("transport", "coaps");
#else
    BENCH_META("transport", "coap");
#endif

    /* Report initial heap usage (boot overhead) */
    report_heap_stats("boot");

    /* Report which key-exchange algorithm was compiled in */
#if defined(WOLFSSL_ALGO_MLKEM1024)
    BENCH_META("key_exchange", "ML-KEM-1024");
#elif defined(WOLFSSL_ALGO_MLKEM768)
    BENCH_META("key_exchange", "ML-KEM-768");
#elif defined(WOLFSSL_ALGO_MLKEM512)
    BENCH_META("key_exchange", "ML-KEM-512");
#elif defined(WOLFSSL_ALGO_X25519)
    BENCH_META("key_exchange", "X25519");
#elif defined(WOLFSSL_ALGO_ECDHE_P256)
    BENCH_META("key_exchange", "ECDHE-P256");
#else
    BENCH_META("key_exchange", "none");
#endif

    /* Report which signature algorithm was compiled in */
#if defined(WOLFSSL_SIG_MLDSA44)
    BENCH_META("signature", "ML-DSA-44");
#else
    BENCH_META("signature", "ECDSA-P256");
#endif

#ifdef SKIP_PEER_VERIFY
    BENCH_META("cert_verify", "disabled");
#else
    BENCH_META("cert_verify", "enabled");
#endif

    /* ---- Phase 1: Local entropy pool benchmarks ---- */
    printf("\n======== PHASE 1: Local Entropy Pool Benchmarks ========\n");
    bench_entropy_extraction(entropy_dev);
    bench_entropy_injection(entropy_dev);
    bench_entropy_roundtrip(entropy_dev);

    /* ---- Phase 2: Full cycle with CoAP server ---- */
    printf("\n======== PHASE 2: Full Cycle Benchmarks ========\n");
    bench_full_cycle(entropy_dev);

    BENCH_FOOTER();

    printf("\n========================================\n");
    printf("QEaaS Benchmark Complete\n");
    printf("========================================\n");

    return EXIT_SUCCESS;
}