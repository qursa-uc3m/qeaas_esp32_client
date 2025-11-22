/* QEaaS entropy pool validation & latency benchmarks */

#include <zephyr/kernel.h>
#include <zephyr/device.h>
#include <zephyr/drivers/entropy.h>
#include <zephyr/sys/printk.h>
#include <zephyr/logging/log.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#ifdef CONFIG_SOC_ESP32
#include <esp_timer.h>
#endif

/* High-resolution time source (microseconds). Fallback to uptime (ms->us) if esp_timer unavailable. */
static inline uint64_t get_time_us(void)
{
#ifdef CONFIG_SOC_ESP32
    return esp_timer_get_time();
#else
    return (uint64_t)k_uptime_get() * 1000ULL;
#endif
}

LOG_MODULE_REGISTER(entropy_test, LOG_LEVEL_INF);

/* Test configuration */
#define TEST_BUFFER_SIZE         64
#define TEST_SMALL_BUFFER        16
#define TEST_LARGE_BUFFER        256
#define TEST_ITERATIONS          10
#define TEST_CONTINUOUS_COUNT    100
#define QUANTUM_ENTROPY_SIZE     32
#define LATENCY_ITERATIONS        100

/* Color codes for test output */
#define COLOR_RESET   "\033[0m"
#define COLOR_GREEN   "\033[32m"
#define COLOR_RED     "\033[31m"
#define COLOR_YELLOW  "\033[33m"
#define COLOR_BLUE    "\033[34m"
#define COLOR_MAGENTA "\033[35m"
#define COLOR_CYAN    "\033[36m"

/* Test statistics */
struct test_stats {
uint32_t tests_passed;
uint32_t tests_failed;
uint32_t total_bytes_extracted;
uint32_t total_quantum_bytes_added;
};

static struct test_stats stats = {0};
static bool quantum_pass = false;
static bool continuous_pass = false;
static bool boundary_pass = false;

/* Hex dump removed for minimal output */

/* Helper: Check if buffer has non-zero data */
static bool buffer_has_data(const uint8_t *buf, size_t len)
{
uint8_t accum = 0;
for (size_t i = 0; i < len; i++) {
accum |= buf[i];
}
return accum != 0;
}

/* Test 1: multiple consecutive extractions */
static void test_multiple_extractions(const struct device *entropy_dev)
{
    uint8_t buffer[TEST_SMALL_BUFFER];
    int failures = 0;

    printf("\nT1 multiple extractions\n");

    for (int i = 0; i < TEST_ITERATIONS; i++) {
        memset(buffer, 0, sizeof(buffer));
        int ret = entropy_get_entropy(entropy_dev, buffer, sizeof(buffer));

        if (ret == 0 && buffer_has_data(buffer, sizeof(buffer))) {
            stats.total_bytes_extracted += sizeof(buffer);
        } else {
            failures++;
        }
        k_msleep(10);
    }

    if (failures == 0) { stats.tests_passed++; } else { stats.tests_failed++; }
    printf("Result: %s (failures=%d)\n", failures == 0 ? "PASS" : "FAIL", failures);
}

/* ISR tests removed */

/* Test 2: quantum entropy injection */
static void test_external_entropy_addition(const struct device *entropy_dev)
{
    uint8_t quantum_entropy[QUANTUM_ENTROPY_SIZE];
    uint8_t mixed_output[TEST_BUFFER_SIZE];
    int ret;

    printf("\nT2 quantum entropy injection\n");

    /* Simulate receiving quantum entropy from QEaaS server */
    for (size_t i = 0; i < sizeof(quantum_entropy); i++) {
        quantum_entropy[i] = (uint8_t)(k_cycle_get_32() & 0xFF);
    }

    /* silent simulation */

    /* Add quantum entropy to the pool */
    ret = entropy_add_entropy(entropy_dev, quantum_entropy, sizeof(quantum_entropy),
                              sizeof(quantum_entropy) * 8);
    if (ret == 0) {
        stats.total_quantum_bytes_added += sizeof(quantum_entropy);
        printf(COLOR_GREEN "✓" COLOR_RESET " Quantum entropy added\n");

        /* Extract entropy to verify mixing (only check non-zero data) */
        k_msleep(50);
        ret = entropy_get_entropy(entropy_dev, mixed_output, sizeof(mixed_output));
        if (ret == 0 && buffer_has_data(mixed_output, sizeof(mixed_output))) {
            printf(COLOR_GREEN "PASS" COLOR_RESET "\n");
            stats.tests_passed++;
            quantum_pass = true;
            stats.total_bytes_extracted += sizeof(mixed_output);
        } else {
            printf(COLOR_RED "FAIL (post-mix extract)" COLOR_RESET "\n");
            stats.tests_failed++;
        }
    } else {
        printf(COLOR_RED "FAIL (add ret=%d)" COLOR_RESET "\n", ret);
        stats.tests_failed++;
    }
}

/* Test 3: continuous high-rate operation */
static void test_continuous_operation(const struct device *entropy_dev)
{
uint8_t buffer[TEST_SMALL_BUFFER];
int failures = 0;
uint32_t start_time, end_time;

printf("\nT3 continuous operation\n");

start_time = k_uptime_get_32();

for (int i = 0; i < TEST_CONTINUOUS_COUNT; i++) {
memset(buffer, 0, sizeof(buffer));
int ret = entropy_get_entropy(entropy_dev, buffer, sizeof(buffer));

if (ret != 0 || !buffer_has_data(buffer, sizeof(buffer))) {
failures++;
} else {
stats.total_bytes_extracted += sizeof(buffer);
}
}

end_time = k_uptime_get_32();
uint32_t duration_ms = end_time - start_time;
uint32_t rate_kbps = (TEST_CONTINUOUS_COUNT * TEST_SMALL_BUFFER * 8) / duration_ms;

printf("Extracted %d blocks in %u ms\n", TEST_CONTINUOUS_COUNT, duration_ms);
printf("Throughput: ~%u Kbits/sec\n", rate_kbps);
printf("Failures: %d/%d\n", failures, TEST_CONTINUOUS_COUNT);

if (failures == 0) {
    printf(COLOR_GREEN "PASS" COLOR_RESET "\n");
    stats.tests_passed++;
    continuous_pass = true;
} else {
    printf(COLOR_RED "FAIL (%d failures)" COLOR_RESET "\n", failures);
    stats.tests_failed++;
}
}

/* Test 4: boundary conditions */
/* Test 5: entropy extraction latency */
static void test_entropy_latency(const struct device *entropy_dev)
{
    uint8_t buffer[TEST_SMALL_BUFFER];
    uint64_t total_cycles = 0, total_us = 0;
    int failures = 0;
    uint64_t processed_bytes = 0;
    printf("\nT5 extraction latency\n");
    for (int i = 0; i < LATENCY_ITERATIONS; i++) {
        memset(buffer, 0, sizeof(buffer));
        uint32_t c0 = k_cycle_get_32();
        uint64_t t0 = get_time_us();
        int ret = entropy_get_entropy(entropy_dev, buffer, sizeof(buffer));
        uint32_t c1 = k_cycle_get_32();
        uint64_t t1 = get_time_us();
        total_cycles += (uint32_t)(c1 - c0);
        total_us     += (t1 - t0);
        if (ret != 0 || !buffer_has_data(buffer, sizeof(buffer))) {
            failures++;
        } else {
            stats.total_bytes_extracted += sizeof(buffer);
            processed_bytes += sizeof(buffer);
        }
    }
    uint64_t avg_cycles = total_cycles / LATENCY_ITERATIONS;
    uint64_t avg_us     = total_us / LATENCY_ITERATIONS;
    uint64_t cycles_per_byte = processed_bytes ? (total_cycles / processed_bytes) : 0;
    uint64_t us_per_byte     = processed_bytes ? (total_us / processed_bytes) : 0;
    printf(" iterations=%d avg_cycles=%llu cycles/byte=%llu avg_us=%llu us/byte=%llu failures=%d\n",
           LATENCY_ITERATIONS,
           (unsigned long long)avg_cycles,
           (unsigned long long)cycles_per_byte,
           (unsigned long long)avg_us,
           (unsigned long long)us_per_byte,
           failures);
    if (failures == 0) { stats.tests_passed++; } else { stats.tests_failed++; }
    printf("Result: %s\n", failures==0?"PASS":"FAIL");
}

/* Test 6: entropy injection latency */
static void test_injection_latency(const struct device *entropy_dev)
{
    uint8_t quantum_entropy[QUANTUM_ENTROPY_SIZE];
    uint64_t total_cycles = 0, total_us = 0;
    int failures = 0;
    uint64_t processed_bytes = 0;
    printf("\nT6 injection latency\n");
    for (int i = 0; i < LATENCY_ITERATIONS; i++) {
        for (size_t j = 0; j < sizeof(quantum_entropy); j++) {
            quantum_entropy[j] = (uint8_t)(k_cycle_get_32() & 0xFF);
        }
        uint32_t c0 = k_cycle_get_32();
        uint64_t t0 = get_time_us();
        int ret = entropy_add_entropy(entropy_dev, quantum_entropy,
                                      sizeof(quantum_entropy),
                                      sizeof(quantum_entropy)*8);
        uint32_t c1 = k_cycle_get_32();
        uint64_t t1 = get_time_us();
        total_cycles += (uint32_t)(c1 - c0);
        total_us     += (t1 - t0);
        if (ret != 0) {
            failures++;
        } else {
            stats.total_quantum_bytes_added += sizeof(quantum_entropy);
            processed_bytes += sizeof(quantum_entropy);
        }
    }
    uint64_t avg_cycles = total_cycles / LATENCY_ITERATIONS;
    uint64_t avg_us     = total_us / LATENCY_ITERATIONS;
    uint64_t cycles_per_byte = processed_bytes ? (total_cycles / processed_bytes) : 0;
    uint64_t us_per_byte     = processed_bytes ? (total_us / processed_bytes) : 0;
    printf(" iterations=%d avg_cycles=%llu cycles/byte=%llu avg_us=%llu us/byte=%llu failures=%d\n",
           LATENCY_ITERATIONS,
           (unsigned long long)avg_cycles,
           (unsigned long long)cycles_per_byte,
           (unsigned long long)avg_us,
           (unsigned long long)us_per_byte,
           failures);
    if (failures == 0) { stats.tests_passed++; } else { stats.tests_failed++; }
    printf("Result: %s\n", failures==0?"PASS":"FAIL");
}
static void test_boundary_conditions(const struct device *entropy_dev)
{
uint8_t tiny_buffer[1];
uint8_t large_buffer[TEST_LARGE_BUFFER];
int ret;
int test_failures = 0;

printf("\nT4 boundary conditions\n");

/* Test 7a: Single byte extraction */
memset(tiny_buffer, 0, sizeof(tiny_buffer));
ret = entropy_get_entropy(entropy_dev, tiny_buffer, sizeof(tiny_buffer));
if (ret == 0 && tiny_buffer[0] != 0) {
printf(" single-byte: OK\n");
stats.total_bytes_extracted += sizeof(tiny_buffer);
} else {
printf(COLOR_RED "✗" COLOR_RESET " Single-byte extraction: FAILED\n");
test_failures++;
}

/* Test 7b: Large buffer extraction */
memset(large_buffer, 0, sizeof(large_buffer));
ret = entropy_get_entropy(entropy_dev, large_buffer, sizeof(large_buffer));
if (ret == 0 && buffer_has_data(large_buffer, sizeof(large_buffer))) {
printf(" large buffer: OK (%d bytes)\n", TEST_LARGE_BUFFER);
stats.total_bytes_extracted += sizeof(large_buffer);
} else {
printf(COLOR_RED "✗" COLOR_RESET " Large buffer extraction: FAILED\n");
test_failures++;
}

/* Test 7c: Back-to-back extractions */
uint8_t buffer1[TEST_SMALL_BUFFER];
uint8_t buffer2[TEST_SMALL_BUFFER];
memset(buffer1, 0, sizeof(buffer1));
memset(buffer2, 0, sizeof(buffer2));

ret = entropy_get_entropy(entropy_dev, buffer1, sizeof(buffer1));
int ret2 = entropy_get_entropy(entropy_dev, buffer2, sizeof(buffer2));

if (ret == 0 && ret2 == 0 && 
    buffer_has_data(buffer1, sizeof(buffer1)) && 
    buffer_has_data(buffer2, sizeof(buffer2))) {
printf(" back-to-back: OK\n");
stats.total_bytes_extracted += sizeof(buffer1) + sizeof(buffer2);
} else {
printf(COLOR_RED "✗" COLOR_RESET " Back-to-back extractions: FAILED\n");
test_failures++;
}

if (test_failures == 0) { stats.tests_passed++; boundary_pass = true; printf("Result: PASS\n"); }
else { stats.tests_failed++; printf("Result: FAIL (%d)\n", test_failures); }
}

/**
 * Print comprehensive test report
 */
static void print_test_report(void)
{
    printf("\nSummary\n");
    printf(" passed=%u failed=%u total=%u\n", stats.tests_passed, stats.tests_failed,
        stats.tests_passed + stats.tests_failed);
    printf(" bytes_extracted=%u quantum_added=%u\n", stats.total_bytes_extracted,
        stats.total_quantum_bytes_added);
}

int main(void)
{
const struct device *entropy_dev;

printf("\nQEaaS entropy pool validation (minimal output)\n");

/* Get entropy device */
entropy_dev = DEVICE_DT_GET(DT_CHOSEN(zephyr_entropy));
if (!device_is_ready(entropy_dev)) {
printf(COLOR_RED "\n✗ FATAL: Entropy device not ready\n" COLOR_RESET);
return EXIT_FAILURE;
}

printf("\n" COLOR_GREEN "✓ Entropy device ready: %s" COLOR_RESET "\n", entropy_dev->name);

/* Wait for initialization to complete */
k_msleep(500);

/* Run test suite (Test 1 removed: merged into multiple extractions) */
test_multiple_extractions(entropy_dev);
test_external_entropy_addition(entropy_dev);
test_continuous_operation(entropy_dev);
test_boundary_conditions(entropy_dev);

/* Latency benchmarks (not part of core success check) */
test_entropy_latency(entropy_dev);
test_injection_latency(entropy_dev);

/* Print final report */
print_test_report();

/* Wait for report to be read */
k_msleep(5000);

/* Core success: quantum addition + continuous operation + boundary checks */
bool core_success = (quantum_pass && continuous_pass && boundary_pass);

if (core_success) {
    printf(COLOR_GREEN "\nCORE PASS\n" COLOR_RESET);
    printf("final passed=%u failed=%u\n", stats.tests_passed, stats.tests_failed);
    return EXIT_SUCCESS;
} else {
    printf(COLOR_RED "\nCORE FAIL\n" COLOR_RESET);
    printf("final passed=%u failed=%u\n", stats.tests_passed, stats.tests_failed);
    return EXIT_FAILURE;
}
}
