#include "sm4.h"
#include <stdio.h>
#include <time.h>
#include <sys/time.h>

// Utility function to print data in hexadecimal format
void sm4_print_hex(const uint8_t *data, size_t len) {
    size_t i;
    for (i = 0; i < len; i++) {
        printf("%02x", data[i]);
        if ((i + 1) % 16 == 0) {
            printf("\n");
        } else if ((i + 1) % 8 == 0) {
            printf("  ");
        } else {
            printf(" ");
        }
    }
    if (len % 16 != 0) {
        printf("\n");
    }
}

// Utility function to print labeled data block
void sm4_print_block(const char *label, const uint8_t *data, size_t len) {
    printf("%s (%zu bytes):\n", label, len);
    sm4_print_hex(data, len);
    printf("\n");
}

// CPU feature detection functions (declared in sm4.h)
// Implementations are in specific optimization files to avoid duplicates

// High-resolution timer functions
static uint64_t get_cpu_cycles(void) {
    uint32_t low, high;
    __asm__ volatile (
        "rdtsc"
        : "=a" (low), "=d" (high)
    );
    return ((uint64_t)high << 32) | low;
}

static double get_time_in_seconds(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec + tv.tv_usec * 1e-6;
}

// CPU frequency detection (approximation)
static double get_cpu_frequency_ghz(void) {
    // Simple frequency detection by measuring cycles over time
    uint64_t start_cycles, end_cycles;
    double start_time, end_time;
    
    start_cycles = get_cpu_cycles();
    start_time = get_time_in_seconds();
    
    // Wait for approximately 100ms
    double target_time = start_time + 0.1;
    while (get_time_in_seconds() < target_time) {
        // Busy wait
    }
    
    end_cycles = get_cpu_cycles();
    end_time = get_time_in_seconds();
    
    double elapsed_time = end_time - start_time;
    uint64_t elapsed_cycles = end_cycles - start_cycles;
    
    return (double)elapsed_cycles / elapsed_time / 1e9;
}

// Benchmark function for SM4 implementations
void sm4_benchmark(const char *impl_name, 
                   void (*encrypt_func)(const uint8_t*, const uint8_t*, uint8_t*),
                   sm4_perf_result *result) {
    
    const size_t num_iterations = 10000;
    const size_t block_size = SM4_BLOCK_SIZE;
    const size_t total_bytes = num_iterations * block_size;
    
    uint8_t key[SM4_KEY_SIZE] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
    };
    
    uint8_t plaintext[SM4_BLOCK_SIZE] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
    };
    
    uint8_t ciphertext[SM4_BLOCK_SIZE];
    
    printf("Benchmarking %s implementation...\n", impl_name);
    
    // Warm-up run
    for (size_t i = 0; i < 1000; i++) {
        encrypt_func(key, plaintext, ciphertext);
    }
    
    // Actual benchmark
    uint64_t start_cycles = get_cpu_cycles();
    double start_time = get_time_in_seconds();
    
    for (size_t i = 0; i < num_iterations; i++) {
        encrypt_func(key, plaintext, ciphertext);
    }
    
    uint64_t end_cycles = get_cpu_cycles();
    double end_time = get_time_in_seconds();
    
    uint64_t total_cycles = end_cycles - start_cycles;
    double elapsed_time = end_time - start_time;
    
    // Calculate results
    result->total_cycles = total_cycles;
    result->total_bytes = total_bytes;
    result->cycles_per_byte = (double)total_cycles / (double)total_bytes;
    result->mbytes_per_sec = (double)total_bytes / elapsed_time / (1024.0 * 1024.0);
    
    printf("  Total operations: %zu\n", num_iterations);
    printf("  Total bytes processed: %zu\n", total_bytes);
    printf("  Total cycles: %lu\n", total_cycles);
    printf("  Elapsed time: %.6f seconds\n", elapsed_time);
    printf("  Cycles per byte: %.2f\n", result->cycles_per_byte);
    printf("  Throughput: %.2f MB/s\n", result->mbytes_per_sec);
    printf("  Operations per second: %.0f\n", (double)num_iterations / elapsed_time);
    printf("\n");
}

// Memory comparison function (constant-time)
int sm4_memcmp_const_time(const uint8_t *a, const uint8_t *b, size_t len) {
    volatile uint8_t result = 0;
    size_t i;
    
    for (i = 0; i < len; i++) {
        result |= a[i] ^ b[i];
    }
    
    return result;
}

// Secure memory clearing function
void sm4_memzero(void *ptr, size_t len) {
    volatile uint8_t *p = (volatile uint8_t *)ptr;
    size_t i;
    
    for (i = 0; i < len; i++) {
        p[i] = 0;
    }
}

// Random number generation for testing (simple PRNG)
static uint32_t rng_state = 1;

void sm4_srand(uint32_t seed) {
    rng_state = seed;
}

uint32_t sm4_rand(void) {
    // Linear congruential generator
    rng_state = rng_state * 1103515245 + 12345;
    return rng_state;
}

void sm4_rand_bytes(uint8_t *buf, size_t len) {
    size_t i;
    for (i = 0; i < len; i++) {
        if (i % 4 == 0) {
            uint32_t r = sm4_rand();
            buf[i] = r & 0xFF;
            if (i + 1 < len) buf[i + 1] = (r >> 8) & 0xFF;
            if (i + 2 < len) buf[i + 2] = (r >> 16) & 0xFF;
            if (i + 3 < len) buf[i + 3] = (r >> 24) & 0xFF;
        }
    }
}

// Performance analysis functions
void sm4_print_cpu_info(void) {
    printf("CPU Feature Detection:\n");
    printf("  AES-NI support: %s\n", sm4_cpu_support_aesni() ? "Yes" : "No");
    printf("  GFNI support: %s\n", sm4_cpu_support_gfni() ? "Yes" : "No");
    printf("  AVX2 support: %s\n", sm4_cpu_support_avx2() ? "Yes" : "No");
    printf("  Estimated CPU frequency: %.2f GHz\n", get_cpu_frequency_ghz());
    printf("\n");
}

// Comparative benchmark function
void sm4_compare_implementations(void) {
    sm4_perf_result results[4];
    const char *impl_names[] = {"Basic", "T-table", "AES-NI", "GFNI"};
    void (*encrypt_funcs[])(const uint8_t*, const uint8_t*, uint8_t*) = {
        sm4_basic_encrypt,
        sm4_ttable_encrypt,
        sm4_aesni_encrypt,
#ifdef __GFNI__
        sm4_gfni_encrypt
#else
        sm4_basic_encrypt  // Fallback if GFNI not available
#endif
    };
    
    printf("=== SM4 Implementation Performance Comparison ===\n\n");
    sm4_print_cpu_info();
    
    for (int i = 0; i < 4; i++) {
        sm4_benchmark(impl_names[i], encrypt_funcs[i], &results[i]);
    }
    
    printf("=== Performance Summary ===\n");
    printf("Implementation | Cycles/Byte | Throughput (MB/s) | Speedup\n");
    printf("---------------|-------------|-------------------|--------\n");
    
    double baseline_cpb = results[0].cycles_per_byte;
    
    for (int i = 0; i < 4; i++) {
        double speedup = baseline_cpb / results[i].cycles_per_byte;
        printf("%-13s | %11.2f | %17.2f | %6.2fx\n", 
               impl_names[i], 
               results[i].cycles_per_byte,
               results[i].mbytes_per_sec,
               speedup);
    }
    printf("\n");
}
