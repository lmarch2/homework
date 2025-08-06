#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <stdint.h>

// Test data
static const uint8_t test_key[16] = {
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};

static const uint8_t test_plaintext[16] = {
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};

// Function pointers for different implementations
typedef void (*sm4_encrypt_func_t)(const uint8_t *key, const uint8_t *input, uint8_t *output);

// External functions
extern void sm4_basic_encrypt(const uint8_t *key, const uint8_t *input, uint8_t *output);

// Utility functions
double get_time_ms()
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec * 1000.0 + tv.tv_usec / 1000.0;
}

uint64_t rdtsc()
{
    uint32_t lo, hi;
    __asm__ __volatile__("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
}

void print_hex(const uint8_t *data, size_t len)
{
    for (size_t i = 0; i < len; i++)
    {
        printf("%02x", data[i]);
    }
    printf("\n");
}

// Benchmark function with cycle counting
void benchmark_implementation(const char *name, sm4_encrypt_func_t encrypt_func, int iterations)
{
    uint8_t input[16], output[16];
    memcpy(input, test_plaintext, 16);

    printf("=== %s Implementation ===\n", name);

    // Warmup
    for (int i = 0; i < 1000; i++)
    {
        encrypt_func(test_key, input, output);
    }

    // Time-based benchmark
    double start_time = get_time_ms();
    for (int i = 0; i < iterations; i++)
    {
        encrypt_func(test_key, input, output);
    }
    double end_time = get_time_ms();

    double elapsed_ms = end_time - start_time;
    double blocks_per_sec = (iterations * 1000.0) / elapsed_ms;
    double mb_per_sec = (blocks_per_sec * 16) / (1024 * 1024);

    // Cycle-based benchmark (more accurate for small operations)
    uint64_t start_cycles = rdtsc();
    for (int i = 0; i < 10000; i++)
    {
        encrypt_func(test_key, input, output);
    }
    uint64_t end_cycles = rdtsc();

    uint64_t cycles_per_block = (end_cycles - start_cycles) / 10000;
    double cycles_per_byte = cycles_per_block / 16.0;

    printf("Time-based (100k iterations):\n");
    printf("  Elapsed: %.2f ms\n", elapsed_ms);
    printf("  Performance: %.2f MB/s\n", mb_per_sec);
    printf("  Blocks/sec: %.0f\n", blocks_per_sec);

    printf("Cycle-based (10k iterations):\n");
    printf("  Cycles/block: %lu\n", cycles_per_block);
    printf("  Cycles/byte: %.2f\n", cycles_per_byte);

    // Verify correctness
    uint8_t expected_output[16];
    sm4_basic_encrypt(test_key, input, expected_output);

    if (memcmp(output, expected_output, 16) == 0)
    {
        printf("  Correctness: ✓ PASS\n");
    }
    else
    {
        printf("  Correctness: ✗ FAIL\n");
        printf("  Expected: ");
        print_hex(expected_output, 16);
        printf("  Got:      ");
        print_hex(output, 16);
    }

    printf("\n");
}

// Memory access pattern analysis
void analyze_memory_patterns(const char *name, sm4_encrypt_func_t encrypt_func)
{
    printf("=== %s Memory Analysis ===\n", name);

    uint8_t input[16], output[16];
    memcpy(input, test_plaintext, 16);

    // Test cache behavior with different data patterns
    const int test_sizes[] = {1, 16, 256, 4096, 65536};
    const int num_sizes = sizeof(test_sizes) / sizeof(test_sizes[0]);

    for (int s = 0; s < num_sizes; s++)
    {
        int data_size = test_sizes[s];
        uint8_t *test_data = malloc(data_size * 16);

        // Fill with different patterns
        for (int i = 0; i < data_size; i++)
        {
            memcpy(test_data + i * 16, test_plaintext, 16);
            test_data[i * 16] = i & 0xFF; // Make each block unique
        }

        // Benchmark with this data size
        uint64_t start_cycles = rdtsc();
        for (int i = 0; i < data_size; i++)
        {
            encrypt_func(test_key, test_data + i * 16, output);
        }
        uint64_t end_cycles = rdtsc();

        double cycles_per_block = (double)(end_cycles - start_cycles) / data_size;

        printf("  Data size %d blocks: %.2f cycles/block\n", data_size, cycles_per_block);

        free(test_data);
    }

    printf("\n");
}

// CPU feature detection
void print_cpu_features()
{
    printf("=== CPU Feature Detection ===\n");

    uint32_t eax, ebx, ecx, edx;

    // Get basic CPU info
    __asm__("cpuid" : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx) : "a"(0));
    printf("Max CPUID level: %u\n", eax);

    // Get feature flags
    __asm__("cpuid" : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx) : "a"(1));
    printf("CPU Features:\n");
    printf("  SSE2: %s\n", (edx & (1 << 26)) ? "YES" : "NO");
    printf("  AES-NI: %s\n", (ecx & (1 << 25)) ? "YES" : "NO");
    printf("  AVX: %s\n", (ecx & (1 << 28)) ? "YES" : "NO");

    // Get extended features
    __asm__("cpuid" : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx) : "a"(7), "c"(0));
    printf("  AVX2: %s\n", (ebx & (1 << 5)) ? "YES" : "NO");
    printf("  GFNI: %s\n", (ecx & (1 << 8)) ? "YES" : "NO");

    printf("\n");
}

int main()
{
    printf("=== SM4 Comprehensive Performance Analysis ===\n\n");

    print_cpu_features();

    // Benchmark basic implementation with different optimization levels
    printf("=== Compilation Optimization Analysis ===\n");
    printf("This test shows how different GCC optimization levels affect performance:\n");
    printf("- Pure: gcc with no optimization flags\n");
    printf("- O3: gcc -O3 optimization\n");
    printf("- Native: gcc -O3 -march=native optimization\n\n");

    // Test basic implementation
    benchmark_implementation("SM4 Basic", sm4_basic_encrypt, 100000);

    // Memory pattern analysis
    analyze_memory_patterns("SM4 Basic", sm4_basic_encrypt);

    printf("=== Performance Summary ===\n");
    printf("Target performance goals based on analysis.md:\n");
    printf("- Basic implementation: ~60 cycles/byte (baseline)\n");
    printf("- T-table optimization: 50-55 cycles/byte (10-20%% improvement)\n");
    printf("- AES-NI optimization: 40-45 cycles/byte (25-35%% improvement)\n");
    printf("- GFNI optimization: 30-35 cycles/byte (40-50%% improvement)\n\n");

    printf("=== Negative Optimization Analysis ===\n");
    printf("Common causes of negative optimization:\n");
    printf("1. CPUID overhead: 100-300 cycles per call\n");
    printf("2. Function call overhead: 5-20 cycles per call\n");
    printf("3. Cache misses: 100-300 cycles per miss\n");
    printf("4. Branch misprediction: 10-20 cycles per miss\n");
    printf("5. False optimization: Complex code that doesn't use hardware features\n\n");

    return 0;
}
