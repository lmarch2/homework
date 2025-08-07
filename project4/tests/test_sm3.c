#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include <stdlib.h>
#include "../src/sm3.h"

void print_hex(const uint8_t *data, size_t len)
{
    for (size_t i = 0; i < len; i++)
    {
        printf("%02x", data[i]);
    }
    printf("\n");
}

void test_sm3_basic_vectors()
{
    printf("Testing SM3 basic test vectors...\n");

    const char *test1 = "abc";
    uint8_t expected1[] = {0x66, 0xc7, 0xf0, 0xf4, 0x62, 0xee, 0xed, 0xd9,
                           0xd1, 0xf2, 0xd4, 0x6b, 0xdc, 0x10, 0xe4, 0xe2,
                           0x41, 0x67, 0xc4, 0x87, 0x5c, 0xf2, 0xf7, 0xa2,
                           0x29, 0x7d, 0xa0, 0x2b, 0x8f, 0x4b, 0xa8, 0xe0};

    uint8_t result1[SM3_DIGEST_SIZE];
    sm3_hash((uint8_t *)test1, strlen(test1), result1);

    printf("Input: %s\n", test1);
    printf("Expected: ");
    print_hex(expected1, SM3_DIGEST_SIZE);
    printf("Got:      ");
    print_hex(result1, SM3_DIGEST_SIZE);

    assert(memcmp(result1, expected1, SM3_DIGEST_SIZE) == 0);
    printf("✓ Test 1 passed\n\n");

    const char *test2 = "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd";
    uint8_t expected2[] = {0xde, 0xbe, 0x9f, 0xf9, 0x22, 0x75, 0xb8, 0xa1,
                           0x38, 0x60, 0x48, 0x89, 0xc1, 0x8e, 0x5a, 0x4d,
                           0x6f, 0xdb, 0x70, 0xe5, 0x38, 0x7e, 0x57, 0x65,
                           0x29, 0x3d, 0xcb, 0xa3, 0x9c, 0x0c, 0x57, 0x32};

    uint8_t result2[SM3_DIGEST_SIZE];
    sm3_hash((uint8_t *)test2, strlen(test2), result2);

    printf("Input: %s\n", test2);
    printf("Expected: ");
    print_hex(expected2, SM3_DIGEST_SIZE);
    printf("Got:      ");
    print_hex(result2, SM3_DIGEST_SIZE);

    assert(memcmp(result2, expected2, SM3_DIGEST_SIZE) == 0);
    printf("✓ Test 2 passed\n\n");
}

void test_sm3_optimized_vs_basic()
{
    printf("Testing optimized vs basic implementation...\n");

    const char *test_data[] = {
        "",
        "a",
        "abc",
        "The quick brown fox jumps over the lazy dog",
        "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd",
        "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua."};

    int num_tests = sizeof(test_data) / sizeof(test_data[0]);

    for (int i = 0; i < num_tests; i++)
    {
        uint8_t basic_result[SM3_DIGEST_SIZE];
        uint8_t optimized_result[SM3_DIGEST_SIZE];

        sm3_hash((uint8_t *)test_data[i], strlen(test_data[i]), basic_result);
        sm3_hash_optimized((uint8_t *)test_data[i], strlen(test_data[i]), optimized_result);

        printf("Test %d: %s\n", i + 1, strlen(test_data[i]) > 50 ? "Long message" : test_data[i]);
        printf("Basic:     ");
        print_hex(basic_result, SM3_DIGEST_SIZE);
        printf("Optimized: ");
        print_hex(optimized_result, SM3_DIGEST_SIZE);

        assert(memcmp(basic_result, optimized_result, SM3_DIGEST_SIZE) == 0);
        printf("✓ Match confirmed\n\n");
    }
}

void test_sm3_incremental()
{
    printf("Testing incremental hashing...\n");

    const char *message = "The quick brown fox jumps over the lazy dog";
    size_t len = strlen(message);

    uint8_t full_hash[SM3_DIGEST_SIZE];
    sm3_hash((uint8_t *)message, len, full_hash);

    sm3_ctx_t ctx;
    sm3_init(&ctx);

    for (size_t i = 0; i < len; i++)
    {
        sm3_update(&ctx, (uint8_t *)&message[i], 1);
    }

    uint8_t incremental_hash[SM3_DIGEST_SIZE];
    sm3_final(&ctx, incremental_hash);

    printf("Full hash:        ");
    print_hex(full_hash, SM3_DIGEST_SIZE);
    printf("Incremental hash: ");
    print_hex(incremental_hash, SM3_DIGEST_SIZE);

    assert(memcmp(full_hash, incremental_hash, SM3_DIGEST_SIZE) == 0);
    printf("✓ Incremental hashing test passed\n\n");
}

void performance_test()
{
    printf("Performance testing...\n");

    const size_t test_sizes[] = {1024, 10240, 102400, 1048576};
    const int num_sizes = sizeof(test_sizes) / sizeof(test_sizes[0]);
    const int iterations = 100;

    for (int i = 0; i < num_sizes; i++)
    {
        uint8_t *test_data = malloc(test_sizes[i]);
        for (size_t j = 0; j < test_sizes[i]; j++)
        {
            test_data[j] = (uint8_t)(j & 0xFF);
        }

        uint8_t hash[SM3_DIGEST_SIZE];

        clock_t start = clock();
        for (int iter = 0; iter < iterations; iter++)
        {
            sm3_hash(test_data, test_sizes[i], hash);
        }
        clock_t basic_time = clock() - start;

        start = clock();
        for (int iter = 0; iter < iterations; iter++)
        {
            sm3_hash_optimized(test_data, test_sizes[i], hash);
        }
        clock_t optimized_time = clock() - start;

        double basic_mb_per_sec = (double)(test_sizes[i] * iterations) / (1024 * 1024) /
                                  ((double)basic_time / CLOCKS_PER_SEC);
        double optimized_mb_per_sec = (double)(test_sizes[i] * iterations) / (1024 * 1024) /
                                      ((double)optimized_time / CLOCKS_PER_SEC);

        printf("Size: %zu bytes\n", test_sizes[i]);
        printf("  Basic:     %.2f MB/s\n", basic_mb_per_sec);
        printf("  Optimized: %.2f MB/s\n", optimized_mb_per_sec);
        printf("  Speedup:   %.2fx\n\n", optimized_mb_per_sec / basic_mb_per_sec);

        free(test_data);
    }
}

int main()
{
    printf("SM3 Algorithm Test Suite\n");
    printf("========================\n\n");

    test_sm3_basic_vectors();
    test_sm3_optimized_vs_basic();
    test_sm3_incremental();
    performance_test();

    printf("All SM3 tests passed!\n");
    return 0;
}
