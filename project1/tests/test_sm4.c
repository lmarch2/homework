#include "../src/sm4.h"
#include "test_vectors.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>

// Test result structure
typedef struct
{
    int total_tests;
    int passed_tests;
    int failed_tests;
} test_results;

// Global test results
static test_results results = {0, 0, 0};

// Helper function to run a test
static void run_test(const char *test_name, int (*test_func)(void))
{
    printf("Running %s... ", test_name);
    fflush(stdout);

    results.total_tests++;

    if (test_func() == 0)
    {
        printf("PASSED\n");
        results.passed_tests++;
    }
    else
    {
        printf("FAILED\n");
        results.failed_tests++;
    }
}

// Helper function to compare arrays
static int compare_arrays(const uint8_t *a, const uint8_t *b, size_t len, const char *name)
{
    if (memcmp(a, b, len) != 0)
    {
        printf("\n%s mismatch!\n", name);
        printf("Expected: ");
        sm4_print_hex(b, len);
        printf("Got:      ");
        sm4_print_hex(a, len);
        return -1;
    }
    return 0;
}

// Test basic SM4 encryption/decryption
static int test_basic_encryption(void)
{
    uint8_t output[16];
    uint8_t decrypted[16];

    // Test encryption
    sm4_basic_encrypt(test_key1, test_plaintext1, output);
    if (compare_arrays(output, test_ciphertext1, 16, "Basic encryption") != 0)
    {
        return -1;
    }

    // Test decryption
    sm4_basic_decrypt(test_key1, test_ciphertext1, decrypted);
    if (compare_arrays(decrypted, test_plaintext1, 16, "Basic decryption") != 0)
    {
        return -1;
    }

    return 0;
}

// Test T-table optimized implementation
static int test_ttable_encryption(void)
{
    uint8_t output[16];
    uint8_t decrypted[16];

    // Test encryption
    sm4_ttable_encrypt(test_key1, test_plaintext1, output);
    if (compare_arrays(output, test_ciphertext1, 16, "T-table encryption") != 0)
    {
        return -1;
    }

    // Test decryption
    sm4_ttable_decrypt(test_key1, test_ciphertext1, decrypted);
    if (compare_arrays(decrypted, test_plaintext1, 16, "T-table decryption") != 0)
    {
        return -1;
    }

    return 0;
}

// Test AES-NI optimized implementation
static int test_aesni_encryption(void)
{
    uint8_t output[16];
    uint8_t decrypted[16];

    // Test encryption
    sm4_aesni_encrypt(test_key1, test_plaintext1, output);
    if (compare_arrays(output, test_ciphertext1, 16, "AES-NI encryption") != 0)
    {
        return -1;
    }

    // Test decryption
    sm4_aesni_decrypt(test_key1, test_ciphertext1, decrypted);
    if (compare_arrays(decrypted, test_plaintext1, 16, "AES-NI decryption") != 0)
    {
        return -1;
    }

    return 0;
}

// Test GFNI optimized implementation (if available)
static int test_gfni_encryption(void)
{
#ifdef __GFNI__
    if (!sm4_cpu_support_gfni())
    {
        printf("(GFNI not supported, skipping) ");
        return 0;
    }

    uint8_t output[16];
    uint8_t decrypted[16];

    // Test encryption
    sm4_gfni_encrypt(test_key1, test_plaintext1, output);
    if (compare_arrays(output, test_ciphertext1, 16, "GFNI encryption") != 0)
    {
        return -1;
    }

    // Test decryption
    sm4_gfni_decrypt(test_key1, test_ciphertext1, decrypted);
    if (compare_arrays(decrypted, test_plaintext1, 16, "GFNI decryption") != 0)
    {
        return -1;
    }
#else
    printf("(GFNI not compiled in, skipping) ");
#endif

    return 0;
}

// Test implementation consistency
static int test_implementation_consistency(void)
{
    uint8_t basic_output[16];
    uint8_t ttable_output[16];
    uint8_t aesni_output[16];

    // Encrypt with all implementations
    sm4_basic_encrypt(test_key1, test_plaintext1, basic_output);
    sm4_ttable_encrypt(test_key1, test_plaintext1, ttable_output);
    sm4_aesni_encrypt(test_key1, test_plaintext1, aesni_output);

    // Compare results
    if (compare_arrays(ttable_output, basic_output, 16, "T-table vs Basic") != 0)
    {
        return -1;
    }

    if (compare_arrays(aesni_output, basic_output, 16, "AES-NI vs Basic") != 0)
    {
        return -1;
    }

#ifdef __GFNI__
    if (sm4_cpu_support_gfni())
    {
        uint8_t gfni_output[16];
        sm4_gfni_encrypt(test_key1, test_plaintext1, gfni_output);
        if (compare_arrays(gfni_output, basic_output, 16, "GFNI vs Basic") != 0)
        {
            return -1;
        }
    }
#endif

    return 0;
}

// Test million rounds (stress test)
static int test_million_rounds(void)
{
    uint8_t plaintext[16];
    uint8_t ciphertext[16];
    int i;

    // Initialize with test vector
    memcpy(plaintext, test_plaintext2, 16);

    printf("\n  Running 1,000,000 encryption rounds... ");
    fflush(stdout);

    // Encrypt 1,000,000 times
    for (i = 0; i < 1000000; i++)
    {
        sm4_basic_encrypt(test_key2, plaintext, ciphertext);
        memcpy(plaintext, ciphertext, 16);
    }

    printf("done\n  ");

    // Compare with expected result
    if (compare_arrays(ciphertext, test_ciphertext2_1000000, 16, "Million rounds result") != 0)
    {
        return -1;
    }

    return 0;
}

// Test key expansion
static int test_key_expansion(void)
{
    sm4_context ctx_enc, ctx_dec;
    uint8_t output[16];
    uint8_t decrypted[16];

    // Test key expansion for encryption
    sm4_setkey_enc(&ctx_enc, test_key1);

    // Test key expansion for decryption
    sm4_setkey_dec(&ctx_dec, test_key1);

    // Test encryption
    sm4_crypt_ecb(&ctx_enc, 1, test_plaintext1, output);
    if (compare_arrays(output, test_ciphertext1, 16, "Key expansion encryption") != 0)
    {
        return -1;
    }

    // Test decryption
    sm4_crypt_ecb(&ctx_dec, 0, test_ciphertext1, decrypted);
    if (compare_arrays(decrypted, test_plaintext1, 16, "Key expansion decryption") != 0)
    {
        return -1;
    }

    return 0;
}

// Test GCM mode
static int test_gcm_mode(void)
{
    uint8_t ciphertext[16];
    uint8_t tag[16];
    uint8_t decrypted[16];
    int ret;

    // Test GCM encryption
    ret = sm4_gcm_encrypt(gcm_key, gcm_iv, 12, gcm_aad, 8,
                          gcm_plaintext, 16, ciphertext, tag, 16);
    if (ret != 0)
    {
        printf("\nGCM encryption failed with error %d", ret);
        return -1;
    }

    // Test GCM decryption
    ret = sm4_gcm_decrypt(gcm_key, gcm_iv, 12, gcm_aad, 8,
                          ciphertext, 16, tag, 16, decrypted);
    if (ret != 0)
    {
        printf("\nGCM decryption failed with error %d", ret);
        return -1;
    }

    // Verify decrypted plaintext
    if (compare_arrays(decrypted, gcm_plaintext, 16, "GCM decrypted plaintext") != 0)
    {
        return -1;
    }

    // Test authentication failure
    uint8_t bad_tag[16];
    memcpy(bad_tag, tag, 16);
    bad_tag[0] ^= 1; // Corrupt tag

    ret = sm4_gcm_decrypt(gcm_key, gcm_iv, 12, gcm_aad, 8,
                          ciphertext, 16, bad_tag, 16, decrypted);
    if (ret != -2)
    {
        printf("\nGCM should have failed authentication but didn't");
        return -1;
    }

    return 0;
}

// Test random data
static int test_random_data(void)
{
    const int num_tests = 100;
    uint8_t key[16], plaintext[16], ciphertext[16], decrypted[16];
    int i;

    printf("\n  Testing %d random vectors... ", num_tests);
    fflush(stdout);

    // Seed random number generator
    sm4_srand(12345);

    for (i = 0; i < num_tests; i++)
    {
        // Generate random key and plaintext
        sm4_rand_bytes(key, 16);
        sm4_rand_bytes(plaintext, 16);

        // Encrypt and decrypt
        sm4_basic_encrypt(key, plaintext, ciphertext);
        sm4_basic_decrypt(key, ciphertext, decrypted);

        // Verify round-trip
        if (memcmp(plaintext, decrypted, 16) != 0)
        {
            printf("\nRandom test %d failed!", i);
            return -1;
        }
    }

    printf("done\n  ");
    return 0;
}

// Test CPU features
static int test_cpu_features(void)
{
    printf("\n  CPU Features:\n");
    printf("    AES-NI: %s\n", sm4_cpu_support_aesni() ? "Yes" : "No");
    printf("    GFNI:   %s\n", sm4_cpu_support_gfni() ? "Yes" : "No");
    printf("    AVX2:   %s\n", sm4_cpu_support_avx2() ? "Yes" : "No");
    printf("  ");

    return 0;
}

// Main test function
int main(void)
{
    printf("=== SM4 Implementation Test Suite ===\n\n");

    // Run all tests
    run_test("CPU Feature Detection", test_cpu_features);
    run_test("Basic Implementation", test_basic_encryption);
    run_test("T-table Implementation", test_ttable_encryption);
    run_test("AES-NI Implementation", test_aesni_encryption);
    run_test("GFNI Implementation", test_gfni_encryption);
    run_test("Implementation Consistency", test_implementation_consistency);
    run_test("Key Expansion", test_key_expansion);
    run_test("Million Rounds Test", test_million_rounds);
    run_test("GCM Mode", test_gcm_mode);
    run_test("Random Data Test", test_random_data);

    // Print summary
    printf("\n=== Test Summary ===\n");
    printf("Total tests: %d\n", results.total_tests);
    printf("Passed: %d\n", results.passed_tests);
    printf("Failed: %d\n", results.failed_tests);

    if (results.failed_tests == 0)
    {
        printf("\nAll tests PASSED! ✓\n");
        return 0;
    }
    else
    {
        printf("\n%d test(s) FAILED! ✗\n", results.failed_tests);
        return 1;
    }
}
