#include "../src/sm4.h"
#include <stdio.h>
#include <string.h>
#include <time.h>

// Test key and data
static const uint8_t test_key[16] = {
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};

static const uint8_t test_iv[12] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b};

static const uint8_t test_aad[8] = {
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa};

void test_performance(const char *name, 
                     int (*encrypt_func)(const uint8_t *, const uint8_t *, size_t,
                                       const uint8_t *, size_t,
                                       const uint8_t *, size_t,
                                       uint8_t *, uint8_t *, size_t),
                     int (*decrypt_func)(const uint8_t *, const uint8_t *, size_t,
                                       const uint8_t *, size_t,
                                       const uint8_t *, size_t,
                                       const uint8_t *, size_t, uint8_t *))
{
    const int iterations = 10000;
    uint8_t plaintext[16] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};
    uint8_t ciphertext[16];
    uint8_t decrypted[16];
    uint8_t tag[16];
    clock_t start, end;

    printf("=== %s Performance Test ===\n", name);

    // 测试正确性
    printf("Testing correctness...\n");
    int ret = encrypt_func(test_key, test_iv, 12, test_aad, 8,
                          plaintext, 16, ciphertext, tag, 16);
    if (ret != 0) {
        printf("Encryption failed\n");
        return;
    }

    ret = decrypt_func(test_key, test_iv, 12, test_aad, 8,
                      ciphertext, 16, tag, 16, decrypted);
    if (ret != 0) {
        printf("Decryption failed\n");
        return;
    }

    if (memcmp(plaintext, decrypted, 16) != 0) {
        printf("Decryption mismatch\n");
        return;
    }

    printf("Correctness test PASSED\n");

    // 性能测试 - 加密
    printf("Benchmarking encryption...\n");
    start = clock();
    for (int i = 0; i < iterations; i++) {
        encrypt_func(test_key, test_iv, 12, test_aad, 8,
                    plaintext, 16, ciphertext, tag, 16);
    }
    end = clock();

    double cpu_time = ((double)(end - start)) / CLOCKS_PER_SEC;
    double blocks_per_sec = iterations / cpu_time;
    double mb_per_sec = (blocks_per_sec * 16) / (1024 * 1024);

    printf("Iterations: %d\n", iterations);
    printf("Time: %.3f seconds\n", cpu_time);
    printf("Performance: %.2f MB/s\n", mb_per_sec);
    printf("Blocks/sec: %.0f\n", blocks_per_sec);
    printf("Note: Includes encryption + authentication\n\n");
}

int main()
{
    printf("=== SM4-GCM Performance Comparison ===\n\n");

    // Test basic implementation
    test_performance("SM4-GCM Basic", sm4_gcm_encrypt, sm4_gcm_decrypt);

    // Test optimized implementation
    test_performance("SM4-GCM Optimized", sm4_gcm_encrypt_opt, sm4_gcm_decrypt_opt);

    return 0;
}
