#include "../src/sm4.h"
#include <stdio.h>
#include <string.h>
#include <time.h>

// 添加GCM需要的辅助函数
int sm4_memcmp_const_time(const uint8_t *a, const uint8_t *b, size_t len)
{
    int diff = 0;
    for (size_t i = 0; i < len; i++)
    {
        diff |= a[i] ^ b[i];
    }
    return diff;
}

void sm4_memzero(void *ptr, size_t size)
{
    volatile uint8_t *p = (volatile uint8_t *)ptr;
    for (size_t i = 0; i < size; i++)
    {
        p[i] = 0;
    }
}

// Test key and data
static const uint8_t test_key[16] = {
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};

static const uint8_t test_iv[12] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b};

static const uint8_t test_aad[8] = {
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa};

int main()
{
    const int iterations = 10000; // 减少迭代次数，因为GCM比ECB慢
    uint8_t plaintext[16] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};
    uint8_t ciphertext[16];
    uint8_t tag[16];
    clock_t start, end;

    printf("=== SM4-GCM Performance Test ===\n\n");

    // 测试正确性
    printf("Testing SM4-GCM correctness...\n");
    int ret = sm4_gcm_encrypt(test_key, test_iv, 12, test_aad, 8,
                              plaintext, 16, ciphertext, tag, 16);
    if (ret != 0)
    {
        printf("GCM encryption failed\n");
        return 1;
    }

    uint8_t decrypted[16];
    ret = sm4_gcm_decrypt(test_key, test_iv, 12, test_aad, 8,
                          ciphertext, 16, tag, 16, decrypted);
    if (ret != 0)
    {
        printf("GCM decryption failed\n");
        return 1;
    }

    if (memcmp(plaintext, decrypted, 16) != 0)
    {
        printf("GCM decryption mismatch\n");
        return 1;
    }

    printf("Correctness test PASSED\n\n");

    // 性能测试 - GCM加密
    printf("Benchmarking SM4-GCM Encryption...\n");
    start = clock();
    for (int i = 0; i < iterations; i++)
    {
        sm4_gcm_encrypt(test_key, test_iv, 12, test_aad, 8,
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
    printf("Note: GCM includes encryption + authentication\n");

    return 0;
}
