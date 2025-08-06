#include "src/sm4.h"
#include <stdio.h>
#include <string.h>

// Helper function to print hex
void print_hex(const uint8_t *data, size_t len)
{
    for (size_t i = 0; i < len; i++)
    {
        printf("%02x ", data[i]);
        if ((i + 1) % 8 == 0)
            printf(" ");
    }
    printf("\n");
}

// Test vectors from test_vectors.h
static const uint8_t test_key1[16] = {
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};

static const uint8_t test_plaintext1[16] = {
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};

static const uint8_t test_ciphertext1[16] = {
    0x68, 0x1e, 0xdf, 0x34, 0xd2, 0x06, 0x96, 0x5e,
    0x86, 0xb3, 0xe9, 0x4f, 0x53, 0x6e, 0x42, 0x46};

int main()
{
    uint8_t output[16];

    printf("=== SM4 Implementation Debug ===\n");

    printf("Test Key: ");
    print_hex(test_key1, 16);

    printf("Plaintext: ");
    print_hex(test_plaintext1, 16);

    printf("Expected: ");
    print_hex(test_ciphertext1, 16);

    // Test basic implementation
    sm4_basic_encrypt(test_key1, test_plaintext1, output);
    printf("Basic:    ");
    print_hex(output, 16);
    printf("Basic correct: %s\n", memcmp(output, test_ciphertext1, 16) == 0 ? "YES" : "NO");

    // Test T-table implementation
    sm4_ttable_encrypt(test_key1, test_plaintext1, output);
    printf("T-table:  ");
    print_hex(output, 16);
    printf("T-table correct: %s\n", memcmp(output, test_ciphertext1, 16) == 0 ? "YES" : "NO");

    return 0;
}
