#include "src/sm4.h"
#include <stdio.h>
#include <string.h>

// Helper function to print hex
void print_hex(const uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02x ", data[i]);
        if ((i + 1) % 8 == 0) printf(" ");
    }
    printf("\n");
}

// Test vectors from test_vectors.h
static const uint8_t test_key1[16] = {
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
};

static const uint8_t test_plaintext1[16] = {
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
};

static const uint8_t test_ciphertext1[16] = {
    0x68, 0x1e, 0xdf, 0x34, 0xd2, 0x06, 0x96, 0x5e,
    0x86, 0xb3, 0xe9, 0x4f, 0x53, 0x6e, 0x42, 0x46
};

// Compare first few round keys
void compare_round_keys() {
    // Basic implementation
    sm4_context ctx_basic;
    sm4_setkey_enc(&ctx_basic, test_key1);
    
    printf("Basic round keys (first 4):\n");
    for (int i = 0; i < 4; i++) {
        printf("  rk[%d] = 0x%08x\n", i, ctx_basic.rk[i]);
    }
    
    // T-table implementation - we need to expose internal function
    printf("\nNote: Cannot easily compare T-table keys due to internal implementation\n");
}

int main() {
    printf("=== SM4 Round Key Debug ===\n");
    compare_round_keys();
    
    return 0;
}
