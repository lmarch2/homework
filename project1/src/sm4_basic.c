#include "sm4.h"
#include <stdio.h>

// System parameters FK
const uint32_t FK[4] = {
    0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC
};

// Fixed parameters CK
const uint32_t CK[32] = {
    0x00070E15, 0x1C232A31, 0x383F464D, 0x545B6269,
    0x70777E85, 0x8C939AA1, 0xA8AFB6BD, 0xC4CBD2D9,
    0xE0E7EEF5, 0xFC030A11, 0x181F262D, 0x343B4249,
    0x50575E65, 0x6C737A81, 0x888F969D, 0xA4ABB2B9,
    0xC0C7CED5, 0xDCE3EAF1, 0xF8FF060D, 0x141B2229,
    0x30373E45, 0x4C535A61, 0x686F767D, 0x848B9299,
    0xA0A7AEB5, 0xBCC3CAD1, 0xD8DFE6ED, 0xF4FB0209,
    0x10171E25, 0x2C333A41, 0x484F565D, 0x646B7279
};

// SM4 S-box
const uint8_t SM4_SBOX[256] = {
    0xD6, 0x90, 0xE9, 0xFE, 0xCC, 0xE1, 0x3D, 0xB7, 0x16, 0xB6, 0x14, 0xC2, 0x28, 0xFB, 0x2C, 0x05,
    0x2B, 0x67, 0x9A, 0x76, 0x2A, 0xBE, 0x04, 0xC3, 0xAA, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
    0x9C, 0x42, 0x50, 0xF4, 0x91, 0xEF, 0x98, 0x7A, 0x33, 0x54, 0x0B, 0x43, 0xED, 0xCF, 0xAC, 0x62,
    0xE4, 0xB3, 0x1C, 0xA9, 0xC9, 0x08, 0xE8, 0x95, 0x80, 0xDF, 0x94, 0xFA, 0x75, 0x8F, 0x3F, 0xA6,
    0x47, 0x07, 0xA7, 0xFC, 0xF3, 0x73, 0x17, 0xBA, 0x83, 0x59, 0x3C, 0x19, 0xE6, 0x85, 0x4F, 0xA8,
    0x68, 0x6B, 0x81, 0xB2, 0x71, 0x64, 0xDA, 0x8B, 0xF8, 0xEB, 0x0F, 0x4B, 0x70, 0x56, 0x9D, 0x35,
    0x1E, 0x24, 0x0E, 0x5E, 0x63, 0x58, 0xD1, 0xA2, 0x25, 0x22, 0x7C, 0x3B, 0x01, 0x21, 0x78, 0x87,
    0xD4, 0x00, 0x46, 0x57, 0x9F, 0xD3, 0x27, 0x52, 0x4C, 0x36, 0x02, 0xE7, 0xA0, 0xC4, 0xC8, 0x9E,
    0xEA, 0xBF, 0x8A, 0xD2, 0x40, 0xC7, 0x38, 0xB5, 0xA3, 0xF7, 0xF2, 0xCE, 0xF9, 0x61, 0x15, 0xA1,
    0xE0, 0xAE, 0x5D, 0xA4, 0x9B, 0x34, 0x1A, 0x55, 0xAD, 0x93, 0x32, 0x30, 0xF5, 0x8C, 0xB1, 0xE3,
    0x1D, 0xF6, 0xE2, 0x2E, 0x82, 0x66, 0xCA, 0x60, 0xC0, 0x29, 0x23, 0xAB, 0x0D, 0x53, 0x4E, 0x6F,
    0xD5, 0xDB, 0x37, 0x45, 0xDE, 0xFD, 0x8E, 0x2F, 0x03, 0xFF, 0x6A, 0x72, 0x6D, 0x6C, 0x5B, 0x51,
    0x8D, 0x1B, 0xAF, 0x92, 0xBB, 0xDD, 0xBC, 0x7F, 0x11, 0xD9, 0x5C, 0x41, 0x1F, 0x10, 0x5A, 0xD8,
    0x0A, 0xC1, 0x31, 0x88, 0xA5, 0xCD, 0x7B, 0xBD, 0x2D, 0x74, 0xD0, 0x12, 0xB8, 0xE5, 0xB4, 0xB0,
    0x89, 0x69, 0x97, 0x4A, 0x0C, 0x96, 0x77, 0x7E, 0x65, 0xB9, 0xF1, 0x09, 0xC5, 0x6E, 0xC6, 0x84,
    0x18, 0xF0, 0x7D, 0xEC, 0x3A, 0xDC, 0x4D, 0x20, 0x79, 0xEE, 0x5F, 0x3E, 0xD7, 0xCB, 0x39, 0x48
};

// Helper functions
static inline uint32_t rotl(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}

static inline uint32_t get_u32_be(const uint8_t *data) {
    return ((uint32_t)data[0] << 24) |
           ((uint32_t)data[1] << 16) |
           ((uint32_t)data[2] << 8) |
           ((uint32_t)data[3]);
}

static inline void put_u32_be(uint8_t *data, uint32_t value) {
    data[0] = (value >> 24) & 0xFF;
    data[1] = (value >> 16) & 0xFF;
    data[2] = (value >> 8) & 0xFF;
    data[3] = value & 0xFF;
}

// Non-linear transformation τ (S-box substitution)
static uint32_t sm4_sbox_transform(uint32_t x) {
    uint8_t a[4];
    a[0] = (x >> 24) & 0xFF;
    a[1] = (x >> 16) & 0xFF;
    a[2] = (x >> 8) & 0xFF;
    a[3] = x & 0xFF;
    
    return ((uint32_t)SM4_SBOX[a[0]] << 24) |
           ((uint32_t)SM4_SBOX[a[1]] << 16) |
           ((uint32_t)SM4_SBOX[a[2]] << 8) |
           ((uint32_t)SM4_SBOX[a[3]]);
}

// Linear transformation L
static uint32_t sm4_linear_transform(uint32_t x) {
    return x ^ rotl(x, 2) ^ rotl(x, 10) ^ rotl(x, 18) ^ rotl(x, 24);
}

// Linear transformation L' for key expansion
static uint32_t sm4_linear_transform_key(uint32_t x) {
    return x ^ rotl(x, 13) ^ rotl(x, 23);
}

// Round function F
static uint32_t sm4_round_function(uint32_t x) {
    return sm4_linear_transform(sm4_sbox_transform(x));
}

// Round function T' for key expansion
static uint32_t sm4_key_round_function(uint32_t x) {
    return sm4_linear_transform_key(sm4_sbox_transform(x));
}

// Key expansion
void sm4_setkey_enc(sm4_context *ctx, const uint8_t key[SM4_KEY_SIZE]) {
    uint32_t K[4];
    uint32_t rk[4];
    int i;
    
    // Convert key to 32-bit words
    K[0] = get_u32_be(key);
    K[1] = get_u32_be(key + 4);
    K[2] = get_u32_be(key + 8);
    K[3] = get_u32_be(key + 12);
    
    // Initialize with system parameters
    rk[0] = K[0] ^ FK[0];
    rk[1] = K[1] ^ FK[1];
    rk[2] = K[2] ^ FK[2];
    rk[3] = K[3] ^ FK[3];
    
    // Generate round keys
    for (i = 0; i < SM4_ROUNDS; i++) {
        ctx->rk[i] = rk[(i + 4) % 4] = rk[i % 4] ^ 
            sm4_key_round_function(rk[(i + 1) % 4] ^ rk[(i + 2) % 4] ^ rk[(i + 3) % 4] ^ CK[i]);
    }
}

// For decryption, we use the same round keys in reverse order
void sm4_setkey_dec(sm4_context *ctx, const uint8_t key[SM4_KEY_SIZE]) {
    sm4_context temp_ctx;
    int i;
    
    // Generate encryption round keys
    sm4_setkey_enc(&temp_ctx, key);
    
    // Reverse the order for decryption
    for (i = 0; i < SM4_ROUNDS; i++) {
        ctx->rk[i] = temp_ctx.rk[SM4_ROUNDS - 1 - i];
    }
}

// SM4 encryption/decryption (ECB mode)
void sm4_crypt_ecb(sm4_context *ctx, int mode, const uint8_t input[SM4_BLOCK_SIZE], uint8_t output[SM4_BLOCK_SIZE]) {
    uint32_t X[4];
    int i;
    
    // Convert input to 32-bit words
    X[0] = get_u32_be(input);
    X[1] = get_u32_be(input + 4);
    X[2] = get_u32_be(input + 8);
    X[3] = get_u32_be(input + 12);
    
    // 32 rounds of encryption/decryption
    for (i = 0; i < SM4_ROUNDS; i++) {
        uint32_t temp = X[0];
        X[0] = X[1];
        X[1] = X[2];
        X[2] = X[3];
        X[3] = temp ^ sm4_round_function(X[0] ^ X[1] ^ X[2] ^ ctx->rk[i]);
    }
    
    // Convert output from 32-bit words (reverse byte order for output)
    put_u32_be(output, X[3]);
    put_u32_be(output + 4, X[2]);
    put_u32_be(output + 8, X[1]);
    put_u32_be(output + 12, X[0]);
}

// Basic implementation wrapper functions
void sm4_basic_encrypt(const uint8_t *key, const uint8_t *input, uint8_t *output) {
    sm4_context ctx;
    sm4_setkey_enc(&ctx, key);
    sm4_crypt_ecb(&ctx, 1, input, output);
}

void sm4_basic_decrypt(const uint8_t *key, const uint8_t *input, uint8_t *output) {
    sm4_context ctx;
    sm4_setkey_dec(&ctx, key);
    sm4_crypt_ecb(&ctx, 0, input, output);
}
