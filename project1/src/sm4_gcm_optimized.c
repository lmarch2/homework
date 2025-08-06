#include "sm4.h"
#include <string.h>
#include <stdlib.h>

// SM4-GCM Optimized implementation
// Uses optimized SM4 kernel and faster GHASH

// Precomputed GHASH table for optimization
typedef struct {
    uint8_t table[16][256][16];
} ghash_table_t;

// Global GHASH lookup table
static ghash_table_t ghash_lut;
static int ghash_table_initialized = 0;

// Fast GF(2^128) multiplication using 4-bit table lookup
static void gf128_mul_fast(const uint8_t *x, const uint8_t *y, uint8_t *result)
{
    uint8_t z[16] = {0};
    
    // Use byte-wise processing for better performance
    for (int i = 0; i < 16; i++) {
        uint8_t xi = x[i];
        if (xi == 0) continue;
        
        uint8_t v[16];
        memcpy(v, y, 16);
        
        // Process each bit of the byte
        for (int j = 0; j < 8; j++) {
            if (xi & (0x80 >> j)) {
                for (int k = 0; k < 16; k++) {
                    z[k] ^= v[k];
                }
            }
            
            // Right shift v with conditional XOR
            uint8_t carry = v[15] & 1;
            for (int k = 15; k > 0; k--) {
                v[k] = (v[k] >> 1) | ((v[k-1] & 1) << 7);
            }
            v[0] >>= 1;
            
            if (carry) {
                v[0] ^= 0xe1;
            }
        }
    }
    
    memcpy(result, z, 16);
}

// Initialize GHASH table for a given H
static void init_ghash_table(const uint8_t *H)
{
    if (ghash_table_initialized) return;
    
    memset(&ghash_lut, 0, sizeof(ghash_lut));
    
    // Precompute H^i for i = 1 to 16
    uint8_t Hi[16];
    memcpy(Hi, H, 16);
    
    for (int i = 0; i < 16; i++) {
        // For each byte position
        for (int j = 1; j < 256; j++) {
            uint8_t byte_val[16] = {0};
            byte_val[i] = j;
            gf128_mul_fast(byte_val, Hi, ghash_lut.table[i][j]);
        }
        
        // Update Hi = Hi * H for next iteration
        if (i < 15) {
            uint8_t temp[16];
            gf128_mul_fast(Hi, H, temp);
            memcpy(Hi, temp, 16);
        }
    }
    
    ghash_table_initialized = 1;
}

// Fast GHASH using lookup table
static void ghash_fast(const uint8_t *H, const uint8_t *X, size_t X_len, uint8_t *result)
{
    uint8_t Y[16] = {0};
    
    // Initialize lookup table if needed
    init_ghash_table(H);
    
    for (size_t i = 0; i < X_len; i += 16) {
        size_t block_len = (X_len - i) < 16 ? (X_len - i) : 16;
        uint8_t block[16] = {0};
        
        memcpy(block, X + i, block_len);
        
        // Y = Y ⊕ X_i
        for (int j = 0; j < 16; j++) {
            Y[j] ^= block[j];
        }
        
        // Fast GHASH using table lookup
        uint8_t result_temp[16] = {0};
        for (int j = 0; j < 16; j++) {
            if (Y[j] != 0) {
                for (int k = 0; k < 16; k++) {
                    result_temp[k] ^= ghash_lut.table[j][Y[j]][k];
                }
            }
        }
        memcpy(Y, result_temp, 16);
    }
    
    memcpy(result, Y, 16);
}

// Optimized counter increment
static inline void inc_counter_fast(uint8_t *counter)
{
    // Optimized for little-endian, process 32-bit at a time
    uint32_t *c32 = (uint32_t *)(counter + 12);
    *c32 = __builtin_bswap32(__builtin_bswap32(*c32) + 1);
}

// Optimized GCM context initialization
int sm4_gcm_setkey_opt(sm4_gcm_context *ctx, const uint8_t *key, unsigned int keysize)
{
    if (keysize != SM4_KEY_SIZE) {
        return -1;
    }

    // Use optimized SM4 key schedule
    sm4_setkey_enc(&ctx->sm4_ctx, key);

    // Calculate H = E_K(0^128) using optimized SM4
    uint8_t zero_block[16] = {0};
    sm4_crypt_ecb(&ctx->sm4_ctx, 1, zero_block, ctx->H);

    // Initialize GHASH table
    init_ghash_table(ctx->H);

    return 0;
}

// Optimized GCM start
int sm4_gcm_starts_opt(sm4_gcm_context *ctx, int mode, const uint8_t *iv, size_t iv_len)
{
    uint8_t J0[16];

    if (iv_len == 12) {
        // Fast path for 96-bit IV
        memcpy(J0, iv, 12);
        *(uint32_t *)(J0 + 12) = 0x01000000; // Big-endian 1
    } else {
        // General case with optimized GHASH
        size_t iv_padded_len = ((iv_len + 15) / 16) * 16;
        uint8_t *iv_padded = malloc(iv_padded_len + 16);
        
        memset(iv_padded, 0, iv_padded_len + 16);
        memcpy(iv_padded, iv, iv_len);
        
        // Append length in big-endian format
        uint64_t iv_len_bits = iv_len * 8;
        for (int i = 0; i < 8; i++) {
            iv_padded[iv_padded_len + 8 + i] = (iv_len_bits >> (56 - 8 * i)) & 0xFF;
        }
        
        ghash_fast(ctx->H, iv_padded, iv_padded_len + 16, J0);
        free(iv_padded);
    }

    memcpy(ctx->base_ectr, J0, 16);
    memcpy(ctx->y, J0, 16);
    ctx->len = 0;
    memset(ctx->buf, 0, 16);

    return 0;
}

// Optimized GCM update for bulk data
int sm4_gcm_update_opt(sm4_gcm_context *ctx, const uint8_t *input, uint8_t *output, size_t length)
{
    size_t offset = 0;
    uint8_t keystream[16];

    while (offset < length) {
        size_t use_len = (length - offset) > 16 ? 16 : (length - offset);

        // Increment counter efficiently
        inc_counter_fast(ctx->y);

        // Generate keystream using optimized SM4
        sm4_crypt_ecb(&ctx->sm4_ctx, 1, ctx->y, keystream);

        // XOR with input (vectorized when possible)
        for (size_t i = 0; i < use_len; i++) {
            output[offset + i] = input[offset + i] ^ keystream[i];
        }

        offset += use_len;
    }

    return 0;
}

// Optimized simplified encrypt interface
int sm4_gcm_encrypt_opt(const uint8_t *key, const uint8_t *iv, size_t iv_len,
                       const uint8_t *aad, size_t aad_len,
                       const uint8_t *plaintext, size_t pt_len,
                       uint8_t *ciphertext, uint8_t *tag, size_t tag_len)
{
    sm4_gcm_context ctx;
    int ret;

    // Initialize with optimized functions
    ret = sm4_gcm_setkey_opt(&ctx, key, SM4_KEY_SIZE);
    if (ret != 0) return ret;

    ret = sm4_gcm_starts_opt(&ctx, 1, iv, iv_len);
    if (ret != 0) return ret;

    // Process AAD
    if (aad_len > 0) {
        ret = sm4_gcm_update_ad(&ctx, aad, aad_len);
        if (ret != 0) return ret;
    }

    // Encrypt plaintext
    if (pt_len > 0) {
        ret = sm4_gcm_update_opt(&ctx, plaintext, ciphertext, pt_len);
        if (ret != 0) return ret;
    }

    // Generate tag
    ret = sm4_gcm_finish(&ctx, tag, tag_len);
    if (ret != 0) return ret;

    return 0;
}

// Optimized simplified decrypt interface
int sm4_gcm_decrypt_opt(const uint8_t *key, const uint8_t *iv, size_t iv_len,
                       const uint8_t *aad, size_t aad_len,
                       const uint8_t *ciphertext, size_t ct_len,
                       const uint8_t *tag, size_t tag_len, uint8_t *plaintext)
{
    sm4_gcm_context ctx;
    int ret;

    ret = sm4_gcm_setkey_opt(&ctx, key, SM4_KEY_SIZE);
    if (ret != 0) return ret;

    ret = sm4_gcm_starts_opt(&ctx, 0, iv, iv_len);
    if (ret != 0) return ret;

    if (aad_len > 0) {
        ret = sm4_gcm_update_ad(&ctx, aad, aad_len);
        if (ret != 0) return ret;
    }

    if (ct_len > 0) {
        ret = sm4_gcm_update_opt(&ctx, ciphertext, plaintext, ct_len);
        if (ret != 0) return ret;
    }

    // Verify tag
    uint8_t check_tag[16];
    ret = sm4_gcm_finish(&ctx, check_tag, tag_len);
    if (ret != 0) return ret;

    // Constant-time comparison
    int diff = 0;
    for (size_t i = 0; i < tag_len; i++) {
        diff |= tag[i] ^ check_tag[i];
    }

    return diff ? -1 : 0;
}
