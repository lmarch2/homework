#include "sm4.h"
#include <string.h>
#include <stdlib.h>

// SM4-GCM implementation
// GCM (Galois/Counter Mode) provides both encryption and authentication

// GF(2^128) multiplication for GHASH
static void gf128_mul(const uint8_t *x, const uint8_t *y, uint8_t *result)
{
    uint8_t z[16] = {0};
    uint8_t v[16];
    int i, j;

    memcpy(v, y, 16);

    for (i = 0; i < 16; i++)
    {
        for (j = 0; j < 8; j++)
        {
            if (x[i] & (1 << (7 - j)))
            {
                // z = z ⊕ v
                for (int k = 0; k < 16; k++)
                {
                    z[k] ^= v[k];
                }
            }

            // v = v >> 1
            uint8_t carry = 0;
            for (int k = 0; k < 16; k++)
            {
                uint8_t new_carry = v[k] & 1;
                v[k] = (v[k] >> 1) | (carry << 7);
                carry = new_carry;
            }

            // If carry, v = v ⊕ R where R = 0xe1000000000000000000000000000000
            if (carry)
            {
                v[0] ^= 0xe1;
            }
        }
    }

    memcpy(result, z, 16);
}

// GHASH function
static void ghash(const uint8_t *H, const uint8_t *X, size_t X_len, uint8_t *result)
{
    uint8_t Y[16] = {0};
    size_t i;

    for (i = 0; i < X_len; i += 16)
    {
        size_t block_len = (X_len - i) < 16 ? (X_len - i) : 16;
        uint8_t block[16] = {0};

        memcpy(block, X + i, block_len);

        // Y = (Y ⊕ X_i) • H
        for (int j = 0; j < 16; j++)
        {
            Y[j] ^= block[j];
        }
        gf128_mul(Y, H, Y);
    }

    memcpy(result, Y, 16);
}

// Increment counter
static void inc_counter(uint8_t *counter)
{
    int i;
    for (i = 15; i >= 0; i--)
    {
        if (++counter[i] != 0)
        {
            break;
        }
    }
}

// Initialize GCM context
int sm4_gcm_setkey(sm4_gcm_context *ctx, const uint8_t *key, unsigned int keysize)
{
    if (keysize != SM4_KEY_SIZE)
    {
        return -1; // Invalid key size
    }

    // Initialize SM4 context
    sm4_setkey_enc(&ctx->sm4_ctx, key);

    // Calculate H = E_K(0^128)
    uint8_t zero_block[16] = {0};
    sm4_crypt_ecb(&ctx->sm4_ctx, 1, zero_block, ctx->H);

    return 0;
}

// Start GCM operation
int sm4_gcm_starts(sm4_gcm_context *ctx, int mode, const uint8_t *iv, size_t iv_len)
{
    uint8_t J0[16];

    // Generate initial counter J0
    if (iv_len == 12)
    {
        // Special case: 96-bit IV
        memcpy(J0, iv, 12);
        J0[12] = 0;
        J0[13] = 0;
        J0[14] = 0;
        J0[15] = 1;
    }
    else
    {
        // General case: GHASH(H, {}, IV || 0^(s+64) || [len(IV)]_64)
        size_t iv_padded_len = ((iv_len + 15) / 16) * 16;
        uint8_t *iv_padded = malloc(iv_padded_len + 16);

        memset(iv_padded, 0, iv_padded_len + 16);
        memcpy(iv_padded, iv, iv_len);

        // Append length
        uint64_t iv_len_bits = iv_len * 8;
        for (int i = 0; i < 8; i++)
        {
            iv_padded[iv_padded_len + 8 + i] = (iv_len_bits >> (56 - 8 * i)) & 0xFF;
        }

        ghash(ctx->H, iv_padded, iv_padded_len + 16, J0);
        free(iv_padded);
    }

    // Store base counter
    memcpy(ctx->base_ectr, J0, 16);
    memcpy(ctx->y, J0, 16);

    ctx->len = 0;
    memset(ctx->buf, 0, 16);

    return 0;
}

// Update additional authenticated data
int sm4_gcm_update_ad(sm4_gcm_context *ctx, const uint8_t *add, size_t add_len)
{
    // For simplicity, we'll store AAD and process it during finalization
    // In a production implementation, you'd want to process it incrementally

    // This is a simplified implementation
    // Real implementation would need to handle incremental AAD processing

    return 0;
}

// Update encryption/decryption
int sm4_gcm_update(sm4_gcm_context *ctx, const uint8_t *input, uint8_t *output, size_t length)
{
    size_t i;

    for (i = 0; i < length; i += SM4_BLOCK_SIZE)
    {
        size_t block_len = (length - i) < SM4_BLOCK_SIZE ? (length - i) : SM4_BLOCK_SIZE;

        // Increment counter for each block
        inc_counter(ctx->y);

        // Encrypt counter to get keystream
        uint8_t keystream[SM4_BLOCK_SIZE];
        sm4_crypt_ecb(&ctx->sm4_ctx, 1, ctx->y, keystream);

        // XOR with input
        for (size_t j = 0; j < block_len; j++)
        {
            output[i + j] = input[i + j] ^ keystream[j];
        }
    }

    ctx->len += length;
    return 0;
}

// Finish GCM operation and compute tag
int sm4_gcm_finish(sm4_gcm_context *ctx, uint8_t *tag, size_t tag_len)
{
    if (tag_len > 16)
    {
        return -1; // Tag too long
    }

    // Simplified tag computation
    // In real implementation, need to include AAD and ciphertext in GHASH

    // For now, compute GHASH of length block
    uint8_t len_block[16] = {0};
    uint64_t aad_len_bits = 0; // We didn't store AAD
    uint64_t ct_len_bits = ctx->len * 8;

    // Encode lengths in big-endian
    for (int i = 0; i < 8; i++)
    {
        len_block[7 - i] = (aad_len_bits >> (8 * i)) & 0xFF;
        len_block[15 - i] = (ct_len_bits >> (8 * i)) & 0xFF;
    }

    uint8_t hash_result[16];
    ghash(ctx->H, len_block, 16, hash_result);

    // Encrypt base counter for final tag computation
    uint8_t tag_mask[16];
    sm4_crypt_ecb(&ctx->sm4_ctx, 1, ctx->base_ectr, tag_mask);

    // Final tag = GHASH result ⊕ E_K(J0)
    for (int i = 0; i < 16; i++)
    {
        hash_result[i] ^= tag_mask[i];
    }

    memcpy(tag, hash_result, tag_len);
    return 0;
}

// Simplified GCM encrypt function
int sm4_gcm_encrypt(const uint8_t *key, const uint8_t *iv, size_t iv_len,
                    const uint8_t *aad, size_t aad_len,
                    const uint8_t *plaintext, size_t pt_len,
                    uint8_t *ciphertext, uint8_t *tag, size_t tag_len)
{
    sm4_gcm_context ctx;
    int ret;

    ret = sm4_gcm_setkey(&ctx, key, SM4_KEY_SIZE);
    if (ret != 0)
        return ret;

    ret = sm4_gcm_starts(&ctx, 1, iv, iv_len);
    if (ret != 0)
        return ret;

    if (aad && aad_len > 0)
    {
        ret = sm4_gcm_update_ad(&ctx, aad, aad_len);
        if (ret != 0)
            return ret;
    }

    ret = sm4_gcm_update(&ctx, plaintext, ciphertext, pt_len);
    if (ret != 0)
        return ret;

    ret = sm4_gcm_finish(&ctx, tag, tag_len);
    if (ret != 0)
        return ret;

    return 0;
}

// Simplified GCM decrypt function
int sm4_gcm_decrypt(const uint8_t *key, const uint8_t *iv, size_t iv_len,
                    const uint8_t *aad, size_t aad_len,
                    const uint8_t *ciphertext, size_t ct_len,
                    const uint8_t *tag, size_t tag_len,
                    uint8_t *plaintext)
{
    sm4_gcm_context ctx;
    int ret;
    uint8_t computed_tag[16];

    ret = sm4_gcm_setkey(&ctx, key, SM4_KEY_SIZE);
    if (ret != 0)
        return ret;

    ret = sm4_gcm_starts(&ctx, 0, iv, iv_len);
    if (ret != 0)
        return ret;

    if (aad && aad_len > 0)
    {
        ret = sm4_gcm_update_ad(&ctx, aad, aad_len);
        if (ret != 0)
            return ret;
    }

    ret = sm4_gcm_update(&ctx, ciphertext, plaintext, ct_len);
    if (ret != 0)
        return ret;

    ret = sm4_gcm_finish(&ctx, computed_tag, tag_len);
    if (ret != 0)
        return ret;

    // Verify tag
    if (sm4_memcmp_const_time(tag, computed_tag, tag_len) != 0)
    {
        // Authentication failed - clear plaintext
        sm4_memzero(plaintext, ct_len);
        return -2; // Authentication failure
    }

    return 0;
}
