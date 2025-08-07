#include "sm3.h"
#include <string.h>

static const uint32_t SM3_IV[8] = {
    0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
    0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E
};

#define ROUND_F(A, B, C, D, E, F, G, H, W, W1, j) do { \
    uint32_t T = (j <= 15) ? 0x79CC4519 : 0x7A879D8A; \
    uint32_t SS1 = ROTL((ROTL(A, 12) + E + ROTL(T, j % 32)), 7); \
    uint32_t SS2 = SS1 ^ ROTL(A, 12); \
    uint32_t TT1 = FF(A, B, C, j) + D + SS2 + W1; \
    uint32_t TT2 = GG(E, F, G, j) + H + SS1 + W; \
    D = C; \
    C = ROTL(B, 9); \
    B = A; \
    A = TT1; \
    H = G; \
    G = ROTL(F, 19); \
    F = E; \
    E = P0(TT2); \
} while(0)

static void sm3_process_block_optimized(sm3_ctx_t *ctx, const uint8_t *block) {
    uint32_t W[68], W1[64];
    uint32_t A, B, C, D, E, F, G, H;
    int j;

    const uint32_t *w32 = (const uint32_t *)block;
    for (j = 0; j < 16; j++) {
        W[j] = __builtin_bswap32(w32[j]);
    }

    for (j = 16; j < 68; j++) {
        uint32_t temp = W[j-16] ^ W[j-9] ^ ROTL(W[j-3], 15);
        W[j] = P1(temp) ^ ROTL(W[j-13], 7) ^ W[j-6];
    }

    for (j = 0; j < 64; j++) {
        W1[j] = W[j] ^ W[j + 4];
    }

    A = ctx->state[0];
    B = ctx->state[1];
    C = ctx->state[2];
    D = ctx->state[3];
    E = ctx->state[4];
    F = ctx->state[5];
    G = ctx->state[6];
    H = ctx->state[7];

    for (j = 0; j < 16; j += 4) {
        ROUND_F(A, B, C, D, E, F, G, H, W[j], W1[j], j);
        ROUND_F(H, A, B, C, D, E, F, G, W[j+1], W1[j+1], j+1);
        ROUND_F(G, H, A, B, C, D, E, F, W[j+2], W1[j+2], j+2);
        ROUND_F(F, G, H, A, B, C, D, E, W[j+3], W1[j+3], j+3);
    }

    for (j = 16; j < 64; j += 4) {
        ROUND_F(A, B, C, D, E, F, G, H, W[j], W1[j], j);
        ROUND_F(H, A, B, C, D, E, F, G, W[j+1], W1[j+1], j+1);
        ROUND_F(G, H, A, B, C, D, E, F, W[j+2], W1[j+2], j+2);
        ROUND_F(F, G, H, A, B, C, D, E, W[j+3], W1[j+3], j+3);
    }

    ctx->state[0] ^= A;
    ctx->state[1] ^= B;
    ctx->state[2] ^= C;
    ctx->state[3] ^= D;
    ctx->state[4] ^= E;
    ctx->state[5] ^= F;
    ctx->state[6] ^= G;
    ctx->state[7] ^= H;
}

void sm3_init_optimized(sm3_ctx_t *ctx) {
    memcpy(ctx->state, SM3_IV, sizeof(SM3_IV));
    ctx->count = 0;
    memset(ctx->buffer, 0, SM3_BLOCK_SIZE);
}

void sm3_update_optimized(sm3_ctx_t *ctx, const uint8_t *data, size_t len) {
    size_t buffer_pos = ctx->count % SM3_BLOCK_SIZE;
    size_t remaining = SM3_BLOCK_SIZE - buffer_pos;

    ctx->count += len;

    if (len >= remaining) {
        memcpy(ctx->buffer + buffer_pos, data, remaining);
        sm3_process_block_optimized(ctx, ctx->buffer);
        data += remaining;
        len -= remaining;

        while (len >= SM3_BLOCK_SIZE) {
            sm3_process_block_optimized(ctx, data);
            data += SM3_BLOCK_SIZE;
            len -= SM3_BLOCK_SIZE;
        }
        buffer_pos = 0;
    }

    if (len > 0) {
        memcpy(ctx->buffer + buffer_pos, data, len);
    }
}

void sm3_final_optimized(sm3_ctx_t *ctx, uint8_t *digest) {
    size_t buffer_pos = ctx->count % SM3_BLOCK_SIZE;
    uint64_t bit_count = ctx->count * 8;
    uint8_t padding[SM3_BLOCK_SIZE * 2];
    size_t padding_len;

    padding[0] = 0x80;
    if (buffer_pos < 56) {
        padding_len = 56 - buffer_pos;
    } else {
        padding_len = 120 - buffer_pos;
    }
    memset(padding + 1, 0, padding_len - 1);

    for (int i = 0; i < 8; i++) {
        padding[padding_len + i] = (uint8_t)(bit_count >> (56 - i * 8));
    }
    padding_len += 8;

    sm3_update_optimized(ctx, padding, padding_len);

    for (int i = 0; i < 8; i++) {
        uint32_t state = ctx->state[i];
        digest[i * 4] = (uint8_t)(state >> 24);
        digest[i * 4 + 1] = (uint8_t)(state >> 16);
        digest[i * 4 + 2] = (uint8_t)(state >> 8);
        digest[i * 4 + 3] = (uint8_t)(state);
    }
}

void sm3_hash_optimized(const uint8_t *data, size_t len, uint8_t *digest) {
    sm3_ctx_t ctx;
    sm3_init_optimized(&ctx);
    sm3_update_optimized(&ctx, data, len);
    sm3_final_optimized(&ctx, digest);
}
