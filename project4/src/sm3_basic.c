#include "sm3.h"
#include <string.h>

static const uint32_t SM3_IV[8] = {
    0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
    0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E
};

static const uint32_t SM3_T[64] = {
    0x79CC4519, 0x79CC4519, 0x79CC4519, 0x79CC4519,
    0x79CC4519, 0x79CC4519, 0x79CC4519, 0x79CC4519,
    0x79CC4519, 0x79CC4519, 0x79CC4519, 0x79CC4519,
    0x79CC4519, 0x79CC4519, 0x79CC4519, 0x79CC4519,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A
};

static void sm3_process_block(sm3_ctx_t *ctx, const uint8_t *block) {
    uint32_t W[68], W1[64];
    uint32_t A, B, C, D, E, F, G, H;
    uint32_t SS1, SS2, TT1, TT2;
    int j;

    for (j = 0; j < 16; j++) {
        W[j] = (block[j * 4] << 24) | (block[j * 4 + 1] << 16) | 
               (block[j * 4 + 2] << 8) | block[j * 4 + 3];
    }

    for (j = 16; j < 68; j++) {
        W[j] = P1(W[j-16] ^ W[j-9] ^ ROTL(W[j-3], 15)) ^ ROTL(W[j-13], 7) ^ W[j-6];
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

    for (j = 0; j < 64; j++) {
        SS1 = ROTL((ROTL(A, 12) + E + ROTL(SM3_T[j], j % 32)), 7);
        SS2 = SS1 ^ ROTL(A, 12);
        TT1 = FF(A, B, C, j) + D + SS2 + W1[j];
        TT2 = GG(E, F, G, j) + H + SS1 + W[j];
        D = C;
        C = ROTL(B, 9);
        B = A;
        A = TT1;
        H = G;
        G = ROTL(F, 19);
        F = E;
        E = P0(TT2);
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

void sm3_init(sm3_ctx_t *ctx) {
    memcpy(ctx->state, SM3_IV, sizeof(SM3_IV));
    ctx->count = 0;
    memset(ctx->buffer, 0, SM3_BLOCK_SIZE);
}

void sm3_update(sm3_ctx_t *ctx, const uint8_t *data, size_t len) {
    size_t buffer_pos = ctx->count % SM3_BLOCK_SIZE;
    size_t remaining = SM3_BLOCK_SIZE - buffer_pos;

    ctx->count += len;

    if (len >= remaining) {
        memcpy(ctx->buffer + buffer_pos, data, remaining);
        sm3_process_block(ctx, ctx->buffer);
        data += remaining;
        len -= remaining;

        while (len >= SM3_BLOCK_SIZE) {
            sm3_process_block(ctx, data);
            data += SM3_BLOCK_SIZE;
            len -= SM3_BLOCK_SIZE;
        }
        buffer_pos = 0;
    }

    if (len > 0) {
        memcpy(ctx->buffer + buffer_pos, data, len);
    }
}

void sm3_final(sm3_ctx_t *ctx, uint8_t *digest) {
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

    sm3_update(ctx, padding, padding_len);

    for (int i = 0; i < 8; i++) {
        digest[i * 4] = (uint8_t)(ctx->state[i] >> 24);
        digest[i * 4 + 1] = (uint8_t)(ctx->state[i] >> 16);
        digest[i * 4 + 2] = (uint8_t)(ctx->state[i] >> 8);
        digest[i * 4 + 3] = (uint8_t)(ctx->state[i]);
    }
}

void sm3_hash(const uint8_t *data, size_t len, uint8_t *digest) {
    sm3_ctx_t ctx;
    sm3_init(&ctx);
    sm3_update(&ctx, data, len);
    sm3_final(&ctx, digest);
}
