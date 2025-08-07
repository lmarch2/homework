#ifndef SM3_H
#define SM3_H

#include <stdint.h>
#include <stddef.h>

#define SM3_DIGEST_SIZE 32
#define SM3_BLOCK_SIZE 64

typedef struct {
    uint32_t state[8];
    uint64_t count;
    uint8_t buffer[SM3_BLOCK_SIZE];
} sm3_ctx_t;

void sm3_init(sm3_ctx_t *ctx);
void sm3_update(sm3_ctx_t *ctx, const uint8_t *data, size_t len);
void sm3_final(sm3_ctx_t *ctx, uint8_t *digest);
void sm3_hash(const uint8_t *data, size_t len, uint8_t *digest);

void sm3_init_optimized(sm3_ctx_t *ctx);
void sm3_update_optimized(sm3_ctx_t *ctx, const uint8_t *data, size_t len);
void sm3_final_optimized(sm3_ctx_t *ctx, uint8_t *digest);
void sm3_hash_optimized(const uint8_t *data, size_t len, uint8_t *digest);

int sm3_length_extension_attack(const uint8_t *original_hash, 
                               uint64_t original_len,
                               const uint8_t *append_data, 
                               size_t append_len,
                               uint8_t *new_hash,
                               uint8_t **extended_message,
                               size_t *extended_len);

#define ROTL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

static inline uint32_t P0(uint32_t x) {
    return x ^ ROTL(x, 9) ^ ROTL(x, 17);
}

static inline uint32_t P1(uint32_t x) {
    return x ^ ROTL(x, 15) ^ ROTL(x, 23);
}

static inline uint32_t FF(uint32_t x, uint32_t y, uint32_t z, int j) {
    return (j <= 15) ? (x ^ y ^ z) : ((x & y) | (x & z) | (y & z));
}

static inline uint32_t GG(uint32_t x, uint32_t y, uint32_t z, int j) {
    return (j <= 15) ? (x ^ y ^ z) : ((x & y) | (~x & z));
}

#endif
