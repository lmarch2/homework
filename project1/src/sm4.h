#ifndef SM4_H
#define SM4_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <immintrin.h>

#ifdef __cplusplus
extern "C" {
#endif

// SM4 constants
#define SM4_BLOCK_SIZE 16
#define SM4_KEY_SIZE   16
#define SM4_ROUNDS     32

// SM4 context structure
typedef struct {
    uint32_t rk[SM4_ROUNDS];  // Round keys
} sm4_context;

// System parameters FK
extern const uint32_t FK[4];

// Fixed parameters CK
extern const uint32_t CK[32];

// S-box
extern const uint8_t SM4_SBOX[256];

// Basic SM4 functions
void sm4_setkey_enc(sm4_context *ctx, const uint8_t key[SM4_KEY_SIZE]);
void sm4_setkey_dec(sm4_context *ctx, const uint8_t key[SM4_KEY_SIZE]);
void sm4_crypt_ecb(sm4_context *ctx, int mode, const uint8_t input[SM4_BLOCK_SIZE], uint8_t output[SM4_BLOCK_SIZE]);

// Different implementation variants
// Basic implementation
void sm4_basic_encrypt(const uint8_t *key, const uint8_t *input, uint8_t *output);
void sm4_basic_decrypt(const uint8_t *key, const uint8_t *input, uint8_t *output);

// T-table optimized implementation
void sm4_ttable_encrypt(const uint8_t *key, const uint8_t *input, uint8_t *output);
void sm4_ttable_decrypt(const uint8_t *key, const uint8_t *input, uint8_t *output);

// AES-NI optimized implementation
void sm4_aesni_encrypt(const uint8_t *key, const uint8_t *input, uint8_t *output);
void sm4_aesni_decrypt(const uint8_t *key, const uint8_t *input, uint8_t *output);

// GFNI optimized implementation (if available)
#ifdef __GFNI__
void sm4_gfni_encrypt(const uint8_t *key, const uint8_t *input, uint8_t *output);
void sm4_gfni_decrypt(const uint8_t *key, const uint8_t *input, uint8_t *output);
#endif

// GCM mode
typedef struct {
    sm4_context sm4_ctx;
    uint8_t H[16];           // Hash subkey
    uint8_t base_ectr[16];   // Base counter
    uint8_t y[16];           // Current counter
    uint8_t buf[16];         // Buffer
    size_t len;              // Length of processed data
} sm4_gcm_context;

int sm4_gcm_setkey(sm4_gcm_context *ctx, const uint8_t *key, unsigned int keysize);
int sm4_gcm_starts(sm4_gcm_context *ctx, int mode, const uint8_t *iv, size_t iv_len);
int sm4_gcm_update_ad(sm4_gcm_context *ctx, const uint8_t *add, size_t add_len);
int sm4_gcm_update(sm4_gcm_context *ctx, const uint8_t *input, uint8_t *output, size_t length);
int sm4_gcm_finish(sm4_gcm_context *ctx, uint8_t *tag, size_t tag_len);

// Utility functions
void sm4_print_block(const char *label, const uint8_t *data, size_t len);
void sm4_print_hex(const uint8_t *data, size_t len);

// CPU feature detection
int sm4_cpu_support_aesni(void);
int sm4_cpu_support_gfni(void);
int sm4_cpu_support_avx2(void);

// Performance measurement
typedef struct {
    double cycles_per_byte;
    double mbytes_per_sec;
    uint64_t total_cycles;
    size_t total_bytes;
} sm4_perf_result;

void sm4_benchmark(const char *impl_name, 
                   void (*encrypt_func)(const uint8_t*, const uint8_t*, uint8_t*),
                   sm4_perf_result *result);

#ifdef __cplusplus
}
#endif

#endif // SM4_H
