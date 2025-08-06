#include "sm4.h"
#include <immintrin.h>

#ifdef __GFNI__

// GFNI (Galois Field New Instructions) optimized implementation
// Uses latest Intel instruction set for Galois Field operations

// Affine transformation matrices for SM4 S-box using GFNI
// The SM4 S-box can be decomposed into GF(2^8) operations followed by affine transformation
static const uint64_t SM4_SBOX_MATRIX = 0xF1E2C78F1F3E7CFULL;
static const uint8_t SM4_SBOX_CONST = 0xD6;

// Inverse matrix for decryption optimization
static const uint64_t SM4_SBOX_INV_MATRIX = 0x8F1F3E7CF1E2C78FULL;
static const uint8_t SM4_SBOX_INV_CONST = 0x26;

// Check GFNI support
int sm4_cpu_support_gfni(void) {
    uint32_t eax, ebx, ecx, edx;
    
    // Check CPUID for GFNI support (Structured Extended Feature Flags)
    __asm__ volatile (
        "cpuid"
        : "=a" (eax), "=b" (ebx), "=c" (ecx), "=d" (edx)
        : "a" (7), "c" (0)
    );
    
    return (ecx & (1 << 8)) != 0;  // GFNI flag
}

// Check AVX512 support for wider vector operations
int sm4_cpu_support_avx512(void) {
    uint32_t eax, ebx, ecx, edx;
    
    __asm__ volatile (
        "cpuid"
        : "=a" (eax), "=b" (ebx), "=c" (ecx), "=d" (edx)
        : "a" (7), "c" (0)
    );
    
    return (ebx & (1 << 16)) != 0;  // AVX512F flag
}

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

// GFNI-accelerated S-box transformation
static __m128i sm4_sbox_gfni(__m128i input) {
    // Use GFNI affine transformation to compute SM4 S-box
    __m128i matrix = _mm_set1_epi64x(SM4_SBOX_MATRIX);
    return _mm_gf2p8affine_epi64_epi8(input, matrix, SM4_SBOX_CONST);
}

// Vectorized linear transformation using AVX2/AVX512
static __m128i sm4_linear_transform_gfni(__m128i x) {
    // L(x) = x ^ rotl(x, 2) ^ rotl(x, 10) ^ rotl(x, 18) ^ rotl(x, 24)
    __m128i result = x;
    
    // Use vector rotate instructions if available (AVX512)
    if (sm4_cpu_support_avx512()) {
        __m512i x512 = _mm512_castsi128_si512(x);
        __m512i rot2 = _mm512_rol_epi32(x512, 2);
        __m512i rot10 = _mm512_rol_epi32(x512, 10);
        __m512i rot18 = _mm512_rol_epi32(x512, 18);
        __m512i rot24 = _mm512_rol_epi32(x512, 24);
        
        __m512i temp = _mm512_xor_si512(x512, rot2);
        temp = _mm512_xor_si512(temp, rot10);
        temp = _mm512_xor_si512(temp, rot18);
        temp = _mm512_xor_si512(temp, rot24);
        
        result = _mm512_castsi512_si128(temp);
    } else {
        // Fallback to 128-bit operations
        // Note: No direct rotate in AVX2, need to emulate
        __m128i rot2_l = _mm_slli_epi32(x, 2);
        __m128i rot2_r = _mm_srli_epi32(x, 30);
        __m128i rot2 = _mm_or_si128(rot2_l, rot2_r);
        
        __m128i rot10_l = _mm_slli_epi32(x, 10);
        __m128i rot10_r = _mm_srli_epi32(x, 22);
        __m128i rot10 = _mm_or_si128(rot10_l, rot10_r);
        
        __m128i rot18_l = _mm_slli_epi32(x, 18);
        __m128i rot18_r = _mm_srli_epi32(x, 14);
        __m128i rot18 = _mm_or_si128(rot18_l, rot18_r);
        
        __m128i rot24_l = _mm_slli_epi32(x, 24);
        __m128i rot24_r = _mm_srli_epi32(x, 8);
        __m128i rot24 = _mm_or_si128(rot24_l, rot24_r);
        
        result = _mm_xor_si128(result, rot2);
        result = _mm_xor_si128(result, rot10);
        result = _mm_xor_si128(result, rot18);
        result = _mm_xor_si128(result, rot24);
    }
    
    return result;
}

// GFNI-optimized round function
static uint32_t sm4_round_function_gfni(uint32_t x) {
    __m128i input = _mm_set1_epi32(x);
    __m128i sbox_result = sm4_sbox_gfni(input);
    __m128i linear_result = sm4_linear_transform_gfni(sbox_result);
    
    return _mm_extract_epi32(linear_result, 0);
}

// Linear transformation L' for key expansion using GFNI
static __m128i sm4_linear_transform_key_gfni(__m128i x) {
    // L'(x) = x ^ rotl(x, 13) ^ rotl(x, 23)
    __m128i result = x;
    
    if (sm4_cpu_support_avx512()) {
        __m512i x512 = _mm512_castsi128_si512(x);
        __m512i rot13 = _mm512_rol_epi32(x512, 13);
        __m512i rot23 = _mm512_rol_epi32(x512, 23);
        
        __m512i temp = _mm512_xor_si512(x512, rot13);
        temp = _mm512_xor_si512(temp, rot23);
        
        result = _mm512_castsi512_si128(temp);
    } else {
        __m128i rot13_l = _mm_slli_epi32(x, 13);
        __m128i rot13_r = _mm_srli_epi32(x, 19);
        __m128i rot13 = _mm_or_si128(rot13_l, rot13_r);
        
        __m128i rot23_l = _mm_slli_epi32(x, 23);
        __m128i rot23_r = _mm_srli_epi32(x, 9);
        __m128i rot23 = _mm_or_si128(rot23_l, rot23_r);
        
        result = _mm_xor_si128(result, rot13);
        result = _mm_xor_si128(result, rot23);
    }
    
    return result;
}

// GFNI-optimized key round function
static uint32_t sm4_key_round_function_gfni(uint32_t x) {
    __m128i input = _mm_set1_epi32(x);
    __m128i sbox_result = sm4_sbox_gfni(input);
    __m128i linear_result = sm4_linear_transform_key_gfni(sbox_result);
    
    return _mm_extract_epi32(linear_result, 0);
}

// GFNI-optimized key expansion
static void sm4_setkey_enc_gfni(uint32_t rk[SM4_ROUNDS], const uint8_t key[SM4_KEY_SIZE]) {
    extern const uint32_t FK[4];
    extern const uint32_t CK[32];
    
    uint32_t K[4];
    uint32_t temp_rk[4];
    int i;
    
    // Convert key to 32-bit words
    K[0] = get_u32_be(key);
    K[1] = get_u32_be(key + 4);
    K[2] = get_u32_be(key + 8);
    K[3] = get_u32_be(key + 12);
    
    // Initialize with system parameters
    temp_rk[0] = K[0] ^ FK[0];
    temp_rk[1] = K[1] ^ FK[1];
    temp_rk[2] = K[2] ^ FK[2];
    temp_rk[3] = K[3] ^ FK[3];
    
    // Generate round keys using GFNI acceleration
    for (i = 0; i < SM4_ROUNDS; i++) {
        rk[i] = temp_rk[(i + 4) % 4] = temp_rk[i % 4] ^ 
            sm4_key_round_function_gfni(temp_rk[(i + 1) % 4] ^ temp_rk[(i + 2) % 4] ^ temp_rk[(i + 3) % 4] ^ CK[i]);
    }
}

// GFNI-optimized encryption
static void sm4_encrypt_gfni(const uint32_t rk[SM4_ROUNDS], const uint8_t input[SM4_BLOCK_SIZE], uint8_t output[SM4_BLOCK_SIZE]) {
    uint32_t X[4];
    int i;
    
    // Convert input to 32-bit words
    X[0] = get_u32_be(input);
    X[1] = get_u32_be(input + 4);
    X[2] = get_u32_be(input + 8);
    X[3] = get_u32_be(input + 12);
    
    // 32 rounds of encryption using GFNI acceleration
    for (i = 0; i < SM4_ROUNDS; i++) {
        uint32_t temp = X[0];
        X[0] = X[1];
        X[1] = X[2];
        X[2] = X[3];
        X[3] = temp ^ sm4_round_function_gfni(X[0] ^ X[1] ^ X[2] ^ rk[i]);
    }
    
    // Convert output from 32-bit words (reverse byte order for output)
    put_u32_be(output, X[3]);
    put_u32_be(output + 4, X[2]);
    put_u32_be(output + 8, X[1]);
    put_u32_be(output + 12, X[0]);
}

// GFNI-optimized decryption
static void sm4_decrypt_gfni(const uint32_t rk[SM4_ROUNDS], const uint8_t input[SM4_BLOCK_SIZE], uint8_t output[SM4_BLOCK_SIZE]) {
    uint32_t X[4];
    int i;
    
    // Convert input to 32-bit words
    X[0] = get_u32_be(input);
    X[1] = get_u32_be(input + 4);
    X[2] = get_u32_be(input + 8);
    X[3] = get_u32_be(input + 12);
    
    // 32 rounds of decryption using GFNI acceleration (reverse key order)
    for (i = 0; i < SM4_ROUNDS; i++) {
        uint32_t temp = X[0];
        X[0] = X[1];
        X[1] = X[2];
        X[2] = X[3];
        X[3] = temp ^ sm4_round_function_gfni(X[0] ^ X[1] ^ X[2] ^ rk[SM4_ROUNDS - 1 - i]);
    }
    
    // Convert output from 32-bit words (reverse byte order for output)
    put_u32_be(output, X[3]);
    put_u32_be(output + 4, X[2]);
    put_u32_be(output + 8, X[1]);
    put_u32_be(output + 12, X[0]);
}

// Public interface functions
void sm4_gfni_encrypt(const uint8_t *key, const uint8_t *input, uint8_t *output) {
    if (!sm4_cpu_support_gfni()) {
        // Fallback to AES-NI implementation
        sm4_aesni_encrypt(key, input, output);
        return;
    }
    
    uint32_t rk[SM4_ROUNDS];
    sm4_setkey_enc_gfni(rk, key);
    sm4_encrypt_gfni(rk, input, output);
}

void sm4_gfni_decrypt(const uint8_t *key, const uint8_t *input, uint8_t *output) {
    if (!sm4_cpu_support_gfni()) {
        // Fallback to AES-NI implementation
        sm4_aesni_decrypt(key, input, output);
        return;
    }
    
    uint32_t rk[SM4_ROUNDS];
    sm4_setkey_enc_gfni(rk, key);
    sm4_decrypt_gfni(rk, input, output);
}

#endif // __GFNI__
