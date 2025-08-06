#include "sm4.h"

// Pre-computed T-tables for optimized implementation
// T0[a] = L(Sbox(a, 0, 0, 0))
// T1[a] = L(Sbox(0, a, 0, 0)) = rotl(T0[a], 8)
// T2[a] = L(Sbox(0, 0, a, 0)) = rotl(T0[a], 16)
// T3[a] = L(Sbox(0, 0, 0, a)) = rotl(T0[a], 24)

static uint32_t T0[256];
static uint32_t T1[256];
static uint32_t T2[256];
static uint32_t T3[256];

// Key expansion T-tables
static uint32_t T0_key[256];
static uint32_t T1_key[256];
static uint32_t T2_key[256];
static uint32_t T3_key[256];

static int tables_initialized = 0;

// Helper functions from basic implementation
extern const uint8_t SM4_SBOX[256];

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

// Linear transformation L
static uint32_t sm4_linear_transform(uint32_t x) {
    return x ^ rotl(x, 2) ^ rotl(x, 10) ^ rotl(x, 18) ^ rotl(x, 24);
}

// Linear transformation L' for key expansion
static uint32_t sm4_linear_transform_key(uint32_t x) {
    return x ^ rotl(x, 13) ^ rotl(x, 23);
}

// Initialize T-tables
static void init_ttables(void) {
    if (tables_initialized) return;
    
    int i;
    uint32_t sbox_val;
    
    for (i = 0; i < 256; i++) {
        // Encryption T-tables
        sbox_val = (uint32_t)SM4_SBOX[i] << 24;  // S(i,0,0,0)
        T0[i] = sm4_linear_transform(sbox_val);
        T1[i] = rotl(T0[i], 8);   // Equivalent to L(S(0,i,0,0))
        T2[i] = rotl(T0[i], 16);  // Equivalent to L(S(0,0,i,0))
        T3[i] = rotl(T0[i], 24);  // Equivalent to L(S(0,0,0,i))
        
        // Key expansion T-tables
        T0_key[i] = sm4_linear_transform_key(sbox_val);
        T1_key[i] = rotl(T0_key[i], 8);
        T2_key[i] = rotl(T0_key[i], 16);
        T3_key[i] = rotl(T0_key[i], 24);
    }
    
    tables_initialized = 1;
}

// Optimized round function using T-tables
static uint32_t sm4_round_function_ttable(uint32_t x) {
    uint8_t a[4];
    a[0] = (x >> 24) & 0xFF;
    a[1] = (x >> 16) & 0xFF;
    a[2] = (x >> 8) & 0xFF;
    a[3] = x & 0xFF;
    
    return T0[a[0]] ^ T1[a[1]] ^ T2[a[2]] ^ T3[a[3]];
}

// Optimized key round function using T-tables
static uint32_t sm4_key_round_function_ttable(uint32_t x) {
    uint8_t a[4];
    a[0] = (x >> 24) & 0xFF;
    a[1] = (x >> 16) & 0xFF;
    a[2] = (x >> 8) & 0xFF;
    a[3] = x & 0xFF;
    
    return T0_key[a[0]] ^ T1_key[a[1]] ^ T2_key[a[2]] ^ T3_key[a[3]];
}

// T-table optimized key expansion
static void sm4_setkey_enc_ttable(uint32_t rk[SM4_ROUNDS], const uint8_t key[SM4_KEY_SIZE]) {
    extern const uint32_t FK[4];
    extern const uint32_t CK[32];
    
    uint32_t K[4];
    uint32_t temp_rk[4];
    int i;
    
    init_ttables();
    
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
    
    // Generate round keys using T-tables
    for (i = 0; i < SM4_ROUNDS; i++) {
        rk[i] = temp_rk[(i + 4) % 4] = temp_rk[i % 4] ^ 
            sm4_key_round_function_ttable(temp_rk[(i + 1) % 4] ^ temp_rk[(i + 2) % 4] ^ temp_rk[(i + 3) % 4] ^ CK[i]);
    }
}

// T-table optimized encryption
static void sm4_encrypt_ttable(const uint32_t rk[SM4_ROUNDS], const uint8_t input[SM4_BLOCK_SIZE], uint8_t output[SM4_BLOCK_SIZE]) {
    uint32_t X[4];
    int i;
    
    init_ttables();
    
    // Convert input to 32-bit words
    X[0] = get_u32_be(input);
    X[1] = get_u32_be(input + 4);
    X[2] = get_u32_be(input + 8);
    X[3] = get_u32_be(input + 12);
    
    // 32 rounds of encryption using T-tables
    for (i = 0; i < SM4_ROUNDS; i++) {
        uint32_t temp = X[0];
        X[0] = X[1];
        X[1] = X[2];
        X[2] = X[3];
        X[3] = temp ^ sm4_round_function_ttable(X[0] ^ X[1] ^ X[2] ^ rk[i]);
    }
    
    // Convert output from 32-bit words (reverse byte order for output)
    put_u32_be(output, X[3]);
    put_u32_be(output + 4, X[2]);
    put_u32_be(output + 8, X[1]);
    put_u32_be(output + 12, X[0]);
}

// T-table optimized decryption
static void sm4_decrypt_ttable(const uint32_t rk[SM4_ROUNDS], const uint8_t input[SM4_BLOCK_SIZE], uint8_t output[SM4_BLOCK_SIZE]) {
    uint32_t X[4];
    int i;
    
    init_ttables();
    
    // Convert input to 32-bit words
    X[0] = get_u32_be(input);
    X[1] = get_u32_be(input + 4);
    X[2] = get_u32_be(input + 8);
    X[3] = get_u32_be(input + 12);
    
    // 32 rounds of decryption using T-tables (reverse key order)
    for (i = 0; i < SM4_ROUNDS; i++) {
        uint32_t temp = X[0];
        X[0] = X[1];
        X[1] = X[2];
        X[2] = X[3];
        X[3] = temp ^ sm4_round_function_ttable(X[0] ^ X[1] ^ X[2] ^ rk[SM4_ROUNDS - 1 - i]);
    }
    
    // Convert output from 32-bit words (reverse byte order for output)
    put_u32_be(output, X[3]);
    put_u32_be(output + 4, X[2]);
    put_u32_be(output + 8, X[1]);
    put_u32_be(output + 12, X[0]);
}

// Public interface functions
void sm4_ttable_encrypt(const uint8_t *key, const uint8_t *input, uint8_t *output) {
    uint32_t rk[SM4_ROUNDS];
    sm4_setkey_enc_ttable(rk, key);
    sm4_encrypt_ttable(rk, input, output);
}

void sm4_ttable_decrypt(const uint8_t *key, const uint8_t *input, uint8_t *output) {
    uint32_t rk[SM4_ROUNDS];
    sm4_setkey_enc_ttable(rk, key);
    sm4_decrypt_ttable(rk, input, output);
}
