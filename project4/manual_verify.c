#include <stdio.h>
#include <string.h>
#include "src/sm3.h"

void print_hex(const uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

void merkle_compute_leaf_hash(const uint8_t *data, size_t len, uint8_t *hash) {
    sm3_ctx_t ctx;
    sm3_init(&ctx);
    
    uint8_t prefix = 0x00;
    sm3_update(&ctx, &prefix, 1);
    sm3_update(&ctx, data, len);
    sm3_final(&ctx, hash);
}

void merkle_compute_internal_hash(const uint8_t *left, const uint8_t *right, uint8_t *hash) {
    sm3_ctx_t ctx;
    sm3_init(&ctx);
    
    uint8_t prefix = 0x01;
    sm3_update(&ctx, &prefix, 1);
    sm3_update(&ctx, left, 32);
    sm3_update(&ctx, right, 32);
    sm3_final(&ctx, hash);
}

int main() {
    uint8_t hash_A[32], hash_B[32], hash_C[32];
    uint8_t hash_AB[32], hash_BC[32];
    uint8_t root_hash[32];
    
    merkle_compute_leaf_hash((uint8_t*)"A", 1, hash_A);
    merkle_compute_leaf_hash((uint8_t*)"B", 1, hash_B);
    merkle_compute_leaf_hash((uint8_t*)"C", 1, hash_C);
    
    printf("Hash A: "); print_hex(hash_A, 32);
    printf("Hash B: "); print_hex(hash_B, 32);
    printf("Hash C: "); print_hex(hash_C, 32);
    
    merkle_compute_internal_hash(hash_A, hash_B, hash_AB);
    printf("Hash AB: "); print_hex(hash_AB, 32);
    
    merkle_compute_internal_hash(hash_AB, hash_C, root_hash);
    printf("Root hash (AB,C): "); print_hex(root_hash, 32);
    
    uint8_t verify_hash[32];
    merkle_compute_internal_hash(hash_A, hash_B, verify_hash);
    merkle_compute_internal_hash(verify_hash, hash_C, verify_hash);
    printf("Manual verify: "); print_hex(verify_hash, 32);
    
    return 0;
}
