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
    uint8_t temp[32];
    
    merkle_compute_leaf_hash((uint8_t*)"A", 1, hash_A);
    merkle_compute_leaf_hash((uint8_t*)"B", 1, hash_B);
    merkle_compute_leaf_hash((uint8_t*)"C", 1, hash_C);
    
    printf("Testing audit proof for A (index 0):\n");
    printf("Leaf A: "); print_hex(hash_A, 32);
    
    uint8_t path0[] = {0x19,0x62,0xbc,0x3b,0x77,0x9e,0x84,0x9a,0x04,0xf8,0x9c,0x80,0x76,0x88,0x53,0x2a,
                       0xf5,0x14,0xe3,0x43,0xcf,0xcb,0xf0,0x57,0x37,0xbb,0x76,0x95,0x93,0xa0,0x91,0xc3};
    uint8_t path1[] = {0x83,0xc8,0x31,0xb7,0xa3,0x50,0x65,0x9c,0x7a,0xd3,0xef,0x3a,0xad,0x0e,0x51,0x6e,
                       0xe4,0xc1,0x94,0xcb,0xba,0x6e,0xd6,0x31,0xbd,0x49,0x05,0xde,0xbb,0xc6,0x1b,0x38};
    
    printf("Path[0]: "); print_hex(path0, 32);
    printf("Path[1]: "); print_hex(path1, 32);
    
    uint64_t index = 0;
    memcpy(temp, hash_A, 32);
    
    printf("\nStep 1: index = %lu, index %% 2 = %lu\n", index, index % 2);
    if (index % 2 == 0) {
        printf("Left: current, Right: path[0]\n");
        merkle_compute_internal_hash(temp, path0, temp);
    } else {
        printf("Left: path[0], Right: current\n");
        merkle_compute_internal_hash(path0, temp, temp);
    }
    printf("Result: "); print_hex(temp, 32);
    index /= 2;
    
    printf("\nStep 2: index = %lu, index %% 2 = %lu\n", index, index % 2);
    if (index % 2 == 0) {
        printf("Left: current, Right: path[1]\n");
        merkle_compute_internal_hash(temp, path1, temp);
    } else {
        printf("Left: path[1], Right: current\n");
        merkle_compute_internal_hash(path1, temp, temp);
    }
    printf("Final: "); print_hex(temp, 32);
    
    return 0;
}
