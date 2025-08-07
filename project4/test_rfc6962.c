#include "src/sm3.h"
#include "src/merkle.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// 严格按照RFC6962实现的简化版本

// MTH函数：计算Merkle树哈希
void compute_mth(uint8_t **leaves, int n, uint8_t *result) {
    if (n == 0) {
        sm3_hash(NULL, 0, result);
        return;
    }
    
    if (n == 1) {
        memcpy(result, leaves[0], 32);
        return;
    }
    
    // 找到k = 2^floor(log2(n))
    int k = 1;
    while (k < n) k <<= 1;
    k >>= 1;
    
    uint8_t left_hash[32], right_hash[32];
    compute_mth(leaves, k, left_hash);
    compute_mth(leaves + k, n - k, right_hash);
    
    merkle_compute_internal_hash(left_hash, right_hash, result);
}

// PATH函数：生成审计路径
void generate_path(uint8_t **leaves, int n, int m, uint8_t path[][32], int *path_len) {
    if (n == 1) return;
    
    int k = 1;
    while (k < n) k <<= 1;
    k >>= 1;
    
    if (m < k) {
        // m在左子树，需要右子树的根
        uint8_t right_root[32];
        compute_mth(leaves + k, n - k, right_root);
        memcpy(path[*path_len], right_root, 32);
        (*path_len)++;
        generate_path(leaves, k, m, path, path_len);
    } else {
        // m在右子树，需要左子树的根
        uint8_t left_root[32];
        compute_mth(leaves, k, left_root);
        memcpy(path[*path_len], left_root, 32);
        (*path_len)++;
        generate_path(leaves + k, n - k, m - k, path, path_len);
    }
}

// RFC6962验证算法
int verify_path_rfc6962(int leaf_index, uint8_t *leaf_hash, uint8_t path[][32], int path_len, uint8_t *root_hash, int tree_size) {
    uint8_t computed[32];
    memcpy(computed, leaf_hash, 32);
    
    int index = leaf_index;
    int size = tree_size;
    
    for (int i = 0; i < path_len; i++) {
        int k = 1;
        while (k < size) k <<= 1;
        k >>= 1;
        
        uint8_t temp[32];
        if (index < k) {
            // 在左子树
            merkle_compute_internal_hash(computed, path[i], temp);
        } else {
            // 在右子树
            merkle_compute_internal_hash(path[i], computed, temp);
            index -= k;
        }
        memcpy(computed, temp, 32);
        size = k; // 这里有问题，size应该更新
    }
    
    return memcmp(computed, root_hash, 32) == 0 ? 0 : -1;
}

void test_rfc6962_implementation() {
    printf("Testing RFC6962 Implementation\n");
    printf("==============================\n\n");
    
    const int LEAF_COUNT = 15;
    
    // 准备叶子哈希
    uint8_t **leaf_hashes = malloc(LEAF_COUNT * sizeof(uint8_t*));
    for (int i = 0; i < LEAF_COUNT; i++) {
        leaf_hashes[i] = malloc(32);
        char data[32];
        sprintf(data, "leaf_%d", i);
        merkle_compute_leaf_hash((uint8_t*)data, strlen(data), leaf_hashes[i]);
    }
    
    // 计算根哈希
    uint8_t root[32];
    compute_mth(leaf_hashes, LEAF_COUNT, root);
    printf("Root hash: ");
    for (int i = 0; i < 8; i++) printf("%02x", root[i]);
    printf("...\n\n");
    
    // 测试叶子14
    printf("Testing leaf 14:\n");
    uint8_t path[20][32];
    int path_len = 0;
    
    generate_path(leaf_hashes, LEAF_COUNT, 14, path, &path_len);
    
    printf("Path length: %d\n", path_len);
    for (int i = 0; i < path_len; i++) {
        printf("Path[%d]: ", i);
        for (int j = 0; j < 8; j++) printf("%02x", path[i][j]);
        printf("...\n");
    }
    
    int result = verify_path_rfc6962(14, leaf_hashes[14], path, path_len, root, LEAF_COUNT);
    printf("Verification result: %s\n", result == 0 ? "SUCCESS" : "FAILED");
    
    // 清理
    for (int i = 0; i < LEAF_COUNT; i++) {
        free(leaf_hashes[i]);
    }
    free(leaf_hashes);
}

int main() {
    test_rfc6962_implementation();
    return 0;
}
