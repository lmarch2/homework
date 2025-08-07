#include "src/sm3.h"
#include "src/merkle.h"
#include <stdio.h>
#include <string.h>

void print_hash(const uint8_t *hash, const char *label) {
    printf("%s: ", label);
    for (int i = 0; i < 32; i++) {
        printf("%02x", hash[i]);
    }
    printf("\n");
}

// 测试叶子6的具体验证
int main() {
    printf("Testing leaf 6 verification specifically\n");
    printf("========================================\n");
    
    // 已知的哈希值 (从之前的分析)
    uint8_t leaf6[32];
    merkle_compute_leaf_hash((uint8_t*)"data6", 5, leaf6);
    print_hash(leaf6, "Leaf 6");
    
    uint8_t right_45[32];
    uint8_t leaf4[32], leaf5[32];
    merkle_compute_leaf_hash((uint8_t*)"data4", 5, leaf4);
    merkle_compute_leaf_hash((uint8_t*)"data5", 5, leaf5);
    merkle_compute_internal_hash(leaf4, leaf5, right_45);
    print_hash(right_45, "Right_45 (sibling)");
    
    uint8_t left_subtree[32];
    // 计算左子树哈希(叶子0-3)
    uint8_t leaf0[32], leaf1[32], leaf2[32], leaf3[32];
    merkle_compute_leaf_hash((uint8_t*)"data0", 5, leaf0);
    merkle_compute_leaf_hash((uint8_t*)"data1", 5, leaf1);
    merkle_compute_leaf_hash((uint8_t*)"data2", 5, leaf2);
    merkle_compute_leaf_hash((uint8_t*)"data3", 5, leaf3);
    
    uint8_t left_01[32], left_23[32];
    merkle_compute_internal_hash(leaf0, leaf1, left_01);
    merkle_compute_internal_hash(leaf2, leaf3, left_23);
    merkle_compute_internal_hash(left_01, left_23, left_subtree);
    print_hash(left_subtree, "Left subtree");
    
    uint8_t expected_root[32];
    uint8_t right_subtree[32];
    merkle_compute_internal_hash(right_45, leaf6, right_subtree);
    merkle_compute_internal_hash(left_subtree, right_subtree, expected_root);
    print_hash(expected_root, "Expected root");
    
    // 现在测试不同的验证方法
    printf("\nTesting different verification approaches:\n");
    
    // 方法1: 按照算法生成的路径 [right_45, left_subtree] 进行验证
    printf("Method 1: path=[right_45, left_subtree], index=6\n");
    uint8_t current1[32];
    memcpy(current1, leaf6, 32);
    uint64_t idx1 = 6;
    
    // Step 1: index=6 (even), Hash(current, right_45)
    uint8_t temp1[32];
    merkle_compute_internal_hash(current1, right_45, temp1);
    memcpy(current1, temp1, 32);
    print_hash(current1, "After step 1");
    idx1 /= 2; // idx1 = 3
    
    // Step 2: index=3 (odd), Hash(left_subtree, current)  
    uint8_t temp2[32];
    merkle_compute_internal_hash(left_subtree, current1, temp2);
    memcpy(current1, temp2, 32);
    print_hash(current1, "After step 2");
    
    printf("Method 1 result: %s\n", memcmp(current1, expected_root, 32) == 0 ? "SUCCESS" : "FAILED");
    
    return 0;
}
