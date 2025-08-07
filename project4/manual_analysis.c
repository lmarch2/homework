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

// 手动计算7叶子树的根和路径
void manual_tree_analysis() {
    printf("Manual Tree Analysis for 7 leaves\n");
    printf("==================================\n");
    
    const char *data[] = {"data0", "data1", "data2", "data3", "data4", "data5", "data6"};
    uint8_t leaf_hashes[7][32];
    
    // 计算所有叶子哈希
    for (int i = 0; i < 7; i++) {
        merkle_compute_leaf_hash((uint8_t*)data[i], strlen(data[i]), leaf_hashes[i]);
        char label[32];
        sprintf(label, "Leaf %d", i);
        print_hash(leaf_hashes[i], label);
    }
    
    // 根据RFC6962构建树
    // 7个叶子: k = 4, 左子树4个叶子，右子树3个叶子
    printf("\nTree structure: 7 leaves = 4 (left) + 3 (right)\n");
    
    // 左子树 (叶子0-3)
    uint8_t left_01[32], left_23[32], left_subtree[32];
    merkle_compute_internal_hash(leaf_hashes[0], leaf_hashes[1], left_01);
    merkle_compute_internal_hash(leaf_hashes[2], leaf_hashes[3], left_23);
    merkle_compute_internal_hash(left_01, left_23, left_subtree);
    print_hash(left_subtree, "Left subtree");
    
    // 右子树 (叶子4-6)  
    uint8_t right_45[32], right_subtree[32];
    merkle_compute_internal_hash(leaf_hashes[4], leaf_hashes[5], right_45);
    merkle_compute_internal_hash(right_45, leaf_hashes[6], right_subtree);
    print_hash(right_subtree, "Right subtree");
    
    // 根
    uint8_t root[32];
    merkle_compute_internal_hash(left_subtree, right_subtree, root);
    print_hash(root, "Root");
    
    // 叶子6的审计路径应该是: right_45, left_subtree
    printf("\nExpected audit path for leaf 6:\n");
    print_hash(right_45, "Sibling (right_45)");
    print_hash(left_subtree, "Uncle (left_subtree)");
    
    // 验证叶子6
    printf("\nManual verification for leaf 6:\n");
    uint8_t current[32];
    memcpy(current, leaf_hashes[6], 32);
    print_hash(current, "Start (leaf 6)");
    
    // 第一步: Hash(right_45, leaf6)
    uint8_t step1[32];
    merkle_compute_internal_hash(right_45, current, step1);
    print_hash(step1, "Step 1: Hash(right_45, leaf6)");
    
    // 第二步: Hash(left_subtree, step1)
    uint8_t step2[32];
    merkle_compute_internal_hash(left_subtree, step1, step2);
    print_hash(step2, "Step 2: Hash(left_subtree, step1)");
    
    printf("Should match root: %s\n", memcmp(step2, root, 32) == 0 ? "YES" : "NO");
}

int main() {
    manual_tree_analysis();
    return 0;
}
