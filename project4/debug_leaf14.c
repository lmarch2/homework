#include "src/sm3.h"
#include "src/merkle.h"
#include <stdio.h>
#include <string.h>

void debug_leaf_14() {
    printf("Debugging Leaf 14 in 15-leaf tree\n");
    printf("==================================\n\n");
    
    merkle_tree_t *tree = merkle_tree_create();
    
    // 创建15个叶子
    for (int i = 0; i < 15; i++) {
        char data_str[32];
        sprintf(data_str, "leaf_%d", i);
        merkle_tree_add_leaf(tree, (uint8_t*)data_str, strlen(data_str));
    }
    
    merkle_tree_build(tree);
    
    uint8_t root[32];
    merkle_get_root_hash(tree, root);
    printf("Root hash: ");
    for (int i = 0; i < 8; i++) printf("%02x", root[i]);
    printf("...\n\n");
    
    // 分析叶子14
    printf("Analyzing leaf 14:\n");
    
    char data_str[32];
    sprintf(data_str, "leaf_14");
    uint8_t leaf_hash[32];
    merkle_compute_leaf_hash((uint8_t*)data_str, strlen(data_str), leaf_hash);
    printf("Leaf 14 hash: ");
    for (int i = 0; i < 8; i++) printf("%02x", leaf_hash[i]);
    printf("...\n");
    
    audit_proof_t proof;
    if (merkle_generate_audit_proof(tree, 14, &proof) == 0) {
        printf("Proof path length: %d\n", proof.path_len);
        for (int i = 0; i < proof.path_len; i++) {
            printf("Path[%d]: ", i);
            for (int j = 0; j < 8; j++) printf("%02x", proof.path[i][j]);
            printf("...\n");
        }
        
        // 手动验证步骤
        printf("\nManual verification:\n");
        uint8_t current[32];
        memcpy(current, leaf_hash, 32);
        printf("Start: ");
        for (int i = 0; i < 8; i++) printf("%02x", current[i]);
        printf("...\n");
        
        uint64_t index = 14;
        for (int i = proof.path_len - 1; i >= 0; i--) {
            uint8_t temp[32];
            printf("Step %d: index=%lu, ", proof.path_len - i, index);
            
            if (index % 2 == 0) {
                printf("Hash(current, path[%d])\n", i);
                merkle_compute_internal_hash(current, proof.path[i], temp);
            } else {
                printf("Hash(path[%d], current)\n", i);
                merkle_compute_internal_hash(proof.path[i], current, temp);
            }
            
            memcpy(current, temp, 32);
            printf("Result: ");
            for (int j = 0; j < 8; j++) printf("%02x", current[j]);
            printf("...\n");
            
            index /= 2;
        }
        
        printf("\nFinal comparison:\n");
        printf("Computed: ");
        for (int i = 0; i < 8; i++) printf("%02x", current[i]);
        printf("...\n");
        printf("Expected: ");
        for (int i = 0; i < 8; i++) printf("%02x", root[i]);
        printf("...\n");
        
        if (memcmp(current, root, 32) == 0) {
            printf("✓ Manual verification PASSED\n");
        } else {
            printf("✗ Manual verification FAILED\n");
        }
        
    } else {
        printf("Failed to generate proof\n");
    }
    
    merkle_tree_destroy(tree);
}

int main() {
    debug_leaf_14();
    return 0;
}
