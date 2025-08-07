#include "src/sm3.h"
#include "src/merkle.h"
#include <stdio.h>
#include <string.h>

void test_simple_cases() {
    printf("Testing Simple Merkle Tree Cases\n");
    printf("=================================\n\n");
    
    // 测试3个叶子的情况
    printf("Test 1: 3 leaves\n");
    merkle_tree_t *tree = merkle_tree_create();
    
    const char *data[] = {"A", "B", "C"};
    for (int i = 0; i < 3; i++) {
        merkle_tree_add_leaf(tree, (uint8_t*)data[i], strlen(data[i]));
    }
    
    if (merkle_tree_build(tree) == 0) {
        printf("✓ Tree built successfully\n");
        
        uint8_t root[32];
        merkle_get_root_hash(tree, root);
        printf("Root: ");
        for (int i = 0; i < 8; i++) printf("%02x", root[i]);
        printf("...\n");
        
        // 测试叶子0的证明
        audit_proof_t proof;
        if (merkle_generate_audit_proof(tree, 0, &proof) == 0) {
            printf("✓ Proof generated for leaf 0, length: %d\n", proof.path_len);
            
            uint8_t leaf_hash[32];
            merkle_compute_leaf_hash((uint8_t*)data[0], strlen(data[0]), leaf_hash);
            
            if (merkle_verify_audit_proof(&proof, leaf_hash, root) == 0) {
                printf("✓ Proof verified successfully\n");
            } else {
                printf("✗ Proof verification failed\n");
            }
        } else {
            printf("✗ Failed to generate proof\n");
        }
    } else {
        printf("✗ Failed to build tree\n");
    }
    
    merkle_tree_destroy(tree);
    printf("\n");
    
    // 测试15个叶子的情况
    printf("Test 2: 15 leaves\n");
    tree = merkle_tree_create();
    
    for (int i = 0; i < 15; i++) {
        char data_str[32];
        sprintf(data_str, "leaf_%d", i);
        merkle_tree_add_leaf(tree, (uint8_t*)data_str, strlen(data_str));
    }
    
    if (merkle_tree_build(tree) == 0) {
        printf("✓ Tree built successfully\n");
        
        uint8_t root[32];
        merkle_get_root_hash(tree, root);
        printf("Root: ");
        for (int i = 0; i < 8; i++) printf("%02x", root[i]);
        printf("...\n");
        
        // 测试几个叶子的证明
        int test_indices[] = {0, 7, 14};
        int success_count = 0;
        
        for (int t = 0; t < 3; t++) {
            int idx = test_indices[t];
            audit_proof_t proof;
            
            if (merkle_generate_audit_proof(tree, idx, &proof) == 0) {
                char data_str[32];
                sprintf(data_str, "leaf_%d", idx);
                uint8_t leaf_hash[32];
                merkle_compute_leaf_hash((uint8_t*)data_str, strlen(data_str), leaf_hash);
                
                if (merkle_verify_audit_proof(&proof, leaf_hash, root) == 0) {
                    success_count++;
                    printf("✓ Leaf %d proof verified (length: %d)\n", idx, proof.path_len);
                } else {
                    printf("✗ Leaf %d proof verification failed\n", idx);
                }
            } else {
                printf("✗ Failed to generate proof for leaf %d\n", idx);
            }
        }
        
        printf("Success rate: %d/3\n", success_count);
    } else {
        printf("✗ Failed to build tree\n");
    }
    
    merkle_tree_destroy(tree);
    printf("\n");
}

int main() {
    test_simple_cases();
    return 0;
}
