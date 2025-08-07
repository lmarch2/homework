#include "../src/sm3.h"
#include "../src/merkle.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {
    printf("Simple Merkle Tree Audit Proof Test\n");
    printf("====================================\n\n");
    
    // Create tree
    merkle_tree_t *tree = merkle_tree_create();
    if (!tree) {
        printf("Failed to create tree\n");
        return 1;
    }
    
    // Add 4 leaves for simple testing
    const char *leaves[] = {"A", "B", "C", "D"};
    int num_leaves = 4;
    
    for (int i = 0; i < num_leaves; i++) {
        if (merkle_tree_add_leaf(tree, (uint8_t*)leaves[i], 1) != 0) {
            printf("Failed to add leaf %d\n", i);
            return 1;
        }
    }
    
    // Build tree
    if (merkle_tree_build(tree) != 0) {
        printf("Failed to build tree\n");
        return 1;
    }
    
    printf("Tree built with %lu leaves\n\n", merkle_get_leaf_count(tree));
    
    // Get root hash
    uint8_t root_hash[MERKLE_NODE_SIZE];
    merkle_get_root_hash(tree, root_hash);
    
    printf("Root hash: ");
    for (int i = 0; i < MERKLE_NODE_SIZE; i++) {
        printf("%02x", root_hash[i]);
    }
    printf("\n\n");
    
    // Test audit proof for each leaf
    for (int leaf_idx = 0; leaf_idx < num_leaves; leaf_idx++) {
        printf("Testing leaf %d ('%s'):\n", leaf_idx, leaves[leaf_idx]);
        
        // Generate audit proof
        audit_proof_t proof;
        if (merkle_generate_audit_proof(tree, leaf_idx, &proof) != 0) {
            printf("  Failed to generate audit proof\n");
            continue;
        }
        
        // Compute leaf hash
        uint8_t leaf_hash[MERKLE_NODE_SIZE];
        merkle_compute_leaf_hash((uint8_t*)leaves[leaf_idx], 1, leaf_hash);
        
        printf("  Leaf hash: ");
        for (int i = 0; i < 8; i++) printf("%02x", leaf_hash[i]);
        printf("...\n");
        
        printf("  Audit path length: %d\n", proof.path_len);
        for (int i = 0; i < proof.path_len; i++) {
            printf("    [%d]: ", i);
            for (int j = 0; j < 8; j++) printf("%02x", proof.path[i][j]);
            printf("...\n");
        }
        
        // Verify proof
        int result = merkle_verify_audit_proof(&proof, leaf_hash, root_hash);
        printf("  Verification: %s\n\n", result == 0 ? "PASS" : "FAIL");
    }
    
    merkle_tree_destroy(tree);
    return 0;
}
