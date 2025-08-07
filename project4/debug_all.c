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

int main() {
    printf("Detailed Merkle Tree Debug\n");
    printf("===========================\n");
    
    merkle_tree_t *tree = merkle_tree_create();
    
    const char *data[] = {"data0", "data1", "data2", "data3", "data4", "data5", "data6"};
    int num_leaves = 7;
    
    for (int i = 0; i < num_leaves; i++) {
        merkle_tree_add_leaf(tree, (uint8_t *)data[i], strlen(data[i]));
    }
    
    merkle_tree_build(tree);
    
    uint8_t root_hash[32];
    merkle_get_root_hash(tree, root_hash);
    print_hash(root_hash, "Root");
    
    // 测试每个叶子的审计证明
    for (int leaf_idx = 0; leaf_idx < num_leaves; leaf_idx++) {
        printf("\n=== Testing leaf %d (%s) ===\n", leaf_idx, data[leaf_idx]);
        
        uint8_t leaf_hash[32];
        merkle_compute_leaf_hash((uint8_t*)data[leaf_idx], strlen(data[leaf_idx]), leaf_hash);
        print_hash(leaf_hash, "Leaf hash");
        
        audit_proof_t proof;
        if (merkle_generate_audit_proof(tree, leaf_idx, &proof) != 0) {
            printf("Failed to generate proof for leaf %d\n", leaf_idx);
            continue;
        }
        
        printf("Proof path length: %d\n", proof.path_len);
        for (int i = 0; i < proof.path_len; i++) {
            char label[32];
            sprintf(label, "Path[%d]", i);
            print_hash(proof.path[i], label);
        }
        
        int result = merkle_verify_audit_proof(&proof, leaf_hash, root_hash);
        printf("Verification: %s\n", result == 0 ? "SUCCESS" : "FAILED");
        
        if (result != 0) {
            printf("Manual verification steps:\n");
            uint8_t current[32];
            memcpy(current, leaf_hash, 32);
            uint64_t index = leaf_idx;
            
            for (int i = proof.path_len - 1; i >= 0; i--) {
                printf("  Step %d: index=%lu, ", proof.path_len - i, index);
                uint8_t temp[32];
                if (index % 2 == 0) {
                    printf("Hash(current, path[%d])\n", i);
                    merkle_compute_internal_hash(current, proof.path[i], temp);
                } else {
                    printf("Hash(path[%d], current)\n", i);
                    merkle_compute_internal_hash(proof.path[i], current, temp);
                }
                memcpy(current, temp, 32);
                char step_label[32];
                sprintf(step_label, "    Result");
                print_hash(current, step_label);
                index /= 2;
            }
            printf("Expected root: ");
            for (int i = 0; i < 32; i++) printf("%02x", root_hash[i]);
            printf("\n");
            printf("Computed root: ");
            for (int i = 0; i < 32; i++) printf("%02x", current[i]);
            printf("\n");
        }
    }
    
    merkle_tree_destroy(tree);
    return 0;
}
