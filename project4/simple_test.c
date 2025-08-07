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
    printf("Simple Merkle Tree Test\n");
    printf("=======================\n");
    
    // 创建一个简单的3叶子树
    merkle_tree_t *tree = merkle_tree_create();
    
    const char *data1 = "leaf1";
    const char *data2 = "leaf2"; 
    const char *data3 = "leaf3";
    
    merkle_tree_add_leaf(tree, (uint8_t*)data1, strlen(data1));
    merkle_tree_add_leaf(tree, (uint8_t*)data2, strlen(data2));
    merkle_tree_add_leaf(tree, (uint8_t*)data3, strlen(data3));
    
    if (merkle_tree_build(tree) != 0) {
        printf("Failed to build tree\n");
        return 1;
    }
    
    uint8_t root_hash[32];
    merkle_get_root_hash(tree, root_hash);
    print_hash(root_hash, "Root");
    
    // 测试叶子0的审计证明
    printf("\nTesting audit proof for leaf 0:\n");
    
    uint8_t leaf0_hash[32];
    merkle_compute_leaf_hash((uint8_t*)data1, strlen(data1), leaf0_hash);
    print_hash(leaf0_hash, "Leaf 0");
    
    audit_proof_t proof;
    if (merkle_generate_audit_proof(tree, 0, &proof) != 0) {
        printf("Failed to generate audit proof\n");
        return 1;
    }
    
    printf("Audit path length: %d\n", proof.path_len);
    for (int i = 0; i < proof.path_len; i++) {
        char label[32];
        sprintf(label, "Path[%d]", i);
        print_hash(proof.path[i], label);
    }
    
    // 验证审计证明
    int result = merkle_verify_audit_proof(&proof, leaf0_hash, root_hash);
    printf("Verification result: %s\n", result == 0 ? "SUCCESS" : "FAILED");
    
    if (result != 0) {
        printf("\nManual verification:\n");
        uint8_t current[32];
        memcpy(current, leaf0_hash, 32);
        print_hash(current, "Start");
        
        uint64_t index = 0;
        for (int i = proof.path_len - 1; i >= 0; i--) {
            uint8_t temp[32];
            if (index % 2 == 0) {
                printf("Computing Hash(current, path[%d])\n", i);
                merkle_compute_internal_hash(current, proof.path[i], temp);
            } else {
                printf("Computing Hash(path[%d], current)\n", i);
                merkle_compute_internal_hash(proof.path[i], current, temp);
            }
            memcpy(current, temp, 32);
            char label[32];
            sprintf(label, "Step %d", proof.path_len - i);
            print_hash(current, label);
            index /= 2;
        }
        
        printf("Compare with root:\n");
        print_hash(root_hash, "Expected");
        print_hash(current, "Computed");
    }
    
    merkle_tree_destroy(tree);
    return 0;
}
