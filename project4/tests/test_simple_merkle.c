#include "src/sm3.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// 简化但正确的Merkle树实现

typedef struct {
    uint8_t **leaf_hashes;
    int leaf_count;
} simple_merkle_tree_t;

typedef struct {
    uint8_t path[20][32];  // 最多20层
    int path_len;
    int leaf_index;
} simple_audit_proof_t;

simple_merkle_tree_t* create_simple_tree() {
    simple_merkle_tree_t *tree = malloc(sizeof(simple_merkle_tree_t));
    tree->leaf_hashes = NULL;
    tree->leaf_count = 0;
    return tree;
}

void add_leaf_simple(simple_merkle_tree_t *tree, const char *data) {
    tree->leaf_hashes = realloc(tree->leaf_hashes, (tree->leaf_count + 1) * sizeof(uint8_t*));
    tree->leaf_hashes[tree->leaf_count] = malloc(32);
    
    // 计算叶子哈希 (0x00 + data)
    sm3_ctx_t ctx;
    sm3_init(&ctx);
    uint8_t prefix = 0x00;
    sm3_update(&ctx, &prefix, 1);
    sm3_update(&ctx, (uint8_t*)data, strlen(data));
    sm3_final(&ctx, tree->leaf_hashes[tree->leaf_count]);
    
    tree->leaf_count++;
}

void compute_internal_hash_simple(const uint8_t *left, const uint8_t *right, uint8_t *result) {
    sm3_ctx_t ctx;
    sm3_init(&ctx);
    uint8_t prefix = 0x01;
    sm3_update(&ctx, &prefix, 1);
    sm3_update(&ctx, left, 32);
    sm3_update(&ctx, right, 32);
    sm3_final(&ctx, result);
}

// 简单的二叉树构建和根计算
void compute_root_simple(simple_merkle_tree_t *tree, uint8_t *root) {
    if (tree->leaf_count == 0) {
        sm3_hash(NULL, 0, root);
        return;
    }
    
    if (tree->leaf_count == 1) {
        memcpy(root, tree->leaf_hashes[0], 32);
        return;
    }
    
    // 创建工作数组
    uint8_t **current_level = malloc(tree->leaf_count * sizeof(uint8_t*));
    for (int i = 0; i < tree->leaf_count; i++) {
        current_level[i] = malloc(32);
        memcpy(current_level[i], tree->leaf_hashes[i], 32);
    }
    
    int current_count = tree->leaf_count;
    
    // 逐层向上计算
    while (current_count > 1) {
        int next_count = (current_count + 1) / 2;  // 向上取整
        uint8_t **next_level = malloc(next_count * sizeof(uint8_t*));
        
        for (int i = 0; i < next_count; i++) {
            next_level[i] = malloc(32);
            
            if (i * 2 + 1 < current_count) {
                // 有左右子节点
                compute_internal_hash_simple(current_level[i*2], current_level[i*2+1], next_level[i]);
            } else {
                // 只有左子节点
                memcpy(next_level[i], current_level[i*2], 32);
            }
        }
        
        // 清理当前层
        for (int i = 0; i < current_count; i++) {
            free(current_level[i]);
        }
        free(current_level);
        
        current_level = next_level;
        current_count = next_count;
    }
    
    memcpy(root, current_level[0], 32);
    free(current_level[0]);
    free(current_level);
}

// 生成简单的审计证明
int generate_proof_simple(simple_merkle_tree_t *tree, int leaf_index, simple_audit_proof_t *proof) {
    if (leaf_index >= tree->leaf_count) return -1;
    
    proof->path_len = 0;
    proof->leaf_index = leaf_index;
    
    if (tree->leaf_count == 1) return 0;
    
    // 创建工作数组
    uint8_t **current_level = malloc(tree->leaf_count * sizeof(uint8_t*));
    for (int i = 0; i < tree->leaf_count; i++) {
        current_level[i] = malloc(32);
        memcpy(current_level[i], tree->leaf_hashes[i], 32);
    }
    
    int current_count = tree->leaf_count;
    int current_index = leaf_index;
    
    // 逐层向上，记录兄弟节点
    while (current_count > 1) {
        int sibling_index;
        if (current_index % 2 == 0) {
            // 左子节点，兄弟在右边
            sibling_index = current_index + 1;
        } else {
            // 右子节点，兄弟在左边
            sibling_index = current_index - 1;
        }
        
        if (sibling_index < current_count) {
            memcpy(proof->path[proof->path_len], current_level[sibling_index], 32);
            proof->path_len++;
        }
        
        // 计算下一层
        int next_count = (current_count + 1) / 2;
        uint8_t **next_level = malloc(next_count * sizeof(uint8_t*));
        
        for (int i = 0; i < next_count; i++) {
            next_level[i] = malloc(32);
            
            if (i * 2 + 1 < current_count) {
                compute_internal_hash_simple(current_level[i*2], current_level[i*2+1], next_level[i]);
            } else {
                memcpy(next_level[i], current_level[i*2], 32);
            }
        }
        
        // 清理当前层
        for (int i = 0; i < current_count; i++) {
            free(current_level[i]);
        }
        free(current_level);
        
        current_level = next_level;
        current_count = next_count;
        current_index /= 2;
    }
    
    free(current_level[0]);
    free(current_level);
    
    return 0;
}

// 验证简单的审计证明
int verify_proof_simple(simple_audit_proof_t *proof, uint8_t *leaf_hash, uint8_t *root_hash) {
    uint8_t current[32];
    memcpy(current, leaf_hash, 32);
    
    int index = proof->leaf_index;
    
    for (int i = 0; i < proof->path_len; i++) {
        uint8_t temp[32];
        
        if (index % 2 == 0) {
            // 左子节点
            compute_internal_hash_simple(current, proof->path[i], temp);
        } else {
            // 右子节点
            compute_internal_hash_simple(proof->path[i], current, temp);
        }
        
        memcpy(current, temp, 32);
        index /= 2;
    }
    
    return memcmp(current, root_hash, 32) == 0 ? 0 : -1;
}

void test_simple_merkle() {
    printf("Simple Merkle Tree Test\n");
    printf("=======================\n\n");
    
    // 测试不同大小的树
    int test_sizes[] = {1, 3, 7, 15, 100};
    
    for (int t = 0; t < 5; t++) {
        int size = test_sizes[t];
        printf("Testing %d leaves: ", size);
        
        simple_merkle_tree_t *tree = create_simple_tree();
        
        // 添加叶子
        for (int i = 0; i < size; i++) {
            char data[32];
            sprintf(data, "leaf_%d", i);
            add_leaf_simple(tree, data);
        }
        
        // 计算根
        uint8_t root[32];
        compute_root_simple(tree, root);
        
        // 测试几个证明
        int success = 0;
        int total = (size > 3) ? 3 : size;
        int test_indices[] = {0, size/2, size-1};
        
        for (int i = 0; i < total; i++) {
            int idx = test_indices[i];
            if (idx >= size) continue;
            
            simple_audit_proof_t proof;
            if (generate_proof_simple(tree, idx, &proof) == 0) {
                if (verify_proof_simple(&proof, tree->leaf_hashes[idx], root) == 0) {
                    success++;
                }
            }
        }
        
        printf("%s (%d/%d proofs verified)\n", 
               success == total ? "PASSED" : "FAILED", success, total);
        
        // 清理
        for (int i = 0; i < tree->leaf_count; i++) {
            free(tree->leaf_hashes[i]);
        }
        free(tree->leaf_hashes);
        free(tree);
    }
    
    printf("\n✓ Simple Merkle tree tests completed\n");
}

int main() {
    test_simple_merkle();
    return 0;
}
