#include "merkle.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

merkle_tree_t* merkle_tree_create(void) {
    merkle_tree_t *tree = malloc(sizeof(merkle_tree_t));
    if (!tree) return NULL;
    
    tree->root = NULL;
    tree->leaf_count = 0;
    tree->leaves = NULL;
    tree->leaf_sizes = NULL;
    
    return tree;
}

void merkle_node_destroy(merkle_node_t *node) {
    if (!node) return;
    
    if (!node->is_leaf) {
        merkle_node_destroy(node->left);
        merkle_node_destroy(node->right);
    }
    
    free(node);
}

void merkle_tree_destroy(merkle_tree_t *tree) {
    if (!tree) return;
    
    merkle_node_destroy(tree->root);
    
    if (tree->leaves) {
        for (uint64_t i = 0; i < tree->leaf_count; i++) {
            free(tree->leaves[i]);
        }
        free(tree->leaves);
    }
    
    free(tree->leaf_sizes);
    free(tree);
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
    sm3_update(&ctx, left, MERKLE_NODE_SIZE);
    sm3_update(&ctx, right, MERKLE_NODE_SIZE);
    sm3_final(&ctx, hash);
}

int merkle_tree_add_leaf(merkle_tree_t *tree, const uint8_t *data, size_t len) {
    if (!tree || !data) return -1;
    
    tree->leaves = realloc(tree->leaves, (tree->leaf_count + 1) * sizeof(uint8_t*));
    tree->leaf_sizes = realloc(tree->leaf_sizes, (tree->leaf_count + 1) * sizeof(size_t));
    
    if (!tree->leaves || !tree->leaf_sizes) return -1;
    
    tree->leaves[tree->leaf_count] = malloc(len);
    if (!tree->leaves[tree->leaf_count]) return -1;
    
    memcpy(tree->leaves[tree->leaf_count], data, len);
    tree->leaf_sizes[tree->leaf_count] = len;
    tree->leaf_count++;
    
    return 0;
}

static merkle_node_t* build_tree_recursive(uint8_t **leaves, size_t *leaf_sizes, 
                                          uint64_t start, uint64_t end) {
    if (start >= end) return NULL;
    
    merkle_node_t *node = malloc(sizeof(merkle_node_t));
    if (!node) return NULL;
    
    if (start + 1 == end) {
        node->is_leaf = 1;
        node->left = NULL;
        node->right = NULL;
        merkle_compute_leaf_hash(leaves[start], leaf_sizes[start], node->hash);
        return node;
    }
    
    node->is_leaf = 0;
    uint64_t k = 1;
    while (k < (end - start)) k <<= 1;
    k >>= 1;
    
    uint64_t mid = start + k;
    if (mid > end) mid = end;
    
    node->left = build_tree_recursive(leaves, leaf_sizes, start, mid);
    node->right = build_tree_recursive(leaves, leaf_sizes, mid, end);
    
    if (!node->left && !node->right) {
        free(node);
        return NULL;
    }
    
    if (!node->right) {
        memcpy(node->hash, node->left->hash, MERKLE_NODE_SIZE);
    } else if (!node->left) {
        memcpy(node->hash, node->right->hash, MERKLE_NODE_SIZE);
    } else {
        merkle_compute_internal_hash(node->left->hash, node->right->hash, node->hash);
    }
    
    return node;
}

int merkle_tree_build(merkle_tree_t *tree) {
    if (!tree || tree->leaf_count == 0) return -1;
    
    if (tree->root) {
        merkle_node_destroy(tree->root);
    }
    
    if (tree->leaf_count == 1) {
        tree->root = malloc(sizeof(merkle_node_t));
        if (!tree->root) return -1;
        
        tree->root->is_leaf = 1;
        tree->root->left = NULL;
        tree->root->right = NULL;
        merkle_compute_leaf_hash(tree->leaves[0], tree->leaf_sizes[0], tree->root->hash);
        return 0;
    }
    
    tree->root = build_tree_recursive(tree->leaves, tree->leaf_sizes, 0, tree->leaf_count);
    return tree->root ? 0 : -1;
}

static int generate_audit_path_recursive(merkle_node_t *node, uint64_t target_index,
                                        uint64_t start, uint64_t end, 
                                        audit_proof_t *proof) {
    if (!node || start >= end) return -1;
    
    if (node->is_leaf) {
        return (start == target_index) ? 0 : -1;
    }
    
    uint64_t k = 1;
    while (k < (end - start)) k <<= 1;
    k >>= 1;
    
    uint64_t mid = start + k;
    if (mid > end) mid = end;
    
    if (target_index < mid) {
        int result = generate_audit_path_recursive(node->left, target_index, start, mid, proof);
        if (result == 0 && node->right && proof->path_len < MAX_AUDIT_PATH) {
            memcpy(proof->path[proof->path_len], node->right->hash, MERKLE_NODE_SIZE);
            proof->path_len++;
        }
        return result;
    } else {
        int result = generate_audit_path_recursive(node->right, target_index, mid, end, proof);
        if (result == 0 && node->left && proof->path_len < MAX_AUDIT_PATH) {
            memcpy(proof->path[proof->path_len], node->left->hash, MERKLE_NODE_SIZE);
            proof->path_len++;
        }
        return result;
    }
}

int merkle_generate_audit_proof(merkle_tree_t *tree, uint64_t leaf_index, audit_proof_t *proof) {
    if (!tree || !proof || leaf_index >= tree->leaf_count) return -1;
    
    proof->path_len = 0;
    proof->leaf_index = leaf_index;
    
    if (tree->leaf_count == 1) {
        return 0;
    }
    
    return generate_audit_path_recursive(tree->root, leaf_index, 0, tree->leaf_count, proof);
}

int merkle_verify_audit_proof(const audit_proof_t *proof, const uint8_t *leaf_hash, 
                              const uint8_t *root_hash) {
    if (!proof || !leaf_hash || !root_hash) return -1;
    
    uint8_t current_hash[MERKLE_NODE_SIZE];
    memcpy(current_hash, leaf_hash, MERKLE_NODE_SIZE);
    
    uint64_t index = proof->leaf_index;
    
    for (int i = 0; i < proof->path_len; i++) {
        uint8_t temp_hash[MERKLE_NODE_SIZE];
        
        if (index % 2 == 0) {
            merkle_compute_internal_hash(current_hash, proof->path[i], temp_hash);
        } else {
            merkle_compute_internal_hash(proof->path[i], current_hash, temp_hash);
        }
        
        memcpy(current_hash, temp_hash, MERKLE_NODE_SIZE);
        index /= 2;
    }
    
    return memcmp(current_hash, root_hash, MERKLE_NODE_SIZE) == 0 ? 0 : -1;
}

void merkle_get_root_hash(merkle_tree_t *tree, uint8_t *root_hash) {
    if (!tree || !root_hash) return;
    
    if (tree->root) {
        memcpy(root_hash, tree->root->hash, MERKLE_NODE_SIZE);
    } else {
        memset(root_hash, 0, MERKLE_NODE_SIZE);
    }
}

uint64_t merkle_get_leaf_count(merkle_tree_t *tree) {
    return tree ? tree->leaf_count : 0;
}

void merkle_print_tree(merkle_tree_t *tree) {
    if (!tree) return;
    
    printf("Merkle Tree with %lu leaves\n", tree->leaf_count);
    printf("Root hash: ");
    for (int i = 0; i < MERKLE_NODE_SIZE; i++) {
        printf("%02x", tree->root->hash[i]);
    }
    printf("\n");
}

void merkle_print_proof(const audit_proof_t *proof) {
    if (!proof) return;
    
    printf("Audit proof for leaf %lu:\n", proof->leaf_index);
    printf("Path length: %d\n", proof->path_len);
    for (int i = 0; i < proof->path_len; i++) {
        printf("  [%d]: ", i);
        for (int j = 0; j < MERKLE_NODE_SIZE; j++) {
            printf("%02x", proof->path[i][j]);
        }
        printf("\n");
    }
}
