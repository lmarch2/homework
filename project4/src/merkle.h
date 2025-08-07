#ifndef MERKLE_H
#define MERKLE_H

#include <stdint.h>
#include <stddef.h>
#include "sm3.h"

#define MERKLE_NODE_SIZE 32
#define MAX_AUDIT_PATH 64

typedef struct merkle_node
{
    uint8_t hash[MERKLE_NODE_SIZE];
    struct merkle_node *left;
    struct merkle_node *right;
    int is_leaf;
} merkle_node_t;

typedef struct
{
    merkle_node_t *root;
    uint64_t leaf_count;
    uint8_t **leaves;
    size_t *leaf_sizes;
} merkle_tree_t;

typedef struct
{
    uint8_t path[MAX_AUDIT_PATH][MERKLE_NODE_SIZE];
    int path_len;
    uint64_t leaf_index;
    uint8_t leaf_hash[MERKLE_NODE_SIZE]; // 添加叶子哈希字段
    uint64_t tree_size;                  // 添加树大小字段
} audit_proof_t;

typedef struct
{
    uint8_t proof[MAX_AUDIT_PATH][MERKLE_NODE_SIZE];
    int proof_len;
    uint64_t old_size;
    uint64_t new_size;
} consistency_proof_t;

merkle_tree_t *merkle_tree_create(void);
void merkle_tree_destroy(merkle_tree_t *tree);

int merkle_tree_add_leaf(merkle_tree_t *tree, const uint8_t *data, size_t len);
int merkle_tree_build(merkle_tree_t *tree);

void merkle_compute_leaf_hash(const uint8_t *data, size_t len, uint8_t *hash);
void merkle_compute_internal_hash(const uint8_t *left, const uint8_t *right, uint8_t *hash);

int merkle_generate_audit_proof(merkle_tree_t *tree, uint64_t leaf_index, audit_proof_t *proof);
int merkle_verify_audit_proof(const audit_proof_t *proof, const uint8_t *leaf_hash,
                              const uint8_t *root_hash);

// 不存在性证明函数
int merkle_prove_non_existence(merkle_tree_t *tree, const uint8_t *data, size_t len,
                               audit_proof_t **left_proof, audit_proof_t **right_proof);
int merkle_verify_non_existence(const uint8_t *data, size_t len,
                                const audit_proof_t *left_proof,
                                const audit_proof_t *right_proof,
                                const uint8_t *root_hash);

int merkle_generate_consistency_proof(merkle_tree_t *old_tree, merkle_tree_t *new_tree,
                                      consistency_proof_t *proof);
int merkle_verify_consistency_proof(const consistency_proof_t *proof,
                                    const uint8_t *old_root, const uint8_t *new_root);

void merkle_get_root_hash(merkle_tree_t *tree, uint8_t *root_hash);
uint64_t merkle_get_leaf_count(merkle_tree_t *tree);

void merkle_print_tree(merkle_tree_t *tree);
void merkle_print_proof(const audit_proof_t *proof);

#endif
