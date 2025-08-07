#include "merkle.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

merkle_tree_t *merkle_tree_create(void)
{
    merkle_tree_t *tree = malloc(sizeof(merkle_tree_t));
    if (!tree)
        return NULL;

    tree->root = NULL;
    tree->leaf_count = 0;
    tree->leaves = NULL;
    tree->leaf_sizes = NULL;

    return tree;
}

void merkle_tree_destroy(merkle_tree_t *tree)
{
    if (!tree)
        return;

    if (tree->leaves)
    {
        for (uint64_t i = 0; i < tree->leaf_count; i++)
        {
            free(tree->leaves[i]);
        }
        free(tree->leaves);
    }

    free(tree->leaf_sizes);
    free(tree);
}

void merkle_compute_leaf_hash(const uint8_t *data, size_t len, uint8_t *hash)
{
    sm3_ctx_t ctx;
    sm3_init(&ctx);

    uint8_t prefix = 0x00;
    sm3_update(&ctx, &prefix, 1);
    sm3_update(&ctx, data, len);
    sm3_final(&ctx, hash);
}

void merkle_compute_internal_hash(const uint8_t *left, const uint8_t *right, uint8_t *hash)
{
    sm3_ctx_t ctx;
    sm3_init(&ctx);

    uint8_t prefix = 0x01;
    sm3_update(&ctx, &prefix, 1);
    sm3_update(&ctx, left, MERKLE_NODE_SIZE);
    sm3_update(&ctx, right, MERKLE_NODE_SIZE);
    sm3_final(&ctx, hash);
}

int merkle_tree_add_leaf(merkle_tree_t *tree, const uint8_t *data, size_t len)
{
    if (!tree || !data)
        return -1;

    tree->leaves = realloc(tree->leaves, (tree->leaf_count + 1) * sizeof(uint8_t *));
    tree->leaf_sizes = realloc(tree->leaf_sizes, (tree->leaf_count + 1) * sizeof(size_t));

    if (!tree->leaves || !tree->leaf_sizes)
        return -1;

    tree->leaves[tree->leaf_count] = malloc(len);
    if (!tree->leaves[tree->leaf_count])
        return -1;

    memcpy(tree->leaves[tree->leaf_count], data, len);
    tree->leaf_sizes[tree->leaf_count] = len;
    tree->leaf_count++;

    return 0;
}

static void mth_recursive(uint8_t **leaf_hashes, uint64_t n, uint8_t *result)
{
    if (n == 0)
    {
        sm3_hash(NULL, 0, result);
        return;
    }

    if (n == 1)
    {
        memcpy(result, leaf_hashes[0], MERKLE_NODE_SIZE);
        return;
    }

    uint64_t k = 1;
    while (k < n)
        k <<= 1;
    k >>= 1;

    uint8_t left_hash[MERKLE_NODE_SIZE];
    uint8_t right_hash[MERKLE_NODE_SIZE];

    mth_recursive(leaf_hashes, k, left_hash);
    mth_recursive(leaf_hashes + k, n - k, right_hash);

    merkle_compute_internal_hash(left_hash, right_hash, result);
}

int merkle_tree_build(merkle_tree_t *tree)
{
    if (!tree || tree->leaf_count == 0)
        return -1;

    tree->root = malloc(sizeof(merkle_node_t));
    if (!tree->root)
        return -1;

    tree->root->left = NULL;
    tree->root->right = NULL;
    tree->root->is_leaf = 0;

    return 0;
}

static void path_recursive(uint8_t **leaf_hashes, uint64_t n, uint64_t m, audit_proof_t *proof)
{
    if (n <= 1)
        return;

    uint64_t k = 1;
    while (k < n)
        k <<= 1;
    k >>= 1;

    if (m < k)
    {
        uint8_t right_hash[MERKLE_NODE_SIZE];
        mth_recursive(leaf_hashes + k, n - k, right_hash);
        memcpy(proof->path[proof->path_len], right_hash, MERKLE_NODE_SIZE);
        proof->path_len++;
        path_recursive(leaf_hashes, k, m, proof);
    }
    else
    {
        uint8_t left_hash[MERKLE_NODE_SIZE];
        mth_recursive(leaf_hashes, k, left_hash);
        memcpy(proof->path[proof->path_len], left_hash, MERKLE_NODE_SIZE);
        proof->path_len++;
        path_recursive(leaf_hashes + k, n - k, m - k, proof);
    }
}

int merkle_generate_audit_proof(merkle_tree_t *tree, uint64_t leaf_index, audit_proof_t *proof)
{
    if (!tree || !proof || leaf_index >= tree->leaf_count)
        return -1;

    proof->path_len = 0;
    proof->leaf_index = leaf_index;

    if (tree->leaf_count == 1)
        return 0;

    uint8_t **leaf_hashes = malloc(tree->leaf_count * sizeof(uint8_t *));
    if (!leaf_hashes)
        return -1;

    for (uint64_t i = 0; i < tree->leaf_count; i++)
    {
        leaf_hashes[i] = malloc(MERKLE_NODE_SIZE);
        if (!leaf_hashes[i])
        {
            for (uint64_t j = 0; j < i; j++)
                free(leaf_hashes[j]);
            free(leaf_hashes);
            return -1;
        }
        merkle_compute_leaf_hash(tree->leaves[i], tree->leaf_sizes[i], leaf_hashes[i]);
    }

    path_recursive(leaf_hashes, tree->leaf_count, leaf_index, proof);

    for (uint64_t i = 0; i < tree->leaf_count; i++)
        free(leaf_hashes[i]);
    free(leaf_hashes);

    return 0;
}

int merkle_verify_audit_proof(const audit_proof_t *proof, const uint8_t *leaf_hash,
                              const uint8_t *root_hash)
{
    if (!proof || !leaf_hash || !root_hash)
        return -1;

    uint8_t computed_root[MERKLE_NODE_SIZE];
    memcpy(computed_root, leaf_hash, MERKLE_NODE_SIZE);

    uint64_t index = proof->leaf_index;

    for (int i = 0; i < proof->path_len; i++)
    {
        uint8_t temp[MERKLE_NODE_SIZE];

        if (index % 2 == 0)
        {
            merkle_compute_internal_hash(computed_root, proof->path[i], temp);
        }
        else
        {
            merkle_compute_internal_hash(proof->path[i], computed_root, temp);
        }

        memcpy(computed_root, temp, MERKLE_NODE_SIZE);
        index /= 2;
    }

    return memcmp(computed_root, root_hash, MERKLE_NODE_SIZE) == 0 ? 0 : -1;
}

void merkle_get_root_hash(merkle_tree_t *tree, uint8_t *root_hash)
{
    if (!tree || !root_hash || tree->leaf_count == 0)
    {
        memset(root_hash, 0, MERKLE_NODE_SIZE);
        return;
    }

    uint8_t **leaf_hashes = malloc(tree->leaf_count * sizeof(uint8_t *));
    if (!leaf_hashes)
    {
        memset(root_hash, 0, MERKLE_NODE_SIZE);
        return;
    }

    for (uint64_t i = 0; i < tree->leaf_count; i++)
    {
        leaf_hashes[i] = malloc(MERKLE_NODE_SIZE);
        if (!leaf_hashes[i])
        {
            for (uint64_t j = 0; j < i; j++)
                free(leaf_hashes[j]);
            free(leaf_hashes);
            memset(root_hash, 0, MERKLE_NODE_SIZE);
            return;
        }
        merkle_compute_leaf_hash(tree->leaves[i], tree->leaf_sizes[i], leaf_hashes[i]);
    }

    mth_recursive(leaf_hashes, tree->leaf_count, root_hash);

    for (uint64_t i = 0; i < tree->leaf_count; i++)
        free(leaf_hashes[i]);
    free(leaf_hashes);
}

uint64_t merkle_get_leaf_count(merkle_tree_t *tree)
{
    return tree ? tree->leaf_count : 0;
}

void merkle_print_tree(merkle_tree_t *tree)
{
    if (!tree)
        return;

    uint8_t root[MERKLE_NODE_SIZE];
    merkle_get_root_hash(tree, root);

    printf("Merkle Tree with %lu leaves\n", tree->leaf_count);
    printf("Root hash: ");
    for (int i = 0; i < MERKLE_NODE_SIZE; i++)
    {
        printf("%02x", root[i]);
    }
    printf("\n");
}

void merkle_print_proof(const audit_proof_t *proof)
{
    if (!proof)
        return;

    printf("Audit proof for leaf %lu:\n", proof->leaf_index);
    printf("Path length: %d\n", proof->path_len);
    for (int i = 0; i < proof->path_len; i++)
    {
        printf("  [%d]: ", i);
        for (int j = 0; j < MERKLE_NODE_SIZE; j++)
        {
            printf("%02x", proof->path[i][j]);
        }
        printf("\n");
    }
}
