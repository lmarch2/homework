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

static void compute_tree_hashes(uint8_t **leaf_hashes, uint64_t n, uint8_t *result)
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

    compute_tree_hashes(leaf_hashes, k, left_hash);
    compute_tree_hashes(leaf_hashes + k, n - k, right_hash);

    merkle_compute_internal_hash(left_hash, right_hash, result);
}

int merkle_tree_build(merkle_tree_t *tree)
{
    if (!tree || tree->leaf_count == 0)
        return -1;

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

    tree->root = malloc(sizeof(merkle_node_t));
    if (!tree->root)
    {
        for (uint64_t i = 0; i < tree->leaf_count; i++)
            free(leaf_hashes[i]);
        free(leaf_hashes);
        return -1;
    }

    tree->root->left = NULL;
    tree->root->right = NULL;
    tree->root->is_leaf = 0;

    compute_tree_hashes(leaf_hashes, tree->leaf_count, tree->root->hash);

    for (uint64_t i = 0; i < tree->leaf_count; i++)
        free(leaf_hashes[i]);
    free(leaf_hashes);

    return 0;
}

static void audit_path_recursive(uint8_t **leaf_hashes, uint64_t n, uint64_t m,
                                 audit_proof_t *proof)
{
    if (n == 1)
        return;

    uint64_t k = 1;
    while (k < n)
        k <<= 1;
    k >>= 1;

    if (m < k)
    {
        // 叶子在左子树，需要右子树的根作为证明
        uint8_t right_hash[MERKLE_NODE_SIZE];
        compute_tree_hashes(leaf_hashes + k, n - k, right_hash);
        if (proof->path_len < MAX_AUDIT_PATH)
        {
            memcpy(proof->path[proof->path_len], right_hash, MERKLE_NODE_SIZE);
            proof->path_len++;
        }
        audit_path_recursive(leaf_hashes, k, m, proof);
    }
    else
    {
        // 叶子在右子树，需要左子树的根作为证明
        uint8_t left_hash[MERKLE_NODE_SIZE];
        compute_tree_hashes(leaf_hashes, k, left_hash);
        if (proof->path_len < MAX_AUDIT_PATH)
        {
            memcpy(proof->path[proof->path_len], left_hash, MERKLE_NODE_SIZE);
            proof->path_len++;
        }
        audit_path_recursive(leaf_hashes + k, n - k, m - k, proof);
    }
}

int merkle_generate_audit_proof(merkle_tree_t *tree, uint64_t leaf_index, audit_proof_t *proof)
{
    if (!tree || !proof || leaf_index >= tree->leaf_count)
        return -1;

    proof->path_len = 0;
    proof->leaf_index = leaf_index;
    proof->tree_size = tree->leaf_count; // 存储树大小

    // 计算叶子哈希并存储在证明中
    merkle_compute_leaf_hash(tree->leaves[leaf_index], tree->leaf_sizes[leaf_index], proof->leaf_hash);

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

    audit_path_recursive(leaf_hashes, tree->leaf_count, leaf_index, proof);

    for (uint64_t i = 0; i < tree->leaf_count; i++)
        free(leaf_hashes[i]);
    free(leaf_hashes);

    return 0;
}

// 递归验证算法，匹配生成算法的逆向
static int verify_recursive(const uint8_t *leaf_hash, uint64_t leaf_index,
                            uint64_t total_leaves, const audit_proof_t *proof,
                            int *proof_idx, uint8_t *result_hash)
{
    if (total_leaves == 1)
    {
        memcpy(result_hash, leaf_hash, MERKLE_NODE_SIZE);
        return 0;
    }

    uint64_t k = 1;
    while (k < total_leaves)
        k <<= 1;
    k >>= 1;

    // 从证明路径的末尾开始使用（因为生成时是从顶层开始添加的）
    int current_proof_idx = proof->path_len - 1 - *proof_idx;

    if (leaf_index < k)
    {
        // 叶子在左子树
        uint8_t left_hash[MERKLE_NODE_SIZE];
        if (verify_recursive(leaf_hash, leaf_index, k, proof, proof_idx, left_hash) != 0)
            return -1;

        // 右子树哈希来自证明路径
        if (current_proof_idx < 0)
            return -1;
        const uint8_t *right_hash = proof->path[current_proof_idx];
        (*proof_idx)++;

        merkle_compute_internal_hash(left_hash, right_hash, result_hash);
    }
    else
    {
        // 叶子在右子树
        // 左子树哈希来自证明路径
        if (current_proof_idx < 0)
            return -1;
        const uint8_t *left_hash = proof->path[current_proof_idx];
        (*proof_idx)++;

        uint8_t right_hash[MERKLE_NODE_SIZE];
        if (verify_recursive(leaf_hash, leaf_index - k, total_leaves - k, proof, proof_idx, right_hash) != 0)
            return -1;

        merkle_compute_internal_hash(left_hash, right_hash, result_hash);
    }

    return 0;
}

int merkle_verify_audit_proof(const audit_proof_t *proof, const uint8_t *leaf_hash,
                              const uint8_t *root_hash)
{
    if (!proof || !leaf_hash || !root_hash)
        return -1;

    // 创建临时树来验证证明的正确性
    // 这种方法虽然效率不高，但能确保正确性

    uint8_t computed_hash[MERKLE_NODE_SIZE];
    memcpy(computed_hash, leaf_hash, MERKLE_NODE_SIZE);

    // 使用RFC6962的迭代验证方法，但确保正确处理路径
    uint64_t index = proof->leaf_index;
    uint64_t size = proof->tree_size;

    // 从根到叶子的路径记录，用于确定正确的哈希顺序
    int is_left_child[32]; // 记录在每一层是否为左子节点
    int depth = 0;

    // 首先确定从根到叶子的路径
    uint64_t temp_index = index;
    uint64_t temp_size = size;

    while (temp_size > 1)
    {
        uint64_t k = 1;
        while (k < temp_size)
            k <<= 1;
        k >>= 1;

        if (temp_index < k)
        {
            is_left_child[depth] = 1; // 在左子树
            temp_size = k;
        }
        else
        {
            is_left_child[depth] = 0; // 在右子树
            temp_index -= k;
            temp_size = temp_size - k;
        }
        depth++;
    }

    // 现在从叶子向根验证，使用正确的哈希顺序
    for (int level = 0; level < proof->path_len; level++)
    {
        int path_idx = proof->path_len - 1 - level; // 从路径末尾开始

        if (is_left_child[depth - 1 - level])
        {
            // 当前节点在左侧，兄弟在右侧
            merkle_compute_internal_hash(computed_hash, proof->path[path_idx], computed_hash);
        }
        else
        {
            // 当前节点在右侧，兄弟在左侧
            merkle_compute_internal_hash(proof->path[path_idx], computed_hash, computed_hash);
        }
    }

    return memcmp(computed_hash, root_hash, MERKLE_NODE_SIZE) == 0 ? 0 : -1;
}

void merkle_get_root_hash(merkle_tree_t *tree, uint8_t *root_hash)
{
    if (!tree || !root_hash)
        return;

    if (tree->root)
    {
        memcpy(root_hash, tree->root->hash, MERKLE_NODE_SIZE);
    }
    else
    {
        memset(root_hash, 0, MERKLE_NODE_SIZE);
    }
}

uint64_t merkle_get_leaf_count(merkle_tree_t *tree)
{
    return tree ? tree->leaf_count : 0;
}

void merkle_print_tree(merkle_tree_t *tree)
{
    if (!tree)
        return;

    printf("Merkle Tree with %lu leaves\n", tree->leaf_count);
    printf("Root hash: ");
    for (int i = 0; i < MERKLE_NODE_SIZE; i++)
    {
        printf("%02x", tree->root->hash[i]);
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

// 不存在性证明实现
int merkle_prove_non_existence(merkle_tree_t *tree, const uint8_t *data, size_t len,
                               audit_proof_t **left_proof, audit_proof_t **right_proof)
{
    if (!tree || !data || tree->leaf_count == 0)
        return -1;

    // 计算查询数据的哈希
    uint8_t query_hash[MERKLE_NODE_SIZE];
    merkle_compute_leaf_hash(data, len, query_hash);

    // 找到查询哈希在排序后叶子中的位置
    uint64_t insert_pos = 0;
    uint8_t leaf_hash[MERKLE_NODE_SIZE];

    for (uint64_t i = 0; i < tree->leaf_count; i++)
    {
        merkle_compute_leaf_hash(tree->leaves[i], tree->leaf_sizes[i], leaf_hash);
        if (memcmp(leaf_hash, query_hash, MERKLE_NODE_SIZE) < 0)
        {
            insert_pos = i + 1;
        }
        else if (memcmp(leaf_hash, query_hash, MERKLE_NODE_SIZE) == 0)
        {
            // 元素存在，无法生成不存在性证明
            return 0;
        }
        else
        {
            break;
        }
    }

    // 生成左右边界的存在性证明
    *left_proof = NULL;
    *right_proof = NULL;

    if (insert_pos > 0)
    {
        *left_proof = malloc(sizeof(audit_proof_t));
        if (*left_proof && merkle_generate_audit_proof(tree, insert_pos - 1, *left_proof) != 0)
        {
            free(*left_proof);
            *left_proof = NULL;
        }
    }

    if (insert_pos < tree->leaf_count)
    {
        *right_proof = malloc(sizeof(audit_proof_t));
        if (*right_proof && merkle_generate_audit_proof(tree, insert_pos, *right_proof) != 0)
        {
            free(*right_proof);
            *right_proof = NULL;
        }
    }

    return 1; // 不存在
}

int merkle_verify_non_existence(const uint8_t *data, size_t len,
                                const audit_proof_t *left_proof,
                                const audit_proof_t *right_proof,
                                const uint8_t *root_hash)
{
    // 计算查询数据的哈希
    uint8_t query_hash[MERKLE_NODE_SIZE];
    merkle_compute_leaf_hash(data, len, query_hash);

    // 验证左边界证明（如果存在）
    if (left_proof)
    {
        if (merkle_verify_audit_proof(left_proof, left_proof->leaf_hash, root_hash) != 0)
        {
            return 0;
        }

        // 检查左边界确实小于查询哈希
        if (memcmp(left_proof->leaf_hash, query_hash, MERKLE_NODE_SIZE) >= 0)
        {
            return 0;
        }
    }

    // 验证右边界证明（如果存在）
    if (right_proof)
    {
        if (merkle_verify_audit_proof(right_proof, right_proof->leaf_hash, root_hash) != 0)
        {
            return 0;
        }

        // 检查右边界确实大于查询哈希
        if (memcmp(right_proof->leaf_hash, query_hash, MERKLE_NODE_SIZE) <= 0)
        {
            return 0;
        }
    }

    return 1; // 验证通过，数据确实不存在
}
