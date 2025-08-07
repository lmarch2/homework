#include "../src/sm3.h"
#include "../src/merkle.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void print_hash(const uint8_t *hash, const char *label)
{
    printf("%s: ", label);
    for (int i = 0; i < 16; i++)
    {
        printf("%02x", hash[i]);
    }
    printf("...\n");
}

// 手动实现证明生成，跟踪每一步
void manual_audit_path(uint8_t **leaf_hashes, uint64_t n, uint64_t m,
                       uint8_t path[][MERKLE_NODE_SIZE], int *path_len)
{
    printf("\n手动证明生成: n=%lu, m=%lu\n", n, m);

    if (n == 1)
    {
        printf("  到达叶子，返回\n");
        return;
    }

    uint64_t k = 1;
    while (k < n)
        k <<= 1;
    k >>= 1;

    printf("  k=%lu\n", k);

    if (m < k)
    {
        printf("  m(%lu) < k(%lu), 在左子树，需要右子树的根\n", m, k);

        // 计算右子树的根
        uint8_t right_hash[MERKLE_NODE_SIZE];
        printf("  计算右子树根: 叶子[%lu..%lu]\n", k, n - 1);
        if (n - k == 1)
        {
            // 右子树只有一个叶子
            memcpy(right_hash, leaf_hashes[k], MERKLE_NODE_SIZE);
            printf("  右子树是单个叶子%lu\n", k);
        }
        else
        {
            // 需要递归计算右子树
            printf("  右子树需要递归计算\n");
            // 这里简化处理，实际实现中会递归
        }

        char label[64];
        snprintf(label, sizeof(label), "  添加路径[%d]", *path_len);
        print_hash(right_hash, label);
        memcpy(path[*path_len], right_hash, MERKLE_NODE_SIZE);
        (*path_len)++;

        manual_audit_path(leaf_hashes, k, m, path, path_len);
    }
    else
    {
        printf("  m(%lu) >= k(%lu), 在右子树，需要左子树的根\n", m, k);

        // 计算左子树的根
        uint8_t left_hash[MERKLE_NODE_SIZE];
        printf("  计算左子树根: 叶子[0..%lu]\n", k - 1);
        if (k == 1)
        {
            // 左子树只有一个叶子
            memcpy(left_hash, leaf_hashes[0], MERKLE_NODE_SIZE);
            printf("  左子树是单个叶子0\n");
        }
        else
        {
            // 需要递归计算左子树
            printf("  左子树需要递归计算\n");
        }

        char label[64];
        snprintf(label, sizeof(label), "  添加路径[%d]", *path_len);
        print_hash(left_hash, label);
        memcpy(path[*path_len], left_hash, MERKLE_NODE_SIZE);
        (*path_len)++;

        manual_audit_path(leaf_hashes + k, n - k, m - k, path, path_len);
    }
}

int main()
{
    printf("Debug: 手动跟踪证明生成\n");

    // 准备叶子哈希
    uint8_t leaf_hashes[3][MERKLE_NODE_SIZE];
    const char *data[] = {"leaf_1", "leaf_3", "leaf_5"};

    for (int i = 0; i < 3; i++)
    {
        merkle_compute_leaf_hash((uint8_t *)data[i], strlen(data[i]), leaf_hashes[i]);
        char label[32];
        snprintf(label, sizeof(label), "叶子%d哈希", i);
        print_hash(leaf_hashes[i], label);
    }

    // 手动生成叶子1的证明
    uint8_t *leaf_hash_ptrs[3] = {leaf_hashes[0], leaf_hashes[1], leaf_hashes[2]};
    uint8_t manual_path[16][MERKLE_NODE_SIZE];
    int manual_path_len = 0;

    printf("\n开始为叶子1生成审计路径：");
    manual_audit_path(leaf_hash_ptrs, 3, 1, manual_path, &manual_path_len);

    printf("\n手动生成的路径：\n");
    for (int i = 0; i < manual_path_len; i++)
    {
        char label[32];
        snprintf(label, sizeof(label), "手动路径[%d]", i);
        print_hash(manual_path[i], label);
    }

    // 与实际实现比较
    printf("\n与实际实现比较：\n");
    merkle_tree_t *tree = merkle_tree_create();
    for (int i = 0; i < 3; i++)
    {
        merkle_tree_add_leaf(tree, (uint8_t *)data[i], strlen(data[i]));
    }
    merkle_tree_build(tree);

    audit_proof_t proof;
    merkle_generate_audit_proof(tree, 1, &proof);

    for (int i = 0; i < proof.path_len; i++)
    {
        char label[32];
        snprintf(label, sizeof(label), "实际路径[%d]", i);
        print_hash(proof.path[i], label);
    }

    merkle_tree_destroy(tree);
    return 0;
}
