#include "../src/sm3.h"
#include "../src/merkle.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void print_hash(const uint8_t *hash, const char *label)
{
    printf("%s: ", label);
    for (int i = 0; i < 16; i++)
        printf("%02x", hash[i]);
    printf("...\n");
}

// 手动验证证明的递归函数
static int manual_verify_recursive(const uint8_t *leaf_hash, uint64_t leaf_index,
                                   uint64_t total_leaves, const audit_proof_t *proof,
                                   int *proof_idx, uint8_t *result_hash, int depth)
{
    printf("%*s验证层级 %d: 叶子索引=%lu, 总叶子=%lu\n", depth * 2, "", depth, leaf_index, total_leaves);

    if (total_leaves == 1)
    {
        memcpy(result_hash, leaf_hash, MERKLE_NODE_SIZE);
        printf("%*s  -> 叶子节点，直接返回\n", depth * 2, "");
        return 0;
    }

    uint64_t k = 1;
    while (k < total_leaves)
        k <<= 1;
    k >>= 1;

    printf("%*s  k=%lu\n", depth * 2, "", k);

    if (leaf_index < k)
    {
        printf("%*s  叶子在左子树\n", depth * 2, "");
        // 叶子在左子树
        uint8_t left_hash[32];
        if (manual_verify_recursive(leaf_hash, leaf_index, k, proof, proof_idx, left_hash, depth + 1) != 0)
            return -1;

        // 右子树哈希来自证明路径
        if (*proof_idx >= proof->path_len)
        {
            printf("%*s  错误：proof_idx=%d >= path_len=%d\n", depth * 2, "", *proof_idx, proof->path_len);
            return -1;
        }

        const uint8_t *right_hash = proof->path[(*proof_idx)++];
        printf("%*s  使用证明路径[%d]作为右子树\n", depth * 2, "", *proof_idx - 1);

        merkle_compute_internal_hash(left_hash, right_hash, result_hash);
    }
    else
    {
        printf("%*s  叶子在右子树\n", depth * 2, "");
        // 叶子在右子树
        // 左子树哈希来自证明路径
        if (*proof_idx >= proof->path_len)
        {
            printf("%*s  错误：proof_idx=%d >= path_len=%d\n", depth * 2, "", *proof_idx, proof->path_len);
            return -1;
        }

        const uint8_t *left_hash = proof->path[(*proof_idx)++];
        printf("%*s  使用证明路径[%d]作为左子树\n", depth * 2, "", *proof_idx - 1);

        uint8_t right_hash[32];
        if (manual_verify_recursive(leaf_hash, leaf_index - k, total_leaves - k, proof, proof_idx, right_hash, depth + 1) != 0)
            return -1;

        merkle_compute_internal_hash(left_hash, right_hash, result_hash);
    }

    return 0;
}

int main()
{
    printf("Debug: 详细验证过程\n");

    merkle_tree_t *tree = merkle_tree_create();

    // 添加3个叶子
    const char *data[] = {"leaf_1", "leaf_3", "leaf_5"};

    for (int i = 0; i < 3; i++)
    {
        merkle_tree_add_leaf(tree, (uint8_t *)data[i], strlen(data[i]));
    }

    merkle_tree_build(tree);

    uint8_t root_hash[32];
    merkle_get_root_hash(tree, root_hash);
    print_hash(root_hash, "树根哈希");

    // 测试叶子0
    printf("\n=== 测试叶子0 ===\n");
    audit_proof_t proof;
    merkle_generate_audit_proof(tree, 0, &proof);

    printf("证明信息：\n");
    printf("  叶子索引: %lu\n", proof.leaf_index);
    printf("  树大小: %lu\n", proof.tree_size);
    printf("  路径长度: %d\n", proof.path_len);

    for (int i = 0; i < proof.path_len; i++)
    {
        printf("  路径[%d]: ", i);
        for (int j = 0; j < 16; j++)
            printf("%02x", proof.path[i][j]);
        printf("...\n");
    }

    printf("\n手动验证过程：\n");
    uint8_t computed_root[32];
    int proof_idx = 0;

    int result = manual_verify_recursive(proof.leaf_hash, proof.leaf_index, proof.tree_size,
                                         &proof, &proof_idx, computed_root, 0);

    printf("\n验证结果: %s\n", result == 0 ? "成功" : "失败");
    printf("使用的证明路径数量: %d / %d\n", proof_idx, proof.path_len);

    print_hash(computed_root, "计算的根哈希");
    print_hash(root_hash, "实际根哈希");

    int match = memcmp(computed_root, root_hash, 32) == 0;
    printf("哈希匹配: %s\n", match ? "是" : "否");

    merkle_tree_destroy(tree);
    return 0;
}
