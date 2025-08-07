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

int main()
{
    printf("Debug: 不存在性证明问题\n");

    merkle_tree_t *tree = merkle_tree_create();

    // 添加3个叶子用于简单测试
    const char *data[] = {"leaf_1", "leaf_3", "leaf_5"};

    for (int i = 0; i < 3; i++)
    {
        merkle_tree_add_leaf(tree, (uint8_t *)data[i], strlen(data[i]));
    }

    merkle_tree_build(tree);

    printf("构建3叶子树，查询 'leaf_2' (应该在leaf_1和leaf_3之间)\n\n");

    // 打印所有叶子的哈希值
    for (int i = 0; i < 3; i++)
    {
        uint8_t hash[32];
        merkle_compute_leaf_hash((uint8_t *)data[i], strlen(data[i]), hash);
        printf("叶子%d (%s): ", i, data[i]);
        for (int j = 0; j < 16; j++)
            printf("%02x", hash[j]);
        printf("...\n");
    }

    // 查询leaf_2的哈希
    uint8_t query_hash[32];
    merkle_compute_leaf_hash((uint8_t *)"leaf_2", 6, query_hash);
    print_hash(query_hash, "查询 'leaf_2'");

    printf("\n");

    // 测试不存在性证明
    audit_proof_t *left_proof = NULL, *right_proof = NULL;

    int result = merkle_prove_non_existence(tree, (uint8_t *)"leaf_2", 6,
                                            &left_proof, &right_proof);

    printf("证明生成结果: %d\n", result);

    if (left_proof)
    {
        printf("左边界证明: 叶子索引%lu\n", left_proof->leaf_index);
        print_hash(left_proof->leaf_hash, "左边界哈希");
    }
    else
    {
        printf("无左边界证明\n");
    }

    if (right_proof)
    {
        printf("右边界证明: 叶子索引%lu\n", right_proof->leaf_index);
        print_hash(right_proof->leaf_hash, "右边界哈希");
    }
    else
    {
        printf("无右边界证明\n");
    }

    if (result == 1)
    {
        uint8_t root_hash[32];
        merkle_get_root_hash(tree, root_hash);

        int verify_result = merkle_verify_non_existence((uint8_t *)"leaf_2", 6,
                                                        left_proof, right_proof,
                                                        root_hash);

        printf("验证结果: %s\n", verify_result ? "通过" : "失败");

        // 验证边界证明本身
        if (left_proof)
        {
            int left_verify = merkle_verify_audit_proof(left_proof, left_proof->leaf_hash, root_hash);
            printf("左边界证明验证: %s\n", left_verify == 0 ? "通过" : "失败");
        }

        if (right_proof)
        {
            int right_verify = merkle_verify_audit_proof(right_proof, right_proof->leaf_hash, root_hash);
            printf("右边界证明验证: %s\n", right_verify == 0 ? "通过" : "失败");
        }

        // 检查哈希值大小关系
        if (left_proof)
        {
            int cmp = memcmp(left_proof->leaf_hash, query_hash, 32);
            printf("左边界 < 查询: %s (cmp=%d)\n", cmp < 0 ? "是" : "否", cmp);
        }

        if (right_proof)
        {
            int cmp = memcmp(right_proof->leaf_hash, query_hash, 32);
            printf("右边界 > 查询: %s (cmp=%d)\n", cmp > 0 ? "是" : "否", cmp);
        }
    }

    free(left_proof);
    free(right_proof);
    merkle_tree_destroy(tree);

    return 0;
}
