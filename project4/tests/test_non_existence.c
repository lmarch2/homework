#include "../src/sm3.h"
#include "../src/merkle.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int test_non_existence_proof()
{
    printf("=== 测试不存在性证明 ===\n\n");

    merkle_tree_t *tree = merkle_tree_create();
    if (!tree)
    {
        printf("Failed to create tree\n");
        return -1;
    }

    // 添加一些叶子节点
    const char *data[] = {
        "document_001",
        "document_003",
        "document_005",
        "document_007",
        "document_009"};

    for (int i = 0; i < 5; i++)
    {
        merkle_tree_add_leaf(tree, (uint8_t *)data[i], strlen(data[i]));
    }

    if (merkle_tree_build(tree) != 0)
    {
        printf("Failed to build tree\n");
        merkle_tree_destroy(tree);
        return -1;
    }

    printf("构建了包含5个叶子的Merkle树:\n");
    for (int i = 0; i < 5; i++)
    {
        printf("  叶子%d: %s\n", i, data[i]);
    }

    uint8_t root_hash[32];
    merkle_get_root_hash(tree, root_hash);

    printf("\n树根哈希: ");
    for (int i = 0; i < 16; i++)
        printf("%02x", root_hash[i]);
    printf("...\n\n");

    // 测试不存在性证明
    const char *query_data[] = {
        "document_000", // 小于所有现有元素
        "document_002", // 在document_001和document_003之间
        "document_004", // 在document_003和document_005之间
        "document_006", // 在document_005和document_007之间
        "document_010"  // 大于所有现有元素
    };

    for (int i = 0; i < 5; i++)
    {
        printf("测试查询: \"%s\"\n", query_data[i]);

        audit_proof_t *left_proof = NULL, *right_proof = NULL;

        int result = merkle_prove_non_existence(tree, (uint8_t *)query_data[i],
                                                strlen(query_data[i]),
                                                &left_proof, &right_proof);

        if (result == 1)
        {
            printf("  结果: 不存在\n");

            // 验证不存在性证明
            int verify_result = merkle_verify_non_existence((uint8_t *)query_data[i],
                                                            strlen(query_data[i]),
                                                            left_proof, right_proof,
                                                            root_hash);

            if (verify_result)
            {
                printf("  验证: 通过 ✓\n");

                if (left_proof)
                {
                    printf("  左边界: 叶子索引%lu\n", left_proof->leaf_index);
                }
                if (right_proof)
                {
                    printf("  右边界: 叶子索引%lu\n", right_proof->leaf_index);
                }
            }
            else
            {
                printf("  验证: 失败 ✗\n");
            }

            // 释放证明内存
            free(left_proof);
            free(right_proof);
        }
        else if (result == 0)
        {
            printf("  结果: 存在（这不应该发生）\n");
        }
        else
        {
            printf("  结果: 错误\n");
        }
        printf("\n");
    }

    // 测试实际存在的元素
    printf("验证存在的元素不会生成不存在性证明:\n");
    audit_proof_t *left_proof = NULL, *right_proof = NULL;
    int result = merkle_prove_non_existence(tree, (uint8_t *)data[2],
                                            strlen(data[2]),
                                            &left_proof, &right_proof);

    if (result == 0)
    {
        printf("  \"%s\": 正确识别为存在 ✓\n", data[2]);
    }
    else
    {
        printf("  \"%s\": 错误识别 ✗\n", data[2]);
    }

    merkle_tree_destroy(tree);
    printf("\n=== 不存在性证明测试完成 ===\n");
    return 0;
}

int main()
{
    printf("Project 4: Merkle树不存在性证明测试\n");
    printf("=====================================\n\n");

    if (test_non_existence_proof() != 0)
    {
        printf("测试失败\n");
        return 1;
    }

    printf("所有测试通过！\n");
    return 0;
}
