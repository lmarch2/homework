#include "../src/sm3.h"
#include "../src/merkle.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main()
{
    printf("Project 4: 全面Merkle树测试\n");
    printf("===============================\n\n");

    // 测试不同大小的树
    int tree_sizes[] = {1, 2, 3, 4, 5, 7, 8, 15, 16, 31, 32};
    int num_sizes = sizeof(tree_sizes) / sizeof(tree_sizes[0]);

    for (int s = 0; s < num_sizes; s++)
    {
        int size = tree_sizes[s];
        printf("测试 %d 叶子树:\n", size);

        merkle_tree_t *tree = merkle_tree_create();

        // 添加叶子
        for (int i = 0; i < size; i++)
        {
            char data[32];
            snprintf(data, sizeof(data), "document_%03d", i);
            merkle_tree_add_leaf(tree, (uint8_t *)data, strlen(data));
        }

        merkle_tree_build(tree);

        uint8_t root_hash[32];
        merkle_get_root_hash(tree, root_hash);

        // 测试每个叶子的审计证明
        int success_count = 0;
        for (uint64_t i = 0; i < size; i++)
        {
            audit_proof_t proof;
            int gen_result = merkle_generate_audit_proof(tree, i, &proof);

            if (gen_result == 0)
            {
                int verify_result = merkle_verify_audit_proof(&proof, proof.leaf_hash, root_hash);
                if (verify_result == 0)
                {
                    success_count++;
                }
            }
        }

        printf("  验证结果: %d/%d 叶子成功 %s\n",
               success_count, size,
               success_count == size ? "✓" : "✗");

        merkle_tree_destroy(tree);

        if (success_count != size)
        {
            printf("  错误: 大小 %d 的树验证失败\n", size);
            break;
        }
    }

    printf("\n=== Merkle树审计证明测试完成 ===\n");
    return 0;
}
