#include "../src/sm3.h"
#include "../src/merkle.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main()
{
    printf("Debug: 基础审计证明验证\n");

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

    printf("树根哈希: ");
    for (int i = 0; i < 16; i++)
        printf("%02x", root_hash[i]);
    printf("...\n\n");

    // 测试每个叶子的审计证明
    for (int i = 0; i < 3; i++)
    {
        printf("测试叶子%d (%s):\n", i, data[i]);

        audit_proof_t proof;
        int gen_result = merkle_generate_audit_proof(tree, i, &proof);

        printf("  证明生成: %s\n", gen_result == 0 ? "成功" : "失败");
        printf("  证明路径长度: %d\n", proof.path_len);

        if (gen_result == 0)
        {
            // 验证证明
            int verify_result = merkle_verify_audit_proof(&proof, proof.leaf_hash, root_hash);
            printf("  证明验证: %s\n", verify_result == 0 ? "成功" : "失败");

            // 手动验证叶子哈希
            uint8_t expected_hash[32];
            merkle_compute_leaf_hash((uint8_t *)data[i], strlen(data[i]), expected_hash);

            int hash_match = memcmp(proof.leaf_hash, expected_hash, 32) == 0;
            printf("  叶子哈希匹配: %s\n", hash_match ? "是" : "否");

            if (!hash_match)
            {
                printf("    证明中的哈希: ");
                for (int j = 0; j < 16; j++)
                    printf("%02x", proof.leaf_hash[j]);
                printf("...\n");
                printf("    期望的哈希: ");
                for (int j = 0; j < 16; j++)
                    printf("%02x", expected_hash[j]);
                printf("...\n");
            }
        }
        printf("\n");
    }

    merkle_tree_destroy(tree);
    return 0;
}
