#include "../src/sm3.h"
#include "../src/merkle.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main()
{
    printf("Debug: 测试更大的树\n");

    merkle_tree_t *tree = merkle_tree_create();

    // 添加8个叶子
    for (int i = 0; i < 8; i++)
    {
        char data[16];
        snprintf(data, sizeof(data), "leaf_%d", i);
        merkle_tree_add_leaf(tree, (uint8_t *)data, strlen(data));
    }

    merkle_tree_build(tree);

    uint8_t root_hash[32];
    merkle_get_root_hash(tree, root_hash);

    printf("8叶子树根哈希: ");
    for (int i = 0; i < 16; i++)
        printf("%02x", root_hash[i]);
    printf("...\n\n");

    // 测试每个叶子的审计证明
    int success_count = 0;
    for (uint64_t i = 0; i < 8; i++)
    {
        audit_proof_t proof;
        int gen_result = merkle_generate_audit_proof(tree, i, &proof);

        if (gen_result == 0)
        {
            int verify_result = merkle_verify_audit_proof(&proof, proof.leaf_hash, root_hash);

            printf("叶子%lu: 生成=%s, 验证=%s, 路径长度=%d\n",
                   i,
                   gen_result == 0 ? "成功" : "失败",
                   verify_result == 0 ? "成功" : "失败",
                   proof.path_len);

            if (verify_result == 0)
                success_count++;
        }
    }

    printf("\n总结: %d/8 个叶子验证成功\n", success_count);

    merkle_tree_destroy(tree);
    return 0;
}
