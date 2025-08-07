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

int main()
{
    printf("Debug: 路径使用顺序验证\n");

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
    printf("\n");

    // 测试叶子0的证明
    audit_proof_t proof;
    merkle_generate_audit_proof(tree, 0, &proof);

    printf("叶子0证明信息：\n");
    printf("  索引: %lu, 树大小: %lu, 路径长度: %d\n",
           proof.leaf_index, proof.tree_size, proof.path_len);

    print_hash(proof.leaf_hash, "叶子0哈希");
    for (int i = 0; i < proof.path_len; i++)
    {
        char label[32];
        snprintf(label, sizeof(label), "路径[%d]", i);
        print_hash(proof.path[i], label);
    }
    printf("\n");

    // 手动验证 - 使用从末尾开始的顺序
    printf("手动验证 (从路径末尾开始)：\n");
    uint8_t computed[32];
    memcpy(computed, proof.leaf_hash, 32);
    print_hash(computed, "初始 (叶子0)");

    uint64_t index = proof.leaf_index;
    uint64_t size = proof.tree_size;
    int path_idx = proof.path_len - 1;
    int step = 1;

    while (size > 1)
    {
        uint64_t k = 1;
        while (k < size)
            k <<= 1;
        k >>= 1;

        printf("\n第%d步：size=%lu, index=%lu, k=%lu\n", step, size, index, k);

        if (index < k)
        {
            printf("index(%lu) < k(%lu), 在左子树\n", index, k);
            printf("使用路径[%d]作为右兄弟\n", path_idx);
            merkle_compute_internal_hash(computed, proof.path[path_idx], computed);
            size = k;
        }
        else
        {
            printf("index(%lu) >= k(%lu), 在右子树\n", index, k);
            printf("使用路径[%d]作为左兄弟\n", path_idx);
            merkle_compute_internal_hash(proof.path[path_idx], computed, computed);
            index -= k;
            size = size - k;
        }

        path_idx--;
        char label[32];
        snprintf(label, sizeof(label), "第%d步结果", step);
        print_hash(computed, label);
        step++;
    }

    printf("\n最终验证结果：\n");
    int result = memcmp(computed, root_hash, 32);
    printf("验证: %s\n", result == 0 ? "成功" : "失败");

    if (result != 0)
    {
        print_hash(computed, "计算得到");
        print_hash(root_hash, "期望根哈希");
    }

    merkle_tree_destroy(tree);
    return 0;
}
