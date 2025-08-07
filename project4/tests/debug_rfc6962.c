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
    printf("Debug: RFC6962算法步骤分析\n");

    merkle_tree_t *tree = merkle_tree_create();
    const char *data[] = {"leaf_1", "leaf_3", "leaf_5"};

    for (int i = 0; i < 3; i++)
    {
        merkle_tree_add_leaf(tree, (uint8_t *)data[i], strlen(data[i]));
    }
    merkle_tree_build(tree);

    uint8_t root_hash[32];
    merkle_get_root_hash(tree, root_hash);
    print_hash(root_hash, "树根哈希");

    // 获取叶子1的证明
    audit_proof_t proof;
    merkle_generate_audit_proof(tree, 1, &proof);

    printf("\n叶子1证明：\n");
    printf("索引: %lu, 树大小: %lu\n", proof.leaf_index, proof.tree_size);
    print_hash(proof.leaf_hash, "叶子1哈希");
    for (int i = 0; i < proof.path_len; i++)
    {
        char label[32];
        snprintf(label, sizeof(label), "路径[%d]", i);
        print_hash(proof.path[i], label);
    }

    // 按照RFC6962算法精确模拟
    printf("\nRFC6962验证过程：\n");
    uint8_t computed[32];
    memcpy(computed, proof.leaf_hash, 32);

    uint64_t index = proof.leaf_index; // 1
    uint64_t size = proof.tree_size;   // 3
    int path_idx = proof.path_len - 1; // 1

    printf("初始: index=%lu, size=%lu, path_idx=%d\n", index, size, path_idx);
    print_hash(computed, "computed");

    int step = 1;
    while (size > 1)
    {
        // 计算k
        uint64_t k = 1;
        while (k < size)
            k <<= 1;
        k >>= 1;

        printf("\n第%d步: size=%lu, index=%lu, k=%lu\n", step, size, index, k);

        if (index < k)
        {
            printf("  index(%lu) < k(%lu) -> 在左子树\n", index, k);
            printf("  需要右兄弟，使用路径[%d]\n", path_idx);
            printf("  hash(computed, 路径[%d])\n", path_idx);
            merkle_compute_internal_hash(computed, proof.path[path_idx], computed);
            size = k;
            // index不变
        }
        else
        {
            printf("  index(%lu) >= k(%lu) -> 在右子树\n", index, k);
            printf("  需要左兄弟，使用路径[%d]\n", path_idx);
            printf("  hash(路径[%d], computed)\n", path_idx);
            merkle_compute_internal_hash(proof.path[path_idx], computed, computed);
            index -= k;
            size = size - k;
        }

        path_idx--;
        printf("  新状态: index=%lu, size=%lu, path_idx=%d\n", index, size, path_idx);
        print_hash(computed, "  computed");
        step++;
    }

    printf("\n最终验证: %s\n", memcmp(computed, root_hash, 32) == 0 ? "成功" : "失败");

    merkle_tree_destroy(tree);
    return 0;
}
