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

void debug_leaf_verification(merkle_tree_t *tree, uint64_t leaf_idx, const uint8_t *root_hash)
{
    printf("\n=== 调试叶子%lu ===\n", leaf_idx);

    audit_proof_t proof;
    int gen_result = merkle_generate_audit_proof(tree, leaf_idx, &proof);

    if (gen_result != 0)
    {
        printf("证明生成失败\n");
        return;
    }

    printf("证明信息: 索引=%lu, 树大小=%lu, 路径长度=%d\n",
           proof.leaf_index, proof.tree_size, proof.path_len);

    print_hash(proof.leaf_hash, "叶子哈希");
    for (int i = 0; i < proof.path_len; i++)
    {
        char label[32];
        snprintf(label, sizeof(label), "路径[%d]", i);
        print_hash(proof.path[i], label);
    }

    // 手动验证过程
    printf("\n手动验证过程：\n");
    uint8_t computed[32];
    memcpy(computed, proof.leaf_hash, 32);
    print_hash(computed, "初始");

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

        printf("\n第%d步: size=%lu, index=%lu, k=%lu\n", step, size, index, k);

        if (index < k)
        {
            printf("  index < k: 在左半部分，使用路径[%d]作为右兄弟\n", path_idx);
            printf("  计算: hash(当前, 路径[%d])\n", path_idx);
            merkle_compute_internal_hash(computed, proof.path[path_idx], computed);
            size = k;
        }
        else
        {
            printf("  index >= k: 在右半部分，使用路径[%d]作为左兄弟\n", path_idx);
            printf("  计算: hash(路径[%d], 当前)\n", path_idx);
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

    int verify_result = memcmp(computed, root_hash, 32);
    printf("\n验证结果: %s\n", verify_result == 0 ? "成功" : "失败");

    if (verify_result != 0)
    {
        print_hash(computed, "计算结果");
        print_hash(root_hash, "期望根哈希");
    }
}

int main()
{
    printf("Debug: 详细分析8叶子树的验证过程\n");

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
    print_hash(root_hash, "8叶子树根哈希");

    // 详细分析几个失败的叶子
    debug_leaf_verification(tree, 1, root_hash);
    debug_leaf_verification(tree, 3, root_hash);

    merkle_tree_destroy(tree);
    return 0;
}
