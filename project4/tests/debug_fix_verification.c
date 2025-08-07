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
    printf("Debug: 修正验证算法中的哈希计算顺序\n");

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
    print_hash(proof.leaf_hash, "叶子1哈希");
    for (int i = 0; i < proof.path_len; i++)
    {
        char label[32];
        snprintf(label, sizeof(label), "路径[%d]", i);
        print_hash(proof.path[i], label);
    }

    // 修正的验证过程
    printf("\n修正的验证过程：\n");
    uint8_t computed[32];
    memcpy(computed, proof.leaf_hash, 32);

    uint64_t index = proof.leaf_index;
    uint64_t size = proof.tree_size;
    int path_idx = proof.path_len - 1;

    // 第1步：size=3, index=1, k=2
    // index < k，在左子树，需要右兄弟
    printf("第1步: size=%lu, index=%lu, k=2\n", size, index);
    printf("  在左子树，使用路径[%d]作为右兄弟\n", path_idx);
    merkle_compute_internal_hash(computed, proof.path[path_idx], computed);
    print_hash(computed, "第1步结果");

    // 更新状态
    size = 2; // k
    path_idx--;

    // 第2步：size=2, index=1, k=1
    // index >= k，在右子树，需要左兄弟
    printf("\n第2步: size=%lu, index=%lu, k=1\n", size, index);
    printf("  在右子树，使用路径[%d]作为左兄弟\n", path_idx);

    // 但是这里有个问题：在大小为2的子树中，如果index=1表示在右侧
    // 那么我们需要确保哈希计算时左右顺序正确
    // 我们有：叶子1(右)和叶子0(左)，应该计算hash(叶子0, 叶子1)
    merkle_compute_internal_hash(proof.path[path_idx], computed, computed);
    print_hash(computed, "第2步结果");

    printf("\n最终验证: %s\n", memcmp(computed, root_hash, 32) == 0 ? "成功" : "失败");

    // 对比：如果第1步计算顺序错误会怎样
    printf("\n如果第1步计算顺序错误：\n");
    uint8_t wrong_computed[32];
    memcpy(wrong_computed, proof.leaf_hash, 32);

    // 错误的第1步：hash(右兄弟, 当前) 而不是 hash(当前, 右兄弟)
    merkle_compute_internal_hash(proof.path[1], wrong_computed, wrong_computed);
    print_hash(wrong_computed, "错误第1步结果");

    merkle_compute_internal_hash(proof.path[0], wrong_computed, wrong_computed);
    print_hash(wrong_computed, "错误第2步结果");

    printf("错误验证: %s\n", memcmp(wrong_computed, root_hash, 32) == 0 ? "成功" : "失败");

    merkle_tree_destroy(tree);
    return 0;
}
