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
    printf("Debug: 重新分析叶子1的树结构\n");

    // 手动计算叶子哈希
    uint8_t leaf0_hash[32], leaf1_hash[32], leaf2_hash[32];
    merkle_compute_leaf_hash((uint8_t *)"leaf_1", strlen("leaf_1"), leaf0_hash);
    merkle_compute_leaf_hash((uint8_t *)"leaf_3", strlen("leaf_3"), leaf1_hash);
    merkle_compute_leaf_hash((uint8_t *)"leaf_5", strlen("leaf_5"), leaf2_hash);

    print_hash(leaf0_hash, "叶子0哈希");
    print_hash(leaf1_hash, "叶子1哈希");
    print_hash(leaf2_hash, "叶子2哈希");
    printf("\n");

    // 手动构建树结构
    uint8_t internal01[32]; // 叶子0和叶子1的父节点
    merkle_compute_internal_hash(leaf0_hash, leaf1_hash, internal01);
    print_hash(internal01, "内部节点(0,1)");

    uint8_t root[32]; // 根节点
    merkle_compute_internal_hash(internal01, leaf2_hash, root);
    print_hash(root, "根节点");
    printf("\n");

    // 现在分析叶子1的审计路径应该是什么
    printf("叶子1的审计路径分析：\n");
    printf("叶子1在内部节点(0,1)的右侧，需要左兄弟: 叶子0哈希\n");
    printf("内部节点(0,1)在根的左侧，需要右兄弟: 叶子2哈希\n");
    printf("\n");

    // 验证叶子1，使用正确的路径
    printf("手动验证叶子1 (使用正确理解的路径)：\n");

    // 第1步：叶子1 + 叶子0 (左兄弟) = 内部节点(0,1)
    uint8_t step1[32];
    merkle_compute_internal_hash(leaf0_hash, leaf1_hash, step1);
    print_hash(step1, "第1步: hash(叶子0, 叶子1)");

    // 第2步：内部节点(0,1) + 叶子2 (右兄弟) = 根
    uint8_t step2[32];
    merkle_compute_internal_hash(step1, leaf2_hash, step2);
    print_hash(step2, "第2步: hash(内部01, 叶子2)");

    printf("验证: %s\n", memcmp(step2, root, 32) == 0 ? "成功" : "失败");
    printf("\n");

    // 现在创建实际的树并检查
    merkle_tree_t *tree = merkle_tree_create();
    const char *data[] = {"leaf_1", "leaf_3", "leaf_5"};

    for (int i = 0; i < 3; i++)
    {
        merkle_tree_add_leaf(tree, (uint8_t *)data[i], strlen(data[i]));
    }
    merkle_tree_build(tree);

    uint8_t actual_root[32];
    merkle_get_root_hash(tree, actual_root);
    print_hash(actual_root, "实际根哈希");

    audit_proof_t proof;
    merkle_generate_audit_proof(tree, 1, &proof);

    printf("实际证明路径：\n");
    for (int i = 0; i < proof.path_len; i++)
    {
        char label[32];
        snprintf(label, sizeof(label), "路径[%d]", i);
        print_hash(proof.path[i], label);
    }

    merkle_tree_destroy(tree);
    return 0;
}
