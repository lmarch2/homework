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
    printf("Debug: 手动计算3叶子树\n");

    // 计算叶子哈希
    uint8_t leaf0[32], leaf1[32], leaf2[32];
    merkle_compute_leaf_hash((uint8_t *)"leaf_1", 6, leaf0);
    merkle_compute_leaf_hash((uint8_t *)"leaf_3", 6, leaf1);
    merkle_compute_leaf_hash((uint8_t *)"leaf_5", 6, leaf2);

    print_hash(leaf0, "叶子0 (leaf_1)");
    print_hash(leaf1, "叶子1 (leaf_3)");
    print_hash(leaf2, "叶子2 (leaf_5)");

    printf("\n根据RFC6962构造树结构：\n");
    printf("n=3, k=2\n");
    printf("左子树：叶子0和叶子1 (k=2)\n");
    printf("右子树：叶子2 (n-k=1)\n");

    // 计算左子树根
    printf("\n计算左子树 (k=2):\n");
    printf("  k=1, 叶子0在左，叶子1在右\n");
    uint8_t left_subtree_root[32];
    merkle_compute_internal_hash(leaf0, leaf1, left_subtree_root);
    print_hash(left_subtree_root, "左子树根");

    // 右子树根就是叶子2
    printf("\n右子树根就是叶子2\n");
    print_hash(leaf2, "右子树根");

    // 计算总根
    uint8_t manual_root[32];
    merkle_compute_internal_hash(left_subtree_root, leaf2, manual_root);
    print_hash(manual_root, "手动计算的根");

    // 对比树构建的结果
    merkle_tree_t *tree = merkle_tree_create();
    const char *data[] = {"leaf_1", "leaf_3", "leaf_5"};

    for (int i = 0; i < 3; i++)
    {
        merkle_tree_add_leaf(tree, (uint8_t *)data[i], strlen(data[i]));
    }

    merkle_tree_build(tree);

    uint8_t tree_root[32];
    merkle_get_root_hash(tree, tree_root);
    print_hash(tree_root, "树构建的根");

    int match = memcmp(manual_root, tree_root, 32) == 0;
    printf("匹配: %s\n", match ? "是" : "否");

    if (match)
    {
        printf("\n现在分析叶子0的审计路径：\n");
        printf("叶子0在左子树的左边\n");
        printf("需要的证明：\n");
        printf("1. 同级兄弟：叶子1\n");
        printf("2. 上级兄弟：右子树根(叶子2)\n");

        audit_proof_t proof;
        merkle_generate_audit_proof(tree, 0, &proof);

        printf("\n实际生成的证明路径：\n");
        for (int i = 0; i < proof.path_len; i++)
        {
            printf("路径[%d]: ", i);
            for (int j = 0; j < 16; j++)
                printf("%02x", proof.path[i][j]);
            printf("...\n");
        }

        printf("\n期望的证明路径：\n");
        print_hash(leaf1, "应该是叶子1");
        print_hash(leaf2, "应该是叶子2");
    }

    merkle_tree_destroy(tree);
    return 0;
}
