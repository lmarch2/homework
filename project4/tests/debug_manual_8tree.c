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
    printf("Debug: 手动构建8叶子树并分析结构\n");

    // 计算所有叶子哈希
    uint8_t leaf_hashes[8][32];
    for (int i = 0; i < 8; i++)
    {
        char data[16];
        snprintf(data, sizeof(data), "leaf_%d", i);
        merkle_compute_leaf_hash((uint8_t *)data, strlen(data), leaf_hashes[i]);
        char label[32];
        snprintf(label, sizeof(label), "叶子%d", i);
        print_hash(leaf_hashes[i], label);
    }
    printf("\n");

    // 手动构建树结构 (完美二叉树，8叶子)
    // 第1层：叶子两两配对
    uint8_t level1[4][32];
    merkle_compute_internal_hash(leaf_hashes[0], leaf_hashes[1], level1[0]); // 内部(0,1)
    merkle_compute_internal_hash(leaf_hashes[2], leaf_hashes[3], level1[1]); // 内部(2,3)
    merkle_compute_internal_hash(leaf_hashes[4], leaf_hashes[5], level1[2]); // 内部(4,5)
    merkle_compute_internal_hash(leaf_hashes[6], leaf_hashes[7], level1[3]); // 内部(6,7)

    print_hash(level1[0], "内部(0,1)");
    print_hash(level1[1], "内部(2,3)");
    print_hash(level1[2], "内部(4,5)");
    print_hash(level1[3], "内部(6,7)");
    printf("\n");

    // 第2层：4个内部节点两两配对
    uint8_t level2[2][32];
    merkle_compute_internal_hash(level1[0], level1[1], level2[0]); // 内部(0-3)
    merkle_compute_internal_hash(level1[2], level1[3], level2[1]); // 内部(4-7)

    print_hash(level2[0], "内部(0-3)");
    print_hash(level2[1], "内部(4-7)");
    printf("\n");

    // 第3层：根节点
    uint8_t root[32];
    merkle_compute_internal_hash(level2[0], level2[1], root);
    print_hash(root, "根节点");
    printf("\n");

    // 现在分析叶子1的手动审计路径
    printf("叶子1的手动审计路径分析：\n");
    printf("叶子1在内部(0,1)的右侧，需要叶子0作为左兄弟\n");
    printf("内部(0,1)在内部(0-3)的左侧，需要内部(2,3)作为右兄弟\n");
    printf("内部(0-3)在根的左侧，需要内部(4-7)作为右兄弟\n");

    printf("\n手动验证叶子1：\n");
    uint8_t step1[32], step2[32], step3[32];

    // 第1步：叶子1 + 叶子0 = 内部(0,1)
    merkle_compute_internal_hash(leaf_hashes[0], leaf_hashes[1], step1);
    print_hash(step1, "第1步: hash(叶子0, 叶子1)");
    printf("匹配内部(0,1): %s\n", memcmp(step1, level1[0], 32) == 0 ? "是" : "否");

    // 第2步：内部(0,1) + 内部(2,3) = 内部(0-3)
    merkle_compute_internal_hash(step1, level1[1], step2);
    print_hash(step2, "第2步: hash(内部(0,1), 内部(2,3))");
    printf("匹配内部(0-3): %s\n", memcmp(step2, level2[0], 32) == 0 ? "是" : "否");

    // 第3步：内部(0-3) + 内部(4-7) = 根
    merkle_compute_internal_hash(step2, level2[1], step3);
    print_hash(step3, "第3步: hash(内部(0-3), 内部(4-7))");
    printf("匹配根节点: %s\n", memcmp(step3, root, 32) == 0 ? "是" : "否");

    printf("\n所以叶子1的正确审计路径应该是：\n");
    printf("路径[0]: 叶子0哈希\n");
    printf("路径[1]: 内部(2,3)哈希\n");
    printf("路径[2]: 内部(4-7)哈希\n");

    // 与实际生成的证明比较
    printf("\n与实际证明比较：\n");
    merkle_tree_t *tree = merkle_tree_create();
    for (int i = 0; i < 8; i++)
    {
        char data[16];
        snprintf(data, sizeof(data), "leaf_%d", i);
        merkle_tree_add_leaf(tree, (uint8_t *)data, strlen(data));
    }
    merkle_tree_build(tree);

    audit_proof_t proof;
    merkle_generate_audit_proof(tree, 1, &proof);

    for (int i = 0; i < proof.path_len; i++)
    {
        char label[32];
        snprintf(label, sizeof(label), "实际路径[%d]", i);
        print_hash(proof.path[i], label);
    }

    printf("\n比较结果：\n");
    printf("实际路径[0] vs 叶子0: %s\n", memcmp(proof.path[0], leaf_hashes[0], 32) == 0 ? "匹配" : "不匹配");
    printf("实际路径[1] vs 内部(2,3): %s\n", memcmp(proof.path[1], level1[1], 32) == 0 ? "匹配" : "不匹配");
    printf("实际路径[2] vs 内部(4-7): %s\n", memcmp(proof.path[2], level2[1], 32) == 0 ? "匹配" : "不匹配");

    merkle_tree_destroy(tree);
    return 0;
}
