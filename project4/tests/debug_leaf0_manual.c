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
    printf("Debug: 手动验证叶子0\n");

    merkle_tree_t *tree = merkle_tree_create();
    const char *data[] = {"leaf_1", "leaf_3", "leaf_5"};

    for (int i = 0; i < 3; i++)
    {
        merkle_tree_add_leaf(tree, (uint8_t *)data[i], strlen(data[i]));
    }

    merkle_tree_build(tree);

    audit_proof_t proof;
    merkle_generate_audit_proof(tree, 0, &proof);

    uint8_t root_hash[32];
    merkle_get_root_hash(tree, root_hash);

    printf("叶子0证明信息：\n");
    printf("  索引: %lu, 树大小: %lu, 路径长度: %d\n",
           proof.leaf_index, proof.tree_size, proof.path_len);

    print_hash(proof.leaf_hash, "叶子0哈希");
    for (int i = 0; i < proof.path_len; i++)
    {
        printf("路径[%d]: ", i);
        for (int j = 0; j < 16; j++)
            printf("%02x", proof.path[i][j]);
        printf("...\n");
    }
    print_hash(root_hash, "根哈希");

    printf("\n手动验证过程：\n");
    uint8_t computed[32];
    memcpy(computed, proof.leaf_hash, 32);
    print_hash(computed, "初始 (叶子0)");

    uint64_t index = 0;
    uint64_t size = 3;
    int path_idx = proof.path_len - 1;

    printf("\n第1步：size=3, index=0, k=2\n");
    printf("index(0) < k(2), 在左子树\n");
    printf("使用路径[%d]作为右兄弟\n", path_idx);
    merkle_compute_internal_hash(computed, proof.path[path_idx], computed);
    print_hash(computed, "第1步结果");
    path_idx--;
    size = 2;

    printf("\n第2步：size=2, index=0, k=1\n");
    printf("index(0) < k(1), 在左子树\n");
    printf("使用路径[%d]作为右兄弟\n", path_idx);
    merkle_compute_internal_hash(computed, proof.path[path_idx], computed);
    print_hash(computed, "第2步结果 (应该是根)");

    int match = memcmp(computed, root_hash, 32) == 0;
    printf("\n最终验证: %s\n", match ? "成功" : "失败");

    merkle_tree_destroy(tree);
    return 0;
}
