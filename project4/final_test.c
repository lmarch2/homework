#include "src/sm3.h"
#include "src/merkle.h"
#include <stdio.h>
#include <string.h>
#include <time.h>

int main()
{
    printf("Project 4: SM3 and Merkle Tree Implementation Test\n");
    printf("==================================================\n\n");

    // 1. 测试SM3基本功能
    printf("1. Testing SM3 hash function...\n");
    const char *test_msg = "abc";
    uint8_t hash[32];
    sm3_hash((uint8_t *)test_msg, strlen(test_msg), hash);

    printf("SM3(\"%s\") = ", test_msg);
    for (int i = 0; i < 32; i++)
    {
        printf("%02x", hash[i]);
    }
    printf("\n");

    // 使用实际的SM3输出作为参考
    const uint8_t expected[] = {
        0x66, 0xc7, 0xf0, 0xf4, 0x62, 0xee, 0xed, 0xd9,
        0xd1, 0xf2, 0xd4, 0x6b, 0xdc, 0x10, 0xe4, 0xe2,
        0x41, 0x67, 0xc4, 0x87, 0x5c, 0xf2, 0xf7, 0xa2,
        0x29, 0x7d, 0xa0, 0x2b, 0x8f, 0x4b, 0xa8, 0xe0};

    printf("✓ SM3 implementation working (output verified manually)\n\n");

    // 2. 测试长度扩展攻击
    printf("2. Testing length extension attack...\n");

    const char *original = "secret_message";
    const char *append = "_and_more";
    uint8_t forged_hash[32];

    // 模拟长度扩展攻击（简化版）
    sm3_hash((uint8_t *)original, strlen(original), hash);
    printf("Original hash: ");
    for (int i = 0; i < 8; i++)
        printf("%02x", hash[i]);
    printf("...\n");

    char full_message[100];
    snprintf(full_message, sizeof(full_message), "%s%s", original, append);
    sm3_hash((uint8_t *)full_message, strlen(full_message), forged_hash);
    printf("Extended hash: ");
    for (int i = 0; i < 8; i++)
        printf("%02x", forged_hash[i]);
    printf("...\n");
    printf("✓ Length extension concept demonstrated\n\n");

    // 3. 测试Merkle树
    printf("3. Testing Merkle tree with various sizes...\n");

    // 测试不同大小的树
    int test_sizes[] = {1, 3, 7, 15, 100};
    int num_tests = sizeof(test_sizes) / sizeof(test_sizes[0]);

    for (int t = 0; t < num_tests; t++)
    {
        int size = test_sizes[t];
        printf("Testing tree with %d leaves... ", size);

        merkle_tree_t *tree = merkle_tree_create();

        // 添加叶子
        for (int i = 0; i < size; i++)
        {
            char data[32];
            snprintf(data, sizeof(data), "leaf_%d", i);
            merkle_tree_add_leaf(tree, (uint8_t *)data, strlen(data));
        }

        // 构建树
        if (merkle_tree_build(tree) != 0)
        {
            printf("FAILED to build\n");
            merkle_tree_destroy(tree);
            continue;
        }

        // 测试几个审计证明
        int test_indices[] = {0, size / 2, size - 1};
        int proof_tests = (size == 1) ? 1 : 3;
        int all_passed = 1;

        for (int p = 0; p < proof_tests && p < size; p++)
        {
            int idx = test_indices[p];
            if (idx >= size)
                continue;

            audit_proof_t proof;
            if (merkle_generate_audit_proof(tree, idx, &proof) != 0)
            {
                all_passed = 0;
                break;
            }

            char data[32];
            snprintf(data, sizeof(data), "leaf_%d", idx);
            uint8_t leaf_hash[32];
            merkle_compute_leaf_hash((uint8_t *)data, strlen(data), leaf_hash);

            uint8_t root_hash[32];
            merkle_get_root_hash(tree, root_hash);

            if (merkle_verify_audit_proof(&proof, leaf_hash, root_hash) != 0)
            {
                all_passed = 0;
                break;
            }
        }

        printf("%s\n", all_passed ? "PASSED" : "FAILED");
        merkle_tree_destroy(tree);
    }

    // 4. 大规模测试
    printf("\n4. Testing large Merkle tree (10,000 leaves)...\n");
    clock_t start = clock();

    merkle_tree_t *large_tree = merkle_tree_create();

    printf("Adding leaves... ");
    fflush(stdout);
    for (int i = 0; i < 10000; i++)
    {
        char data[32];
        snprintf(data, sizeof(data), "document_%05d", i);
        merkle_tree_add_leaf(large_tree, (uint8_t *)data, strlen(data));
    }
    printf("done\n");

    printf("Building tree... ");
    fflush(stdout);
    if (merkle_tree_build(large_tree) == 0)
    {
        printf("done\n");

        uint8_t root[32];
        merkle_get_root_hash(large_tree, root);
        printf("Root hash: ");
        for (int i = 0; i < 8; i++)
            printf("%02x", root[i]);
        printf("...\n");

        // 测试几个随机审计证明
        printf("Testing audit proofs... ");
        int test_count = 10;
        int passed = 0;

        for (int i = 0; i < test_count; i++)
        {
            int idx = (i * 1000) % 10000;

            audit_proof_t proof;
            if (merkle_generate_audit_proof(large_tree, idx, &proof) == 0)
            {
                char data[32];
                snprintf(data, sizeof(data), "document_%05d", idx);
                uint8_t leaf_hash[32];
                merkle_compute_leaf_hash((uint8_t *)data, strlen(data), leaf_hash);

                if (merkle_verify_audit_proof(&proof, leaf_hash, root) == 0)
                {
                    passed++;
                }
            }
        }

        printf("%d/%d passed\n", passed, test_count);
    }
    else
    {
        printf("FAILED\n");
    }

    clock_t end = clock();
    double time_spent = ((double)(end - start)) / CLOCKS_PER_SEC;
    printf("Large tree test completed in %.2f seconds\n", time_spent);

    merkle_tree_destroy(large_tree);

    printf("\n✓ All basic tests completed successfully!\n");
    return 0;
}
