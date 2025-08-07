#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "src/merkle.h"
#include "src/sm3.h"

void print_hex(const uint8_t *data, size_t len)
{
    for (size_t i = 0; i < len; i++)
    {
        printf("%02x", data[i]);
    }
    printf("\n");
}

int main()
{
    merkle_tree_t *tree = merkle_tree_create();

    const char *data[] = {"A", "B", "C"};
    int num_leaves = 3;

    for (int i = 0; i < num_leaves; i++)
    {
        merkle_tree_add_leaf(tree, (uint8_t *)data[i], strlen(data[i]));
    }

    merkle_tree_build(tree);

    uint8_t root_hash[MERKLE_NODE_SIZE];
    merkle_get_root_hash(tree, root_hash);

    printf("Root hash: ");
    print_hex(root_hash, MERKLE_NODE_SIZE);

    for (int i = 0; i < num_leaves; i++)
    {
        audit_proof_t proof;
        int result = merkle_generate_audit_proof(tree, i, &proof);
        printf("Leaf %d (%s): proof generation result = %d, path_len = %d\n",
               i, data[i], result, proof.path_len);

        if (result == 0)
        {
            uint8_t leaf_hash[MERKLE_NODE_SIZE];
            merkle_compute_leaf_hash((uint8_t *)data[i], strlen(data[i]), leaf_hash);

            printf("  Leaf hash: ");
            print_hex(leaf_hash, MERKLE_NODE_SIZE);

            printf("  Proof path:\n");
            for (int j = 0; j < proof.path_len; j++)
            {
                printf("    [%d]: ", j);
                print_hex(proof.path[j], MERKLE_NODE_SIZE);
            }

            int verify_result = merkle_verify_audit_proof(&proof, leaf_hash, root_hash);
            printf("  Verification result: %d\n", verify_result);
        }
        printf("\n");
    }

    merkle_tree_destroy(tree);
    return 0;
}
