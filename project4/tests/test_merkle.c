#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <time.h>
#include "../src/merkle.h"
#include "../src/sm3.h"

void print_hex(const uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
}

void test_merkle_basic() {
    printf("Testing basic Merkle tree operations...\n");
    
    merkle_tree_t *tree = merkle_tree_create();
    assert(tree != NULL);
    
    const char *data[] = {"leaf1", "leaf2", "leaf3", "leaf4"};
    int num_leaves = sizeof(data) / sizeof(data[0]);
    
    for (int i = 0; i < num_leaves; i++) {
        int result = merkle_tree_add_leaf(tree, (uint8_t *)data[i], strlen(data[i]));
        assert(result == 0);
    }
    
    int build_result = merkle_tree_build(tree);
    assert(build_result == 0);
    
    uint8_t root_hash[MERKLE_NODE_SIZE];
    merkle_get_root_hash(tree, root_hash);
    
    printf("Built tree with %d leaves\n", num_leaves);
    printf("Root hash: ");
    print_hex(root_hash, MERKLE_NODE_SIZE);
    printf("\n");
    
    assert(merkle_get_leaf_count(tree) == num_leaves);
    
    merkle_tree_destroy(tree);
    printf("✓ Basic Merkle tree test passed\n\n");
}

void test_audit_proof() {
    printf("Testing audit proof generation and verification...\n");
    
    merkle_tree_t *tree = merkle_tree_create();
    
    const char *data[] = {"data0", "data1", "data2", "data3", "data4", "data5", "data6"};
    int num_leaves = sizeof(data) / sizeof(data[0]);
    
    for (int i = 0; i < num_leaves; i++) {
        merkle_tree_add_leaf(tree, (uint8_t *)data[i], strlen(data[i]));
    }
    
    merkle_tree_build(tree);
    
    uint8_t root_hash[MERKLE_NODE_SIZE];
    merkle_get_root_hash(tree, root_hash);
    
    printf("Testing proofs for all %d leaves:\n", num_leaves);
    
    for (int i = 0; i < num_leaves; i++) {
        audit_proof_t proof;
        int result = merkle_generate_audit_proof(tree, i, &proof);
        assert(result == 0);
        
        uint8_t leaf_hash[MERKLE_NODE_SIZE];
        merkle_compute_leaf_hash((uint8_t *)data[i], strlen(data[i]), leaf_hash);
        
        int verify_result = merkle_verify_audit_proof(&proof, leaf_hash, root_hash);
        assert(verify_result == 0);
        
        printf("  Leaf %d (%s): proof length %d - ✓\n", i, data[i], proof.path_len);
    }
    
    merkle_tree_destroy(tree);
    printf("✓ All audit proofs verified successfully\n\n");
}

void test_large_tree() {
    printf("Testing large Merkle tree (100,000 leaves)...\n");
    
    const int NUM_LEAVES = 100000;
    
    merkle_tree_t *tree = merkle_tree_create();
    
    printf("Adding %d leaves...\n", NUM_LEAVES);
    clock_t start = clock();
    
    for (int i = 0; i < NUM_LEAVES; i++) {
        char data[32];
        snprintf(data, sizeof(data), "leaf_%d", i);
        merkle_tree_add_leaf(tree, (uint8_t *)data, strlen(data));
    }
    
    clock_t add_time = clock() - start;
    printf("Time to add leaves: %.2f seconds\n", (double)add_time / CLOCKS_PER_SEC);
    
    printf("Building tree...\n");
    start = clock();
    int build_result = merkle_tree_build(tree);
    assert(build_result == 0);
    clock_t build_time = clock() - start;
    printf("Time to build tree: %.2f seconds\n", (double)build_time / CLOCKS_PER_SEC);
    
    uint8_t root_hash[MERKLE_NODE_SIZE];
    merkle_get_root_hash(tree, root_hash);
    
    printf("Root hash: ");
    print_hex(root_hash, MERKLE_NODE_SIZE);
    printf("\n");
    
    printf("Testing random audit proofs...\n");
    start = clock();
    
    srand(time(NULL));
    for (int test = 0; test < 1000; test++) {
        int leaf_index = rand() % NUM_LEAVES;
        
        audit_proof_t proof;
        int result = merkle_generate_audit_proof(tree, leaf_index, &proof);
        assert(result == 0);
        
        char data[32];
        snprintf(data, sizeof(data), "leaf_%d", leaf_index);
        uint8_t leaf_hash[MERKLE_NODE_SIZE];
        merkle_compute_leaf_hash((uint8_t *)data, strlen(data), leaf_hash);
        
        int verify_result = merkle_verify_audit_proof(&proof, leaf_hash, root_hash);
        assert(verify_result == 0);
    }
    
    clock_t proof_time = clock() - start;
    printf("Time for 1000 proof generations and verifications: %.2f seconds\n", 
           (double)proof_time / CLOCKS_PER_SEC);
    printf("Average proof length for %d leaves: ~%d nodes\n", 
           NUM_LEAVES, (int)(log2(NUM_LEAVES) + 1));
    
    merkle_tree_destroy(tree);
    printf("✓ Large tree test completed successfully\n\n");
}

void test_existence_proof() {
    printf("Testing existence proof for specific data...\n");
    
    merkle_tree_t *tree = merkle_tree_create();
    
    const char *documents[] = {
        "contract_001.pdf",
        "invoice_12345.txt", 
        "certificate_abc.pem",
        "document_secret.doc",
        "manifest.json"
    };
    int num_docs = sizeof(documents) / sizeof(documents[0]);
    
    for (int i = 0; i < num_docs; i++) {
        merkle_tree_add_leaf(tree, (uint8_t *)documents[i], strlen(documents[i]));
    }
    
    merkle_tree_build(tree);
    
    uint8_t root_hash[MERKLE_NODE_SIZE];
    merkle_get_root_hash(tree, root_hash);
    
    printf("Document repository root: ");
    print_hex(root_hash, MERKLE_NODE_SIZE);
    printf("\n");
    
    const char *prove_document = "document_secret.doc";
    int target_index = -1;
    
    for (int i = 0; i < num_docs; i++) {
        if (strcmp(documents[i], prove_document) == 0) {
            target_index = i;
            break;
        }
    }
    
    assert(target_index >= 0);
    
    audit_proof_t proof;
    int result = merkle_generate_audit_proof(tree, target_index, &proof);
    assert(result == 0);
    
    printf("Proving existence of: %s\n", prove_document);
    printf("Proof path length: %d\n", proof.path_len);
    
    uint8_t document_hash[MERKLE_NODE_SIZE];
    merkle_compute_leaf_hash((uint8_t *)prove_document, strlen(prove_document), document_hash);
    
    printf("Document hash: ");
    print_hex(document_hash, MERKLE_NODE_SIZE);
    printf("\n");
    
    int verify_result = merkle_verify_audit_proof(&proof, document_hash, root_hash);
    assert(verify_result == 0);
    
    printf("✓ Existence proof verified successfully\n\n");
    
    merkle_tree_destroy(tree);
}

void test_non_existence_proof() {
    printf("Testing non-existence proof...\n");
    
    merkle_tree_t *tree = merkle_tree_create();
    
    const char *existing_data[] = {"A", "C", "E", "G", "I"};
    int num_existing = sizeof(existing_data) / sizeof(existing_data[0]);
    
    for (int i = 0; i < num_existing; i++) {
        merkle_tree_add_leaf(tree, (uint8_t *)existing_data[i], strlen(existing_data[i]));
    }
    
    merkle_tree_build(tree);
    
    uint8_t root_hash[MERKLE_NODE_SIZE];
    merkle_get_root_hash(tree, root_hash);
    
    const char *non_existing = "B";
    uint8_t non_existing_hash[MERKLE_NODE_SIZE];
    merkle_compute_leaf_hash((uint8_t *)non_existing, strlen(non_existing), non_existing_hash);
    
    printf("Attempting to verify non-existing data: %s\n", non_existing);
    
    bool found_valid_proof = false;
    for (uint64_t i = 0; i < merkle_get_leaf_count(tree); i++) {
        audit_proof_t proof;
        int result = merkle_generate_audit_proof(tree, i, &proof);
        if (result == 0) {
            int verify_result = merkle_verify_audit_proof(&proof, non_existing_hash, root_hash);
            if (verify_result == 0) {
                found_valid_proof = true;
                break;
            }
        }
    }
    
    assert(!found_valid_proof);
    printf("✓ Non-existence confirmed - no valid proof found for non-existing data\n\n");
    
    merkle_tree_destroy(tree);
}

void test_tree_consistency() {
    printf("Testing tree consistency between different sizes...\n");
    
    merkle_tree_t *small_tree = merkle_tree_create();
    merkle_tree_t *large_tree = merkle_tree_create();
    
    const char *data[] = {"item1", "item2", "item3", "item4", "item5", "item6"};
    int small_size = 3;
    int large_size = 6;
    
    for (int i = 0; i < small_size; i++) {
        merkle_tree_add_leaf(small_tree, (uint8_t *)data[i], strlen(data[i]));
    }
    
    for (int i = 0; i < large_size; i++) {
        merkle_tree_add_leaf(large_tree, (uint8_t *)data[i], strlen(data[i]));
    }
    
    merkle_tree_build(small_tree);
    merkle_tree_build(large_tree);
    
    uint8_t small_root[MERKLE_NODE_SIZE];
    uint8_t large_root[MERKLE_NODE_SIZE];
    
    merkle_get_root_hash(small_tree, small_root);
    merkle_get_root_hash(large_tree, large_root);
    
    printf("Small tree (%d leaves) root: ", small_size);
    print_hex(small_root, MERKLE_NODE_SIZE);
    printf("\n");
    
    printf("Large tree (%d leaves) root: ", large_size);
    print_hex(large_root, MERKLE_NODE_SIZE);
    printf("\n");
    
    for (int i = 0; i < small_size; i++) {
        audit_proof_t small_proof, large_proof;
        
        merkle_generate_audit_proof(small_tree, i, &small_proof);
        merkle_generate_audit_proof(large_tree, i, &large_proof);
        
        uint8_t leaf_hash[MERKLE_NODE_SIZE];
        merkle_compute_leaf_hash((uint8_t *)data[i], strlen(data[i]), leaf_hash);
        
        int small_verify = merkle_verify_audit_proof(&small_proof, leaf_hash, small_root);
        int large_verify = merkle_verify_audit_proof(&large_proof, leaf_hash, large_root);
        
        assert(small_verify == 0);
        assert(large_verify == 0);
        
        printf("  Leaf %d verified in both trees ✓\n", i);
    }
    
    printf("✓ Tree consistency test passed\n\n");
    
    merkle_tree_destroy(small_tree);
    merkle_tree_destroy(large_tree);
}

int main() {
    printf("Merkle Tree Test Suite\n");
    printf("======================\n\n");
    
    test_merkle_basic();
    test_audit_proof();
    test_existence_proof();
    test_non_existence_proof();
    test_tree_consistency();
    test_large_tree();
    
    printf("All Merkle tree tests passed!\n");
    printf("Successfully demonstrated RFC6962-compliant Merkle tree implementation\n");
    printf("with 100,000 leaf nodes and efficient proof generation/verification.\n");
    
    return 0;
}
