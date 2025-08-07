#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include "../src/sm3.h"

void print_hex(const uint8_t *data, size_t len)
{
    for (size_t i = 0; i < len; i++)
    {
        printf("%02x", data[i]);
    }
}

void test_length_extension_basic()
{
    printf("Testing basic length extension attack...\n");

    const char *secret = "secret_key";
    const char *original_msg = "original_message";
    const char *append_msg = "malicious_append";

    printf("Secret: %s\n", secret);
    printf("Original message: %s\n", original_msg);
    printf("Append message: %s\n", append_msg);

    int result = verify_length_extension_attack(secret, original_msg, append_msg);

    if (result == 0)
    {
        printf("✓ Length extension attack successful!\n\n");
    }
    else
    {
        printf("✗ Length extension attack failed!\n\n");
        assert(0);
    }
}

void test_length_extension_detailed()
{
    printf("Testing detailed length extension attack process...\n");

    const char *secret = "my_secret_key";
    const char *original_msg = "authenticate_this_message";
    const char *append_msg = "admin=true&balance=999999";

    size_t secret_len = strlen(secret);
    size_t original_msg_len = strlen(original_msg);
    size_t total_original_len = secret_len + original_msg_len;

    char *full_original = malloc(total_original_len);
    memcpy(full_original, secret, secret_len);
    memcpy(full_original + secret_len, original_msg, original_msg_len);

    uint8_t original_hash[SM3_DIGEST_SIZE];
    sm3_hash((uint8_t *)full_original, total_original_len, original_hash);

    printf("Original message: %s\n", original_msg);
    printf("Original hash: ");
    print_hex(original_hash, SM3_DIGEST_SIZE);
    printf("\n");

    uint8_t *extended_message;
    size_t extended_len;
    uint8_t new_hash[SM3_DIGEST_SIZE];

    int attack_result = sm3_length_extension_attack(
        original_hash,
        total_original_len,
        (uint8_t *)append_msg,
        strlen(append_msg),
        new_hash,
        &extended_message,
        &extended_len);

    assert(attack_result == 0);

    printf("Extended message (hex): ");
    print_hex(extended_message, extended_len);
    printf("\n");

    printf("New hash from attack: ");
    print_hex(new_hash, SM3_DIGEST_SIZE);
    printf("\n");

    size_t final_msg_len = total_original_len + extended_len;
    char *final_message = malloc(final_msg_len);
    memcpy(final_message, full_original, total_original_len);
    memcpy(final_message + total_original_len, extended_message, extended_len);

    uint8_t expected_hash[SM3_DIGEST_SIZE];
    sm3_hash((uint8_t *)final_message, final_msg_len, expected_hash);

    printf("Expected hash:        ");
    print_hex(expected_hash, SM3_DIGEST_SIZE);
    printf("\n");

    assert(memcmp(new_hash, expected_hash, SM3_DIGEST_SIZE) == 0);
    printf("✓ Hashes match - attack successful!\n\n");

    free(full_original);
    free(extended_message);
    free(final_message);
}

void test_authentication_bypass()
{
    printf("Testing authentication bypass scenario...\n");

    const char *secret = "server_secret_2024";
    const char *user_data = "user=guest&role=user&permissions=read";
    const char *malicious_append = "&role=admin&permissions=all";

    size_t secret_len = strlen(secret);
    size_t user_data_len = strlen(user_data);
    size_t total_len = secret_len + user_data_len;

    char *original_message = malloc(total_len);
    memcpy(original_message, secret, secret_len);
    memcpy(original_message + secret_len, user_data, user_data_len);

    uint8_t legitimate_mac[SM3_DIGEST_SIZE];
    sm3_hash((uint8_t *)original_message, total_len, legitimate_mac);

    printf("Legitimate user data: %s\n", user_data);
    printf("Legitimate MAC: ");
    print_hex(legitimate_mac, SM3_DIGEST_SIZE);
    printf("\n");

    uint8_t *forged_padding;
    size_t padding_len;
    uint8_t forged_mac[SM3_DIGEST_SIZE];

    int result = sm3_length_extension_attack(
        legitimate_mac,
        total_len,
        (uint8_t *)malicious_append,
        strlen(malicious_append),
        forged_mac,
        &forged_padding,
        &padding_len);

    assert(result == 0);

    printf("Forged MAC: ");
    print_hex(forged_mac, SM3_DIGEST_SIZE);
    printf("\n");

    printf("Forged message contains: %s", user_data);
    printf("[PADDING]");
    printf("%s\n", malicious_append);

    size_t final_len = total_len + padding_len;
    char *final_forged = malloc(final_len);
    memcpy(final_forged, original_message, total_len);
    memcpy(final_forged + total_len, forged_padding, padding_len);

    uint8_t verification_hash[SM3_DIGEST_SIZE];
    sm3_hash((uint8_t *)final_forged, final_len, verification_hash);

    assert(memcmp(forged_mac, verification_hash, SM3_DIGEST_SIZE) == 0);
    printf("✓ Authentication bypass successful!\n\n");

    free(original_message);
    free(forged_padding);
    free(final_forged);
}

void test_multiple_extensions()
{
    printf("Testing multiple length extensions...\n");

    const char *secret = "base_key";
    const char *msg1 = "step1";
    const char *msg2 = "step2";
    const char *msg3 = "step3";

    size_t secret_len = strlen(secret);

    char *current_msg = malloc(secret_len + strlen(msg1));
    memcpy(current_msg, secret, secret_len);
    memcpy(current_msg + secret_len, msg1, strlen(msg1));
    size_t current_len = secret_len + strlen(msg1);

    uint8_t hash1[SM3_DIGEST_SIZE];
    sm3_hash((uint8_t *)current_msg, current_len, hash1);

    printf("After step 1: ");
    print_hex(hash1, SM3_DIGEST_SIZE);
    printf("\n");

    uint8_t *ext1;
    size_t ext1_len;
    uint8_t hash2[SM3_DIGEST_SIZE];

    sm3_length_extension_attack(hash1, current_len, (uint8_t *)msg2, strlen(msg2),
                                hash2, &ext1, &ext1_len);

    printf("After step 2: ");
    print_hex(hash2, SM3_DIGEST_SIZE);
    printf("\n");

    uint8_t *ext2;
    size_t ext2_len;
    uint8_t hash3[SM3_DIGEST_SIZE];

    sm3_length_extension_attack(hash2, current_len + ext1_len, (uint8_t *)msg3, strlen(msg3),
                                hash3, &ext2, &ext2_len);

    printf("After step 3: ");
    print_hex(hash3, SM3_DIGEST_SIZE);
    printf("\n");

    size_t final_len = current_len + ext1_len + ext2_len;
    char *final_msg = malloc(final_len);
    memcpy(final_msg, current_msg, current_len);
    memcpy(final_msg + current_len, ext1, ext1_len);
    memcpy(final_msg + current_len + ext1_len, ext2, ext2_len);

    uint8_t verification[SM3_DIGEST_SIZE];
    sm3_hash((uint8_t *)final_msg, final_len, verification);

    assert(memcmp(hash3, verification, SM3_DIGEST_SIZE) == 0);
    printf("✓ Multiple extensions successful!\n\n");

    free(current_msg);
    free(ext1);
    free(ext2);
    free(final_msg);
}

int main()
{
    printf("SM3 Length Extension Attack Test Suite\n");
    printf("=======================================\n\n");

    test_length_extension_basic();
    test_length_extension_detailed();
    test_authentication_bypass();
    test_multiple_extensions();

    printf("All length extension attack tests passed!\n");
    printf("This demonstrates the vulnerability of SM3 to length extension attacks\n");
    printf("when used improperly for message authentication.\n");

    return 0;
}
