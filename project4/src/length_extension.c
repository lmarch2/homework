#include "sm3.h"
#include <stdlib.h>
#include <string.h>

static size_t calculate_padding_len(uint64_t original_len) {
    size_t padding_len = 1;
    size_t total_bits = (original_len + padding_len) * 8;
    
    while ((total_bits + 64) % 512 != 0) {
        padding_len++;
        total_bits = (original_len + padding_len) * 8;
    }
    
    padding_len += 8;
    return padding_len;
}

static void construct_padding(uint64_t original_len, uint8_t *padding, size_t padding_len) {
    memset(padding, 0, padding_len);
    padding[0] = 0x80;
    
    uint64_t bit_count = original_len * 8;
    for (int i = 0; i < 8; i++) {
        padding[padding_len - 8 + i] = (uint8_t)(bit_count >> (56 - i * 8));
    }
}

int sm3_length_extension_attack(const uint8_t *original_hash, 
                               uint64_t original_len,
                               const uint8_t *append_data, 
                               size_t append_len,
                               uint8_t *new_hash,
                               uint8_t **extended_message,
                               size_t *extended_len) {
    
    if (!original_hash || !append_data || !new_hash || !extended_message || !extended_len) {
        return -1;
    }

    size_t padding_len = calculate_padding_len(original_len);
    *extended_len = padding_len + append_len;
    
    *extended_message = malloc(*extended_len);
    if (!*extended_message) {
        return -1;
    }

    construct_padding(original_len, *extended_message, padding_len);
    memcpy(*extended_message + padding_len, append_data, append_len);

    sm3_ctx_t ctx;
    
    for (int i = 0; i < 8; i++) {
        ctx.state[i] = (original_hash[i * 4] << 24) | 
                       (original_hash[i * 4 + 1] << 16) | 
                       (original_hash[i * 4 + 2] << 8) | 
                       original_hash[i * 4 + 3];
    }
    
    ctx.count = original_len + padding_len;
    memset(ctx.buffer, 0, SM3_BLOCK_SIZE);

    sm3_update(&ctx, append_data, append_len);
    sm3_final(&ctx, new_hash);

    return 0;
}

int verify_length_extension_attack(const char *secret, 
                                   const char *original_msg,
                                   const char *append_msg) {
    uint8_t original_hash[SM3_DIGEST_SIZE];
    uint8_t expected_hash[SM3_DIGEST_SIZE];
    uint8_t attack_hash[SM3_DIGEST_SIZE];
    uint8_t *extended_message;
    size_t extended_len;
    
    size_t secret_len = strlen(secret);
    size_t original_msg_len = strlen(original_msg);
    size_t total_original_len = secret_len + original_msg_len;
    
    char *full_original = malloc(total_original_len);
    memcpy(full_original, secret, secret_len);
    memcpy(full_original + secret_len, original_msg, original_msg_len);
    
    sm3_hash((uint8_t *)full_original, total_original_len, original_hash);
    
    int result = sm3_length_extension_attack(original_hash, 
                                            total_original_len,
                                            (uint8_t *)append_msg, 
                                            strlen(append_msg),
                                            attack_hash,
                                            &extended_message,
                                            &extended_len);
    
    if (result != 0) {
        free(full_original);
        return -1;
    }
    
    size_t final_msg_len = total_original_len + extended_len;
    char *final_message = malloc(final_msg_len);
    memcpy(final_message, full_original, total_original_len);
    memcpy(final_message + total_original_len, extended_message, extended_len);
    
    sm3_hash((uint8_t *)final_message, final_msg_len, expected_hash);
    
    int success = (memcmp(attack_hash, expected_hash, SM3_DIGEST_SIZE) == 0);
    
    free(full_original);
    free(extended_message);
    free(final_message);
    
    return success ? 0 : -1;
}
