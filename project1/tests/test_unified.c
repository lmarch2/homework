#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

// Test vectors
static const uint8_t test_key[16] = {
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};

static const uint8_t test_plaintext[16] = {
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};

static const uint8_t expected_ciphertext[16] = {
    0x68, 0x1e, 0xdf, 0x34, 0xd2, 0x06, 0x96, 0x5e,
    0x86, 0xb3, 0xe9, 0x4f, 0x53, 0x6e, 0x42, 0x46};

// Function pointers - will be linked to different implementations
extern void sm4_basic_encrypt(const uint8_t *key, const uint8_t *input, uint8_t *output);
extern void sm4_basic_decrypt(const uint8_t *key, const uint8_t *input, uint8_t *output);

// Use weak symbols to allow different implementations
void __attribute__((weak)) sm4_ttable_encrypt(const uint8_t *key, const uint8_t *input, uint8_t *output)
{
    sm4_basic_encrypt(key, input, output);
}

void __attribute__((weak)) sm4_aesni_encrypt(const uint8_t *key, const uint8_t *input, uint8_t *output)
{
    sm4_basic_encrypt(key, input, output);
}

void __attribute__((weak)) sm4_gfni_encrypt(const uint8_t *key, const uint8_t *input, uint8_t *output)
{
    sm4_basic_encrypt(key, input, output);
}

void print_hex(const uint8_t *data, size_t len)
{
    for (size_t i = 0; i < len; i++)
    {
        printf("%02x", data[i]);
    }
    printf("\n");
}

int test_correctness(const char *impl_name, void (*encrypt_func)(const uint8_t *, const uint8_t *, uint8_t *))
{
    uint8_t ciphertext[16];
    uint8_t decrypted[16];

    printf("Testing %s Implementation...\n", impl_name);

    // Encrypt
    encrypt_func(test_key, test_plaintext, ciphertext);

    printf("Key:        ");
    print_hex(test_key, 16);
    printf("Plaintext:  ");
    print_hex(test_plaintext, 16);
    printf("Ciphertext: ");
    print_hex(ciphertext, 16);
    printf("Expected:   ");
    print_hex(expected_ciphertext, 16);

    // Check if encryption is correct
    if (memcmp(ciphertext, expected_ciphertext, 16) != 0)
    {
        printf("ERROR: Encryption failed!\n");
        return 0;
    }

    // Decrypt
    sm4_basic_decrypt(test_key, ciphertext, decrypted);

    printf("Decrypted:  ");
    print_hex(decrypted, 16);

    // Check if decryption is correct
    if (memcmp(decrypted, test_plaintext, 16) != 0)
    {
        printf("ERROR: Decryption failed!\n");
        return 0;
    }

    printf("SUCCESS: %s implementation works correctly!\n", impl_name);
    return 1;
}

void benchmark_implementation(const char *impl_name, void (*encrypt_func)(const uint8_t *, const uint8_t *, uint8_t *))
{
    uint8_t input[16], output[16];
    clock_t start, end;
    const int iterations = 100000;

    printf("\nBenchmarking %s Implementation...\n", impl_name);

    memcpy(input, test_plaintext, 16);

    start = clock();
    for (int i = 0; i < iterations; i++)
    {
        encrypt_func(test_key, input, output);
    }
    end = clock();

    double cpu_time = ((double)(end - start)) / CLOCKS_PER_SEC;
    double blocks_per_sec = iterations / cpu_time;
    double mb_per_sec = (blocks_per_sec * 16) / (1024 * 1024);

    printf("Iterations: %d\n", iterations);
    printf("Time: %.3f seconds\n", cpu_time);
    printf("Performance: %.2f MB/s\n", mb_per_sec);
    printf("Blocks/sec: %.0f\n", blocks_per_sec);
}

int main()
{
    // Determine which implementation we're testing based on compilation context
    const char *impl_name = "SM4 Basic";
    void (*encrypt_func)(const uint8_t *, const uint8_t *, uint8_t *) = sm4_basic_encrypt;

#ifdef TESTING_TTABLE
    impl_name = "SM4 T-table";
    encrypt_func = sm4_ttable_encrypt;
#elif defined(TESTING_AESNI)
    impl_name = "SM4 AES-NI";
    encrypt_func = sm4_aesni_encrypt;
#elif defined(TESTING_GFNI)
    impl_name = "SM4 GFNI";
    encrypt_func = sm4_gfni_encrypt;
#else
    // For basic and optimized versions, still use basic implementation
    impl_name = "SM4 Basic";
    encrypt_func = sm4_basic_encrypt;
#endif

    printf("=== %s Test ===\n\n", impl_name);

    if (!test_correctness(impl_name, encrypt_func))
    {
        return 1;
    }

    benchmark_implementation(impl_name, encrypt_func);

    return 0;
}
