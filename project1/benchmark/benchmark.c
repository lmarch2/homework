#include "../src/sm4.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    printf("=== SM4 Performance Benchmark ===\n\n");
    
    // Run comparative benchmark
    sm4_compare_implementations();
    
    // Additional detailed benchmarks
    printf("=== Detailed Performance Analysis ===\n\n");
    
    const size_t block_sizes[] = {16, 64, 256, 1024, 4096, 16384};
    const size_t num_block_sizes = sizeof(block_sizes) / sizeof(block_sizes[0]);
    
    uint8_t key[16] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
    };
    
    for (size_t i = 0; i < num_block_sizes; i++) {
        size_t block_size = block_sizes[i];
        size_t num_blocks = block_size / 16;
        
        printf("Testing with %zu bytes (%zu blocks):\n", block_size, num_blocks);
        
        // Allocate memory
        uint8_t *plaintext = malloc(block_size);
        uint8_t *ciphertext = malloc(block_size);
        
        if (!plaintext || !ciphertext) {
            printf("Memory allocation failed!\n");
            continue;
        }
        
        // Initialize test data
        for (size_t j = 0; j < block_size; j++) {
            plaintext[j] = j & 0xFF;
        }
        
        // Benchmark each implementation
        const char *impl_names[] = {"Basic", "T-table", "AES-NI"};
        void (*encrypt_funcs[])(const uint8_t*, const uint8_t*, uint8_t*) = {
            sm4_basic_encrypt,
            sm4_ttable_encrypt,
            sm4_aesni_encrypt
        };
        
        for (int impl = 0; impl < 3; impl++) {
            printf("  %s: ", impl_names[impl]);
            fflush(stdout);
            
            // Warm-up
            for (size_t j = 0; j < num_blocks; j++) {
                encrypt_funcs[impl](key, plaintext + j * 16, ciphertext + j * 16);
            }
            
            // Benchmark
            uint64_t start_cycles = __builtin_ia32_rdtsc();
            double start_time = 0; // Simplified timing
            
            const int iterations = 1000;
            for (int iter = 0; iter < iterations; iter++) {
                for (size_t j = 0; j < num_blocks; j++) {
                    encrypt_funcs[impl](key, plaintext + j * 16, ciphertext + j * 16);
                }
            }
            
            uint64_t end_cycles = __builtin_ia32_rdtsc();
            
            uint64_t total_cycles = end_cycles - start_cycles;
            size_t total_bytes = block_size * iterations;
            double cycles_per_byte = (double)total_cycles / (double)total_bytes;
            
            printf("%.2f cycles/byte\n", cycles_per_byte);
        }
        
        free(plaintext);
        free(ciphertext);
        printf("\n");
    }
    
    return 0;
}
