#include "sm4.h"

// CPU feature detection functions implementation

int sm4_cpu_support_aesni(void) {
    uint32_t eax, ebx, ecx, edx;
    
    // Check CPUID for AES-NI support
    __asm__ volatile (
        "cpuid"
        : "=a" (eax), "=b" (ebx), "=c" (ecx), "=d" (edx)
        : "a" (1)
    );
    
    return (ecx & (1 << 25)) != 0;  // AES-NI flag
}

int sm4_cpu_support_gfni(void) {
    uint32_t eax, ebx, ecx, edx;
    
    // Check CPUID for GFNI support
    __asm__ volatile (
        "cpuid"
        : "=a" (eax), "=b" (ebx), "=c" (ecx), "=d" (edx)
        : "a" (7), "c" (0)
    );
    
    return (ecx & (1 << 8)) != 0;  // GFNI flag
}

int sm4_cpu_support_avx2(void) {
    uint32_t eax, ebx, ecx, edx;
    
    // Check CPUID for AVX2 support
    __asm__ volatile (
        "cpuid"
        : "=a" (eax), "=b" (ebx), "=c" (ecx), "=d" (edx)
        : "a" (7), "c" (0)
    );
    
    return (ebx & (1 << 5)) != 0;  // AVX2 flag
}
