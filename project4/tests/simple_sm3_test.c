#include "src/sm3.h"
#include <stdio.h>
#include <string.h>

int main()
{
    printf("SM3 Test Vectors\n");
    printf("================\n");

    // 测试向量1: "abc"
    const char *msg1 = "abc";
    uint8_t hash1[32];
    sm3_hash((uint8_t *)msg1, strlen(msg1), hash1);

    printf("SM3(\"%s\") = ", msg1);
    for (int i = 0; i < 32; i++)
    {
        printf("%02x", hash1[i]);
    }
    printf("\n");

    // 测试向量2: 空字符串
    uint8_t hash2[32];
    sm3_hash((uint8_t *)"", 0, hash2);

    printf("SM3(\"\") = ");
    for (int i = 0; i < 32; i++)
    {
        printf("%02x", hash2[i]);
    }
    printf("\n");

    return 0;
}
