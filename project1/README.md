# SM4密码算法软件实现与优化

## 1. 项目概述

本项目实现了中国国家标准SM4分组密码算法的高性能软件实现，包括基础实现和多种优化版本，以及SM4-GCM工作模式的实现。

## 2. SM4算法数学原理

### 2.1 算法基本参数

SM4是一个128位分组密码算法，具有以下特征：
- **密钥长度**: 128位
- **分组长度**: 128位  
- **轮数**: 32轮
- **结构**: 非平衡Feistel网络

### 2.2 数学表示

#### 2.2.1 加密过程

设明文为 $P = (P_0, P_1, P_2, P_3)$，其中每个 $P_i$ 为32位字。

加密过程可表示为：
$$X_0 = P_0, X_1 = P_1, X_2 = P_2, X_3 = P_3$$

对于 $i = 0, 1, ..., 31$：
$$X_{i+4} = X_i \oplus F(X_{i+1} \oplus X_{i+2} \oplus X_{i+3} \oplus rk_i)$$

其中 $F$ 为轮函数，$rk_i$ 为第 $i$ 轮的轮密钥。

密文为：
$$C = (X_{35}, X_{34}, X_{33}, X_{32})$$

#### 2.2.2 轮函数F

轮函数 $F$ 定义为：
$$F(A) = L(τ(A))$$

其中：
- $τ$ 为非线性变换（S盒替换）
- $L$ 为线性变换

##### 非线性变换τ

对于32位输入 $A = (a_0, a_1, a_2, a_3)$，其中每个 $a_i$ 为8位：
$$τ(A) = (Sbox(a_0), Sbox(a_1), Sbox(a_2), Sbox(a_3))$$

##### 线性变换L

$$L(B) = B \oplus (B \lll 2) \oplus (B \lll 10) \oplus (B \lll 18) \oplus (B \lll 24)$$

其中 $\lll$ 表示循环左移。

#### 2.2.3 密钥扩展

主密钥 $MK = (MK_0, MK_1, MK_2, MK_3)$，轮密钥生成过程：

1. 计算中间密钥：
   $$K_0 = MK_0 \oplus FK_0, K_1 = MK_1 \oplus FK_1$$
   $$K_2 = MK_2 \oplus FK_2, K_3 = MK_3 \oplus FK_3$$

   其中 $FK$ 为系统参数。

2. 生成轮密钥：
   对于 $i = 0, 1, ..., 31$：
   $$rk_i = K_{i+4} = K_i \oplus T'(K_{i+1} \oplus K_{i+2} \oplus K_{i+3} \oplus CK_i)$$

   其中 $T'(·) = L'(τ(·))$，$L'(B) = B \oplus (B \lll 13) \oplus (B \lll 23)$

### 2.3 算法常数

#### 2.3.1 系统参数FK
```
FK[0] = 0xA3B1BAC6
FK[1] = 0x56AA3350
FK[2] = 0x677D9197
FK[3] = 0xB27022DC
```

#### 2.3.2 固定参数CK
$CK_i$ 由以下公式生成：
$$CK_i = (4i + 0) \cdot 7 \bmod 256 || (4i + 1) \cdot 7 \bmod 256 || (4i + 2) \cdot 7 \bmod 256 || (4i + 3) \cdot 7 \bmod 256$$

## 3. 实现方案

### 3.1 基础实现

基础实现严格按照SM4标准规范，提供：
- 标准的S盒查表实现
- 按位操作的线性变换
- 基本的密钥扩展算法

### 3.2 优化实现

#### 3.2.1 T-table优化

通过预计算合并S盒和线性变换：
$$T_0[a] = L(Sbox(a, 0, 0, 0))$$
$$T_1[a] = L(Sbox(0, a, 0, 0))$$
$$T_2[a] = L(Sbox(0, 0, a, 0))$$
$$T_3[a] = L(Sbox(0, 0, 0, a))$$

轮函数可简化为：
$$F(A) = T_0[a_0] \oplus T_1[a_1] \oplus T_2[a_2] \oplus T_3[a_3]$$

#### 3.2.2 AES-NI优化

利用AES-NI指令集加速S盒操作：
- 使用仿射变换将SM4 S盒映射到AES S盒
- 利用`AESENC`指令加速替换操作

#### 3.2.3 GFNI优化

使用Galois Field New Instructions：
- `GF2P8AFFINEQB`：执行仿射变换
- `GF2P8MULB`：GF(2^8)乘法

#### 3.2.4 VPROLD优化

使用`VPROLD`指令优化循环左移操作，提高线性变换效率。

### 3.3 SM4-GCM模式

实现Galois/Counter Mode：
$$C_i = P_i \oplus E_K(CTR_i)$$
$$T = GHASH_H(A || C || len(A) || len(C))$$

其中 $H = E_K(0^{128})$，$GHASH$ 为GF(2^128)上的哈希函数。

**性能优化**：使用T-table优化的SM4内核替代基本实现，性能从13.14 MB/s提升至19.72 MB/s，**提升50%**。

## 4. 项目结构

```
project1/
├── Makefile
├── README.md
├── benchmark
│   ├── benchmark.c
│   └── comprehensive_analysis.c
├── src
│   ├── cpu_detect.c
│   ├── sm4.h
│   ├── sm4_aesni.c
│   ├── sm4_basic.c
│   ├── sm4_gcm.c
│   ├── sm4_gfni.c
│   ├── sm4_ttable.c
│   └── utils.c
└── tests
    ├── debug.c
    ├── debug_keys.c
    ├── test_basic_only.c
    ├── test_sm4.c
    ├── test_unified.c
    └── test_vectors.h
```

## 5. 实验与测试

### 5.1 正确性验证

使用GM/T 0002-2012标准测试向量验证所有实现：

```bash
$ make test-basic
=== SM4 Basic Test ===
Testing SM4 Basic Implementation...
Key:        0123456789abcdeffedcba9876543210
Plaintext:  0123456789abcdeffedcba9876543210
Ciphertext: 681edf34d206965e86b3e94f536e4246
Expected:   681edf34d206965e86b3e94f536e4246
SUCCESS: SM4 Basic implementation works correctly!
```

**综合测试结果**：
```bash
$ make test-comprehensive
=== SM4 Implementation Test Suite ===

Running CPU Feature Detection... PASSED
Running Basic Implementation... PASSED
Running T-table Implementation... PASSED
Running AES-NI Implementation... PASSED
Running GFNI Implementation... PASSED
Running Implementation Consistency... PASSED
Running Key Expansion... PASSED
Running Million Rounds Test... PASSED
Running GCM Mode... PASSED
Running Random Data Test... PASSED

=== Test Summary ===
Total tests: 10
Passed: 10
Failed: 0

All tests PASSED! ✓
```

**测试覆盖范围**：
- **标准测试向量**：GM/T 0002-2012官方测试数据
- **实现一致性**：所有优化版本结果与基础实现完全一致
- **密钥扩展**：验证32轮轮密钥生成正确性
- **长期稳定性**：百万轮加密测试无错误
- **SM4-GCM模式**：认证加密和解密，包括认证失败检测
- **随机数据测试**：100个随机向量全部通过
- **CPU特性检测**：自动检测AES-NI、GFNI、AVX2支持

所有实现（基础、T-table、AES-NI、GFNI）都产生相同的加密结果，解密测试也全部通过。

### 5.2 性能测试

测试环境：Linux WSL2，GCC 13.3.0，x86-64架构  
测试方法：对每个实现执行100,000次加密操作计时

**基准测试结果**：
```
基础实现 (gcc无优化):   13.50 MB/s  (1.00x)
编译器O3优化:          58.79 MB/s  (4.35x)
O3+march=native:      58.31 MB/s  (4.31x)
T-table算法优化:       59.69 MB/s  (4.42x)
AES-NI指令集优化:      20.85 MB/s  (1.54x)
GFNI指令集优化:        21.57 MB/s  (1.59x)
```

编译器O3优化带来了4.3倍性能提升。T-table实现略优于纯编译优化。AES-NI和GFNI实现性能较低，可能是因为单块处理时向量指令开销较大。

### 5.3 安全性考虑

所有实现都使用查表方式实现S盒，避免了数据相关的分支。T-table实现需要注意缓存侧信道攻击，AES-NI/GFNI硬件指令相对更安全。

## 6. 使用方法

### 6.1 快速测试

```bash
# 进入项目目录
cd project1/

# 运行性能对比
make all

# 测试单个实现
make test-basic    # 基础实现
make test-ttable   # T-table优化
make test-aesni    # AES-NI优化
make test-gfni     # GFNI优化

# 运行综合测试（包括GCM模式）
make test-comprehensive

# 测试SM4-GCM性能
make test-gcm-perf
```

### 6.2 构建选项

```bash
make help    # 查看所有命令
make clean   # 清理编译文件
```

## 7. 项目总结

### 7.1 实现完成情况

| 模块 | 状态 | 性能提升 |
|------|------|----------|
| SM4基础算法 | 完成 | 1.00x (基准) |
| T-table优化 | 完成 | 4.42x |
| AES-NI优化 | 完成 | 1.54x |
| GFNI优化 | 完成 | 1.59x |
| SM4-GCM模式 | 完成 | 19.72 MB/s (T-table优化) |
| 综合测试套件 | 完成 | 10/10测试通过 |

### 7.2 关键发现

1. **编译优化最重要**：gcc -O3带来4.3倍性能提升，远超算法层面优化
2. **T-table效果好**：在O3基础上仍有小幅提升，实现简单稳定  
3. **向量指令有问题**：AES-NI和GFNI性能低于预期，单块处理时向量化开销大
4. **GCM模式实现完整**：12.00 MB/s吞吐量，包含加密+认证功能，相比基础ECB模式略低

### 7.3 后续改进方向

- AES-NI/GFNI实现需要批量处理多个分组以发挥向量化优势
- 移除CPU检测开销，改为编译时特性选择
- 针对不同数据量优化实现选择策略

## 8. 参考文献

1. GM/T 0002-2012 SM4分组密码算法
2. RFC 8998: ShangMi (SM) Cipher Suites for Transport Layer Security (TLS) Protocol Version 1.3
3. ISO/IEC 18033-3:2010/Amd 1:2021 SM4 Block Cipher
