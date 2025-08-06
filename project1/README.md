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

## 4. 代码结构

```
project1/
├── src/
│   ├── sm4_basic.c          # 基础实现
│   ├── sm4_ttable.c         # T-table优化
│   ├── sm4_aesni.c          # AES-NI优化
│   ├── sm4_gfni.c           # GFNI优化
│   ├── sm4_gcm.c            # GCM模式实现
│   ├── sm4.h                # 头文件
│   └── utils.c              # 工具函数
├── tests/
│   ├── test_sm4.c           # 单元测试
│   └── test_vectors.h       # 测试向量
├── benchmark/
│   └── benchmark.c          # 性能测试
└── Makefile                 # 构建脚本
```

## 5. 实验设计

### 5.1 正确性验证
- 使用标准测试向量验证
- 加解密一致性测试
- 不同实现版本结果对比

### 5.2 性能测试
- 单次加密延迟测试
- 吞吐量测试（cycles/byte）
- 不同优化方案性能对比

### 5.3 安全性分析
- 时间攻击resistant测试
- 缓存攻击防护验证

## 6. 构建与运行

```bash
# 编译所有版本
make all

# 运行测试
make test

# 性能测试
make benchmark

# 清理
make clean
```

## 7. 实验结果

（实验结果将在实现完成后更新）

## 8. 参考文献

1. GM/T 0002-2012 SM4分组密码算法
2. RFC 8998: ShangMi (SM) Cipher Suites for Transport Layer Security (TLS) Protocol Version 1.3
3. ISO/IEC 18033-3:2010/Amd 1:2021 SM4 Block Cipher
