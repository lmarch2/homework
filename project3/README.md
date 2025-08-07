# Project 3: 基于Circom的Poseidon2哈希算法电路实现

## 项目概述

本项目使用Circom实现Poseidon2哈希函数的零知识电路，采用参数(n,t,d) = (256,3,5)，并使用Groth16证明系统生成零知识证明。

## 数学背景与算法原理

### Poseidon2哈希函数

Poseidon2是Poseidon哈希函数的优化版本，专门为零知识证明系统设计。它在有限域上运行，使用替换-置换网络(SPN)结构。

#### 算法结构

Poseidon2置换包含以下步骤：

1. **状态初始化**：使用输入值和填充初始化内部状态
2. **轮函数**：应用特定轮数，包含：
   - AddRoundKey (ARK)：添加轮常数
   - SubBytes (S-box)：使用x^d的非线性变换(其中d=5)
   - MixColumns：使用MDS矩阵的线性变换

#### 参数设置

本实现使用参数(n=256, t=3, d=5)：
- **n = 256**：安全级别(比特)
- **t = 3**：状态大小(有限域元素个数)
- **d = 5**：S-box度数(x^5)

#### 轮数设置

基于安全性分析：
- **R_F = 8**：全轮数
- **R_P = 57**：部分轮数(针对t=3)

#### 数学表述

设F_p为素数域，其中p是大素数。Poseidon2置换作用于t个有限域元素的状态。

**状态更新**：
对于每轮i，状态S按以下方式更新：
1. **ARK**：S_i ← S_{i-1} + C_i (其中C_i为轮常数)
2. **S-box**：S_i[j] ← S_i[j]^5 对所有j(全轮)或j=0(部分轮)
3. **MixColumns**：S_i ← M × S_i (其中M为MDS矩阵)

**轮常数**：使用安全方法生成，确保没有可被利用的代数结构。

**MDS矩阵**：最大距离可分矩阵确保最优扩散特性。

### 电路设计

电路实现以下组件：

1. **输入处理**：接收单个有限域元素作为私有输入(原像)
2. **填充**：应用适当填充创建t元素状态
3. **置换**：实现完整的Poseidon2置换
4. **输出**：产生哈希值作为公开输出

#### 安全性质

- **抗碰撞性**：计算上不可行找到具有相同哈希的两个输入
- **抗原像性**：给定哈希值，计算上不可行找到原像
- **抗第二原像性**：给定输入，计算上不可行找到具有相同哈希的不同输入

## 实现方案

### 电路结构

主电路`Poseidon2Hash`包含：
- **私有输入**：`preimage` - 待哈希的值
- **公开输出**：`hash` - preimage的Poseidon2哈希值

### 组件设计

1. **Poseidon2Core**：实现核心置换
2. **AddRoundKey**：向状态添加轮常数
3. **SBox**：实现x^5 S-box变换
4. **MixColumns**：应用MDS矩阵乘法

## 零知识证明生成

项目使用Groth16 zk-SNARK证明系统，提供：
- **简洁性**：证明具有常数大小
- **非交互性**：证明者和验证者之间无需交互
- **零知识**：不泄露私有输入的任何信息

### 证明声明

电路证明："我知道一个原像x使得Poseidon2(x) = h"，而不泄露x。

## 实验结果与性能分析

### 电路测试

实现包含已成功执行的综合测试：

1. **正确性验证**：各种输入的哈希计算工作正常
2. **确定性属性**：相同输入始终产生相同哈希
3. **抗碰撞性**：不同输入产生不同哈希值

#### 测试结果

```
Test Results Summary:
✓ Hash of 0: 20494129443602848678221837396214638521787470948383441422032891971057025688446
✓ Hash of 1: 9054275396596867406088262571755139327178147504922609090580789784689679026528  
✓ Hash of 42: 12734957036258313384458817466501339664620251908681212896654508210380655274248
✓ Different inputs produce different hashes (verified)
✓ Deterministic behavior confirmed
✓ All circuit constraints satisfied
```

### 电路性能分析

#### 编译统计
- **电路编译成功**：使用Circom 2.1.9
- **R1CS约束**：生成成功
- **WASM见证生成**：工作正常
- **编译时间**：< 1秒

#### 电路复杂度
基于Poseidon2实现：
- **状态大小(t)**：3个有限域元素
- **总轮数**：65轮(8全轮 + 57部分轮)
- **S-box度数**：5(x^5运算)
- **有限域运算**：针对bn128曲线优化

#### 安全性分析
- **安全级别**：256比特(符合要求规格)
- **轮数**：足以保证密码学安全性
- **MDS矩阵**：提供最优扩散
- **轮常数**：生成以防止代数攻击

### Groth16证明系统集成

项目包含完整Groth16证明生成工作流的脚本：

1. **电路编译**：将Circom转换为R1CS格式
2. **可信设置**：使用powers of tau仪式
3. **证明密钥生成**：创建zkey文件
4. **见证生成**：计算电路见证
5. **证明生成**：创建Groth16证明
6. **验证**：密码学验证证明

#### 证明生成工作流

```bash
# 1. Compile circuit
npm run compile

# 2. Download powers of tau
wget https://hermez.s3-eu-west-1.amazonaws.com/powersOfTau28_hez_final_12.ptau

# 3. Generate proving key
snarkjs groth16 setup build/poseidon2_hash.r1cs build/powersOfTau28_hez_final_12.ptau build/poseidon2_hash_0000.zkey

# 4. Contribute to ceremony
snarkjs zkey contribute build/poseidon2_hash_0000.zkey build/poseidon2_hash_final.zkey

# 5. Export verification key
snarkjs zkey export verificationkey build/poseidon2_hash_final.zkey build/verification_key.json

# 6. Generate proof
snarkjs groth16 prove build/poseidon2_hash_final.zkey build/witness.wtns build/proof.json build/public.json

# 7. Verify proof
snarkjs groth16 verify build/verification_key.json build/public.json build/proof.json
```

### 实现验证

实现成功演示了：

1. **功能正确性**：所有哈希计算产生预期结果
2. **电路约束**：所有测试中零约束违规
3. **确定性行为**：相同输入的一致输出
4. **密码学特性**：适当的抗碰撞行为
5. **ZK-SNARK集成**：与Groth16证明系统兼容

此Poseidon2电路可用于：
- **隐私保护认证**
- **零知识成员证明**
- **匿名凭证系统**
- **区块链隐私协议**
- **机密交易系统**

## 总结

### 项目结构

```
project3
├── README.md
├── SUMMARY.md
├── build
├── circuits
├── demo.js
├── node_modules
├── package-lock.json
├── package.json
├── scripts
└── test
```
### 性能结果

- **编译时间**：< 1秒
- **见证生成**：高效且工作正常
- **内存使用**：针对约束数量优化
- **证明大小**：常数(Groth16特性)

实现为需要零知识证明系统中密码学哈希函数的隐私保护应用提供了坚实基础。项目成功满足所有指定要求，提供了Poseidon2哈希函数在零知识电路中的工作实现，具备Groth16证明生成能力。
