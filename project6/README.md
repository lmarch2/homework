# Project 6: Google Password Checkup（OPRF + Bloom Filter）

目标：在不泄露客户端口令的前提下，查询其是否出现在服务端的泄露口令集合中；服务端不获知客户端明文。实现采用两轮 OPRF + 分桶 Bloom 的私有集合成员查询（PSM）模式。

## 协议概述

- 群与 OPRF：使用 RFC 3526 的 1536-bit safe prime 群（p=2q+1）。Hash-to-Group：H1(x)=(g^e)^2 mod p，其中 e=SHA-256(x) mod q。平方保证元素落在阶为 q 的子群。服务器密钥 k∈Z_q^*。
- 两轮交互：
  - 客户端盲化 M=H1(x)^r，发送 (bucket_prefix, M)。
  - 服务器返回 N=M^k 及该桶的 Bloom 过滤器。
  - 客户端去盲 Z=N^{r^{-1}}=H1(x)^k，计算 y=H2(Z)，在 Bloom 中查询成员关系。
- 正确性：N=(H1(x)^r)^k，去盲得 H1(x)^k；Bloom 负责集合查询，存在可调 FPR。
- 安全性：本实现未包含 DLEQ 同钥证明；工程上建议使用曲线型 OPRF/VOPRF 与证明以防不诚实服务器。Bloom 误报须通过参数控制。

### 形式化接口

记密码空间为 X，OPRF 为三元组 (Blind, Eval, Finalize)：
- Setup(1^λ): 服务器抽取 k←$ Z_q^*。
- Blind(x): 客户端选 r←$ Z_q^*，输出 M=H1(x)^r、状态 st=r。
- Eval(k, M): 服务器输出 N=M^k。
- Finalize(st, N): 客户端计算 Z=N^{r^{-1}}=H1(x)^k，输出 y=H2(Z)。

安全性（高层直观）：在 DDH 假设下，给定盲化的群元素 M 与返回 N，x 对应的 PRF 输出近似随机且盲化保证服务器看不到 x。Finalize 后的 y 用作集合成员查询键，客户端仅获知自身查询的结果。

### 正确性要点
M=H1(x)^r；Eval 得 N=H1(x)^{rk}；r^{-1} 为模 q 逆元，故 N^{r^{-1}}=H1(x)^k。Bloom 查询以 y=H2(H1(x)^k) 为键，与服务器预先将泄露集合中每个口令 w 的 y_w 加入其所在桶的一致。

## 目录
```
project6/
├── README.md
├── __init__.py
├── experiments.py
├── run_demo.py
└── src
    ├── __init__.py
    ├── bloom.py
    ├── client.py
    ├── oprf_group.py
    ├── protocol.py
    └── server.py
```
本实现仅使用 Python 标准库，无第三方依赖。

## 快速开始
运行环境：Python 3（标准库即可）。在仓库根目录执行以下命令。

```zsh
# 运行最小演示（同进程 client/server，打印查询结果）
python3 project6/run_demo.py

# 运行实验（合成数据，输出 TPR/FPR、平均耗时、平均桶大小）
python3 project6/experiments.py
```

可调参数（直接在脚本内修改）：
- 在 `run_demo.py` 与 `experiments.py` 中，`Protocol.setup(..., b_bits=12, target_fpr=1e-4)` 可调整分桶位数与目标误报；
- 在 `experiments.py` 中，`run_experiment(N, b_bits, fpr, q_pos, q_neg)` 可修改数据规模与查询数量。

示例输出（节选）：

```text
query=b'password' -> leaked=True
query=b'hello1234' -> leaked=False
...

TPR: 1.0
FPR_obs: 0.01
avg_query_time_sec: 0.0025...
avg_bucket_bytes: 138
```

## 实验设计

- 数据集：
  - 合成泄露集：随机生成长度在 [8, 12] 的小写字母密码若干（可配置规模），并额外加入少量常见口令，如 123456、password、qwerty、111111、abc123 等用于命中测试。
  - 查询集：
    - 正样本：来自泄露集的随机子集。
    - 负样本：随机生成不在泄露集中的口令。
- 评估指标：
  - 正确性：正样本命中率（TPR，应为 1）。
  - 误报率：负样本被判定为命中的比例（FPR）。
  - 传输开销：每次查询返回的桶大小（Bloom 位图字节数与参数开销）。
  - 时间：单次查询（盲化、去盲、哈希、Bloom 查询）平均耗时。
- 变量：
  - 分桶位数 b（桶数 2^b）。
  - 每桶 Bloom 位数 m 与哈希函数个数 k（程序根据桶内元素数自适应到近似最优 k= m/n·ln2）。

### 理论分析要点

- Hash-to-Group：使用 e = SHA-256(x) mod q，将 g^e 再平方确保落在阶 q 子群。这样可避免小子群攻击。
- 去盲正确性：N = (H1(x)^r)^k = H1(x)^{rk}，Z = N^{r^{-1}} = H1(x)^k。
- Bloom FPR 近似：p ≈ (1 - e^{-kn/m})^k；在给定 n 与目标 p 下，最优 k ≈ (m/n)·ln2，固定 k 后 m 可按目标 FPR 倒推。实现中 m 以 8 对齐的最小整数，使误报率在一个可接受范围，且每桶最小位数有下界用于小桶。
- 隐私：客户端仅暴露桶前缀（b 比特容量信息泄露）与盲化元素；服务器无法直接得到 x。服务器返回的桶 Bloom 过滤器在语义上包含该桶所有条目的 PRF 值的哈希，客户端只学到自己的查询结果。
- 群选择：选 1536-bit RFC 3526 安全素数群，教学实现便于在纯 Python 中编码与调试；如需更强安全性，可替换为 2048-bit 或椭圆曲线群。
- 无 DLEQ 证明：本实现不包含同钥证明，假设服务器诚实使用统一的 k。可作为后续扩展。
- 分桶策略：prefix = SHA-256(x) 的前 b 位，b 可配置，默认 b=12（4096 桶）。
- 序列化：Bloom 使用自定义头部（m_bits, k, n_items）与位图字节数组，便于跨进程传输。

### 参数选择与复杂度

- 分桶位数 b：桶数 2^b。b 增大可减小单桶元素数 n，从而降低 Bloom 位宽需求与通信，但会增加桶索引泄露（约 b 比特）。
- 每桶 Bloom：对桶内元素数 n，按目标 FPR 计算 m 与 k：
  - m ≈ -n·ln p / (ln 2)^2，k ≈ (m/n)·ln 2；实现中取向上取整并按字节对齐，设置最小位宽避免极小桶退化。
- 计算复杂度：
  - 客户端单次：2 次大数幂（盲化与去盲，指数在 Z_q），若使用曲线可显著加速。
  - 服务器单次：1 次大数幂（评估）。
  - 预处理：服务器对泄露集每条口令 1 次群幂（H1(x)^k）+ 1 次哈希并加入 Bloom。
- 通信复杂度：客户端→服务器发送 (bucket_idx, M)；服务器→客户端返回 (N, Bloom_bucket)。主成本是桶的 Bloom 位图字节数。

### 泄露与对抗性分析

- 泄露面：
  - 桶前缀：暴露 x 的前 b 位哈希信息（容量信息），需权衡 b。
  - Bloom 误报：客户端可能观测到误报，属可控统计误差。
- 非诚实服务器：
  - 无 DLEQ 时，服务器可对不同查询使用不同 k 并植入标记。工程上应使用 VOPRF 与同钥证明，或加入审计与速率限制。
  - 离线枚举：服务器仅见到盲化 M，基于 DDH 盲化应阻断直接枚举。仍需配合速率限制与滥用检测。
- 客户端策略：不得重用 r；实现已避免 r∈{0,1}，并对 e=0 进行修正，防止退化。

### 工程细节与边界条件

- Hash-to-Group：采用 e=SHA-256(x) mod q，计算 (g^e)^2，确保在 QR_p，避免小子群攻击。
- 逆元计算：使用扩展欧几里得算法计算 r^{-1} mod q，r 取值避开非可逆元素。
- 域分离：H1 与 H2 使用不同的 hash 过程，避免关联；实现中 H2 为对群元素编码的 SHA-256。
- 序列化：Bloom 存储 m_bits、k、n_items 与位图，便于网络传输；注意大端编码与对齐。
- 可替代实现：建议采用椭圆曲线群（如 P-256、Ristretto255）上的标准化 OPRF/VOPRF 实现，并加入 DLEQ/POK 以保证同钥与抗联通攻击。

### 实验结果

一次本机示例（N=8000, b=12, 目标 FPR≈1e-4，查询各 300 条）：
- TPR: 1.0
- FPR_obs: 0.01（小桶触达最小位宽时偏高；可增大 m_bits 或 b）
- 平均单次查询耗时（秒）: ≈0.0025
- 平均返回桶大小（字节）: ≈138

注：极小桶的 Bloom 会受最小位宽影响，建议调高 `min_m_bits` 或增大 b 降低 FPR 方差。

### 限制与扩展

- 群为 1536-bit safe prime，教学实现；可替换为 2048-bit 或曲线型群。
- 未加入 DLEQ 同钥证明；可扩展为标准化 OPRF/VOPRF。
- 可扩展为跨进程/网络交互（目前为同进程示范）。

## 参考

- DH、Hash-to-Group 与 Bloom 的标准教材与公开资料。
