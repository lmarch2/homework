# Homework 项目总览

本仓库包含 6 个作业，聚焦于对称密码实现与优化、哈希电路构建、数字水印以及隐私协议原型等方向。本文档提供面向读者的总体性说明与项目要求汇总，不包含运行演示与环境配置细节。

- [Project 1](./project1/README.md): SM4 软件实现与优化（GCM） 
- [Project 2](./project2/README.md): 基于数字水印的图片泄露检测 
- [Project 3](./project3/README.md): 使用 Circom 实现 Poseidon2 哈希电路并用 Groth16 生成证明 
- [Project 4](./project4/README.md): SM3 软件实现与优化、长度扩展攻击与 Merkle 树 
- [Project 5](./project5/README.md): SM2 软件实现与优化、签名误用 PoC 与“伪造中本聪签名”练习 
- [Project 6](./project6/README.md): Google Password Checkup（GPC）协议原型实现 

## 目录结构

- docs/: 讲义与报告 PDF/图片
- project1/: SM4 与 SM4-GCM 的 C 实现与优化
- project2/: 数字水印（Python）
- project3/: Circom 电路与证明（Node.js/circom/snarkjs）
- project4/: SM3 实现与扩展应用（C）
- project5/: SM2 基础与改进尝试（Python）
- project6/: Google Password Checkup 原型（Python）

## 项目概述与要求

### Project 1 — SM4 软件实现与优化（含 GCM）

- 在通用 CPU 上实现并持续优化 SM4 的软件执行效率。
- 要点：
	- 从基础实现出发，覆盖 T-table、AES-NI，以及最新指令集（如 GFNI、VPROLD 等）。
	- 基于 SM4 的实现，完成 SM4-GCM 工作模式的软件优化实现。
	- 形成不同实现/优化策略的性能与安全性比较结论。

### Project 2 — 基于数字水印的图片泄露检测

- 实现鲁棒的图片水印嵌入与提取，支撑泄露检测场景。
- 要点：
	- 编程完成水印嵌入与提取模块（可基于开源项目二次开发）。
	- 进行鲁棒性测试：翻转、平移、裁剪、对比度调整等常见失真。
	- 统计并汇报在各类失真下的提取成功率或质量指标。

### Project 3 — Circom 实现 Poseidon2 哈希电路 + Groth16

- 在 Circom 中实现 Poseidon2 哈希电路，并用 Groth16 生成与验证零知识证明。
- 要点：
	- 参数选择：(n,t,d) = (256,3,5) 或 (256,2,5)，参考文献 Table 1。
	- 电路公开输入为 Poseidon2 哈希值，隐私输入为哈希原像，输入只考虑一个 block。
	- 使用 Groth16 算法进行证明生成与验证。
- 参考：
	- Poseidon2 论文：https://eprint.iacr.org/2023/323.pdf
	- Circom 文档：https://docs.circom.io/
	- Circom 样例：https://github.com/iden3/circomlib

### Project 4 — SM3 软件实现与优化

- 从基础实现出发，对 SM3 的软件性能进行迭代优化，并开展扩展应用与安全性实验。
- 要点：
	- 参考讲义材料逐步优化。
	- 基于实现验证 length-extension attack。
	- 按 RFC6962 构建 Merkle 树（约 10 万叶子），并实现叶子存在性与不存在性证明。

### Project 5 — SM2 软件实现与优化（Python）

- 在 Python 中完成 SM2 基础实现和改进尝试，并复现签名误用相关 PoC。
- 要点：
	- SM2 基础实现与算法优化探索。
	- 基于 20250713-wen-sm2-public.pdf 的签名误用，给出推导文档与验证代码（PoC）。
	- “伪造中本聪的数字签名”的练习与复现。

### Project 6 — Google Password Checkup（GPC）协议原型

- 参考论文 https://eprint.iacr.org/2019/723.pdf 第 3.1 节（Figure 2），实现协议原型。
- 要点：
	- 严格按 Figure 2 的流程与消息格式落地实现。
	- 明确信任模型、威胁模型与隐私保证；给出正确性与安全性说明。

## 版权与声明

- 本仓库代码和文档所有权归原作者所有。
- 本仓库代码仅用于学习与研究，请勿用于任何不当用途。

