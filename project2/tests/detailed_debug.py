#!/usr/bin/env python3
import sys
import os
import cv2
import numpy as np

# 添加src目录到路径
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

from watermark_core import DCTWatermark

def debug_watermark_detailed():
    """详细调试水印过程"""
    
    # 创建简单测试图像
    image = np.ones((64, 64, 3), dtype=np.uint8) * 128  # 简单的灰色图像
    
    # 初始化水印系统
    watermark_system = DCTWatermark(block_size=8, alpha=0.5, seed=42)
    
    print("=== 嵌入过程调试 ===")
    
    # 手动嵌入过程
    yuv_image = cv2.cvtColor(image, cv2.COLOR_BGR2YUV)
    y_channel = yuv_image[:, :, 0].astype(np.float32)
    
    print(f"Y通道形状: {y_channel.shape}")
    print(f"Y通道值范围: {y_channel.min():.2f} - {y_channel.max():.2f}")
    
    # 生成水印序列
    watermark_text = "TEST"
    blocks_h, blocks_w = 8, 8  # 64/8 = 8
    total_blocks = blocks_h * blocks_w
    watermark_sequence = watermark_system._generate_watermark_sequence(total_blocks, watermark_text)
    
    print(f"水印序列长度: {len(watermark_sequence)}")
    print(f"水印序列前10个: {watermark_sequence[:10]}")
    
    # 获取嵌入位置
    positions = watermark_system._select_embedding_positions((8, 8))
    print(f"嵌入位置: {positions}")
    
    # 处理第一个块进行详细分析
    block = y_channel[0:8, 0:8]
    print(f"\n第一个块:")
    print(f"块值范围: {block.min():.2f} - {block.max():.2f}")
    
    # DCT变换
    dct_block = watermark_system._dct2d(block)
    print(f"DCT系数范围: {dct_block.min():.2f} - {dct_block.max():.2f}")
    print(f"DCT系数 (前3x3):")
    print(dct_block[:3, :3])
    
    # 嵌入水印
    watermark_bit = watermark_sequence[0]
    print(f"第一个块的水印位: {watermark_bit}")
    
    original_dct = dct_block.copy()
    for pos in positions:
        u, v = pos
        if u < dct_block.shape[0] and v < dct_block.shape[1]:
            original_coeff = dct_block[u, v]
            modified_coeff = original_coeff + watermark_system.alpha * watermark_bit * abs(original_coeff)
            print(f"位置({u},{v}): {original_coeff:.3f} -> {modified_coeff:.3f}")
            dct_block[u, v] = modified_coeff
    
    # 完整嵌入过程
    print("\n=== 完整嵌入测试 ===")
    watermarked_image, embedding_info = watermark_system.embed_watermark(image, watermark_text)
    
    print(f"嵌入信息: {embedding_info}")
    
    # 提取测试
    print("\n=== 提取过程调试 ===")
    
    # 手动提取第一个块
    yuv_watermarked = cv2.cvtColor(watermarked_image, cv2.COLOR_BGR2YUV)
    y_watermarked = yuv_watermarked[:, :, 0].astype(np.float32)
    
    first_block = y_watermarked[0:8, 0:8]
    dct_first_block = watermark_system._dct2d(first_block)
    
    print(f"提取的第一个块DCT系数 (前3x3):")
    print(dct_first_block[:3, :3])
    
    # 计算响应
    block_response = 0
    valid_positions = 0
    expected_watermark = watermark_sequence[0]
    
    print(f"期望水印位: {expected_watermark}")
    
    for pos in positions:
        u, v = pos
        if u < dct_first_block.shape[0] and v < dct_first_block.shape[1]:
            coeff_value = dct_first_block[u, v]
            response = coeff_value * expected_watermark
            block_response += response
            valid_positions += 1
            print(f"位置({u},{v}): 系数={coeff_value:.3f}, 响应={response:.3f}")
    
    if valid_positions > 0:
        block_response /= valid_positions
    
    print(f"第一个块平均响应: {block_response:.3f}")
    
    # 完整提取
    print("\n=== 完整提取测试 ===")
    detected_text, correlation, extraction_stats = watermark_system.extract_watermark(
        watermarked_image, embedding_info, similarity_threshold=0.1
    )
    
    print(f"提取结果: {detected_text}")
    print(f"相关系数: {correlation:.3f}")
    print(f"检测成功: {extraction_stats['is_present']}")
    print(f"平均响应: {extraction_stats['mean_response']:.3f}")
    
    # 调试序列比较
    print(f"\n=== 序列比较 ===")
    # 重新生成参考序列用于比较
    ref_seq = watermark_system._generate_watermark_sequence(64, watermark_text)
    print(f"参考序列前10个: {ref_seq[:10]}")
    
    # 手动计算提取序列
    yuv_test = cv2.cvtColor(watermarked_image, cv2.COLOR_BGR2YUV)
    y_test = yuv_test[:, :, 0].astype(np.float32)
    extracted_manual = []
    
    for i in range(8):  # 只检查前8个块
        for j in range(8):
            block = y_test[i*8:(i+1)*8, j*8:(j+1)*8]
            dct_block = watermark_system._dct2d(block)
            
            block_idx = i * 8 + j
            current_watermark_bit = ref_seq[block_idx]
            
            block_response = 0
            valid_positions = 0
            
            for pos in positions:
                u, v = pos
                if u < dct_block.shape[0] and v < dct_block.shape[1]:
                    coeff_value = dct_block[u, v]
                    # 新的符号检测逻辑
                    detected_bit = 1 if coeff_value > 0 else -1
                    block_response += detected_bit
                    valid_positions += 1
            
            if valid_positions > 0:
                block_response /= valid_positions
            
            extracted_bit = 1 if block_response > 0 else -1
            extracted_manual.append(extracted_bit)
    
    print(f"提取序列前10个: {extracted_manual[:10]}")
    print(f"匹配数: {sum(1 for i in range(len(extracted_manual)) if extracted_manual[i] == ref_seq[i])}")
    print(f"匹配率: {sum(1 for i in range(len(extracted_manual)) if extracted_manual[i] == ref_seq[i]) / len(extracted_manual) * 100:.1f}%")

if __name__ == "__main__":
    debug_watermark_detailed()
