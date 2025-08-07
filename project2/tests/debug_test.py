#!/usr/bin/env python3
import sys
import os
import cv2
import numpy as np

# 添加src目录到路径
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

from watermark_core import DCTWatermark, calculate_image_quality_metrics

def test_basic_watermark():
    """测试基本水印功能"""
    print("=== 基础水印测试 ===")
    
    # 创建简单的测试图像
    image = np.zeros((256, 256, 3), dtype=np.uint8)
    # 添加一些纹理
    for i in range(0, 256, 32):
        for j in range(0, 256, 32):
            if (i//32 + j//32) % 2 == 0:
                image[i:i+32, j:j+32] = [128, 128, 128]
            else:
                image[i:i+32, j:j+32] = [200, 200, 200]
    
    cv2.imwrite("test_original.png", image)
    print(f"原始图像保存: test_original.png, 尺寸: {image.shape}")
    
    # 初始化水印系统
    watermark_system = DCTWatermark(block_size=8, alpha=0.3, seed=42)  # 增加alpha值
    print(f"水印参数: block_size=8, alpha=0.3, seed=42")
    
    # 嵌入水印
    watermark_text = "TEST2025"
    print(f"嵌入水印: {watermark_text}")
    
    watermarked_image, embedding_info = watermark_system.embed_watermark(image, watermark_text)
    cv2.imwrite("test_watermarked.png", watermarked_image)
    print(f"含水印图像保存: test_watermarked.png")
    
    # 计算质量指标
    metrics = calculate_image_quality_metrics(image, watermarked_image)
    print(f"PSNR: {metrics['PSNR']:.2f} dB")
    print(f"SSIM: {metrics['SSIM']:.3f}")
    
    # 提取水印
    print("\n=== 水印提取测试 ===")
    detected_text, correlation, extraction_stats = watermark_system.extract_watermark(
        watermarked_image, embedding_info, similarity_threshold=0.3  # 降低阈值
    )
    
    print(f"检测到的水印: {detected_text}")
    print(f"相关系数: {correlation:.3f}")
    print(f"检测成功: {'是' if extraction_stats['is_present'] else '否'}")
    print(f"检测率: {extraction_stats['detection_rate']:.1%}")
    print(f"平均响应: {extraction_stats['mean_response']:.3f}")
    print(f"响应标准差: {extraction_stats['std_response']:.3f}")
    
    # 调试信息
    print(f"\n=== 调试信息 ===")
    print(f"总块数: {extraction_stats['total_blocks']}")
    print(f"嵌入位置数: {len(embedding_info['positions'])}")
    print(f"图像块数: {embedding_info['blocks_shape']}")
    
    return watermarked_image, embedding_info, extraction_stats['is_present']

def test_simple_attacks(watermarked_image, embedding_info):
    """测试简单攻击"""
    print("\n=== 简单攻击测试 ===")
    
    watermark_system = DCTWatermark()
    
    # 1. 无攻击baseline
    print("1. 无攻击baseline...")
    detected_text, correlation, stats = watermark_system.extract_watermark(
        watermarked_image, embedding_info, similarity_threshold=0.3
    )
    print(f"   相关系数: {correlation:.3f}, 成功: {'是' if stats['is_present'] else '否'}")
    
    # 2. 轻微噪声
    print("2. 轻微高斯噪声...")
    noise = np.random.normal(0, 5, watermarked_image.shape).astype(np.float32)
    noisy_image = np.clip(watermarked_image.astype(np.float32) + noise, 0, 255).astype(np.uint8)
    
    detected_text, correlation, stats = watermark_system.extract_watermark(
        noisy_image, embedding_info, similarity_threshold=0.3
    )
    print(f"   相关系数: {correlation:.3f}, 成功: {'是' if stats['is_present'] else '否'}")
    cv2.imwrite("test_attacked_noise.png", noisy_image)
    
    # 3. JPEG压缩
    print("3. JPEG压缩 (质量70)...")
    encode_param = [int(cv2.IMWRITE_JPEG_QUALITY), 70]
    _, encoded_img = cv2.imencode('.jpg', watermarked_image, encode_param)
    compressed_image = cv2.imdecode(encoded_img, cv2.IMREAD_COLOR)
    
    detected_text, correlation, stats = watermark_system.extract_watermark(
        compressed_image, embedding_info, similarity_threshold=0.3
    )
    print(f"   相关系数: {correlation:.3f}, 成功: {'是' if stats['is_present'] else '否'}")
    cv2.imwrite("test_attacked_jpeg.png", compressed_image)

if __name__ == "__main__":
    try:
        watermarked_image, embedding_info, success = test_basic_watermark()
        
        if success:
            test_simple_attacks(watermarked_image, embedding_info)
        else:
            print("基础水印测试失败，跳过攻击测试")
            
    except Exception as e:
        print(f"测试过程中出现错误: {e}")
        import traceback
        traceback.print_exc()
