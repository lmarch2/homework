#!/usr/bin/env python3
import sys
import os
import cv2
import numpy as np

# 添加src目录到路径
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

from watermark_core import DCTWatermark, calculate_image_quality_metrics
from robustness_test import RobustnessTestSuite
from evaluation import WatermarkEvaluator

def create_test_images():
    """创建多样化的测试图像"""
    images = []
    
    # 1. 自然渐变图像
    img1 = np.zeros((256, 256, 3), dtype=np.uint8)
    for y in range(256):
        for x in range(256):
            r = int(255 * x / 255)
            g = int(255 * y / 255) 
            b = int(255 * (1 - (x + y) / 510))
            img1[y, x] = [b, g, r]
    cv2.imwrite("images/natural_gradient.png", img1)
    images.append(("natural_gradient.png", img1))
    
    # 2. 高频纹理图像
    img2 = np.random.randint(0, 256, (256, 256, 3), dtype=np.uint8)
    # 添加结构化纹理
    for i in range(0, 256, 16):
        cv2.rectangle(img2, (i, 0), (i+8, 255), (255, 255, 255), 1)
        cv2.rectangle(img2, (0, i), (255, i+8), (255, 255, 255), 1)
    cv2.imwrite("images/texture_pattern.png", img2)
    images.append(("texture_pattern.png", img2))
    
    # 3. 几何图案
    img3 = np.zeros((256, 256, 3), dtype=np.uint8)
    center = (128, 128)
    for r in range(10, 120, 15):
        color = [r*2, 255-r*2, 128]
        cv2.circle(img3, center, r, color, 3)
    cv2.imwrite("images/geometric_pattern.png", img3)
    images.append(("geometric_pattern.png", img3))
    
    # 4. 平滑区域测试
    img4 = np.ones((256, 256, 3), dtype=np.uint8) * 150
    # 添加少量变化
    for i in range(5):
        x, y = np.random.randint(50, 200), np.random.randint(50, 200)
        cv2.circle(img4, (x, y), 20, (160, 160, 160), -1)
    cv2.imwrite("images/smooth_regions.png", img4)
    images.append(("smooth_regions.png", img4))
    
    # 5. 高对比度图像
    img5 = np.zeros((256, 256, 3), dtype=np.uint8)
    for i in range(0, 256, 32):
        for j in range(0, 256, 32):
            if (i//32 + j//32) % 2 == 0:
                img5[i:i+32, j:j+32] = [255, 255, 255]
    cv2.imwrite("images/high_contrast.png", img5)
    images.append(("high_contrast.png", img5))
    
    return images

def run_focused_robustness_test():
    """运行重点攻击测试"""
    print("=== 重点鲁棒性测试 ===")
    
    # 使用几何图案进行测试
    image = cv2.imread("images/geometric_pattern.png")
    if image is None:
        print("无法加载测试图像")
        return
    
    watermark_system = DCTWatermark(block_size=8, alpha=0.35, seed=42)
    
    # 嵌入水印
    watermark_text = "RobustnessTest2025"
    watermarked_image, embedding_info = watermark_system.embed_watermark(image, watermark_text)
    
    # 基础质量评估
    metrics = calculate_image_quality_metrics(image, watermarked_image)
    print(f"基础质量 - PSNR: {metrics['PSNR']:.2f} dB, SSIM: {metrics['SSIM']:.3f}")
    
    # 验证原始提取
    detected_text, correlation, stats = watermark_system.extract_watermark(
        watermarked_image, embedding_info, similarity_threshold=0.3
    )
    print(f"原始检测 - 相关系数: {correlation:.3f}, 成功: {stats['is_present']}")
    
    # 重点攻击测试
    robustness_suite = RobustnessTestSuite()
    
    key_attacks = [
        # 噪声攻击
        {'category': 'noise', 'name': 'gaussian_noise_light', 'params': {'std': 5}},
        {'category': 'noise', 'name': 'gaussian_noise_medium', 'params': {'std': 10}},
        {'category': 'noise', 'name': 'gaussian_noise_heavy', 'params': {'std': 20}},
        
        # 压缩攻击  
        {'category': 'compression', 'name': 'jpeg_high_quality', 'params': {'quality': 80}},
        {'category': 'compression', 'name': 'jpeg_medium_quality', 'params': {'quality': 50}},
        {'category': 'compression', 'name': 'jpeg_low_quality', 'params': {'quality': 20}},
        
        # 几何攻击
        {'category': 'geometric', 'name': 'rotation_small', 'params': {'angle': 2}},
        {'category': 'geometric', 'name': 'scaling_down', 'params': {'scale_x': 0.95, 'scale_y': 0.95}},
        {'category': 'geometric', 'name': 'translation_small', 'params': {'dx': 5, 'dy': 5}},
        {'category': 'geometric', 'name': 'horizontal_flip', 'params': {}},
        {'category': 'geometric', 'name': 'vertical_flip', 'params': {}},
        
        # 图像增强
        {'category': 'enhancement', 'name': 'brightness_increase', 'params': {'brightness': 20}},
        {'category': 'enhancement', 'name': 'contrast_increase', 'params': {'contrast': 1.2}},
        {'category': 'enhancement', 'name': 'gamma_dark', 'params': {'gamma': 0.8}},
        
        # 滤波攻击
        {'category': 'filtering', 'name': 'gaussian_blur_light', 'params': {'kernel_size': 3, 'sigma': 0.5}},
        {'category': 'filtering', 'name': 'median_filter_light', 'params': {'kernel_size': 3}},
    ]
    
    results = {}
    for attack in key_attacks:
        category = attack['category']
        name = attack['name']
        params = attack['params']
        
        if category not in results:
            results[category] = []
        
        try:
            # 应用攻击
            attacked_image = robustness_suite.apply_attack(watermarked_image, name, params)
            
            # 提取水印 (降低阈值)
            detected_text, correlation, extraction_stats = watermark_system.extract_watermark(
                attacked_image, embedding_info, similarity_threshold=0.25
            )
            
            success = extraction_stats['is_present']
            results[category].append({
                'name': name,
                'success': success,
                'correlation': correlation,
                'detection_rate': extraction_stats['detection_rate']
            })
            
            status = "✓" if success else "✗"
            print(f"{status} {name:25} | 相关系数: {correlation:6.3f} | 检测率: {extraction_stats['detection_rate']:5.1%}")
            
        except Exception as e:
            print(f"✗ {name:25} | 错误: {e}")
            results[category].append({
                'name': name,
                'success': False,
                'correlation': 0.0,
                'error': str(e)
            })
    
    # 统计结果
    print(f"\n=== 攻击类别总结 ===")
    for category, attacks in results.items():
        success_count = sum(1 for a in attacks if a.get('success', False))
        total_count = len(attacks)
        success_rate = success_count / total_count * 100
        
        avg_correlation = np.mean([a.get('correlation', 0) for a in attacks if 'correlation' in a])
        
        print(f"{category:12} | 成功率: {success_rate:5.1f}% ({success_count}/{total_count}) | 平均相关系数: {avg_correlation:.3f}")
    
    return results

if __name__ == "__main__":
    print("创建测试图像...")
    create_test_images()
    
    print("\n运行重点鲁棒性测试...")
    results = run_focused_robustness_test()
    
    print("\n实验完成！")
