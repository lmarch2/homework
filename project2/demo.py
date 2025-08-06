#!/usr/bin/env python3
"""
数字水印系统演示脚本
快速演示水印嵌入、提取和鲁棒性测试

@author: Homework Project 2
@date: 2025-08-06
"""

import sys
import os
import cv2
import numpy as np
from pathlib import Path

# 添加src目录到路径
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

from watermark_core import DCTWatermark, calculate_image_quality_metrics
from robustness_test import RobustnessTestSuite
from evaluation import WatermarkEvaluator


def create_demo_image():
    """创建演示图像"""
    # 创建一个彩色渐变图像
    width, height = 512, 512
    image = np.zeros((height, width, 3), dtype=np.uint8)
    
    for y in range(height):
        for x in range(width):
            # 创建彩色渐变
            r = int(255 * x / width)
            g = int(255 * y / height)
            b = int(255 * (1 - (x + y) / (width + height)))
            image[y, x] = [b, g, r]  # BGR格式
    
    return image


def demo_basic_functionality():
    """演示基本功能"""
    print("=== 数字水印系统演示 ===")
    print()
    
    # 确保目录存在
    Path("images").mkdir(exist_ok=True)
    Path("results").mkdir(exist_ok=True)
    
    # 1. 创建测试图像
    print("1. 创建测试图像...")
    demo_image = create_demo_image()
    cv2.imwrite("images/demo_original.png", demo_image)
    print("   测试图像已保存: images/demo_original.png")
    
    # 2. 初始化水印系统
    print("\n2. 初始化水印系统...")
    watermark_system = DCTWatermark(block_size=8, alpha=0.1, seed=42)
    print("   DCT块大小: 8x8")
    print("   嵌入强度: 0.1")
    print("   随机种子: 42")
    
    # 3. 嵌入水印
    print("\n3. 嵌入数字水印...")
    watermark_text = "DemoWatermark2025"
    print(f"   水印文本: {watermark_text}")
    
    watermarked_image, embedding_info = watermark_system.embed_watermark(demo_image, watermark_text)
    cv2.imwrite("images/demo_watermarked.png", watermarked_image)
    print("   含水印图像已保存: images/demo_watermarked.png")
    
    # 4. 计算图像质量
    print("\n4. 评估图像质量...")
    quality_metrics = calculate_image_quality_metrics(demo_image, watermarked_image)
    print(f"   PSNR: {quality_metrics['PSNR']:.2f} dB")
    print(f"   SSIM: {quality_metrics['SSIM']:.3f}")
    print(f"   MSE: {quality_metrics['MSE']:.2f}")
    
    # 5. 验证水印提取
    print("\n5. 验证水印提取...")
    detected_text, correlation, extraction_stats = watermark_system.extract_watermark(
        watermarked_image, embedding_info
    )
    print(f"   检测到的水印: {detected_text}")
    print(f"   相关系数: {correlation:.3f}")
    print(f"   检测成功: {'是' if extraction_stats['is_present'] else '否'}")
    
    return watermarked_image, embedding_info


def demo_robustness_test(watermarked_image, embedding_info):
    """演示鲁棒性测试"""
    print("\n=== 鲁棒性测试演示 ===")
    
    watermark_system = DCTWatermark()
    robustness_suite = RobustnessTestSuite()
    
    # 定义测试攻击
    test_attacks = [
        {'name': 'gaussian_noise_medium', 'params': {'std': 10}},
        {'name': 'jpeg_medium_quality', 'params': {'quality': 50}},
        {'name': 'rotation_small', 'params': {'angle': 5}},
        {'name': 'scaling_down', 'params': {'scale_x': 0.9, 'scale_y': 0.9}},
        {'name': 'brightness_increase', 'params': {'brightness': 20}},
        {'name': 'gaussian_blur_medium', 'params': {'kernel_size': 5, 'sigma': 1.0}},
    ]
    
    success_count = 0
    
    for i, attack in enumerate(test_attacks, 1):
        print(f"\n{i}. 测试 {attack['name']}...")
        
        try:
            # 应用攻击
            attacked_image = robustness_suite.apply_attack(
                watermarked_image, attack['name'], attack['params']
            )
            
            # 保存攻击后的图像
            output_file = f"images/demo_attacked_{attack['name']}.png"
            cv2.imwrite(output_file, attacked_image)
            
            # 提取水印
            detected_text, correlation, extraction_stats = watermark_system.extract_watermark(
                attacked_image, embedding_info
            )
            
            success = extraction_stats['is_present']
            success_count += success
            
            status = "✓ 成功" if success else "✗ 失败"
            print(f"   结果: {status}")
            print(f"   相关系数: {correlation:.3f}")
            print(f"   检测率: {extraction_stats['detection_rate']:.1%}")
            print(f"   图像已保存: {output_file}")
            
        except Exception as e:
            print(f"   错误: {e}")
    
    print(f"\n鲁棒性测试总结: {success_count}/{len(test_attacks)} 成功 ({success_count/len(test_attacks)*100:.1f}%)")


def demo_comprehensive_evaluation():
    """演示综合评估"""
    print("\n=== 综合评估演示 ===")
    
    evaluator = WatermarkEvaluator("results")
    
    # 加载测试图像（如果没有会自动生成）
    image_list = evaluator.load_test_images("images")
    
    if len(image_list) < 3:
        print("   生成额外的测试图像...")
        # 生成更多测试图像
        additional_images = [
            ("natural_512x512.png", create_demo_image()),
            ("simple_pattern.png", create_simple_pattern()),
            ("texture_image.png", create_texture_image())
        ]
        
        for name, img in additional_images:
            cv2.imwrite(f"images/{name}", img)
            image_list.append((name, img))
    
    print(f"   使用 {len(image_list)} 张测试图像")
    
    # 运行快速评估（只使用一个水印文本和部分攻击）
    watermark_texts = ["QuickDemo2025"]
    
    print("   开始快速评估...")
    try:
        results = evaluator.run_comprehensive_evaluation(image_list[:2], watermark_texts)  # 只用前2张图像
        report = evaluator.generate_summary_report(results)
        print("   评估完成！结果保存在 results/ 目录中")
        
        # 显示关键结果
        stats = results['global_statistics']
        print(f"   平均PSNR: {stats['invisibility_statistics']['PSNR']['mean']:.2f} dB")
        print(f"   平均SSIM: {stats['invisibility_statistics']['SSIM']['mean']:.3f}")
        
    except Exception as e:
        print(f"   评估过程中出现错误: {e}")


def create_simple_pattern():
    """创建简单图案"""
    image = np.zeros((256, 256, 3), dtype=np.uint8)
    
    # 创建同心圆
    center = (128, 128)
    for r in range(20, 128, 20):
        color = [255 - r, r, 128]
        cv2.circle(image, center, r, color, 2)
    
    return image


def create_texture_image():
    """创建纹理图像"""
    image = np.random.randint(0, 256, (256, 256, 3), dtype=np.uint8)
    
    # 添加一些结构
    for i in range(0, 256, 32):
        cv2.line(image, (i, 0), (i, 255), (255, 255, 255), 1)
        cv2.line(image, (0, i), (255, i), (255, 255, 255), 1)
    
    return image


def main():
    """主演示函数"""
    print("数字水印系统演示")
    print("作者: Homework Project 2")
    print("日期: 2025-08-06")
    print("=" * 50)
    
    try:
        # 1. 基本功能演示
        watermarked_image, embedding_info = demo_basic_functionality()
        
        # 2. 鲁棒性测试演示
        demo_robustness_test(watermarked_image, embedding_info)
        
        # 3. 综合评估演示
        demo_comprehensive_evaluation()
        
        print("\n" + "=" * 50)
        print("演示完成！")
        print("生成的文件:")
        print("- images/: 包含原始图像、含水印图像和攻击后图像")
        print("- results/: 包含评估结果、图表和报告")
        print("=" * 50)
        
    except KeyboardInterrupt:
        print("\n演示被用户中断")
    except Exception as e:
        print(f"\n演示过程中发生错误: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
