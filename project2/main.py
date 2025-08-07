#!/usr/bin/env python3
import argparse
import cv2
import json
import sys
import os
from pathlib import Path

# 添加src目录到路径
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

from watermark_core import DCTWatermark, calculate_image_quality_metrics
from robustness_test import RobustnessTestSuite
from evaluation import WatermarkEvaluator


def embed_watermark_cmd(args):
    """嵌入水印命令"""
    print(f"嵌入水印到图像: {args.input}")
    
    # 加载图像
    image = cv2.imread(args.input)
    if image is None:
        print(f"错误: 无法加载图像 {args.input}")
        return False
    
    # 创建水印系统
    watermark_system = DCTWatermark(
        block_size=args.block_size,
        alpha=args.alpha,
        seed=args.seed
    )
    
    # 嵌入水印
    print(f"嵌入水印文本: {args.watermark}")
    watermarked_image, embedding_info = watermark_system.embed_watermark(image, args.watermark)
    
    # 保存含水印图像
    cv2.imwrite(args.output, watermarked_image)
    print(f"含水印图像已保存到: {args.output}")
    
    # 计算质量指标
    quality_metrics = calculate_image_quality_metrics(image, watermarked_image)
    print(f"图像质量指标:")
    print(f"  PSNR: {quality_metrics['PSNR']:.2f} dB")
    print(f"  SSIM: {quality_metrics['SSIM']:.3f}")
    print(f"  MSE: {quality_metrics['MSE']:.2f}")
    
    # 保存嵌入信息
    info_file = args.output.replace('.png', '_info.json').replace('.jpg', '_info.json')
    with open(info_file, 'w') as f:
        json.dump(embedding_info, f, indent=2, default=str)
    print(f"嵌入信息已保存到: {info_file}")
    
    return True


def extract_watermark_cmd(args):
    """提取水印命令"""
    print(f"从图像中提取水印: {args.input}")
    
    # 加载含水印图像
    watermarked_image = cv2.imread(args.input)
    if watermarked_image is None:
        print(f"错误: 无法加载图像 {args.input}")
        return False
    
    # 加载嵌入信息
    if not os.path.exists(args.info):
        print(f"错误: 嵌入信息文件不存在 {args.info}")
        return False
    
    with open(args.info, 'r') as f:
        embedding_info = json.load(f)
    
    # 创建水印系统
    watermark_system = DCTWatermark()
    
    # 提取水印
    detected_text, correlation, extraction_stats = watermark_system.extract_watermark(
        watermarked_image, embedding_info, args.threshold
    )
    
    print(f"提取结果:")
    print(f"  检测到的水印: {detected_text}")
    print(f"  相关系数: {correlation:.3f}")
    print(f"  检测阈值: {args.threshold}")
    print(f"  水印存在: {'是' if extraction_stats['is_present'] else '否'}")
    print(f"  检测率: {extraction_stats['detection_rate']:.1%}")
    print(f"  平均响应: {extraction_stats['mean_response']:.3f}")
    
    return True


def test_robustness_cmd(args):
    """测试鲁棒性命令"""
    print(f"测试水印鲁棒性: {args.input}")
    
    # 加载含水印图像
    watermarked_image = cv2.imread(args.input)
    if watermarked_image is None:
        print(f"错误: 无法加载图像 {args.input}")
        return False
    
    # 加载嵌入信息
    if not os.path.exists(args.info):
        print(f"错误: 嵌入信息文件不存在 {args.info}")
        return False
    
    with open(args.info, 'r') as f:
        embedding_info = json.load(f)
    
    # 创建测试系统
    watermark_system = DCTWatermark()
    robustness_suite = RobustnessTestSuite()
    
    # 选择要测试的攻击
    if args.attacks:
        test_categories = args.attacks.split(',')
    else:
        test_categories = ['noise_attacks', 'compression_attacks', 'geometric_attacks']
    
    print(f"测试攻击类别: {', '.join(test_categories)}")
    
    # 执行鲁棒性测试
    test_configs = robustness_suite.get_test_configurations()
    
    success_count = 0
    total_count = 0
    
    for category in test_categories:
        if category not in test_configs:
            print(f"警告: 未知的攻击类别 {category}")
            continue
        
        print(f"\n=== {category} ===")
        
        for test_config in test_configs[category]:
            attack_name = test_config['name']
            attack_params = test_config['params']
            
            try:
                # 应用攻击
                attacked_image = robustness_suite.apply_attack(
                    watermarked_image, attack_name, attack_params
                )
                
                # 提取水印
                detected_text, correlation, extraction_stats = watermark_system.extract_watermark(
                    attacked_image, embedding_info
                )
                
                is_success = extraction_stats['is_present']
                success_count += 1 if is_success else 0
                total_count += 1
                
                status = "✓" if is_success else "✗"
                print(f"  {status} {attack_name}: 相关系数 {correlation:.3f}, "
                      f"检测率 {extraction_stats['detection_rate']:.1%}")
                
                # 保存攻击后的图像
                if args.save_attacked:
                    output_dir = Path(args.input).parent / "attacked_images"
                    output_dir.mkdir(exist_ok=True)
                    output_file = output_dir / f"{Path(args.input).stem}_{attack_name}.png"
                    cv2.imwrite(str(output_file), attacked_image)
                
            except Exception as e:
                print(f"  ✗ {attack_name}: 测试失败 - {e}")
                total_count += 1
    
    print(f"\n总体鲁棒性: {success_count}/{total_count} ({success_count/total_count*100:.1f}%)")
    
    return True


def comprehensive_evaluation_cmd(args):
    """综合评估命令"""
    print("开始综合评估...")
    
    # 创建评估器
    evaluator = WatermarkEvaluator(args.output_dir)
    
    # 加载测试图像
    image_list = evaluator.load_test_images(args.image_dir)
    
    if not image_list:
        print("错误: 未找到测试图像")
        return False
    
    # 设置水印文本
    watermark_texts = args.watermarks.split(',') if args.watermarks else ["TestWatermark2025"]
    
    print(f"测试图像数量: {len(image_list)}")
    print(f"水印文本: {', '.join(watermark_texts)}")
    
    # 运行评估
    results = evaluator.run_comprehensive_evaluation(image_list, watermark_texts)
    
    # 生成报告
    report = evaluator.generate_summary_report(results)
    print("\n" + "="*50)
    print("评估完成!")
    print(f"结果保存在: {args.output_dir}")
    print("="*50)
    
    return True


def main():
    """主函数"""
    parser = argparse.ArgumentParser(description="数字水印系统")
    subparsers = parser.add_subparsers(dest='command', help='可用命令')
    
    # 嵌入水印命令
    embed_parser = subparsers.add_parser('embed', help='嵌入水印')
    embed_parser.add_argument('input', help='输入图像路径')
    embed_parser.add_argument('output', help='输出图像路径')
    embed_parser.add_argument('watermark', help='水印文本')
    embed_parser.add_argument('--block-size', type=int, default=8, help='DCT块大小')
    embed_parser.add_argument('--alpha', type=float, default=0.1, help='嵌入强度')
    embed_parser.add_argument('--seed', type=int, default=42, help='随机种子')
    
    # 提取水印命令
    extract_parser = subparsers.add_parser('extract', help='提取水印')
    extract_parser.add_argument('input', help='含水印图像路径')
    extract_parser.add_argument('info', help='嵌入信息文件路径')
    extract_parser.add_argument('--threshold', type=float, default=0.6, help='检测阈值')
    
    # 鲁棒性测试命令
    test_parser = subparsers.add_parser('test', help='测试鲁棒性')
    test_parser.add_argument('input', help='含水印图像路径')
    test_parser.add_argument('info', help='嵌入信息文件路径')
    test_parser.add_argument('--attacks', help='攻击类别(逗号分隔)')
    test_parser.add_argument('--save-attacked', action='store_true', help='保存攻击后的图像')
    
    # 综合评估命令
    eval_parser = subparsers.add_parser('evaluate', help='综合评估')
    eval_parser.add_argument('image_dir', help='测试图像目录')
    eval_parser.add_argument('--output-dir', default='results', help='输出目录')
    eval_parser.add_argument('--watermarks', help='水印文本列表(逗号分隔)')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    # 执行对应命令
    success = False
    if args.command == 'embed':
        success = embed_watermark_cmd(args)
    elif args.command == 'extract':
        success = extract_watermark_cmd(args)
    elif args.command == 'test':
        success = test_robustness_cmd(args)
    elif args.command == 'evaluate':
        success = comprehensive_evaluation_cmd(args)
    
    if not success:
        sys.exit(1)


if __name__ == "__main__":
    main()
