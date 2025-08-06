"""
数字水印实验评估模块
用于系统性地评估水印算法的性能

@author: Homework Project 2
@date: 2025-08-06
"""

import numpy as np
import cv2
import os
import json
import time
from typing import Dict, List, Tuple, Any
import matplotlib.pyplot as plt
import seaborn as sns
from pathlib import Path
import pandas as pd

from watermark_core import DCTWatermark, calculate_image_quality_metrics
from robustness_test import RobustnessTestSuite


class WatermarkEvaluator:
    """
    数字水印评估器
    """
    
    def __init__(self, output_dir: str = "results"):
        """
        初始化评估器
        
        Args:
            output_dir: 结果输出目录
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        
        # 创建子目录
        (self.output_dir / "images").mkdir(exist_ok=True)
        (self.output_dir / "plots").mkdir(exist_ok=True)
        (self.output_dir / "data").mkdir(exist_ok=True)
        
        self.watermark_system = DCTWatermark()
        self.robustness_suite = RobustnessTestSuite()
        
    def load_test_images(self, image_dir: str) -> List[Tuple[str, np.ndarray]]:
        """
        加载测试图像
        
        Args:
            image_dir: 图像目录路径
            
        Returns:
            图像列表 [(文件名, 图像数据), ...]
        """
        images = []
        supported_formats = ['.jpg', '.jpeg', '.png', '.bmp', '.tiff']
        
        image_path = Path(image_dir)
        if not image_path.exists():
            print(f"图像目录不存在: {image_dir}")
            return images
            
        for file_path in image_path.iterdir():
            if file_path.suffix.lower() in supported_formats:
                try:
                    image = cv2.imread(str(file_path))
                    if image is not None:
                        images.append((file_path.name, image))
                        print(f"加载图像: {file_path.name}, 尺寸: {image.shape}")
                except Exception as e:
                    print(f"加载图像失败 {file_path.name}: {e}")
        
        if not images:
            print("未找到有效的测试图像，将生成合成测试图像")
            images = self._generate_synthetic_images()
            
        return images
    
    def _generate_synthetic_images(self) -> List[Tuple[str, np.ndarray]]:
        """
        生成合成测试图像
        
        Returns:
            合成图像列表
        """
        images = []
        
        # 生成不同类型的测试图像
        sizes = [(512, 512), (256, 256), (1024, 768)]
        
        for i, (width, height) in enumerate(sizes):
            # 1. 渐变图像
            gradient = np.zeros((height, width, 3), dtype=np.uint8)
            for x in range(width):
                gradient[:, x] = [int(255 * x / width), int(255 * (1 - x / width)), 128]
            images.append((f"gradient_{width}x{height}.png", gradient))
            
            # 2. 棋盘图案
            checker = np.zeros((height, width, 3), dtype=np.uint8)
            block_size = 32
            for y in range(0, height, block_size):
                for x in range(0, width, block_size):
                    if (x // block_size + y // block_size) % 2 == 0:
                        checker[y:y+block_size, x:x+block_size] = [255, 255, 255]
            images.append((f"checker_{width}x{height}.png", checker))
            
            # 3. 随机纹理
            texture = np.random.randint(0, 256, (height, width, 3), dtype=np.uint8)
            images.append((f"texture_{width}x{height}.png", texture))
        
        # 保存合成图像
        for name, image in images:
            cv2.imwrite(str(self.output_dir / "images" / name), image)
            
        return images
    
    def evaluate_invisibility(self, original_image: np.ndarray, watermarked_image: np.ndarray) -> Dict[str, float]:
        """
        评估水印的不可见性
        
        Args:
            original_image: 原始图像
            watermarked_image: 含水印图像
            
        Returns:
            不可见性评估指标
        """
        metrics = calculate_image_quality_metrics(original_image, watermarked_image)
        
        # 添加额外的感知质量指标
        # 计算结构相似性指数的变化
        def calculate_local_ssim(img1, img2, window_size=11):
            """计算局部SSIM"""
            from skimage.metrics import structural_similarity
            return structural_similarity(img1, img2, win_size=window_size, multichannel=True)
        
        try:
            local_ssim = calculate_local_ssim(original_image, watermarked_image)
            metrics['Local_SSIM'] = local_ssim
        except:
            metrics['Local_SSIM'] = metrics['SSIM']
        
        # 计算视觉失真度
        visual_distortion = np.mean(np.abs(original_image.astype(np.float32) - watermarked_image.astype(np.float32)))
        metrics['Visual_Distortion'] = visual_distortion
        
        return metrics
    
    def evaluate_robustness(self, watermarked_image: np.ndarray, embedding_info: Dict,
                          test_categories: List[str] = None) -> Dict[str, Any]:
        """
        评估水印的鲁棒性
        
        Args:
            watermarked_image: 含水印图像
            embedding_info: 水印嵌入信息
            test_categories: 要测试的攻击类别
            
        Returns:
            鲁棒性评估结果
        """
        if test_categories is None:
            test_categories = ['noise_attacks', 'compression_attacks', 'geometric_attacks', 
                             'enhancement_attacks', 'filtering_attacks', 'combined_attacks']
        
        test_configs = self.robustness_suite.get_test_configurations()
        results = {}
        
        for category in test_categories:
            if category not in test_configs:
                continue
                
            category_results = []
            
            for test_config in test_configs[category]:
                attack_name = test_config['name']
                attack_params = test_config['params']
                
                try:
                    # 应用攻击
                    attacked_image = self.robustness_suite.apply_attack(
                        watermarked_image, attack_name, attack_params
                    )
                    
                    # 提取水印
                    start_time = time.time()
                    detected_text, correlation, extraction_stats = self.watermark_system.extract_watermark(
                        attacked_image, embedding_info
                    )
                    extraction_time = time.time() - start_time
                    
                    # 记录结果
                    test_result = {
                        'attack_name': attack_name,
                        'attack_params': attack_params,
                        'detected_text': detected_text,
                        'correlation': correlation,
                        'is_present': extraction_stats['is_present'],
                        'detection_rate': extraction_stats['detection_rate'],
                        'extraction_time': extraction_time,
                        'mean_response': extraction_stats['mean_response'],
                        'std_response': extraction_stats['std_response']
                    }
                    
                    category_results.append(test_result)
                    
                except Exception as e:
                    print(f"攻击测试失败 {attack_name}: {e}")
                    category_results.append({
                        'attack_name': attack_name,
                        'attack_params': attack_params,
                        'error': str(e)
                    })
            
            results[category] = category_results
        
        return results
    
    def run_comprehensive_evaluation(self, image_list: List[Tuple[str, np.ndarray]], 
                                   watermark_texts: List[str] = None) -> Dict[str, Any]:
        """
        运行综合评估
        
        Args:
            image_list: 测试图像列表
            watermark_texts: 水印文本列表
            
        Returns:
            综合评估结果
        """
        if watermark_texts is None:
            watermark_texts = ["TestWatermark2025", "SecretMark", "DigitalCopyright"]
        
        comprehensive_results = {
            'evaluation_summary': {
                'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                'total_images': len(image_list),
                'watermark_texts': watermark_texts,
                'algorithm_params': {
                    'block_size': self.watermark_system.block_size,
                    'alpha': self.watermark_system.alpha,
                    'seed': self.watermark_system.seed
                }
            },
            'image_results': {}
        }
        
        total_invisibility_metrics = []
        total_robustness_results = []
        
        for img_name, original_image in image_list:
            print(f"\n=== 评估图像: {img_name} ===")
            
            image_results = {
                'image_info': {
                    'name': img_name,
                    'shape': original_image.shape,
                    'size_mb': original_image.nbytes / (1024 * 1024)
                },
                'watermark_tests': {}
            }
            
            for watermark_text in watermark_texts:
                print(f"  水印文本: {watermark_text}")
                
                # 嵌入水印
                start_time = time.time()
                watermarked_image, embedding_info = self.watermark_system.embed_watermark(
                    original_image, watermark_text
                )
                embedding_time = time.time() - start_time
                
                # 评估不可见性
                invisibility_metrics = self.evaluate_invisibility(original_image, watermarked_image)
                
                # 验证水印提取（无攻击）
                detected_text, correlation, extraction_stats = self.watermark_system.extract_watermark(
                    watermarked_image, embedding_info
                )
                
                # 评估鲁棒性
                robustness_results = self.evaluate_robustness(watermarked_image, embedding_info)
                
                # 汇总结果
                watermark_result = {
                    'watermark_text': watermark_text,
                    'embedding_time': embedding_time,
                    'invisibility_metrics': invisibility_metrics,
                    'baseline_extraction': {
                        'detected_text': detected_text,
                        'correlation': correlation,
                        'extraction_stats': extraction_stats
                    },
                    'robustness_results': robustness_results
                }
                
                image_results['watermark_tests'][watermark_text] = watermark_result
                
                # 收集全局统计
                total_invisibility_metrics.append(invisibility_metrics)
                total_robustness_results.append(robustness_results)
                
                # 保存示例图像
                output_name = f"{img_name.split('.')[0]}_{watermark_text}_watermarked.png"
                cv2.imwrite(str(self.output_dir / "images" / output_name), watermarked_image)
            
            comprehensive_results['image_results'][img_name] = image_results
        
        # 计算全局统计
        comprehensive_results['global_statistics'] = self._calculate_global_statistics(
            total_invisibility_metrics, total_robustness_results
        )
        
        # 保存结果
        self._save_results(comprehensive_results)
        
        return comprehensive_results
    
    def _calculate_global_statistics(self, invisibility_metrics: List[Dict], 
                                   robustness_results: List[Dict]) -> Dict[str, Any]:
        """
        计算全局统计信息
        
        Args:
            invisibility_metrics: 不可见性指标列表
            robustness_results: 鲁棒性结果列表
            
        Returns:
            全局统计信息
        """
        # 不可见性统计
        psnr_values = [m['PSNR'] for m in invisibility_metrics if np.isfinite(m['PSNR'])]
        ssim_values = [m['SSIM'] for m in invisibility_metrics]
        
        invisibility_stats = {
            'PSNR': {
                'mean': np.mean(psnr_values) if psnr_values else 0,
                'std': np.std(psnr_values) if psnr_values else 0,
                'min': np.min(psnr_values) if psnr_values else 0,
                'max': np.max(psnr_values) if psnr_values else 0
            },
            'SSIM': {
                'mean': np.mean(ssim_values),
                'std': np.std(ssim_values),
                'min': np.min(ssim_values),
                'max': np.max(ssim_values)
            }
        }
        
        # 鲁棒性统计
        robustness_stats = {}
        
        all_attacks = {}
        for result in robustness_results:
            for category, tests in result.items():
                for test in tests:
                    if 'error' not in test:
                        attack_name = test['attack_name']
                        if attack_name not in all_attacks:
                            all_attacks[attack_name] = []
                        all_attacks[attack_name].append({
                            'correlation': test['correlation'],
                            'is_present': test['is_present'],
                            'detection_rate': test['detection_rate']
                        })
        
        for attack_name, results in all_attacks.items():
            correlations = [r['correlation'] for r in results]
            detection_rates = [r['detection_rate'] for r in results]
            success_rates = [1 if r['is_present'] else 0 for r in results]
            
            robustness_stats[attack_name] = {
                'correlation': {
                    'mean': np.mean(correlations),
                    'std': np.std(correlations),
                    'min': np.min(correlations),
                    'max': np.max(correlations)
                },
                'detection_rate': {
                    'mean': np.mean(detection_rates),
                    'std': np.std(detection_rates)
                },
                'success_rate': np.mean(success_rates),
                'test_count': len(results)
            }
        
        return {
            'invisibility_statistics': invisibility_stats,
            'robustness_statistics': robustness_stats
        }
    
    def _save_results(self, results: Dict[str, Any]) -> None:
        """
        保存评估结果
        
        Args:
            results: 评估结果
        """
        # 保存JSON格式的详细结果
        results_file = self.output_dir / "data" / "evaluation_results.json"
        with open(results_file, 'w', encoding='utf-8') as f:
            json.dump(results, f, ensure_ascii=False, indent=2, default=str)
        
        print(f"详细结果已保存到: {results_file}")
        
        # 生成可视化图表
        self._generate_visualizations(results)
    
    def _generate_visualizations(self, results: Dict[str, Any]) -> None:
        """
        生成可视化图表
        
        Args:
            results: 评估结果
        """
        plt.style.use('default')
        
        # 1. 不可见性指标可视化
        self._plot_invisibility_metrics(results)
        
        # 2. 鲁棒性结果可视化
        self._plot_robustness_results(results)
        
        # 3. 综合性能雷达图
        self._plot_performance_radar(results)
    
    def _plot_invisibility_metrics(self, results: Dict[str, Any]) -> None:
        """绘制不可见性指标图表"""
        fig, axes = plt.subplots(2, 2, figsize=(12, 10))
        fig.suptitle('水印不可见性评估', fontsize=16)
        
        # 收集数据
        psnr_data = []
        ssim_data = []
        image_names = []
        
        for img_name, img_result in results['image_results'].items():
            for watermark_text, test_result in img_result['watermark_tests'].items():
                metrics = test_result['invisibility_metrics']
                if np.isfinite(metrics['PSNR']):
                    psnr_data.append(metrics['PSNR'])
                    ssim_data.append(metrics['SSIM'])
                    image_names.append(f"{img_name}_{watermark_text}")
        
        # PSNR分布
        axes[0, 0].hist(psnr_data, bins=15, alpha=0.7, color='skyblue', edgecolor='black')
        axes[0, 0].set_title('PSNR分布')
        axes[0, 0].set_xlabel('PSNR (dB)')
        axes[0, 0].set_ylabel('频次')
        axes[0, 0].axvline(np.mean(psnr_data), color='red', linestyle='--', 
                          label=f'均值: {np.mean(psnr_data):.2f}')
        axes[0, 0].legend()
        
        # SSIM分布
        axes[0, 1].hist(ssim_data, bins=15, alpha=0.7, color='lightgreen', edgecolor='black')
        axes[0, 1].set_title('SSIM分布')
        axes[0, 1].set_xlabel('SSIM')
        axes[0, 1].set_ylabel('频次')
        axes[0, 1].axvline(np.mean(ssim_data), color='red', linestyle='--',
                          label=f'均值: {np.mean(ssim_data):.3f}')
        axes[0, 1].legend()
        
        # PSNR vs SSIM散点图
        axes[1, 0].scatter(psnr_data, ssim_data, alpha=0.6, color='orange')
        axes[1, 0].set_title('PSNR vs SSIM')
        axes[1, 0].set_xlabel('PSNR (dB)')
        axes[1, 0].set_ylabel('SSIM')
        axes[1, 0].grid(True, alpha=0.3)
        
        # 质量等级分布
        quality_levels = []
        for psnr, ssim in zip(psnr_data, ssim_data):
            if psnr >= 40 and ssim >= 0.95:
                quality_levels.append('优秀')
            elif psnr >= 35 and ssim >= 0.90:
                quality_levels.append('良好')
            elif psnr >= 30 and ssim >= 0.85:
                quality_levels.append('一般')
            else:
                quality_levels.append('较差')
        
        quality_counts = pd.Series(quality_levels).value_counts()
        axes[1, 1].pie(quality_counts.values, labels=quality_counts.index, autopct='%1.1f%%',
                      colors=['#ff9999', '#66b3ff', '#99ff99', '#ffcc99'])
        axes[1, 1].set_title('图像质量等级分布')
        
        plt.tight_layout()
        plt.savefig(self.output_dir / "plots" / "invisibility_analysis.png", dpi=300, bbox_inches='tight')
        plt.close()
    
    def _plot_robustness_results(self, results: Dict[str, Any]) -> None:
        """绘制鲁棒性结果图表"""
        robustness_stats = results['global_statistics']['robustness_statistics']
        
        if not robustness_stats:
            return
        
        # 创建数据框
        attack_names = list(robustness_stats.keys())
        success_rates = [robustness_stats[name]['success_rate'] for name in attack_names]
        correlations = [robustness_stats[name]['correlation']['mean'] for name in attack_names]
        
        # 按攻击类型分组
        attack_categories = {
            'noise': [name for name in attack_names if 'noise' in name or 'salt_pepper' in name],
            'compression': [name for name in attack_names if 'jpeg' in name],
            'geometric': [name for name in attack_names if any(geo in name for geo in ['rotation', 'scaling', 'translation', 'crop'])],
            'enhancement': [name for name in attack_names if any(enh in name for enh in ['brightness', 'contrast', 'gamma'])],
            'filtering': [name for name in attack_names if any(filt in name for filt in ['blur', 'filter'])],
            'combined': [name for name in attack_names if any(comb in name for comb in ['print', 'histogram'])]
        }
        
        fig, axes = plt.subplots(2, 3, figsize=(18, 12))
        fig.suptitle('水印鲁棒性评估', fontsize=16)
        
        colors = ['#ff7f0e', '#2ca02c', '#d62728', '#9467bd', '#8c564b', '#e377c2']
        
        for idx, (category, attacks) in enumerate(attack_categories.items()):
            if not attacks:
                continue
                
            row = idx // 3
            col = idx % 3
            
            cat_success_rates = [robustness_stats[name]['success_rate'] for name in attacks if name in robustness_stats]
            cat_names = [name.replace('_', '\n') for name in attacks if name in robustness_stats]
            
            if cat_success_rates:
                bars = axes[row, col].bar(range(len(cat_names)), cat_success_rates, 
                                        color=colors[idx % len(colors)], alpha=0.7)
                axes[row, col].set_title(f'{category.capitalize()} Attacks')
                axes[row, col].set_ylabel('Success Rate')
                axes[row, col].set_xticks(range(len(cat_names)))
                axes[row, col].set_xticklabels(cat_names, rotation=45, ha='right', fontsize=8)
                axes[row, col].set_ylim(0, 1)
                axes[row, col].grid(True, alpha=0.3)
                
                # 添加数值标签
                for bar, rate in zip(bars, cat_success_rates):
                    height = bar.get_height()
                    axes[row, col].text(bar.get_x() + bar.get_width()/2., height + 0.01,
                                      f'{rate:.2f}', ha='center', va='bottom', fontsize=8)
        
        plt.tight_layout()
        plt.savefig(self.output_dir / "plots" / "robustness_analysis.png", dpi=300, bbox_inches='tight')
        plt.close()
    
    def _plot_performance_radar(self, results: Dict[str, Any]) -> None:
        """绘制性能雷达图"""
        # 计算各项性能指标
        invisibility_stats = results['global_statistics']['invisibility_statistics']
        robustness_stats = results['global_statistics']['robustness_statistics']
        
        # 定义评估维度
        categories = ['不可见性', '噪声鲁棒性', '压缩鲁棒性', '几何鲁棒性', '增强鲁棒性', '滤波鲁棒性']
        
        # 计算分数 (0-1)
        scores = []
        
        # 不可见性分数 (基于PSNR和SSIM)
        psnr_mean = invisibility_stats['PSNR']['mean']
        ssim_mean = invisibility_stats['SSIM']['mean']
        invisibility_score = min(1.0, (psnr_mean / 50.0 + ssim_mean) / 2)
        scores.append(invisibility_score)
        
        # 各类攻击的鲁棒性分数
        attack_groups = {
            'noise': ['gaussian_noise', 'salt_pepper'],
            'compression': ['jpeg'],
            'geometric': ['rotation', 'scaling', 'translation', 'crop'],
            'enhancement': ['brightness', 'contrast', 'gamma'],
            'filtering': ['blur', 'filter']
        }
        
        for group_attacks in attack_groups.values():
            group_scores = []
            for attack_name, stats in robustness_stats.items():
                if any(keyword in attack_name for keyword in group_attacks):
                    group_scores.append(stats['success_rate'])
            
            if group_scores:
                scores.append(np.mean(group_scores))
            else:
                scores.append(0.5)  # 默认中等分数
        
        # 绘制雷达图
        angles = np.linspace(0, 2 * np.pi, len(categories), endpoint=False)
        scores += scores[:1]  # 闭合图形
        angles = np.concatenate((angles, [angles[0]]))
        
        fig, ax = plt.subplots(figsize=(10, 10), subplot_kw=dict(projection='polar'))
        ax.plot(angles, scores, 'o-', linewidth=2, color='#1f77b4')
        ax.fill(angles, scores, alpha=0.25, color='#1f77b4')
        
        ax.set_xticks(angles[:-1])
        ax.set_xticklabels(categories, fontsize=12)
        ax.set_ylim(0, 1)
        ax.set_yticks([0.2, 0.4, 0.6, 0.8, 1.0])
        ax.set_yticklabels(['0.2', '0.4', '0.6', '0.8', '1.0'])
        ax.grid(True)
        
        plt.title('数字水印综合性能评估', size=16, fontweight='bold', pad=20)
        
        # 添加分数标注
        for angle, score, category in zip(angles[:-1], scores[:-1], categories):
            ax.text(angle, score + 0.05, f'{score:.2f}', 
                   horizontalalignment='center', fontsize=10, fontweight='bold')
        
        plt.savefig(self.output_dir / "plots" / "performance_radar.png", dpi=300, bbox_inches='tight')
        plt.close()
        
    def generate_summary_report(self, results: Dict[str, Any]) -> str:
        """
        生成总结报告
        
        Args:
            results: 评估结果
            
        Returns:
            报告文本
        """
        report = []
        report.append("# 数字水印系统评估报告")
        report.append("=" * 50)
        report.append("")
        
        # 基本信息
        summary = results['evaluation_summary']
        report.append(f"**评估时间**: {summary['timestamp']}")
        report.append(f"**测试图像数量**: {summary['total_images']}")
        report.append(f"**水印文本**: {', '.join(summary['watermark_texts'])}")
        report.append("")
        
        # 算法参数
        params = summary['algorithm_params']
        report.append("## 算法参数")
        report.append(f"- DCT块大小: {params['block_size']}x{params['block_size']}")
        report.append(f"- 嵌入强度系数: {params['alpha']}")
        report.append(f"- 随机种子: {params['seed']}")
        report.append("")
        
        # 不可见性评估
        invisibility_stats = results['global_statistics']['invisibility_statistics']
        report.append("## 不可见性评估")
        report.append(f"- 平均PSNR: {invisibility_stats['PSNR']['mean']:.2f} dB")
        report.append(f"- 平均SSIM: {invisibility_stats['SSIM']['mean']:.3f}")
        report.append(f"- PSNR范围: {invisibility_stats['PSNR']['min']:.2f} - {invisibility_stats['PSNR']['max']:.2f} dB")
        report.append(f"- SSIM范围: {invisibility_stats['SSIM']['min']:.3f} - {invisibility_stats['SSIM']['max']:.3f}")
        report.append("")
        
        # 鲁棒性评估
        robustness_stats = results['global_statistics']['robustness_statistics']
        report.append("## 鲁棒性评估")
        
        # 按类别统计
        attack_categories = {
            'noise': ['gaussian_noise', 'salt_pepper'],
            'compression': ['jpeg'],
            'geometric': ['rotation', 'scaling', 'translation', 'crop'],
            'enhancement': ['brightness', 'contrast', 'gamma'],
            'filtering': ['blur', 'filter']
        }
        
        for category, keywords in attack_categories.items():
            category_success_rates = []
            for attack_name, stats in robustness_stats.items():
                if any(keyword in attack_name for keyword in keywords):
                    category_success_rates.append(stats['success_rate'])
            
            if category_success_rates:
                avg_success_rate = np.mean(category_success_rates)
                report.append(f"- {category.capitalize()}攻击成功率: {avg_success_rate:.1%}")
        
        report.append("")
        
        # 详细攻击结果
        report.append("## 详细攻击测试结果")
        for attack_name, stats in sorted(robustness_stats.items()):
            report.append(f"- **{attack_name}**: 成功率 {stats['success_rate']:.1%}, "
                         f"相关系数 {stats['correlation']['mean']:.3f}±{stats['correlation']['std']:.3f}")
        
        report.append("")
        
        # 结论
        report.append("## 评估结论")
        
        psnr_mean = invisibility_stats['PSNR']['mean']
        ssim_mean = invisibility_stats['SSIM']['mean']
        
        if psnr_mean >= 40 and ssim_mean >= 0.95:
            invisibility_level = "优秀"
        elif psnr_mean >= 35 and ssim_mean >= 0.90:
            invisibility_level = "良好"
        elif psnr_mean >= 30 and ssim_mean >= 0.85:
            invisibility_level = "一般"
        else:
            invisibility_level = "需要改进"
        
        overall_success_rate = np.mean([stats['success_rate'] for stats in robustness_stats.values()])
        
        if overall_success_rate >= 0.8:
            robustness_level = "优秀"
        elif overall_success_rate >= 0.6:
            robustness_level = "良好"
        elif overall_success_rate >= 0.4:
            robustness_level = "一般"
        else:
            robustness_level = "需要改进"
        
        report.append(f"1. **不可见性表现**: {invisibility_level}")
        report.append(f"2. **鲁棒性表现**: {robustness_level}")
        report.append(f"3. **整体成功率**: {overall_success_rate:.1%}")
        
        # 保存报告
        report_text = "\n".join(report)
        report_file = self.output_dir / "evaluation_summary.md"
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write(report_text)
        
        print(f"评估报告已保存到: {report_file}")
        
        return report_text
