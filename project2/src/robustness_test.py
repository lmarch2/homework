
import numpy as np
import cv2
from typing import Tuple, Dict, List
import random
from scipy import ndimage
from skimage import transform, filters


class RobustnessAttacks:
    """
    图像攻击类，用于测试水印的鲁棒性
    
    包含常见的图像处理攻击：
    - 几何攻击：旋转、缩放、平移、剪切
    - 信号处理攻击：压缩、滤波、噪声
    - 图像处理攻击：对比度调整、亮度调整、伽马校正
    """
    
    @staticmethod
    def add_gaussian_noise(image: np.ndarray, mean: float = 0, std: float = 10) -> np.ndarray:
        """
        添加高斯噪声
        
        数学模型：
        I'(x,y) = I(x,y) + N(μ, σ²)
        
        Args:
            image: 输入图像
            mean: 噪声均值
            std: 噪声标准差
            
        Returns:
            添加噪声后的图像
        """
        noise = np.random.normal(mean, std, image.shape).astype(np.float32)
        noisy_image = image.astype(np.float32) + noise
        return np.clip(noisy_image, 0, 255).astype(np.uint8)
    
    @staticmethod
    def add_salt_pepper_noise(image: np.ndarray, salt_prob: float = 0.01, 
                             pepper_prob: float = 0.01) -> np.ndarray:
        """
        添加椒盐噪声
        
        Args:
            image: 输入图像
            salt_prob: 盐噪声概率
            pepper_prob: 胡椒噪声概率
            
        Returns:
            添加椒盐噪声后的图像
        """
        noisy_image = image.copy()
        
        # 添加盐噪声（白点）
        salt_mask = np.random.random(image.shape[:2]) < salt_prob
        noisy_image[salt_mask] = 255
        
        # 添加胡椒噪声（黑点）
        pepper_mask = np.random.random(image.shape[:2]) < pepper_prob
        noisy_image[pepper_mask] = 0
        
        return noisy_image
    
    @staticmethod
    def jpeg_compression(image: np.ndarray, quality: int = 50) -> np.ndarray:
        """
        JPEG压缩攻击
        
        Args:
            image: 输入图像
            quality: JPEG质量因子 (1-100)
            
        Returns:
            JPEG压缩后的图像
        """
        encode_param = [int(cv2.IMWRITE_JPEG_QUALITY), quality]
        _, encoded_img = cv2.imencode('.jpg', image, encode_param)
        compressed_image = cv2.imdecode(encoded_img, cv2.IMREAD_COLOR)
        return compressed_image
    
    @staticmethod
    def rotation(image: np.ndarray, angle: float) -> np.ndarray:
        """
        图像旋转
        
        旋转变换矩阵：
        R = [cos(θ) -sin(θ)]
            [sin(θ)  cos(θ)]
        
        Args:
            image: 输入图像
            angle: 旋转角度（度）
            
        Returns:
            旋转后的图像
        """
        height, width = image.shape[:2]
        center = (width // 2, height // 2)
        
        rotation_matrix = cv2.getRotationMatrix2D(center, angle, 1.0)
        rotated_image = cv2.warpAffine(image, rotation_matrix, (width, height), 
                                     borderMode=cv2.BORDER_CONSTANT, borderValue=(0, 0, 0))
        return rotated_image
    
    @staticmethod
    def scaling(image: np.ndarray, scale_x: float, scale_y: float) -> np.ndarray:
        """
        图像缩放
        
        缩放变换矩阵：
        S = [sx  0 ]
            [0  sy ]
        
        Args:
            image: 输入图像
            scale_x: x方向缩放因子
            scale_y: y方向缩放因子
            
        Returns:
            缩放后的图像
        """
        height, width = image.shape[:2]
        new_width = int(width * scale_x)
        new_height = int(height * scale_y)
        
        scaled_image = cv2.resize(image, (new_width, new_height), interpolation=cv2.INTER_LINEAR)
        
        # 如果缩放后尺寸不同，需要裁剪或填充到原始尺寸
        if new_width != width or new_height != height:
            result = np.zeros_like(image)
            
            # 计算放置位置（居中）
            start_x = max(0, (width - new_width) // 2)
            start_y = max(0, (height - new_height) // 2)
            end_x = min(width, start_x + new_width)
            end_y = min(height, start_y + new_height)
            
            # 计算源图像的对应区域
            src_start_x = max(0, (new_width - width) // 2)
            src_start_y = max(0, (new_height - height) // 2)
            src_end_x = src_start_x + (end_x - start_x)
            src_end_y = src_start_y + (end_y - start_y)
            
            result[start_y:end_y, start_x:end_x] = scaled_image[src_start_y:src_end_y, src_start_x:src_end_x]
            return result
        
        return scaled_image
    
    @staticmethod
    def translation(image: np.ndarray, dx: int, dy: int) -> np.ndarray:
        """
        图像平移
        
        平移变换矩阵：
        T = [1  0  dx]
            [0  1  dy]
        
        Args:
            image: 输入图像
            dx: x方向平移量
            dy: y方向平移量
            
        Returns:
            平移后的图像
        """
        height, width = image.shape[:2]
        translation_matrix = np.float32([[1, 0, dx], [0, 1, dy]])
        translated_image = cv2.warpAffine(image, translation_matrix, (width, height),
                                        borderMode=cv2.BORDER_CONSTANT, borderValue=(0, 0, 0))
        return translated_image
    
    @staticmethod
    def cropping(image: np.ndarray, crop_ratio: float = 0.1) -> np.ndarray:
        """
        图像裁剪
        
        Args:
            image: 输入图像
            crop_ratio: 裁剪比例（从边缘裁剪）
            
        Returns:
            裁剪后的图像（保持原始尺寸，裁剪部分填零）
        """
        height, width = image.shape[:2]
        crop_h = int(height * crop_ratio)
        crop_w = int(width * crop_ratio)
        
        # 创建裁剪后的图像（中心区域）
        cropped = image[crop_h:height-crop_h, crop_w:width-crop_w]
        
        # 创建与原图同样大小的结果图像
        result = np.zeros_like(image)
        
        # 将裁剪后的图像放置在中心
        start_h = crop_h
        start_w = crop_w
        end_h = start_h + cropped.shape[0]
        end_w = start_w + cropped.shape[1]
        
        result[start_h:end_h, start_w:end_w] = cropped
        
        return result
    
    @staticmethod
    def horizontal_flip(image: np.ndarray) -> np.ndarray:
        """
        水平翻转（镜像）
        
        Args:
            image: 输入图像
            
        Returns:
            水平翻转后的图像
        """
        return cv2.flip(image, 1)
    
    @staticmethod
    def vertical_flip(image: np.ndarray) -> np.ndarray:
        """
        垂直翻转（上下翻转）
        
        Args:
            image: 输入图像
            
        Returns:
            垂直翻转后的图像
        """
        return cv2.flip(image, 0)
    
    @staticmethod
    def brightness_adjustment(image: np.ndarray, brightness: int = 30) -> np.ndarray:
        """
        亮度调整
        
        线性亮度调整：
        I'(x,y) = I(x,y) + β
        
        Args:
            image: 输入图像
            brightness: 亮度调整值 (-100 到 100)
            
        Returns:
            亮度调整后的图像
        """
        adjusted = image.astype(np.float32) + brightness
        return np.clip(adjusted, 0, 255).astype(np.uint8)
    
    @staticmethod
    def contrast_adjustment(image: np.ndarray, contrast: float = 1.2) -> np.ndarray:
        """
        对比度调整
        
        线性对比度调整：
        I'(x,y) = α * I(x,y)
        
        Args:
            image: 输入图像
            contrast: 对比度系数 (0.5-2.0)
            
        Returns:
            对比度调整后的图像
        """
        adjusted = image.astype(np.float32) * contrast
        return np.clip(adjusted, 0, 255).astype(np.uint8)
    
    @staticmethod
    def gamma_correction(image: np.ndarray, gamma: float = 0.8) -> np.ndarray:
        """
        伽马校正
        
        伽马校正公式：
        I'(x,y) = 255 * (I(x,y)/255)^γ
        
        Args:
            image: 输入图像
            gamma: 伽马值
            
        Returns:
            伽马校正后的图像
        """
        # 构建查找表
        lookup_table = np.array([((i / 255.0) ** gamma) * 255 for i in np.arange(0, 256)]).astype(np.uint8)
        return cv2.LUT(image, lookup_table)
    
    @staticmethod
    def gaussian_blur(image: np.ndarray, kernel_size: int = 5, sigma: float = 1.0) -> np.ndarray:
        """
        高斯模糊
        
        高斯核函数：
        G(x,y) = (1/(2πσ²)) * e^(-(x²+y²)/(2σ²))
        
        Args:
            image: 输入图像
            kernel_size: 核大小
            sigma: 高斯参数
            
        Returns:
            模糊后的图像
        """
        return cv2.GaussianBlur(image, (kernel_size, kernel_size), sigma)
    
    @staticmethod
    def median_filter(image: np.ndarray, kernel_size: int = 5) -> np.ndarray:
        """
        中值滤波
        
        Args:
            image: 输入图像
            kernel_size: 滤波核大小
            
        Returns:
            滤波后的图像
        """
        return cv2.medianBlur(image, kernel_size)
    
    @staticmethod
    def histogram_equalization(image: np.ndarray) -> np.ndarray:
        """
        直方图均衡化
        
        累积分布函数：
        cdf(i) = ∑(j=0 to i) hist(j) / total_pixels
        
        Args:
            image: 输入图像
            
        Returns:
            直方图均衡化后的图像
        """
        if len(image.shape) == 3:
            # 彩色图像：在YUV空间对Y通道进行均衡化
            yuv = cv2.cvtColor(image, cv2.COLOR_BGR2YUV)
            yuv[:, :, 0] = cv2.equalizeHist(yuv[:, :, 0])
            return cv2.cvtColor(yuv, cv2.COLOR_YUV2BGR)
        else:
            # 灰度图像
            return cv2.equalizeHist(image)
    
    @staticmethod
    def print_attack(image: np.ndarray, dpi: int = 150) -> np.ndarray:
        """
        模拟打印-扫描攻击
        
        包含：
        1. 分辨率降低
        2. 噪声添加
        3. 轻微模糊
        
        Args:
            image: 输入图像
            dpi: 模拟打印分辨率
            
        Returns:
            模拟打印-扫描后的图像
        """
        height, width = image.shape[:2]
        
        # 根据DPI计算缩放因子
        base_dpi = 300  # 基准DPI
        scale_factor = dpi / base_dpi
        
        # 降低分辨率
        temp_h = int(height * scale_factor)
        temp_w = int(width * scale_factor)
        downscaled = cv2.resize(image, (temp_w, temp_h), interpolation=cv2.INTER_LINEAR)
        
        # 恢复原始尺寸
        restored = cv2.resize(downscaled, (width, height), interpolation=cv2.INTER_LINEAR)
        
        # 添加轻微噪声
        noise = np.random.normal(0, 2, restored.shape).astype(np.float32)
        noisy = restored.astype(np.float32) + noise
        noisy = np.clip(noisy, 0, 255).astype(np.uint8)
        
        # 轻微模糊
        blurred = cv2.GaussianBlur(noisy, (3, 3), 0.5)
        
        return blurred


class RobustnessTestSuite:
    """
    鲁棒性测试套件
    """
    
    def __init__(self):
        self.attacks = RobustnessAttacks()
        
    def get_test_configurations(self) -> Dict[str, List[Dict]]:
        """
        获取测试配置
        
        Returns:
            测试配置字典
        """
        return {
            'noise_attacks': [
                {'name': 'gaussian_noise_light', 'params': {'std': 5}},
                {'name': 'gaussian_noise_medium', 'params': {'std': 10}},
                {'name': 'gaussian_noise_heavy', 'params': {'std': 20}},
                {'name': 'salt_pepper_light', 'params': {'salt_prob': 0.005, 'pepper_prob': 0.005}},
                {'name': 'salt_pepper_medium', 'params': {'salt_prob': 0.01, 'pepper_prob': 0.01}},
                {'name': 'salt_pepper_heavy', 'params': {'salt_prob': 0.02, 'pepper_prob': 0.02}},
            ],
            'compression_attacks': [
                {'name': 'jpeg_high_quality', 'params': {'quality': 80}},
                {'name': 'jpeg_medium_quality', 'params': {'quality': 50}},
                {'name': 'jpeg_low_quality', 'params': {'quality': 20}},
                {'name': 'jpeg_very_low_quality', 'params': {'quality': 10}},
            ],
            'geometric_attacks': [
                {'name': 'rotation_small', 'params': {'angle': 1}},
                {'name': 'rotation_medium', 'params': {'angle': 5}},
                {'name': 'rotation_large', 'params': {'angle': 10}},
                {'name': 'scaling_up', 'params': {'scale_x': 1.1, 'scale_y': 1.1}},
                {'name': 'scaling_down', 'params': {'scale_x': 0.9, 'scale_y': 0.9}},
                {'name': 'scaling_non_uniform', 'params': {'scale_x': 1.1, 'scale_y': 0.9}},
                {'name': 'translation_small', 'params': {'dx': 5, 'dy': 5}},
                {'name': 'translation_medium', 'params': {'dx': 10, 'dy': 10}},
                {'name': 'translation_large', 'params': {'dx': 20, 'dy': 20}},
                {'name': 'crop_light', 'params': {'crop_ratio': 0.05}},
                {'name': 'crop_medium', 'params': {'crop_ratio': 0.1}},
                {'name': 'crop_heavy', 'params': {'crop_ratio': 0.15}},
            ],
            'enhancement_attacks': [
                {'name': 'brightness_increase', 'params': {'brightness': 20}},
                {'name': 'brightness_decrease', 'params': {'brightness': -20}},
                {'name': 'contrast_increase', 'params': {'contrast': 1.3}},
                {'name': 'contrast_decrease', 'params': {'contrast': 0.7}},
                {'name': 'gamma_bright', 'params': {'gamma': 1.2}},
                {'name': 'gamma_dark', 'params': {'gamma': 0.8}},
            ],
            'filtering_attacks': [
                {'name': 'gaussian_blur_light', 'params': {'kernel_size': 3, 'sigma': 0.5}},
                {'name': 'gaussian_blur_medium', 'params': {'kernel_size': 5, 'sigma': 1.0}},
                {'name': 'gaussian_blur_heavy', 'params': {'kernel_size': 7, 'sigma': 1.5}},
                {'name': 'median_filter_light', 'params': {'kernel_size': 3}},
                {'name': 'median_filter_medium', 'params': {'kernel_size': 5}},
                {'name': 'median_filter_heavy', 'params': {'kernel_size': 7}},
            ],
            'combined_attacks': [
                {'name': 'print_scan_150dpi', 'params': {'dpi': 150}},
                {'name': 'print_scan_100dpi', 'params': {'dpi': 100}},
                {'name': 'histogram_equalization', 'params': {}},
            ]
        }
    
    def apply_attack(self, image: np.ndarray, attack_name: str, params: dict) -> np.ndarray:
        """
        应用指定的攻击
        
        Args:
            image: 输入图像
            attack_name: 攻击名称
            params: 攻击参数
            
        Returns:
            攻击后的图像
        """
        attack_method_map = {
            'gaussian_noise_light': lambda img, p: self.attacks.add_gaussian_noise(img, **p),
            'gaussian_noise_medium': lambda img, p: self.attacks.add_gaussian_noise(img, **p),
            'gaussian_noise_heavy': lambda img, p: self.attacks.add_gaussian_noise(img, **p),
            'salt_pepper_light': lambda img, p: self.attacks.add_salt_pepper_noise(img, **p),
            'salt_pepper_medium': lambda img, p: self.attacks.add_salt_pepper_noise(img, **p),
            'salt_pepper_heavy': lambda img, p: self.attacks.add_salt_pepper_noise(img, **p),
            'jpeg_high_quality': lambda img, p: self.attacks.jpeg_compression(img, **p),
            'jpeg_medium_quality': lambda img, p: self.attacks.jpeg_compression(img, **p),
            'jpeg_low_quality': lambda img, p: self.attacks.jpeg_compression(img, **p),
            'jpeg_very_low_quality': lambda img, p: self.attacks.jpeg_compression(img, **p),
            'rotation_small': lambda img, p: self.attacks.rotation(img, **p),
            'rotation_medium': lambda img, p: self.attacks.rotation(img, **p),
            'rotation_large': lambda img, p: self.attacks.rotation(img, **p),
            'scaling_up': lambda img, p: self.attacks.scaling(img, **p),
            'scaling_down': lambda img, p: self.attacks.scaling(img, **p),
            'scaling_non_uniform': lambda img, p: self.attacks.scaling(img, **p),
            'translation_small': lambda img, p: self.attacks.translation(img, **p),
            'translation_medium': lambda img, p: self.attacks.translation(img, **p),
            'translation_large': lambda img, p: self.attacks.translation(img, **p),
            'crop_light': lambda img, p: self.attacks.cropping(img, **p),
            'crop_medium': lambda img, p: self.attacks.cropping(img, **p),
            'crop_heavy': lambda img, p: self.attacks.cropping(img, **p),
            'horizontal_flip': lambda img, p: self.attacks.horizontal_flip(img),
            'vertical_flip': lambda img, p: self.attacks.vertical_flip(img),
            'brightness_increase': lambda img, p: self.attacks.brightness_adjustment(img, **p),
            'brightness_decrease': lambda img, p: self.attacks.brightness_adjustment(img, **p),
            'contrast_increase': lambda img, p: self.attacks.contrast_adjustment(img, **p),
            'contrast_decrease': lambda img, p: self.attacks.contrast_adjustment(img, **p),
            'gamma_bright': lambda img, p: self.attacks.gamma_correction(img, **p),
            'gamma_dark': lambda img, p: self.attacks.gamma_correction(img, **p),
            'gaussian_blur_light': lambda img, p: self.attacks.gaussian_blur(img, **p),
            'gaussian_blur_medium': lambda img, p: self.attacks.gaussian_blur(img, **p),
            'gaussian_blur_heavy': lambda img, p: self.attacks.gaussian_blur(img, **p),
            'median_filter_light': lambda img, p: self.attacks.median_filter(img, **p),
            'median_filter_medium': lambda img, p: self.attacks.median_filter(img, **p),
            'median_filter_heavy': lambda img, p: self.attacks.median_filter(img, **p),
            'print_scan_150dpi': lambda img, p: self.attacks.print_attack(img, **p),
            'print_scan_100dpi': lambda img, p: self.attacks.print_attack(img, **p),
            'histogram_equalization': lambda img, p: self.attacks.histogram_equalization(img),
        }
        
        if attack_name in attack_method_map:
            return attack_method_map[attack_name](image, params)
        else:
            raise ValueError(f"未知的攻击类型: {attack_name}")
