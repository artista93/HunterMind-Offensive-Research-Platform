
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime
import math

import logging

logger = logging.getLogger(__name__)


@dataclass
class LearningParameters:
    """معلمات التعلم"""
    learning_rate: float = 0.01
    batch_size: int = 32
    exploration_rate: float = 0.1
    discount_factor: float = 0.95
    update_frequency: int = 100


class AdaptiveLearning:
    """
    التعلم التكيفي المتقدم
    
    الميزات:
    - ضبط معلمات التعلم تلقائياً
    - تكيف مع معدلات النجاح
    - تعديل سرعة التعلم
    - توازن استكشاف/استغلال ديناميكي
    """
    
    def __init__(self, initial_params: LearningParameters = None):
        self._params = initial_params or LearningParameters()
        self._performance_history: List[float] = []
        self._adjustment_history: List[Dict] = []
        
        # حدود المعلمات
        self._param_bounds = {
            "learning_rate": (0.001, 0.5),
            "batch_size": (8, 256),
            "exploration_rate": (0.01, 0.5),
            "discount_factor": (0.8, 0.99),
            "update_frequency": (10, 1000)
        }
        
        logger.info("AdaptiveLearning initialized")
    
    async def adapt_parameters(self, performance_metrics: Dict[str, float]) -> LearningParameters:
        """
        تكييف معلمات التعلم بناءً على مقاييس الأداء
        
        Args:
            performance_metrics: مقاييس الأداء
        
        Returns:
            المعلمات المعدلة
        """
        old_params = self._params
        
        # تسجيل الأداء
        if "success_rate" in performance_metrics:
            self._performance_history.append(performance_metrics["success_rate"])
            if len(self._performance_history) > 100:
                self._performance_history.pop(0)
        
        # تحليل الاتجاه
        trend = await self._calculate_trend()
        
        # ضبط learning_rate
        if trend > 0.05:
            # تحسن سريع - زيادة معدل التعلم
            self._params.learning_rate = min(
                self._params.learning_rate * 1.2,
                self._param_bounds["learning_rate"][1]
            )
        elif trend < -0.05:
            # تدهور - تقليل معدل التعلم
            self._params.learning_rate = max(
                self._params.learning_rate * 0.8,
                self._param_bounds["learning_rate"][0]
            )
        
        # ضبط exploration_rate
        avg_performance = sum(self._performance_history[-20:]) / min(20, len(self._performance_history)) if self._performance_history else 0
        
        if avg_performance > 0.8:
            # أداء جيد - تقليل الاستكشاف
            self._params.exploration_rate = max(
                self._params.exploration_rate * 0.9,
                self._param_bounds["exploration_rate"][0]
            )
        elif avg_performance < 0.4:
            # أداء ضعيف - زيادة الاستكشاف
            self._params.exploration_rate = min(
                self._params.exploration_rate * 1.1,
                self._param_bounds["exploration_rate"][1]
            )
        
        # ضبط batch_size بناءً على استقرار الأداء
        if len(self._performance_history) > 10:
            variance = await self._calculate_variance(self._performance_history[-10:])
            if variance > 0.1:
                # أداء غير مستقر - زيادة batch_size
                self._params.batch_size = min(
                    int(self._params.batch_size * 1.2),
                    self._param_bounds["batch_size"][1]
                )
            elif variance < 0.02:
                # أداء مستقر - تقليل batch_size لتعلم أسرع
                self._params.batch_size = max(
                    int(self._params.batch_size * 0.8),
                    self._param_bounds["batch_size"][0]
                )
        
        # تسجيل التعديل
        self._adjustment_history.append({
            "timestamp": datetime.now().isoformat(),
            "old_params": {
                "learning_rate": old_params.learning_rate,
                "batch_size": old_params.batch_size,
                "exploration_rate": old_params.exploration_rate,
                "discount_factor": old_params.discount_factor,
                "update_frequency": old_params.update_frequency
            },
            "new_params": {
                "learning_rate": self._params.learning_rate,
                "batch_size": self._params.batch_size,
                "exploration_rate": self._params.exploration_rate,
                "discount_factor": self._params.discount_factor,
                "update_frequency": self._params.update_frequency
            },
            "trend": trend,
            "avg_performance": avg_performance
        })
        
        logger.debug(f"Parameters adapted: lr={self._params.learning_rate:.4f}, eps={self._params.exploration_rate:.3f}")
        
        return self._params
    
    async def _calculate_trend(self) -> float:
        """حساب اتجاه الأداء"""
        if len(self._performance_history) < 10:
            return 0.0
        
        recent = self._performance_history[-10:]
        # الانحدار الخطي البسيط
        x = list(range(len(recent)))
        n = len(x)
        
        sum_x = sum(x)
        sum_y = sum(recent)
        sum_xy = sum(x[i] * recent[i] for i in range(n))
        sum_x2 = sum(x[i] * x[i] for i in range(n))
        
        denominator = n * sum_x2 - sum_x * sum_x
        if denominator == 0:
            return 0.0
        
        slope = (n * sum_xy - sum_x * sum_y) / denominator
        return slope / 10  # تطبيع
    
    async def _calculate_variance(self, values: List[float]) -> float:
        """حساب التباين"""
        if not values:
            return 0.0
        
        mean = sum(values) / len(values)
        variance = sum((v - mean) ** 2 for v in values) / len(values)
        return variance
    
    async def get_optimal_batch_size(self, data_size: int) -> int:
        """
        حساب حجم الدفعة الأمثل
        
        Args:
            data_size: حجم البيانات الإجمالي
        
        Returns:
            حجم الدفعة الأمثل
        """
        # حجم الدفعة المثالي = الجذر التربيعي لحجم البيانات
        optimal = int(math.sqrt(data_size))
        
        # تقييد بالحدود
        optimal = max(self._param_bounds["batch_size"][0], min(optimal, self._param_bounds["batch_size"][1]))
        
        return optimal
    
    async def get_current_parameters(self) -> LearningParameters:
        """الحصول على المعلمات الحالية"""
        return self._params
    
    async def get_adaptation_history(self, limit: int = 20) -> List[Dict]:
        """الحصول على تاريخ التكيفات"""
        return self._adjustment_history[-limit:]
    
    async def get_statistics(self) -> Dict:
        """إحصائيات التعلم التكيفي"""
        return {
            "current_parameters": {
                "learning_rate": self._params.learning_rate,
                "batch_size": self._params.batch_size,
                "exploration_rate": self._params.exploration_rate,
                "discount_factor": self._params.discount_factor,
                "update_frequency": self._params.update_frequency
            },
            "performance_history_size": len(self._performance_history),
            "average_performance": sum(self._performance_history[-20:]) / min(20, len(self._performance_history)) if self._performance_history else 0,
            "total_adaptations": len(self._adjustment_history),
            "param_bounds": self._param_bounds
        }

