
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime
import random

import logging

logger = logging.getLogger(__name__)


@dataclass
class Parameter:
    """معلمة قابلة للضبط"""
    name: str
    current_value: Any
    min_value: Any
    max_value: Any
    step: Any
    performance_impact: float  # 0-1
    last_adjusted: datetime = field(default_factory=datetime.now)
    adjustment_count: int = 0


@dataclass
class TuningResult:
    """نتيجة الضبط"""
    parameter: str
    old_value: Any
    new_value: Any
    performance_change: float
    successful: bool
    timestamp: datetime = field(default_factory=datetime.now)


class AutonomousTuner:
    """
    الضبط التلقائي المتقدم
    
    الميزات:
    - ضبط تلقائي للمعلمات
    - تحليل تأثير التغييرات
    - تراجع عن التغييرات غير المفيدة
    - تعلم أنماط الضبط الناجحة
    """
    
    def __init__(self):
        self._parameters: Dict[str, Parameter] = {}
        self._tuning_history: List[TuningResult] = []
        self._learning_rate = 0.1
        
        # تهيئة المعلمات الافتراضية
        self._init_default_parameters()
        
        logger.info("AutonomousTuner initialized")
    
    def _init_default_parameters(self):
        """تهيئة المعلمات الافتراضية"""
        
        self._parameters = {
            "concurrent_scans": Parameter(
                name="concurrent_scans",
                current_value=5,
                min_value=1,
                max_value=20,
                step=1,
                performance_impact=0.8
            ),
            "request_timeout": Parameter(
                name="request_timeout",
                current_value=30,
                min_value=10,
                max_value=120,
                step=5,
                performance_impact=0.6
            ),
            "retry_attempts": Parameter(
                name="retry_attempts",
                current_value=3,
                min_value=1,
                max_value=10,
                step=1,
                performance_impact=0.4
            ),
            "cache_ttl": Parameter(
                name="cache_ttl",
                current_value=300,
                min_value=60,
                max_value=3600,
                step=60,
                performance_impact=0.5
            ),
            "log_level": Parameter(
                name="log_level",
                current_value="INFO",
                min_value="DEBUG",
                max_value="ERROR",
                step=1,
                performance_impact=0.2
            )
        }
    
    async def tune_parameter(
        self,
        param_name: str,
    direction: str = "increase"
    ) -> TuningResult:
        """
        ضبط معلمة واحدة
        
        Args:
            param_name: اسم المعلمة
            direction: اتجاه الضبط (increase/decrease)
        
        Returns:
            نتيجة الضبط
        """
        if param_name not in self._parameters:
            raise ValueError(f"Parameter {param_name} not found")
        
        param = self._parameters[param_name]
        old_value = param.current_value
        
        # حساب القيمة الجديدة
        if direction == "increase":
            if isinstance(param.current_value, (int, float)):
                new_value = min(param.current_value + param.step, param.max_value)
            else:
                new_value = param.current_value
        elif direction == "decrease":
            if isinstance(param.current_value, (int, float)):
                new_value = max(param.current_value - param.step, param.min_value)
            else:
                new_value = param.current_value
        else:
            new_value = param.current_value
        
        # محاكاة تأثير الضبط
        performance_change = random.uniform(-0.1, 0.1) * param.performance_impact
        successful = performance_change > 0
        
        if successful:
            param.current_value = new_value
        
        param.adjustment_count += 1
        param.last_adjusted = datetime.now()
        
        result = TuningResult(
            parameter=param_name,
            old_value=old_value,
            new_value=new_value if successful else old_value,
            performance_change=performance_change,
            successful=successful
        )
        
        self._tuning_history.append(result)
        
        logger.info(f"Parameter tuned: {param_name} = {new_value} (success={successful})")
        return result
    
    async def optimize_parameters(
        self,
        performance_metrics: Dict[str, float]
    ) -> List[TuningResult]:
        """
        تحسين مجموعة من المعلمات بناءً على مقاييس الأداء
        
        Args:
            performance_metrics: مقاييس الأداء
        
        Returns:
            قائمة بنتائج الضبط
        """
        results = []
        
        # تحليل المقاييس لتحديد المعلمات المستهدفة
        if performance_metrics.get("response_time", 0) > 10:
            results.append(await self.tune_parameter("concurrent_scans", "decrease"))
            results.append(await self.tune_parameter("request_timeout", "increase"))
        
        if performance_metrics.get("error_rate", 0) > 0.1:
            results.append(await self.tune_parameter("retry_attempts", "increase"))
        
        if performance_metrics.get("cache_hit_rate", 0) < 0.3:
            results.append(await self.tune_parameter("cache_ttl", "increase"))
        
        # تحسين عشوائي إضافي (استكشاف)
        if random.random() < self._learning_rate:
            random_param = random.choice(list(self._parameters.keys()))
            direction = random.choice(["increase", "decrease"])
            results.append(await self.tune_parameter(random_param, direction))
        
        return results
    
    async def rollback(self, num_steps: int = 1) -> int:
        """
        تراجع عن آخر التغييرات
        
        Args:
            num_steps: عدد الخطوات للتراجع
        
        Returns:
            عدد التغييرات التي تم التراجع عنها
        """
        rolled_back = 0
        
        # جمع التغييرات السابقة
        recent_results = self._tuning_history[-num_steps:]
        
        for result in recent_results:
            if result.parameter in self._parameters:
                param = self._parameters[result.parameter]
                param.current_value = result.old_value
                rolled_back += 1
        
        logger.info(f"Rolled back {rolled_back} changes")
        return rolled_back
    
    async def get_parameter(self, param_name: str) -> Optional[Parameter]:
        """الحصول على معلمة"""
        return self._parameters.get(param_name)
    
    async def get_all_parameters(self) -> Dict[str, Any]:
        """الحصول على جميع المعلمات (قيم فقط)"""
        return {name: param.current_value for name, param in self._parameters.items()}
    
    async def get_tuning_history(self, limit: int = 50) -> List[Dict]:
        """الحصول على تاريخ الضبط"""
        history = [
            {
                "parameter": r.parameter,
                "old_value": r.old_value,
                "new_value": r.new_value,
                "performance_change": r.performance_change,
                "successful": r.successful,
                "timestamp": r.timestamp.isoformat()
            }
            for r in self._tuning_history[-limit:]
        ]
        return history
    
    async def get_statistics(self) -> Dict:
        """إحصائيات الضبط"""
        successful = len([r for r in self._tuning_history if r.successful])
        
        return {
            "total_tunings": len(self._tuning_history),
            "successful_tunings": successful,
            "success_rate": successful / len(self._tuning_history) if self._tuning_history else 0,
            "parameters_count": len(self._parameters),
            "most_tuned_parameter": max(
                self._parameters.values(),
                key=lambda x: x.adjustment_count,
                default=None
            ).name if self._parameters else None,
            "current_parameters": await self.get_all_parameters()
        }

