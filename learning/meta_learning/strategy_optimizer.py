
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from collections import defaultdict
import random

import logging

logger = logging.getLogger(__name__)


@dataclass
class StrategyParameter:
    """معلمة استراتيجية"""
    name: str
    current_value: Any
    min_value: Any
    max_value: Any
    step: Any
    performance_impact: float


@dataclass
class StrategyProfile:
    """ملف استراتيجية"""
    name: str
    parameters: Dict[str, StrategyParameter]
    performance_history: List[float]
    average_performance: float
    last_updated: datetime = field(default_factory=datetime.now)


class StrategyOptimizer:
    """
    محسن الاستراتيجيات المتقدم
    
    الميزات:
    - تحسين معلمات الاستراتيجيات
    - اختبار A/B للاستراتيجيات المختلفة
    - اختيار أفضل استراتيجية للموقف
    - تكيف بناءً على الملاحظات
    """
    
    def __init__(self):
        self._strategies: Dict[str, StrategyProfile] = {}
        self._optimization_history: List[Dict] = []
        
        # تهيئة الاستراتيجيات الافتراضية
        self._init_default_strategies()
        
        logger.info("StrategyOptimizer initialized")
    
    def _init_default_strategies(self):
        """تهيئة الاستراتيجيات الافتراضية"""
        
        strategies = {
            "fast_scan": StrategyProfile(
                name="fast_scan",
                parameters={
                    "concurrency": StrategyParameter(
                        name="concurrency", current_value=10, min_value=5, max_value=20, step=1, performance_impact=0.8
                    ),
                    "timeout": StrategyParameter(
                        name="timeout", current_value=15, min_value=10, max_value=30, step=2, performance_impact=0.6
                    ),
                    "depth": StrategyParameter(
                        name="depth", current_value=2, min_value=1, max_value=5, step=1, performance_impact=0.7
                    )
                },
                performance_history=[],
                average_performance=0.0
            ),
            "deep_scan": StrategyProfile(
                name="deep_scan",
                parameters={
                    "concurrency": StrategyParameter(
                        name="concurrency", current_value=3, min_value=2, max_value=8, step=1, performance_impact=0.8
                    ),
                    "timeout": StrategyParameter(
                        name="timeout", current_value=45, min_value=30, max_value=90, step=5, performance_impact=0.6
                    ),
                    "depth": StrategyParameter(
                        name="depth", current_value=5, min_value=3, max_value=10, step=1, performance_impact=0.7
                    )
                },
                performance_history=[],
                average_performance=0.0
            ),
            "stealth": StrategyProfile(
                name="stealth",
                parameters={
                    "concurrency": StrategyParameter(
                        name="concurrency", current_value=2, min_value=1, max_value=5, step=1, performance_impact=0.8
                    ),
                    "timeout": StrategyParameter(
                        name="timeout", current_value=60, min_value=30, max_value=120, step=10, performance_impact=0.6
                    ),
                    "delay": StrategyParameter(
                        name="delay", current_value=1, min_value=0.5, max_value=5, step=0.5, performance_impact=0.7
                    )
                },
                performance_history=[],
                average_performance=0.0
            )
        }
        
        self._strategies = strategies
    
    async def optimize_parameter(
        self,
        strategy_name: str,
        param_name: str,
        direction: str = "increase"
    ) -> bool:
        """
        تحسين معلمة استراتيجية
        
        Args:
            strategy_name: اسم الاستراتيجية
            param_name: اسم المعلمة
            direction: اتجاه التحسين (increase/decrease)
        
        Returns:
            نجاح التحسين
        """
        if strategy_name not in self._strategies:
            return False
        
        strategy = self._strategies[strategy_name]
        if param_name not in strategy.parameters:
            return False
        
        param = strategy.parameters[param_name]
        old_value = param.current_value
        
        # حساب القيمة الجديدة
        if direction == "increase":
            new_value = min(param.current_value + param.step, param.max_value)
        else:
            new_value = max(param.current_value - param.step, param.min_value)
        
        if new_value == old_value:
            return False
        
        param.current_value = new_value
        strategy.last_updated = datetime.now()
        
        # تسجيل التحسين
        self._optimization_history.append({
            "strategy": strategy_name,
            "parameter": param_name,
            "old_value": old_value,
            "new_value": new_value,
            "direction": direction,
            "timestamp": datetime.now().isoformat()
        })
        
        logger.info(f"Parameter optimized: {strategy_name}.{param_name} = {new_value}")
        return True
    
    async def record_performance(
        self,
        strategy_name: str,
        performance_score: float
    ):
        """
        تسجيل أداء استراتيجية
        
        Args:
            strategy_name: اسم الاستراتيجية
            performance_score: درجة الأداء (0-1)
        """
        if strategy_name not in self._strategies:
            return
        
        strategy = self._strategies[strategy_name]
        strategy.performance_history.append(performance_score)
        
        # الحفاظ على آخر 100 نتيجة
        if len(strategy.performance_history) > 100:
            strategy.performance_history.pop(0)
        
        # تحديث المتوسط
        strategy.average_performance = sum(strategy.performance_history) / len(strategy.performance_history)
        
        logger.debug(f"Performance recorded: {strategy_name} = {performance_score:.2f}")
    
    async def select_best_strategy(self, context: Dict[str, Any] = None) -> str:
        """
        اختيار أفضل استراتيجية للسياق الحالي
        
        Args:
            context: سياق إضافي
        
        Returns:
            اسم أفضل استراتيجية
        """
        scores = {}
        
        for name, strategy in self._strategies.items():
            # حساب الدرجة الأساسية
            score = strategy.average_performance
            
            # تعديل حسب السياق
            if context:
                if context.get("stealth_required", False) and name == "stealth":
                    score *= 1.5
                elif context.get("fast_required", False) and name == "fast_scan":
                    score *= 1.5
                elif context.get("deep_required", False) and name == "deep_scan":
                    score *= 1.5
            
            scores[name] = score
        
        # إضافة بعض العشوائية للاستكشاف
        if random.random() < 0.1:
            return random.choice(list(self._strategies.keys()))
        
        best_strategy = max(scores, key=scores.get)
        logger.debug(f"Selected best strategy: {best_strategy}")
        return best_strategy
    
    async def get_strategy_parameters(self, strategy_name: str) -> Dict[str, Any]:
        """الحصول على معلمات استراتيجية"""
        if strategy_name not in self._strategies:
            return {}
        
        return {
            name: param.current_value
            for name, param in self._strategies[strategy_name].parameters.items()
        }
    
    async def get_optimization_history(self, limit: int = 20) -> List[Dict]:
        """الحصول على تاريخ التحسينات"""
        return self._optimization_history[-limit:]
    
    async def get_statistics(self) -> Dict:
        """إحصائيات المحسن"""
        return {
            "total_strategies": len(self._strategies),
            "strategies_performance": {
                name: {
                    "average_performance": s.average_performance,
                    "times_optimized": len([h for h in self._optimization_history if h["strategy"] == name]),
                    "last_updated": s.last_updated.isoformat()
                }
                for name, s in self._strategies.items()
            },
            "total_optimizations": len(self._optimization_history),
            "best_strategy": max(self._strategies.items(), key=lambda x: x[1].average_performance)[0] if self._strategies else None
        }

