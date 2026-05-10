
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from collections import defaultdict

import logging

logger = logging.getLogger(__name__)


@dataclass
class LearningStrategy:
    """استراتيجية تعلم"""
    name: str
    parameters: Dict[str, Any]
    performance: List[float] = field(default_factory=list)
    average_score: float = 0.0
    times_used: int = 0


class MetaLearner:
    """
    المتعلم الفوقي المتقدم
    
    الميزات:
    - تعلم كيفية التعلم (learning to learn)
    - تحسين معلمات التعلم تلقائياً
    - اختيار أفضل استراتيجية تعلم
    - تكيف مع مهام مختلفة
    """
    
    def __init__(self):
        self._strategies: Dict[str, LearningStrategy] = {}
        self._task_history: List[Dict] = []
        self._meta_knowledge: Dict[str, Any] = {}
        
        # تهيئة استراتيجيات التعلم الافتراضية
        self._init_default_strategies()
        
        logger.info("MetaLearner initialized")
    
    def _init_default_strategies(self):
        """تهيئة استراتيجيات التعلم الافتراضية"""
        
        strategies = [
            LearningStrategy(
                name="aggressive",
                parameters={
                    "learning_rate": 0.1,
                    "exploration_rate": 0.2,
                    "batch_size": 32
                }
            ),
            LearningStrategy(
                name="conservative",
                parameters={
                    "learning_rate": 0.01,
                    "exploration_rate": 0.05,
                    "batch_size": 64
                }
            ),
            LearningStrategy(
                name="adaptive",
                parameters={
                    "learning_rate": 0.05,
                    "exploration_rate": 0.1,
                    "batch_size": 48
                }
            )
        ]
        
        for strategy in strategies:
            self._strategies[strategy.name] = strategy
    
    async def select_strategy(self, task_type: str, context: Dict = None) -> LearningStrategy:
        """
        اختيار أفضل استراتيجية تعلم لمهمة معينة
        
        Args:
            task_type: نوع المهمة
            context: سياق المهمة
        
        Returns:
            استراتيجية التعلم المختارة
        """
        # إذا كانت الاستراتيجيات جديدة، اختر عشوائياً
        if not any(s.times_used > 0 for s in self._strategies.values()):
            return list(self._strategies.values())[0]
        
        # حساب درجة الثقة لكل استراتيجية
        scores = {}
        for name, strategy in self._strategies.items():
            if strategy.times_used > 0:
                # المتوسط المتحرك للأداء
                base_score = strategy.average_score
                
                # تعديل حسب سياق المهمة
                if context:
                    if task_type == "fast_learning" and name == "aggressive":
                        base_score *= 1.2
                    elif task_type == "stable_learning" and name == "conservative":
                        base_score *= 1.2
                    elif task_type == "adaptive" and name == "adaptive":
                        base_score *= 1.2
                
                scores[name] = base_score
            else:
                scores[name] = 0.5  # قيمة افتراضية للاستراتيجيات غير المستخدمة
        
        # اختيار أفضل استراتيجية
        best_strategy = max(scores, key=scores.get)
        
        logger.debug(f"Selected strategy: {best_strategy} for task {task_type}")
        return self._strategies[best_strategy]
    
    async def record_performance(
        self,
        strategy_name: str,
        task_type: str,
        performance_score: float,
        metadata: Dict = None
    ):
        """
        تسجيل أداء استراتيجية تعلم
        
        Args:
            strategy_name: اسم الاستراتيجية
            task_type: نوع المهمة
            performance_score: درجة الأداء (0-1)
            metadata: بيانات إضافية
        """
        if strategy_name not in self._strategies:
            logger.warning(f"Strategy {strategy_name} not found")
            return
        
        strategy = self._strategies[strategy_name]
        strategy.performance.append(performance_score)
        strategy.times_used += 1
        
        # تحديث المتوسط المتحرك
        strategy.average_score = sum(strategy.performance[-50:]) / min(len(strategy.performance), 50)
        
        # تسجيل تاريخ المهمة
        self._task_history.append({
            "strategy": strategy_name,
            "task_type": task_type,
            "performance": performance_score,
            "timestamp": datetime.now().isoformat(),
            "metadata": metadata or {}
        })
        
        # تحديث المعرفة الفوقية
        await self._update_meta_knowledge(strategy_name, task_type, performance_score)
        
        logger.debug(f"Performance recorded: {strategy_name} = {performance_score:.2f}")
    
    async def _update_meta_knowledge(self, strategy_name: str, task_type: str, score: float):
        """تحديث المعرفة الفوقية"""
        key = f"{task_type}:{strategy_name}"
        
        if key not in self._meta_knowledge:
            self._meta_knowledge[key] = {"scores": [], "average": 0.0}
        
        self._meta_knowledge[key]["scores"].append(score)
        if len(self._meta_knowledge[key]["scores"]) > 20:
            self._meta_knowledge[key]["scores"].pop(0)
        
        self._meta_knowledge[key]["average"] = sum(self._meta_knowledge[key]["scores"]) / len(self._meta_knowledge[key]["scores"])
    
    async def get_best_strategy_for_task(self, task_type: str) -> Optional[str]:
        """
        الحصول على أفضل استراتيجية لنوع مهمة معين
        
        Args:
            task_type: نوع المهمة
        
        Returns:
            اسم أفضل استراتيجية أو None
        """
        best_strategy = None
        best_score = -1.0
        
        for strategy_name in self._strategies:
            key = f"{task_type}:{strategy_name}"
            if key in self._meta_knowledge:
                score = self._meta_knowledge[key]["average"]
                if score > best_score:
                    best_score = score
                    best_strategy = strategy_name
        
        return best_strategy
    
    async def adapt_parameters(
        self,
        strategy_name: str,
        performance_trend: List[float]
    ) -> Dict[str, Any]:
        """
        تكييف معلمات الاستراتيجية بناءً على اتجاه الأداء
        
        Args:
            strategy_name: اسم الاستراتيجية
            performance_trend: اتجاه الأداء (قائمة بالقيم الأخيرة)
        
        Returns:
            المعلمات المعدلة
        """
        if strategy_name not in self._strategies:
            return {}
        
        strategy = self._strategies[strategy_name]
        
        # تحليل الاتجاه
        if len(performance_trend) >= 3:
            trend = performance_trend[-1] - performance_trend[0]
            
            if trend > 0.1:
                # تحسن - حافظ على المعلمات
                pass
            elif trend < -0.1:
                # تدهور - عدل المعلمات
                if strategy_name == "aggressive":
                    strategy.parameters["learning_rate"] *= 0.8
                    strategy.parameters["exploration_rate"] *= 0.8
                elif strategy_name == "conservative":
                    strategy.parameters["learning_rate"] *= 1.2
                    strategy.parameters["batch_size"] = max(32, strategy.parameters["batch_size"] // 2)
                elif strategy_name == "adaptive":
                    strategy.parameters["learning_rate"] = 0.05 + (performance_trend[-1] * 0.1)
        
        return strategy.parameters
    
    async def get_strategy_performance(self) -> Dict:
        """الحصول على أداء الاستراتيجيات"""
        return {
            name: {
                "times_used": s.times_used,
                "average_score": s.average_score,
                "recent_performance": s.performance[-10:] if s.performance else []
            }
            for name, s in self._strategies.items()
        }
    
    async def get_task_statistics(self) -> Dict:
        """إحصائيات المهام"""
        task_types = defaultdict(lambda: {"count": 0, "avg_performance": 0.0})
        
        for record in self._task_history:
            task_types[record["task_type"]]["count"] += 1
            task_types[record["task_type"]]["avg_performance"] += record["performance"]
        
        for task_type in task_types:
            task_types[task_type]["avg_performance"] /= task_types[task_type]["count"]
        
        return dict(task_types)
    
    async def get_statistics(self) -> Dict:
        """إحصائيات المتعلم الفوقي"""
        return {
            "total_strategies": len(self._strategies),
            "total_tasks": len(self._task_history),
            "unique_task_types": len(set(r["task_type"] for r in self._task_history)),
            "strategy_performance": await self.get_strategy_performance(),
            "task_statistics": await self.get_task_statistics(),
            "meta_knowledge_size": len(self._meta_knowledge)
        }

