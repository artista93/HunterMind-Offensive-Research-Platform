
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime
import math
import random

import logging

logger = logging.getLogger(__name__)


@dataclass
class ExplorationState:
    """حالة الاستكشاف"""
    current_epsilon: float  # معدل الاستكشاف
    total_attempts: int
    exploration_attempts: int
    exploitation_attempts: int
    last_update: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)


class ExplorationController:
    """
    متحكم الاستكشاف المتقدم
    
    الميزات:
    - إدارة توازن الاستكشاف والاستغلال
    - تخفيف تلقائي للاستكشاف (decay)
    - استراتيجيات استكشاف متعددة
    - تحليل فعالية الاستكشاف
    """
    
    def __init__(self, initial_epsilon: float = 0.3, decay_rate: float = 0.99, min_epsilon: float = 0.01):
        self._initial_epsilon = initial_epsilon
        self._decay_rate = decay_rate
        self._min_epsilon = min_epsilon
        
        self._state = ExplorationState(
            current_epsilon=initial_epsilon,
            total_attempts=0,
            exploration_attempts=0,
            exploitation_attempts=0
        )
        
        self._strategy_performance: Dict[str, List[bool]] = {
            "random": [],
            "uncertainty": [],
            "optimistic": [],
            "epsilon_greedy": []
        }
        
        logger.info(f"ExplorationController initialized (epsilon={initial_epsilon}, decay={decay_rate})")
    
    async def should_explore(self, context: Dict[str, Any] = None) -> bool:
        """
        تحديد ما إذا كان يجب الاستكشاف أو الاستغلال
        
        Args:
            context: سياق إضافي للقرار
        
        Returns:
            True إذا كان يجب الاستكشاف، False للاستغلال
        """
        self._state.total_attempts += 1
        
        # استراتيجية epsilon-greedy الأساسية
        epsilon = self._state.current_epsilon
        
        # تعديل epsilon بناءً على السياق
        if context:
            if context.get("high_uncertainty", False):
                epsilon = min(epsilon * 1.5, 1.0)
            if context.get("time_constrained", False):
                epsilon = max(epsilon * 0.5, self._min_epsilon)
        
        explore = random.random() < epsilon
        
        if explore:
            self._state.exploration_attempts += 1
        else:
            self._state.exploitation_attempts += 1
        
        self._state.last_update = datetime.now()
        
        return explore
    
    async def select_exploration_strategy(self) -> str:
        """
        اختيار استراتيجية استكشاف
        
        Returns:
            اسم الاستراتيجية المختارة
        """
        # حساب أداء الاستراتيجيات
        strategy_scores = {}
        for strategy, results in self._strategy_performance.items():
            if results:
                success_rate = sum(results) / len(results)
                strategy_scores[strategy] = success_rate
            else:
                strategy_scores[strategy] = 0.5
        
        # اختيار الاستراتيجية ذات الأداء الأفضل مع بعض العشوائية
        if random.random() < 0.2:
            # استكشاف الاستراتيجيات
            return random.choice(list(self._strategy_performance.keys()))
        
        # استغلال أفضل استراتيجية
        best_strategy = max(strategy_scores, key=strategy_scores.get)
        return best_strategy
    
    async def record_exploration_result(self, strategy: str, success: bool):
        """
        تسجيل نتيجة استراتيجية استكشاف
        
        Args:
            strategy: اسم الاستراتيجية
            success: نجاح الاستكشاف
        """
        if strategy in self._strategy_performance:
            self._strategy_performance[strategy].append(success)
            # الحفاظ على آخر 100 نتيجة فقط
            if len(self._strategy_performance[strategy]) > 100:
                self._strategy_performance[strategy].pop(0)
    
    async def decay_epsilon(self):
        """تخفيف معدل الاستكشاف"""
        old_epsilon = self._state.current_epsilon
        self._state.current_epsilon = max(self._min_epsilon, self._state.current_epsilon * self._decay_rate)
        
        logger.debug(f"Epsilon decayed: {old_epsilon:.4f} -> {self._state.current_epsilon:.4f}")
    
    async def get_ucb_value(self, successes: int, total: int, total_rounds: int) -> float:
        """
        حساب قيمة UCB (Upper Confidence Bound)
        
        Args:
            successes: عدد النجاحات
            total: عدد المحاولات
            total_rounds: إجمالي الجولات
        
        Returns:
            قيمة UCB
        """
        if total == 0:
            return float('inf')
        
        exploitation = successes / total
        exploration = math.sqrt(2 * math.log(total_rounds) / total)
        
        return exploitation + exploration
    
    async def get_optimistic_value(self, successes: int, total: int) -> float:
        """
        حساب القيمة المتفائلة
        
        Args:
            successes: عدد النجاحات
            total: عدد المحاولات
        
        Returns:
            القيمة المتفائلة
        """
        if total == 0:
            return 1.0
        
        # معادلة متفائلة: نجاح + ربع انحراف
        success_rate = successes / total
        return min(1.0, success_rate + 0.25)
    
    async def get_uncertainty_score(self, successes: int, total: int) -> float:
        """
        حساب درجة عدم اليقين
        
        Args:
            successes: عدد النجاحات
            total: عدد المحاولات
        
        Returns:
            درجة عدم اليقين (0-1)
        """
        if total == 0:
            return 1.0
        
        success_rate = successes / total
        # الانحراف المعياري للتوزيع الثنائي
        uncertainty = math.sqrt(success_rate * (1 - success_rate) / total)
        return min(1.0, uncertainty * 2)  # تطبيع
    
    async def get_statistics(self) -> Dict:
        """إحصائيات متحكم الاستكشاف"""
        total = self._state.total_attempts
        exploration_rate = self._state.exploration_attempts / total if total > 0 else 0
        
        strategy_performance = {}
        for strategy, results in self._strategy_performance.items():
            if results:
                strategy_performance[strategy] = {
                    "attempts": len(results),
                    "success_rate": sum(results) / len(results)
                }
        
        return {
            "current_epsilon": self._state.current_epsilon,
            "total_attempts": self._state.total_attempts,
            "exploration_attempts": self._state.exploration_attempts,
            "exploitation_attempts": self._state.exploitation_attempts,
            "exploration_rate": exploration_rate,
            "strategy_performance": strategy_performance,
            "decay_rate": self._decay_rate,
            "min_epsilon": self._min_epsilon
        }

