
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime
from collections import defaultdict

from .metrics_engine import get_metrics_engine

import logging

logger = logging.getLogger(__name__)


@dataclass
class LearningRecord:
    """سجل تعلم"""
    episode: int
    reward: float
    loss: float
    epsilon: float
    steps: int
    timestamp: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)


class LearningMetrics:
    """
    مقاييس التعلم المتقدم
    
    الميزات:
    - تتبع تقدم التعلم
    - تحليل منحنيات المكافأة والخسارة
    - إحصائيات الاستكشاف والاستغلال
    - تقارير أداء التعلم
    """
    
    def __init__(self):
        self.learning_records: List[LearningRecord] = []
        self.metrics_engine = None
        self._lock = asyncio.Lock()
        
        logger.info("LearningMetrics initialized")
    
    async def initialize(self):
        """تهيئة مقاييس التعلم"""
        self.metrics_engine = await get_metrics_engine()
        logger.info("LearningMetrics connected to metrics engine")
    
    async def record_learning(
        self,
        episode: int,
        reward: float,
        loss: float,
        epsilon: float,
        steps: int,
        metadata: Dict = None
    ):
        """
        تسجيل تقدم التعلم
        
        Args:
            episode: رقم الحلقة
            reward: المكافأة
            loss: الخسارة
            epsilon: معامل الاستكشاف
            steps: عدد الخطوات
            metadata: بيانات إضافية
        """
        record = LearningRecord(
            episode=episode,
            reward=reward,
            loss=loss,
            epsilon=epsilon,
            steps=steps,
            metadata=metadata or {}
        )
        
        async with self._lock:
            self.learning_records.append(record)
            
            # الاحتفاظ بآخر 10000 سجل فقط
            if len(self.learning_records) > 10000:
                self.learning_records = self.learning_records[-10000:]
        
        # تسجيل المقاييس
        if self.metrics_engine:
            await self.metrics_engine.record_gauge(
                "learning.reward",
                reward,
                labels={"episode": str(episode)}
            )
            await self.metrics_engine.record_gauge(
                "learning.loss",
                loss,
                labels={"episode": str(episode)}
            )
            await self.metrics_engine.record_gauge(
                "learning.epsilon",
                epsilon,
                labels={"episode": str(episode)}
            )
        
        logger.debug(f"Learning recorded: episode={episode}, reward={reward:.4f}, loss={loss:.4f}")
    
    async def get_average_reward(self, last_n_episodes: int = 100) -> float:
        """
        حساب متوسط المكافأة
        
        Args:
            last_n_episodes: عدد الحلقات الأخيرة
        
        Returns:
            متوسط المكافأة
        """
        records = self.learning_records[-last_n_episodes:]
        if not records:
            return 0.0
        
        return sum(r.reward for r in records) / len(records)
    
    async def get_average_loss(self, last_n_episodes: int = 100) -> float:
        """
        حساب متوسط الخسارة
        
        Args:
            last_n_episodes: عدد الحلقات الأخيرة
        
        Returns:
            متوسط الخسارة
        """
        records = self.learning_records[-last_n_episodes:]
        if not records:
            return 0.0
        
        return sum(r.loss for r in records) / len(records)
    
    async def get_learning_curve(self) -> Dict:
        """الحصول على منحنى التعلم"""
        if not self.learning_records:
            return {"has_data": False}
        
        episodes = [r.episode for r in self.learning_records]
        rewards = [r.reward for r in self.learning_records]
        losses = [r.loss for r in self.learning_records]
        epsilons = [r.epsilon for r in self.learning_records]
        
        return {
            "has_data": True,
            "total_episodes": len(self.learning_records),
            "episodes": episodes[-100:],
            "rewards": rewards[-100:],
            "losses": losses[-100:],
            "epsilons": epsilons[-100:],
            "best_reward": max(rewards),
            "best_loss": min(losses),
            "final_epsilon": epsilons[-1] if epsilons else 0
        }
    
    async def get_convergence_status(self) -> Dict:
        """
        تحليل حالة التقارب
        
        Returns:
            تحليل التقارب
        """
        if len(self.learning_records) < 50:
            return {"has_enough_data": False}
        
        recent_rewards = [r.reward for r in self.learning_records[-50:]]
        older_rewards = [r.reward for r in self.learning_records[-100:-50]]
        
        recent_avg = sum(recent_rewards) / len(recent_rewards)
        older_avg = sum(older_rewards) / len(older_rewards)
        
        improvement = (recent_avg - older_avg) / older_avg if older_avg > 0 else 0
        
        # حساب التباين
        variance = sum((r - recent_avg) ** 2 for r in recent_rewards) / len(recent_rewards)
        
        if improvement < 0.01 and variance < 0.1:
            status = "converged"
        elif improvement > 0.05:
            status = "improving"
        else:
            status = "learning"
        
        return {
            "has_enough_data": True,
            "status": status,
            "recent_average": recent_avg,
            "older_average": older_avg,
            "improvement": improvement,
            "variance": variance,
            "converged": status == "converged"
        }
    
    async def get_learning_statistics(self) -> Dict:
        """الحصول على إحصائيات التعلم"""
        if not self.learning_records:
            return {"total_episodes": 0}
        
        return {
            "total_episodes": len(self.learning_records),
            "total_steps": sum(r.steps for r in self.learning_records),
            "average_reward": await self.get_average_reward(),
            "average_loss": await self.get_average_loss(),
            "best_episode": max(self.learning_records, key=lambda x: x.reward).episode,
            "worst_episode": min(self.learning_records, key=lambda x: x.reward).episode,
            "learning_curve": await self.get_learning_curve(),
            "convergence": await self.get_convergence_status(),
            "recent_records": [
                {
                    "episode": r.episode,
                    "reward": r.reward,
                    "loss": r.loss,
                    "epsilon": r.epsilon,
                    "steps": r.steps,
                    "timestamp": r.timestamp.isoformat()
                }
                for r in self.learning_records[-20:]
            ]
        }


# نسخة عالمية
_default_metrics = None


async def get_learning_metrics() -> LearningMetrics:
    """الحصول على نسخة عالمية من مقاييس التعلم"""
    global _default_metrics
    if _default_metrics is None:
        _default_metrics = LearningMetrics()
        await _default_metrics.initialize()
    return _default_metrics

