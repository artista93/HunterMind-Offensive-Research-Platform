
import asyncio
import numpy as np
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from collections import deque

from storage.sqlite.learning_db import get_learning_database
from .reward_engine import RewardEngine
from .learning_agent import LearningAgent

import logging

logger = logging.getLogger(__name__)


@dataclass
class TrainingBatch:
    """دفعة تدريبية"""
    states: List[Dict]
    actions: List[str]
    rewards: List[float]
    next_states: List[Dict]
    dones: List[bool]
    timestamp: datetime = field(default_factory=datetime.now)


class OnlineTrainer:
    """
    المدرب عبر الإنترنت المتقدم
    
    الميزات:
    - تدريب مستمر باستخدام البيانات الحية
    - تجميع الدفعات للتدريب الفعال
    - تحديثات تزايدية للنموذج
    - تقييم الأداء بشكل دوري
    - حفظ النماذج المدربة
    """
    
    def __init__(
        self,
        agent: LearningAgent,
        batch_size: int = 32,
        train_interval: int = 10,
        max_buffer_size: int = 10000
    ):
        self._agent = agent
        self._batch_size = batch_size
        self._train_interval = train_interval
        self._max_buffer_size = max_buffer_size
        
        self._reward_engine = RewardEngine()
        self._db = None
        
        # مخزن التجارب
        self._experience_buffer: deque = deque(maxlen=max_buffer_size)
        
        # إحصائيات التدريب
        self._training_stats = {
            "total_training_steps": 0,
            "total_experiences_collected": 0,
            "average_loss": 0.0,
            "last_training_time": None
        }
        
        self._training_task: Optional[asyncio.Task] = None
        self._running = False
        
        logger.info("OnlineTrainer initialized")
    
    async def initialize(self):
        """تهيئة المدرب"""
        self._db = await get_learning_database()
        logger.info("OnlineTrainer initialized with database")
    
    async def start(self):
        """بدء التدريب المستمر"""
        if self._running:
            return
        
        self._running = True
        self._training_task = asyncio.create_task(self._training_loop())
        
        logger.info("OnlineTrainer started")
    
    async def stop(self):
        """إيقاف التدريب"""
        self._running = False
        
        if self._training_task:
            self._training_task.cancel()
            try:
                await self._training_task
            except asyncio.CancelledError:
                pass
        
        logger.info("OnlineTrainer stopped")
    
    async def add_experience(
        self,
        state: Dict,
        action: str,
        reward: float,
        next_state: Dict,
        done: bool
    ):
        """
        إضافة تجربة إلى المخزن
        
        Args:
            state: الحالة
            action: الإجراء
            reward: المكافأة
            next_state: الحالة التالية
            done: هل اكتملت الحلقة؟
        """
        self._experience_buffer.append({
            "state": state,
            "action": action,
            "reward": reward,
            "next_state": next_state,
            "done": done,
            "timestamp": datetime.now()
        })
        
        self._training_stats["total_experiences_collected"] += 1
        
        # تخزين في قاعدة البيانات
        await self._db.store_experience(
            agent_name=self._agent.name,
            state=state,
            action=action,
            reward=reward,
            next_state=next_state,
            done=done,
            metadata={}
        )
    
    async def _training_loop(self):
        """حلقة التدريب المستمر"""
        while self._running:
            await asyncio.sleep(self._train_interval)
            
            if len(self._experience_buffer) >= self._batch_size:
                await self._train_on_batch()
    
    async def _train_on_batch(self):
        """التدريب على دفعة من التجارب"""
        # اختيار عينة عشوائية من المخزن
        batch_size = min(self._batch_size, len(self._experience_buffer))
        batch = np.random.choice(list(self._experience_buffer), batch_size, replace=False)
        
        total_loss = 0.0
        
        for experience in batch:
            state = experience["state"]
            action = experience["action"]
            reward = experience["reward"]
            next_state = experience["next_state"]
            done = experience["done"]
            
            # حساب Q-value الحالي
            state_key = self._agent._state_to_key(state)
            current_q = self._agent._q_table.get(state_key, {}).get(action, 0.0)
            
            # حساب هدف Q-learning
            next_state_key = self._agent._state_to_key(next_state)
            max_next_q = self._agent._get_max_q_value(next_state_key) if not done else 0.0
            target_q = reward + self._agent._discount_factor * max_next_q
            
            # حساب الخسارة (MSE)
            loss = (target_q - current_q) ** 2
            total_loss += loss
            
            # تحديث Q-value
            await self._agent.update_q_value({
                "state": state,
                "action": action,
                "value": current_q + self._agent._learning_rate * (target_q - current_q)
            })
        
        # تحديث الإحصائيات
        avg_loss = total_loss / batch_size
        self._training_stats["average_loss"] = (
            self._training_stats["average_loss"] * 0.9 + avg_loss * 0.1
        )
        self._training_stats["total_training_steps"] += 1
        self._training_stats["last_training_time"] = datetime.now()
        
        logger.debug(f"Training completed: loss={avg_loss:.4f}, batch_size={batch_size}")
    
    async def evaluate_performance(
        self,
        test_episodes: int = 10
    ) -> Dict[str, Any]:
        """
        تقييم أداء الوكيل
        
        Args:
            test_episodes: عدد حلقات الاختبار
        
        Returns:
            نتائج التقييم
        """
        total_rewards = []
        
        for _ in range(test_episodes):
            episode_reward = 0.0
            state = {"test": True}
            done = False
            step = 0
            
            while not done and step < 50:  # حد أقصى 50 خطوة
                action = await self._agent.get_best_action(state)
                # محاكاة بيئة الاختبار
                reward, next_state, done = await self._simulate_step(state, action)
                episode_reward += reward
                state = next_state
                step += 1
            
            total_rewards.append(episode_reward)
        
        return {
            "average_reward": sum(total_rewards) / len(total_rewards),
            "max_reward": max(total_rewards),
            "min_reward": min(total_rewards),
            "std_reward": np.std(total_rewards) if len(total_rewards) > 1 else 0.0,
            "episodes": test_episodes
        }
    
    async def _simulate_step(self, state: Dict, action: str) -> Tuple[float, Dict, bool]:
        """محاكاة خطوة في بيئة الاختبار"""
        # محاكاة بسيطة للاختبار
        if action == "exploit":
            reward = 10.0
            done = True
        elif action == "scan":
            reward = 1.0
            done = False
        else:
            reward = -0.5
            done = False
        
        next_state = {"test": True, "last_action": action}
        
        return reward, next_state, done
    
    async def get_training_stats(self) -> Dict:
        """إحصائيات التدريب"""
        return {
            **self._training_stats,
            "buffer_size": len(self._experience_buffer),
            "batch_size": self._batch_size,
            "train_interval": self._train_interval,
            "is_training": self._running,
            "q_table_size": len(self._agent._q_table)
        }
    
    async def save_model(self, filepath: str):
        """حفظ النموذج المدرب"""
        import pickle
        
        model_data = {
            "q_table": self._agent._q_table,
            "learning_rate": self._agent._learning_rate,
            "discount_factor": self._agent._discount_factor,
            "exploration_rate": self._agent._exploration_rate,
            "training_stats": self._training_stats,
            "saved_at": datetime.now().isoformat()
        }
        
        with open(filepath, 'wb') as f:
            pickle.dump(model_data, f)
        
        logger.info(f"Model saved to {filepath}")
    
    async def load_model(self, filepath: str):
        """تحميل نموذج مدرب"""
        import pickle
        
        with open(filepath, 'rb') as f:
            model_data = pickle.load(f)
        
        self._agent._q_table = model_data["q_table"]
        self._agent._learning_rate = model_data.get("learning_rate", self._agent._learning_rate)
        self._agent._discount_factor = model_data.get("discount_factor", self._agent._discount_factor)
        self._agent._exploration_rate = model_data.get("exploration_rate", self._agent._exploration_rate)
        self._training_stats = model_data.get("training_stats", self._training_stats)
        
        logger.info(f"Model loaded from {filepath}")

