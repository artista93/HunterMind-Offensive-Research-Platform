
import asyncio
import numpy as np
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from collections import defaultdict

import logging

logger = logging.getLogger(__name__)


@dataclass
class StateAction:
    """زوج حالة-إجراء"""
    state: str
    action: str
    value: float = 0.0
    visits: int = 0


class RLPolicy:
    """
    سياسة التعلم المعزز المتقدمة
    
    الميزات:
    - Q-Learning لتحسين القرارات
    - استكشاف (epsilon-greedy) مقابل استغلال
    - تحديث تزايدي للقيم
    - تكامل مع نظام المكافآت
    """
    
    def __init__(self, learning_rate: float = 0.1, discount_factor: float = 0.95, epsilon: float = 0.1):
        self._learning_rate = learning_rate
        self._discount_factor = discount_factor
        self._epsilon = epsilon
        
        # Q-table: state -> action -> value
        self._q_table: Dict[str, Dict[str, float]] = defaultdict(lambda: defaultdict(float))
        self._visits: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
        
        self._training_history: List[Dict] = []
        
        logger.info(f"RLPolicy initialized (lr={learning_rate}, gamma={discount_factor}, epsilon={epsilon})")
    
    async def get_action(self, state: str, available_actions: List[str]) -> str:
        """
        اختيار الإجراء الأمثل للحالة
        
        Args:
            state: الحالة الحالية
            available_actions: قائمة الإجراءات المتاحة
        
        Returns:
            الإجراء المختار
        """
        # استكشاف (epsilon-greedy)
        if np.random.random() < self._epsilon and len(available_actions) > 1:
            action = np.random.choice(available_actions)
            logger.debug(f"Exploration: selected {action}")
            return action
        
        # استغلال: اختيار الإجراء بأعلى قيمة
        q_values = self._q_table[state]
        best_action = max(available_actions, key=lambda a: q_values.get(a, 0.0))
        
        logger.debug(f"Exploitation: selected {best_action}")
        return best_action
    
    async def update(
        self,
        state: str,
        action: str,
        reward: float,
        next_state: str,
        next_actions: List[str]
    ):
        """
        تحديث Q-value باستخدام Q-Learning
        
        Args:
            state: الحالة الحالية
            action: الإجراء المتخذ
            reward: المكافأة المستلمة
            next_state: الحالة التالية
            next_actions: الإجراءات المتاحة في الحالة التالية
        """
        current_q = self._q_table[state].get(action, 0.0)
        
        # حساب max Q-value للحالة التالية
        next_q_values = self._q_table[next_state]
        max_next_q = max([next_q_values.get(a, 0.0) for a in next_actions]) if next_actions else 0.0
        
        # تحديث Q-value
        new_q = current_q + self._learning_rate * (reward + self._discount_factor * max_next_q - current_q)
        
        self._q_table[state][action] = new_q
        self._visits[state][action] = self._visits[state].get(action, 0) + 1
        
        # تسجيل التحديث
        self._training_history.append({
            "timestamp": datetime.now().isoformat(),
            "state": state,
            "action": action,
            "reward": reward,
            "old_q": current_q,
            "new_q": new_q
        })
        
        logger.debug(f"Q-value updated: {state} -> {action} = {new_q:.3f} (reward={reward})")
    
    async def get_q_value(self, state: str, action: str) -> float:
        """الحصول على Q-value لزوج حالة-إجراء"""
        return self._q_table[state].get(action, 0.0)
    
    async def get_best_action_value(self, state: str, actions: List[str]) -> Tuple[str, float]:
        """الحصول على أفضل إجراء وقيمته للحالة"""
        if not actions:
            return "", 0.0
        
        best_action = max(actions, key=lambda a: self._q_table[state].get(a, 0.0))
        best_value = self._q_table[state].get(best_action, 0.0)
        
        return best_action, best_value
    
    async def decay_epsilon(self, decay_rate: float = 0.99, min_epsilon: float = 0.01):
        """تخفيف معامل الاستكشاف تدريجياً"""
        self._epsilon = max(min_epsilon, self._epsilon * decay_rate)
        logger.debug(f"Epsilon decayed to {self._epsilon:.4f}")
    
    async def get_statistics(self) -> Dict:
        """إحصائيات السياسة"""
        total_states = len(self._q_table)
        total_actions = sum(len(actions) for actions in self._q_table.values())
        
        # متوسط عدد الزيارات
        total_visits = sum(sum(visits.values()) for visits in self._visits.values())
        avg_visits = total_visits / total_actions if total_actions > 0 else 0
        
        return {
            "total_states": total_states,
            "total_actions": total_actions,
            "total_visits": total_visits,
            "average_visits_per_action": avg_visits,
            "epsilon": self._epsilon,
            "learning_rate": self._learning_rate,
            "discount_factor": self._discount_factor,
            "training_steps": len(self._training_history)
        }
    
    async def save_policy(self, filepath: str):
        """حفظ السياسة إلى ملف"""
        import pickle
        
        policy_data = {
            "q_table": dict(self._q_table),
            "visits": dict(self._visits),
            "epsilon": self._epsilon,
            "learning_rate": self._learning_rate,
            "discount_factor": self._discount_factor,
            "saved_at": datetime.now().isoformat()
        }
        
        with open(filepath, 'wb') as f:
            pickle.dump(policy_data, f)
        
        logger.info(f"Policy saved to {filepath}")
    
    async def load_policy(self, filepath: str):
        """تحميل سياسة من ملف"""
        import pickle
        
        with open(filepath, 'rb') as f:
            policy_data = pickle.load(f)
        
        self._q_table = defaultdict(lambda: defaultdict(float), policy_data.get("q_table", {}))
        self._visits = defaultdict(lambda: defaultdict(int), policy_data.get("visits", {}))
        self._epsilon = policy_data.get("epsilon", self._epsilon)
        self._learning_rate = policy_data.get("learning_rate", self._learning_rate)
        self._discount_factor = policy_data.get("discount_factor", self._discount_factor)
        
        logger.info(f"Policy loaded from {filepath}")

