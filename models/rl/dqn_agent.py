"""
DQN Agent - Deep Q-Network لاختيار الحمولات بذكاء
"""

import json
import os
import random
import math
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from collections import deque
import time

import logging

logger = logging.getLogger(__name__)


class DQNNetwork:
    """
    شبكة DQN بسيطة (بدون TensorFlow/PyTorch)
    تستخدم Q-table مع state aggregation للتعلم
    
    State: context_type + payload_index
    Action: select_payload / skip / try_next
    """
    
    def __init__(self, state_size: int = 100, action_size: int = 3, learning_rate: float = 0.01):
        self.state_size = state_size
        self.action_size = action_size
        self.learning_rate = learning_rate
        
        # Q-table: state -> action values
        self.q_table: Dict[str, List[float]] = {}
        
        # إحصائيات
        self._updates = 0
        
        logger.info(f"DQN Network initialized (states={state_size}, actions={action_size})")
    
    def _hash_state(self, state: str) -> str:
        """تحويل state إلى مفتاح للـ Q-table"""
        return str(hash(state) % self.state_size)
    
    def get_q_values(self, state: str) -> List[float]:
        """الحصول على Q-values لكل action"""
        key = self._hash_state(state)
        
        if key not in self.q_table:
            # تهيئة عشوائية
            self.q_table[key] = [random.uniform(-0.1, 0.1) for _ in range(self.action_size)]
        
        return self.q_table[key]
    
    def get_best_action(self, state: str) -> int:
        """الحصول على أفضل action"""
        q_values = self.get_q_values(state)
        return q_values.index(max(q_values))
    
    def update(self, state: str, action: int, reward: float, next_state: str, discount: float = 0.95):
        """
        تحديث Q-value باستخدام Bellman equation
        
        Q(s,a) = Q(s,a) + α * [r + γ * max(Q(s',a')) - Q(s,a)]
        """
        key = self._hash_state(state)
        q_values = self.get_q_values(state)
        next_q_values = self.get_q_values(next_state)
        
        # Bellman update
        best_next = max(next_q_values)
        target = reward + discount * best_next
        q_values[action] += self.learning_rate * (target - q_values[action])
        
        self.q_table[key] = q_values
        self._updates += 1
    
    def save(self, path: str):
        """حفظ النموذج"""
        os.makedirs(os.path.dirname(path), exist_ok=True)
        
        with open(path, 'w') as f:
            json.dump({
                "state_size": self.state_size,
                "action_size": self.action_size,
                "learning_rate": self.learning_rate,
                "q_table": self.q_table,
                "updates": self._updates
            }, f, indent=2)
        
        logger.info(f"DQN saved to {path} ({len(self.q_table)} states)")
    
    def load(self, path: str):
        """تحميل النموذج"""
        if not os.path.exists(path):
            logger.warning(f"Model file not found: {path}")
            return
        
        with open(path, 'r') as f:
            data = json.load(f)
        
        self.state_size = data.get("state_size", self.state_size)
        self.action_size = data.get("action_size", self.action_size)
        self.learning_rate = data.get("learning_rate", self.learning_rate)
        self.q_table = data.get("q_table", {})
        self._updates = data.get("updates", 0)
        
        logger.info(f"DQN loaded from {path} ({len(self.q_table)} states, {self._updates} updates)")
    
    def get_stats(self) -> Dict:
        """إحصائيات النموذج"""
        return {
            "states_learned": len(self.q_table),
            "total_updates": self._updates,
            "avg_q_value": sum(sum(v) for v in self.q_table.values()) / max(1, len(self.q_table) * self.action_size),
            "learning_rate": self.learning_rate
        }


class ReplayBuffer:
    """ذاكرة إعادة التشغيل - تخزين التجارب للتعلم"""
    
    def __init__(self, capacity: int = 1000):
        self.capacity = capacity
        self.buffer: deque = deque(maxlen=capacity)
    
    def add(self, state: str, action: int, reward: float, next_state: str):
        """إضافة تجربة"""
        self.buffer.append((state, action, reward, next_state))
    
    def sample(self, batch_size: int = 32) -> List[Tuple]:
        """أخذ عينة عشوائية"""
        if len(self.buffer) < batch_size:
            return list(self.buffer)
        return random.sample(list(self.buffer), batch_size)
    
    def __len__(self) -> int:
        return len(self.buffer)


class DQNAgent:
    """
    وكيل DQN لاختيار الحمولات بذكاء
    
    Actions:
    0: select_best_payload
    1: select_random_payload  
    2: skip_target
    """
    
    def __init__(self, state_size: int = 100, action_size: int = 3):
        self.network = DQNNetwork(state_size, action_size)
        self.replay_buffer = ReplayBuffer(1000)
        
        # Exploration
        self.epsilon = 1.0
        self.epsilon_min = 0.05
        self.epsilon_decay = 0.995
        
        # إحصائيات
        self.total_steps = 0
        self.total_rewards = 0.0
        
        logger.info(f"DQN Agent initialized (epsilon={self.epsilon})")
    
    def select_action(self, state: str) -> int:
        """اختيار action باستخدام epsilon-greedy"""
        self.total_steps += 1
        
        if random.random() < self.epsilon:
            # استكشاف
            return random.randint(0, self.network.action_size - 1)
        
        # استغلال
        return self.network.get_best_action(state)
    
    def learn(self, state: str, action: int, reward: float, next_state: str):
        """تعلم من تجربة"""
        # تخزين في replay buffer
        self.replay_buffer.add(state, action, reward, next_state)
        
        # تحديث Q-network
        self.network.update(state, action, reward, next_state)
        
        # تحديث epsilon
        self.epsilon = max(self.epsilon_min, self.epsilon * self.epsilon_decay)
        
        # تحديث الإحصائيات
        self.total_rewards += reward
    
    def learn_from_batch(self, batch_size: int = 32):
        """تعلم من مجموعة تجارب"""
        batch = self.replay_buffer.sample(batch_size)
        
        for state, action, reward, next_state in batch:
            self.network.update(state, action, reward, next_state)
    
    def build_state(self, context: str, payload_index: int, success_history: List[bool]) -> str:
        """
        بناء state من المعلومات المتاحة
        
        Args:
            context: سياق الصفحة (html, api, auth, query)
            payload_index: فهرس الحمولة الحالية
            success_history: تاريخ النجاح (آخر 5 نتائج)
        
        Returns:
            state string
        """
        # تحويل success_history إلى string
        history_str = ''.join(['1' if s else '0' for s in success_history[-5:]])
        history_str = history_str.ljust(5, '0')
        
        return f"{context}|{payload_index}|{history_str}"
    
    def save(self, path: str = "models/rl/dqn_model.json"):
        """حفظ النموذج"""
        os.makedirs(os.path.dirname(path), exist_ok=True)
        
        self.network.save(path)
        
        # حفظ metadata
        meta_path = path.replace('.json', '_meta.json')
        with open(meta_path, 'w') as f:
            json.dump({
                "epsilon": self.epsilon,
                "total_steps": self.total_steps,
                "total_rewards": self.total_rewards,
                "buffer_size": len(self.replay_buffer)
            }, f, indent=2)
    
    def load(self, path: str = "models/rl/dqn_model.json"):
        """تحميل النموذج"""
        self.network.load(path)
        
        # تحميل metadata
        meta_path = path.replace('.json', '_meta.json')
        if os.path.exists(meta_path):
            with open(meta_path, 'r') as f:
                data = json.load(f)
                self.epsilon = data.get("epsilon", self.epsilon)
                self.total_steps = data.get("total_steps", 0)
                self.total_rewards = data.get("total_rewards", 0.0)
    
    def get_stats(self) -> Dict:
        """إحصائيات الوكيل"""
        return {
            **self.network.get_stats(),
            "epsilon": self.epsilon,
            "total_steps": self.total_steps,
            "total_rewards": round(self.total_rewards, 2),
            "buffer_size": len(self.replay_buffer),
            "avg_reward": round(self.total_rewards / max(1, self.total_steps), 4)
        }


# نسخة عالمية
_default_dqn_agent = None

def get_dqn_agent() -> DQNAgent:
    global _default_dqn_agent
    if _default_dqn_agent is None:
        _default_dqn_agent = DQNAgent()
        _default_dqn_agent.load("models/rl/dqn_model.json")
    return _default_dqn_agent
