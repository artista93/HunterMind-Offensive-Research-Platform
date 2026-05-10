
import random
import numpy as np
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from collections import deque

import logging

logger = logging.getLogger(__name__)


@dataclass
class Experience:
    """تجربة واحدة"""
    state: np.ndarray
    action: int
    reward: float
    next_state: np.ndarray
    done: bool
    priority: float = 1.0
    timestamp: datetime = field(default_factory=datetime.now)


class ReplayBuffer:
    """
    مخزن إعادة التشغيل المتقدم
    
    الميزات:
    - تخزين التجارب بتوزيع عادل
    - أخذ عينات عشوائية للتدريب
    - دعم الأولوية (Prioritized Experience Replay)
    - تنظيف قديم تلقائي
    """
    
    def __init__(
        self,
        capacity: int = 10000,
        prioritized: bool = True,
        alpha: float = 0.6,
        beta: float = 0.4,
        beta_increment: float = 0.001
    ):
        self.capacity = capacity
        self.prioritized = prioritized
        self.alpha = alpha
        self.beta = beta
        self.beta_increment = beta_increment
        
        self.buffer = deque(maxlen=capacity)
        self.priorities = deque(maxlen=capacity)
        self.position = 0
        
        logger.info(f"ReplayBuffer initialized: capacity={capacity}, prioritized={prioritized}")
    
    def push(self, experience: Experience):
        """
        إضافة تجربة إلى المخزن
        
        Args:
            experience: التجربة المراد إضافتها
        """
        if len(self.buffer) < self.capacity:
            self.buffer.append(experience)
            if self.prioritized:
                self.priorities.append(max(self.priorities) if self.priorities else 1.0)
        else:
            self.buffer[self.position] = experience
            if self.prioritized:
                self.priorities[self.position] = max(self.priorities)
        
        self.position = (self.position + 1) % self.capacity
    
    def push_batch(self, experiences: List[Experience]):
        """
        إضافة مجموعة من التجارب
        
        Args:
            experiences: قائمة التجارب
        """
        for exp in experiences:
            self.push(exp)
    
    def sample(self, batch_size: int) -> Tuple[List[Experience], Optional[np.ndarray]]:
        """
        أخذ عينة عشوائية من التجارب
        
        Args:
            batch_size: حجم العينة
        
        Returns:
            (قائمة التجارب, أوزان الأهمية إذا كانت Prioritized)
        """
        if len(self.buffer) < batch_size:
            return [], None
        
        if self.prioritized:
            # أخذ عينات بالأولوية
            probs = np.array(self.priorities) ** self.alpha
            probs /= probs.sum()
            
            indices = np.random.choice(len(self.buffer), batch_size, p=probs)
            batch = [self.buffer[idx] for idx in indices]
            
            # حساب أوزان الأهمية
            total = len(self.buffer)
            weights = (total * probs[indices]) ** (-self.beta)
            weights /= weights.max()
            
            # زيادة beta
            self.beta = min(1.0, self.beta + self.beta_increment)
            
            return batch, weights
        else:
            # أخذ عينات عشوائية عادية
            batch = random.sample(self.buffer, batch_size)
            return batch, None
    
    def update_priorities(self, indices: List[int], td_errors: List[float]):
        """
        تحديث أولويات التجارب (لـ Prioritized Replay)
        
        Args:
            indices: مؤشرات التجارب
            td_errors: أخطاء TD للتجارب
        """
        if not self.prioritized:
            return
        
        for idx, td_error in zip(indices, td_errors):
            priority = (abs(td_error) + 0.01)  # إضافة epsilon لمنع الصفر
            self.priorities[idx] = priority
    
    def get_size(self) -> int:
        """الحصول على حجم المخزن الحالي"""
        return len(self.buffer)
    
    def is_ready(self, batch_size: int) -> bool:
        """التحقق من وجود عدد كافٍ من التجارب للتدريب"""
        return len(self.buffer) >= batch_size
    
    def clear(self):
        """مسح المخزن"""
        self.buffer.clear()
        self.priorities.clear()
        self.position = 0
        logger.info("ReplayBuffer cleared")
    
    def get_statistics(self) -> Dict:
        """إحصائيات المخزن"""
        if not self.buffer:
            return {"size": 0}
        
        rewards = [exp.reward for exp in self.buffer]
        
        return {
            "size": len(self.buffer),
            "capacity": self.capacity,
            "prioritized": self.prioritized,
            "alpha": self.alpha,
            "beta": self.beta,
            "avg_reward": np.mean(rewards),
            "max_reward": np.max(rewards),
            "min_reward": np.min(rewards),
            "fill_ratio": len(self.buffer) / self.capacity
        }

