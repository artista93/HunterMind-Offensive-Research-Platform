
import random
import numpy as np
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from collections import deque

import logging

logger = logging.getLogger(__name__)


@dataclass
class Transition:
    """تحويلة في الذاكرة"""
    state: np.ndarray
    action: int
    reward: float
    next_state: np.ndarray
    done: bool


class DQNAgent:
    """
    وكيل Deep Q-Network المتقدم
    
    الميزات:
    - شبكة Q العميقة لتقدير قيم الإجراءات
    - ذاكرة إعادة التشغيل (Replay Memory)
    - استهداف الشبكة (Target Network)
    - epsilon-greedy للاستكشاف
    """
    
    def __init__(
        self,
        state_size: int,
        action_size: int,
        learning_rate: float = 0.001,
        gamma: float = 0.95,
        epsilon: float = 1.0,
        epsilon_min: float = 0.01,
        epsilon_decay: float = 0.995,
        memory_size: int = 2000,
        batch_size: int = 32
    ):
        self.state_size = state_size
        self.action_size = action_size
        self.learning_rate = learning_rate
        self.gamma = gamma
        self.epsilon = epsilon
        self.epsilon_min = epsilon_min
        self.epsilon_decay = epsilon_decay
        self.batch_size = batch_size
        
        self.memory = deque(maxlen=memory_size)
        self.model = None  # سيتم تهيئته عند الحاجة
        self.target_model = None
        
        self.training_step = 0
        self.update_target_frequency = 100
        
        logger.info(f"DQNAgent initialized: state={state_size}, action={action_size}")
    
    def _build_model(self):
        """بناء نموذج الشبكة العصبية"""
        try:
            import tensorflow as tf
            from tensorflow.keras import layers, models
            
            model = models.Sequential([
                layers.Dense(64, activation='relu', input_shape=(self.state_size,)),
                layers.Dense(64, activation='relu'),
                layers.Dense(32, activation='relu'),
                layers.Dense(self.action_size, activation='linear')
            ])
            
            model.compile(
                optimizer=tf.keras.optimizers.Adam(learning_rate=self.learning_rate),
                loss='mse'
            )
            
            return model
        except ImportError:
            logger.warning("TensorFlow not available, using simplified model")
            return None
    
    async def initialize(self):
        """تهيئة النماذج"""
        self.model = self._build_model()
        self.target_model = self._build_model()
        self._update_target_network()
        
        logger.info("DQNAgent initialized with models")
    
    def _update_target_network(self):
        """تحديث الشبكة الهدف"""
        if self.model and self.target_model:
            self.target_model.set_weights(self.model.get_weights())
    
    async def remember(self, state, action, reward, next_state, done):
        """تخزين تجربة في الذاكرة"""
        transition = Transition(
            state=np.array(state),
            action=action,
            reward=reward,
            next_state=np.array(next_state),
            done=done
        )
        self.memory.append(transition)
    
    async def act(self, state, valid_actions: List[int] = None) -> int:
        """
        اختيار إجراء
        
        Args:
            state: الحالة الحالية
            valid_actions: قائمة الإجراءات الصالحة (اختياري)
        
        Returns:
            الإجراء المختار
        """
        if random.random() <= self.epsilon:
            # استكشاف: اختيار عشوائي
            if valid_actions:
                return random.choice(valid_actions)
            return random.randrange(self.action_size)
        
        # استغلال: اختيار أفضل إجراء من النموذج
        if self.model is None:
            return 0
        
        state_array = np.array(state).reshape(1, -1)
        act_values = self.model.predict(state_array, verbose=0)[0]
        
        if valid_actions:
            # تصفية الإجراءات غير الصالحة
            for a in range(self.action_size):
                if a not in valid_actions:
                    act_values[a] = -np.inf
        
        return np.argmax(act_values)
    
    async def replay(self) -> float:
        """
        تدريب النموذج على دفعة من الذاكرة
        
        Returns:
            قيمة الخسارة
        """
        if len(self.memory) < self.batch_size:
            return 0.0
        
        batch = random.sample(self.memory, self.batch_size)
        
        states = np.array([t.state for t in batch])
        next_states = np.array([t.next_state for t in batch])
        
        if self.model is None:
            return 0.0
        
        # الحصول على قيم Q الحالية
        current_q = self.model.predict(states, verbose=0)
        
        # الحصول على قيم Q المستقبلية من الشبكة الهدف
        next_q = self.target_model.predict(next_states, verbose=0)
        
        # تحديث قيم Q المستهدفة
        X = []
        y = []
        
        for i, transition in enumerate(batch):
            if transition.done:
                target = transition.reward
            else:
                target = transition.reward + self.gamma * np.max(next_q[i])
            
            target_f = current_q[i]
            target_f[transition.action] = target
            
            X.append(states[i])
            y.append(target_f)
        
        # تدريب النموذج
        X = np.array(X)
        y = np.array(y)
        
        history = self.model.fit(X, y, batch_size=self.batch_size, epochs=1, verbose=0)
        loss = history.history['loss'][0]
        
        # تخفيف epsilon
        if self.epsilon > self.epsilon_min:
            self.epsilon *= self.epsilon_decay
        
        # تحديث الشبكة الهدف بشكل دوري
        self.training_step += 1
        if self.training_step % self.update_target_frequency == 0:
            self._update_target_network()
        
        return loss
    
    async def save(self, filepath: str):
        """حفظ النموذج"""
        if self.model:
            self.model.save(filepath)
            logger.info(f"Model saved to {filepath}")
    
    async def load(self, filepath: str):
        """تحميل النموذج"""
        try:
            import tensorflow as tf
            self.model = tf.keras.models.load_model(filepath)
            self._update_target_network()
            logger.info(f"Model loaded from {filepath}")
        except Exception as e:
            logger.error(f"Failed to load model: {e}")
    
    async def get_statistics(self) -> Dict:
        """إحصائيات الوكيل"""
        return {
            "state_size": self.state_size,
            "action_size": self.action_size,
            "epsilon": self.epsilon,
            "memory_size": len(self.memory),
            "training_steps": self.training_step,
            "batch_size": self.batch_size,
            "gamma": self.gamma,
            "learning_rate": self.learning_rate
        }

