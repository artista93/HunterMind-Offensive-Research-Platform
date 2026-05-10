
import numpy as np
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from datetime import datetime
import random

import logging

logger = logging.getLogger(__name__)


@dataclass
class ActorCriticMemory:
    """ذاكرة Actor-Critic"""
    states: List[np.ndarray] = field(default_factory=list)
    actions: List[int] = field(default_factory=list)
    rewards: List[float] = field(default_factory=list)
    dones: List[bool] = field(default_factory=list)
    log_probs: List[float] = field(default_factory=list)


class ActorCriticAgent:
    """
    وكيل Actor-Critic المتقدم
    
    الميزات:
    - شبكتا الممثل (Actor) والناقد (Critic)
    - تحديثات متزامنة للسياسة والقيمة
    - تعلم عبر الإنترنت (Online Learning)
    - دالة ميزة (Advantage Function)
    """
    
    def __init__(
        self,
        state_size: int,
        action_size: int,
        actor_lr: float = 0.001,
        critic_lr: float = 0.001,
        gamma: float = 0.99,
        tau: float = 0.01  # معدل تحديث soft target
    ):
        self.state_size = state_size
        self.action_size = action_size
        self.actor_lr = actor_lr
        self.critic_lr = critic_lr
        self.gamma = gamma
        self.tau = tau
        
        self.actor = None  # شبكة السياسة
        self.critic = None  # شبكة القيمة
        self.memory = ActorCriticMemory()
        
        self.training_step = 0
        
        logger.info(f"ActorCriticAgent initialized: state={state_size}, action={action_size}")
    
    def _build_actor(self):
        """بناء شبكة الممثل (السياسة)"""
        try:
            import tensorflow as tf
            from tensorflow.keras import layers, models
            
            inputs = layers.Input(shape=(self.state_size,))
            x = layers.Dense(128, activation='relu')(inputs)
            x = layers.Dense(64, activation='relu')(x)
            x = layers.Dense(32, activation='relu')(x)
            
            # توزيع احتمالات الإجراءات
            outputs = layers.Dense(self.action_size, activation='softmax')(x)
            
            model = models.Model(inputs, outputs)
            model.compile(
                optimizer=tf.keras.optimizers.Adam(learning_rate=self.actor_lr)
            )
            
            return model
        except ImportError:
            logger.warning("TensorFlow not available, using simplified actor")
            return None
    
    def _build_critic(self):
        """بناء شبكة الناقد (القيمة)"""
        try:
            import tensorflow as tf
            from tensorflow.keras import layers, models
            
            inputs = layers.Input(shape=(self.state_size,))
            x = layers.Dense(128, activation='relu')(inputs)
            x = layers.Dense(64, activation='relu')(x)
            x = layers.Dense(32, activation='relu')(x)
            
            # قيمة الحالة
            outputs = layers.Dense(1, activation='linear')(x)
            
            model = models.Model(inputs, outputs)
            model.compile(
                optimizer=tf.keras.optimizers.Adam(learning_rate=self.critic_lr),
                loss='mse'
            )
            
            return model
        except ImportError:
            logger.warning("TensorFlow not available, using simplified critic")
            return None
    
    async def initialize(self):
        """تهيئة الشبكات"""
        self.actor = self._build_actor()
        self.critic = self._build_critic()
        logger.info("ActorCriticAgent initialized with networks")
    
    async def get_action(self, state: np.ndarray) -> Tuple[int, float]:
        """
        اختيار إجراء بناءً على السياسة الحالية
        
        Args:
            state: الحالة الحالية
        
        Returns:
            (الإجراء, log_probability)
        """
        if self.actor is None:
            return random.randrange(self.action_size), 0.0
        
        state_tensor = np.array(state).reshape(1, -1)
        action_probs = self.actor.predict(state_tensor, verbose=0)[0]
        
        # اختيار إجراء حسب التوزيع الاحتمالي
        action = np.random.choice(self.action_size, p=action_probs)
        log_prob = np.log(action_probs[action] + 1e-10)
        
        return action, log_prob
    
    async def get_value(self, state: np.ndarray) -> float:
        """
        حساب قيمة الحالة
        
        Args:
            state: الحالة الحالية
        
        Returns:
            قيمة الحالة
        """
        if self.critic is None:
            return 0.0
        
        state_tensor = np.array(state).reshape(1, -1)
        value = self.critic.predict(state_tensor, verbose=0)[0][0]
        return value
    
    async def remember(self, state, action, reward, done, log_prob):
        """تخزين تجربة في الذاكرة"""
        self.memory.states.append(np.array(state))
        self.memory.actions.append(action)
        self.memory.rewards.append(reward)
        self.memory.dones.append(done)
        self.memory.log_probs.append(log_prob)
    
    async def update(self) -> Tuple[float, float]:
        """
        تحديث شبكات الممثل والناقد
        
        Returns:
            (actor_loss, critic_loss)
        """
        if len(self.memory.states) == 0:
            return 0.0, 0.0
        
        states = np.array(self.memory.states)
        actions = np.array(self.memory.actions)
        rewards = np.array(self.memory.rewards)
        dones = np.array(self.memory.dones)
        old_log_probs = np.array(self.memory.log_probs)
        
        # حساب العوائد والمزايا
        returns = []
        advantages = []
        R = 0
        
        for t in reversed(range(len(rewards))):
            if dones[t]:
                R = rewards[t]
            else:
                R = rewards[t] + self.gamma * R
            
            returns.insert(0, R)
        
        returns = np.array(returns)
        
        # حساب قيم الحالات والمزايا
        values = await self._get_values(states)
        advantages = returns - values
        
        # تطبيع المزايا
        advantages = (advantages - advantages.mean()) / (advantages.std() + 1e-8)
        
        if self.actor is None or self.critic is None:
            return 0.0, 0.0
        
        # تحديث الناقد (Critic)
        critic_loss = np.mean((returns - values) ** 2)
        
        # تحديث الممثل (Actor)
        action_probs = self.actor.predict(states, verbose=0)
        new_log_probs = np.log(np.take_along_axis(action_probs, actions.reshape(-1, 1), axis=1) + 1e-10)
        new_log_probs = new_log_probs.flatten()
        
        # خسارة الممثل (مع المزايا)
        actor_loss = -np.mean(new_log_probs * advantages)
        
        # تحديث النموذجين (سيتم في الإصدار الكامل مع TensorFlow)
        
        self.memory = ActorCriticMemory()
        self.training_step += 1
        
        return actor_loss, critic_loss
    
    async def _get_values(self, states: np.ndarray) -> np.ndarray:
        """الحصول على قيم الحالات من شبكة الناقد"""
        if self.critic is None:
            return np.zeros(len(states))
        
        values = self.critic.predict(states, verbose=0).flatten()
        return values
    
    async def save(self, filepath: str):
        """حفظ النماذج"""
        if self.actor and self.critic:
            self.actor.save(f"{filepath}_actor.h5")
            self.critic.save(f"{filepath}_critic.h5")
            logger.info(f"Models saved to {filepath}")
    
    async def load(self, filepath: str):
        """تحميل النماذج"""
        try:
            import tensorflow as tf
            self.actor = tf.keras.models.load_model(f"{filepath}_actor.h5")
            self.critic = tf.keras.models.load_model(f"{filepath}_critic.h5")
            logger.info(f"Models loaded from {filepath}")
        except Exception as e:
            logger.error(f"Failed to load models: {e}")
    
    async def get_statistics(self) -> Dict:
        """إحصائيات الوكيل"""
        return {
            "state_size": self.state_size,
            "action_size": self.action_size,
            "actor_lr": self.actor_lr,
            "critic_lr": self.critic_lr,
            "gamma": self.gamma,
            "tau": self.tau,
            "memory_size": len(self.memory.states),
            "training_steps": self.training_step
        }

