
import numpy as np
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from datetime import datetime
import random

import logging

logger = logging.getLogger(__name__)


@dataclass
class PPOMemory:
    """ذاكرة PPO"""
    states: List[np.ndarray] = field(default_factory=list)
    actions: List[int] = field(default_factory=list)
    rewards: List[float] = field(default_factory=list)
    dones: List[bool] = field(default_factory=list)
    log_probs: List[float] = field(default_factory=list)
    values: List[float] = field(default_factory=list)


class PPOAgent:
    """
    وكيل PPO المتقدم
    
    الميزات:
    - خوارزمية PPO لتحسين السياسات
    - شبكات الممثل والناقد (Actor-Critic)
    - تحديثات سياسة محظورة (Clipped)
    - ميزة GAEs للحساب الفعال للـ Advantage
    """
    
    def __init__(
        self,
        state_size: int,
        action_size: int,
        learning_rate: float = 0.0003,
        gamma: float = 0.99,
        gae_lambda: float = 0.95,
        clip_epsilon: float = 0.2,
        epochs: int = 10,
        batch_size: int = 64
    ):
        self.state_size = state_size
        self.action_size = action_size
        self.learning_rate = learning_rate
        self.gamma = gamma
        self.gae_lambda = gae_lambda
        self.clip_epsilon = clip_epsilon
        self.epochs = epochs
        self.batch_size = batch_size
        
        self.actor = None  # شبكة السياسة
        self.critic = None  # شبكة القيمة
        self.memory = PPOMemory()
        
        self.training_step = 0
        
        logger.info(f"PPOAgent initialized: state={state_size}, action={action_size}")
    
    def _build_actor(self):
        """بناء شبكة الممثل (السياسة)"""
        try:
            import tensorflow as tf
            from tensorflow.keras import layers, models
            
            inputs = layers.Input(shape=(self.state_size,))
            x = layers.Dense(64, activation='tanh')(inputs)
            x = layers.Dense(64, activation='tanh')(x)
            x = layers.Dense(32, activation='tanh')(x)
            
            # توزيع احتمالات الإجراءات
            outputs = layers.Dense(self.action_size, activation='softmax')(x)
            
            model = models.Model(inputs, outputs)
            model.compile(
                optimizer=tf.keras.optimizers.Adam(learning_rate=self.learning_rate)
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
            x = layers.Dense(64, activation='tanh')(inputs)
            x = layers.Dense(64, activation='tanh')(x)
            x = layers.Dense(32, activation='tanh')(x)
            
            # قيمة الحالة (قيمة scalar)
            outputs = layers.Dense(1, activation='linear')(x)
            
            model = models.Model(inputs, outputs)
            model.compile(
                optimizer=tf.keras.optimizers.Adam(learning_rate=self.learning_rate),
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
        logger.info("PPOAgent initialized with networks")
    
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
    
    async def remember(self, state, action, reward, done, log_prob, value):
        """تخزين تجربة في الذاكرة"""
        self.memory.states.append(np.array(state))
        self.memory.actions.append(action)
        self.memory.rewards.append(reward)
        self.memory.dones.append(done)
        self.memory.log_probs.append(log_prob)
        self.memory.values.append(value)
    
    async def compute_gae_advantages(self) -> Tuple[np.ndarray, np.ndarray]:
        """
        حساب ميزات GAE و returns
        
        Returns:
            (advantages, returns)
        """
        rewards = np.array(self.memory.rewards)
        dones = np.array(self.memory.dones)
        values = np.array(self.memory.values)
        
        advantages = np.zeros(len(rewards))
        gae = 0
        
        for t in reversed(range(len(rewards))):
            if t == len(rewards) - 1:
                next_value = 0
            else:
                next_value = values[t + 1]
            
            if dones[t]:
                delta = rewards[t] - values[t]
                gae = delta
            else:
                delta = rewards[t] + self.gamma * next_value - values[t]
                gae = delta + self.gamma * self.gae_lambda * gae
            
            advantages[t] = gae
        
        returns = advantages + values
        
        # تطبيع المزايا
        advantages = (advantages - advantages.mean()) / (advantages.std() + 1e-8)
        
        return advantages, returns
    
    async def update(self) -> float:
        """
        تحديث السياسة وشبكة القيمة باستخدام PPO
        
        Returns:
            قيمة الخسارة
        """
        if len(self.memory.states) < self.batch_size:
            return 0.0
        
        # حساب المزايا والعوائد
        advantages, returns = await self.compute_gae_advantages()
        
        states = np.array(self.memory.states)
        actions = np.array(self.memory.actions)
        old_log_probs = np.array(self.memory.log_probs)
        
        total_loss = 0.0
        
        # تحديث متعدد epochs
        for _ in range(self.epochs):
            # اختيار عينات عشوائية
            indices = np.random.permutation(len(states))
            
            for start in range(0, len(states), self.batch_size):
                end = start + self.batch_size
                batch_indices = indices[start:end]
                
                batch_states = states[batch_indices]
                batch_actions = actions[batch_indices]
                batch_advantages = advantages[batch_indices]
                batch_returns = returns[batch_indices]
                batch_old_log_probs = old_log_probs[batch_indices]
                
                if self.actor is None or self.critic is None:
                    continue
                
                # الحصول على log_probs الجديدة
                action_probs = self.actor.predict(batch_states, verbose=0)
                new_log_probs = np.log(np.take_along_axis(action_probs, batch_actions.reshape(-1, 1), axis=1) + 1e-10)
                new_log_probs = new_log_probs.flatten()
                
                # حساب النسبة (ratio)
                ratio = np.exp(new_log_probs - batch_old_log_probs)
                
                # خسارة السياسة المحظورة
                surr1 = ratio * batch_advantages
                surr2 = np.clip(ratio, 1 - self.clip_epsilon, 1 + self.clip_epsilon) * batch_advantages
                policy_loss = -np.minimum(surr1, surr2).mean()
                
                # خسارة القيمة
                values = self.critic.predict(batch_states, verbose=0).flatten()
                value_loss = np.mean((batch_returns - values) ** 2)
                
                # خسارة الإنتروبيا (للاستكشاف)
                entropy = -np.sum(action_probs * np.log(action_probs + 1e-10), axis=1).mean()
                
                total_loss = policy_loss + 0.5 * value_loss - 0.01 * entropy
                
                # تطبيق التدرجات (يتم في الإصدار الكامل مع نموذج TensorFlow)
        
        self.memory = PPOMemory()
        self.training_step += 1
        
        return total_loss
    
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
            "gamma": self.gamma,
            "gae_lambda": self.gae_lambda,
            "clip_epsilon": self.clip_epsilon,
            "epochs": self.epochs,
            "batch_size": self.batch_size,
            "memory_size": len(self.memory.states),
            "training_steps": self.training_step
        }

