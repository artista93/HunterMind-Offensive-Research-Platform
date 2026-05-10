
import numpy as np
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from datetime import datetime

import logging

logger = logging.getLogger(__name__)


@dataclass
class RewardPrediction:
    """تنبؤ المكافأة"""
    state: np.ndarray
    action: int
    predicted_reward: float
    confidence: float
    timestamp: datetime = field(default_factory=datetime.now)


class RewardModel:
    """
    نموذج المكافأة المتقدم
    
    الميزات:
    - تنبؤ المكافآت للحالات والإجراءات
    - تعلم من المكافآت الحقيقية
    - تكيف مع ديناميكيات البيئة
    - تقدير عدم اليقين في التنبؤات
    """
    
    def __init__(
        self,
        state_size: int,
        action_size: int,
        learning_rate: float = 0.001,
        hidden_layers: List[int] = None
    ):
        self.state_size = state_size
        self.action_size = action_size
        self.learning_rate = learning_rate
        self.hidden_layers = hidden_layers or [64, 32]
        
        self.model = None
        self.training_data: List[Tuple[np.ndarray, int, float]] = []
        self.predictions: List[RewardPrediction] = []
        
        logger.info(f"RewardModel initialized: state={state_size}, action={action_size}")
    
    def _build_model(self):
        """بناء نموذج الشبكة العصبية"""
        try:
            import tensorflow as tf
            from tensorflow.keras import layers, models
            
            # إدخال الحالة والإجراء
            state_input = layers.Input(shape=(self.state_size,), name='state')
            action_input = layers.Input(shape=(1,), name='action')
            
            # معالجة الحالة
            x = layers.Dense(self.hidden_layers[0], activation='relu')(state_input)
            for units in self.hidden_layers[1:]:
                x = layers.Dense(units, activation='relu')(x)
            
            # دمج الإجراء
            action_embedding = layers.Dense(16, activation='relu')(action_input)
            combined = layers.Concatenate()([x, action_embedding])
            
            # طبقات الإخراج
            y = layers.Dense(32, activation='relu')(combined)
            y = layers.Dense(16, activation='relu')(y)
            
            # مخرجات: المكافأة المتوقعة وعدم اليقين
            reward = layers.Dense(1, activation='linear', name='reward')(y)
            uncertainty = layers.Dense(1, activation='sigmoid', name='uncertainty')(y)
            
            model = models.Model(
                inputs=[state_input, action_input],
                outputs=[reward, uncertainty]
            )
            
            model.compile(
                optimizer=tf.keras.optimizers.Adam(learning_rate=self.learning_rate),
                loss={'reward': 'mse', 'uncertainty': 'binary_crossentropy'},
                loss_weights={'reward': 1.0, 'uncertainty': 0.1}
            )
            
            return model
        except ImportError:
            logger.warning("TensorFlow not available, using simplified model")
            return None
    
    async def initialize(self):
        """تهيئة النموذج"""
        self.model = self._build_model()
        logger.info("RewardModel initialized")
    
    async def predict(
        self,
        state: np.ndarray,
        action: int,
        return_uncertainty: bool = True
    ) -> float:
        """
        تنبؤ المكافأة لحالة وإجراء معينين
        
        Args:
            state: الحالة
            action: الإجراء
            return_uncertainty: إرجاع عدم اليقين أيضاً
        
        Returns:
            المكافأة المتوقعة (وعدم اليقين إذا طلب)
        """
        if self.model is None:
            return 0.0, 0.5 if return_uncertainty else 0.0
        
        state_tensor = np.array(state).reshape(1, -1)
        action_tensor = np.array([[action]])
        
        reward_pred, uncertainty_pred = self.model.predict(
            [state_tensor, action_tensor],
            verbose=0
        )
        
        reward = float(reward_pred[0][0])
        uncertainty = float(uncertainty_pred[0][0]) if return_uncertainty else None
        
        # تسجيل التنبؤ
        self.predictions.append(RewardPrediction(
            state=state,
            action=action,
            predicted_reward=reward,
            confidence=1 - uncertainty if uncertainty else 0.5
        ))
        
        if return_uncertainty:
            return reward, uncertainty
        return reward
    
    async def update(
        self,
        state: np.ndarray,
        action: int,
        actual_reward: float,
        batch_size: int = 32
    ) -> float:
        """
        تحديث النموذج بمكافأة حقيقية
        
        Args:
            state: الحالة
            action: الإجراء
            actual_reward: المكافأة الحقيقية
            batch_size: حجم الدفعة للتدريب
        
        Returns:
            قيمة الخسارة
        """
        # تخزين البيانات
        self.training_data.append((state, action, actual_reward))
        
        # الاحتفاظ بآخر 10000 عينة فقط
        if len(self.training_data) > 10000:
            self.training_data.pop(0)
        
        if len(self.training_data) < batch_size:
            return 0.0
        
        # اختيار عينات عشوائية
        indices = np.random.choice(len(self.training_data), batch_size, replace=False)
        
        states = np.array([self.training_data[i][0] for i in indices])
        actions = np.array([[self.training_data[i][1]] for i in indices])
        rewards = np.array([self.training_data[i][2] for i in indices])
        
        # عدم اليقين المستهدف (منخفض للبيانات الموثوقة)
        uncertainties = np.ones(batch_size) * 0.1
        
        if self.model is None:
            return 0.0
        
        # تدريب النموذج
        history = self.model.fit(
            [states, actions],
            [rewards, uncertainties],
            batch_size=batch_size,
            epochs=5,
            verbose=0
        )
        
        loss = history.history['loss'][-1]
        return loss
    
    async def get_uncertainty(
        self,
        state: np.ndarray,
        action: int
    ) -> float:
        """
        الحصول على عدم اليقين في التنبؤ
        
        Args:
            state: الحالة
            action: الإجراء
        
        Returns:
            درجة عدم اليقين (0-1)
        """
        _, uncertainty = await self.predict(state, action, return_uncertainty=True)
        return uncertainty
    
    async def get_best_action(
        self,
        state: np.ndarray,
        valid_actions: List[int] = None
    ) -> int:
        """
        الحصول على أفضل إجراء بناءً على المكافآت المتوقعة
        
        Args:
            state: الحالة
            valid_actions: قائمة الإجراءات الصالحة
        
        Returns:
            أفضل إجراء
        """
        if valid_actions is None:
            valid_actions = list(range(self.action_size))
        
        best_action = valid_actions[0]
        best_reward = -float('inf')
        
        for action in valid_actions:
            reward, uncertainty = await self.predict(state, action, return_uncertainty=True)
            
            # تعديل المكافأة بعدم اليقين (تفضيل الإجراءات المؤكدة)
            adjusted_reward = reward * (1 - uncertainty)
            
            if adjusted_reward > best_reward:
                best_reward = adjusted_reward
                best_action = action
        
        return best_action
    
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
            logger.info(f"Model loaded from {filepath}")
        except Exception as e:
            logger.error(f"Failed to load model: {e}")
    
    async def get_statistics(self) -> Dict:
        """إحصائيات النموذج"""
        return {
            "state_size": self.state_size,
            "action_size": self.action_size,
            "hidden_layers": self.hidden_layers,
            "training_samples": len(self.training_data),
            "predictions_made": len(self.predictions),
            "learning_rate": self.learning_rate
        }

