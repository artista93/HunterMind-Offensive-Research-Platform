
import numpy as np
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from collections import deque

import logging

logger = logging.getLogger(__name__)


@dataclass
class TrainingBatch:
    """دفعة تدريبية"""
    id: str
    data: List[Dict]
    labels: List[Any]
    timestamp: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)


class IncrementalTrainer:
    """
    التدريب التزايدي المتقدم
    
    الميزات:
    - تدريب النماذج بشكل تزايدي
    - تحديث النماذج مع البيانات الجديدة فقط
    - الحفاظ على الأداء على البيانات القديمة
    - دعم التحديثات المتكررة
    """
    
    def __init__(self, batch_size: int = 32, learning_rate: float = 0.001):
        self.batch_size = batch_size
        self.learning_rate = learning_rate
        self.model = None
        self.training_batches: List[TrainingBatch] = []
        self.version = 0
        
        logger.info(f"IncrementalTrainer initialized (batch_size={batch_size})")
    
    def _build_model(self, input_dim: int, output_dim: int):
        """بناء نموذج بسيط للتدريب التزايدي"""
        try:
            import tensorflow as tf
            from tensorflow.keras import layers, models
            
            model = models.Sequential([
                layers.Dense(64, activation='relu', input_shape=(input_dim,)),
                layers.Dense(32, activation='relu'),
                layers.Dense(output_dim, activation='softmax')
            ])
            
            model.compile(
                optimizer=tf.keras.optimizers.Adam(learning_rate=self.learning_rate),
                loss='sparse_categorical_crossentropy',
                metrics=['accuracy']
            )
            
            return model
        except ImportError:
            logger.warning("TensorFlow not available, using simplified trainer")
            return None
    
    async def initialize_model(self, input_dim: int, output_dim: int):
        """
        تهيئة النموذج
        
        Args:
            input_dim: أبعاد المدخلات
            output_dim: أبعاد المخرجات
        """
        self.model = self._build_model(input_dim, output_dim)
        self.version += 1
        
        logger.info(f"Model initialized: input_dim={input_dim}, output_dim={output_dim}")
    
    async def train_batch(self, data: List[Dict], labels: List[Any], metadata: Dict = None):
        """
        تدريب النموذج على دفعة جديدة
        
        Args:
            data: بيانات التدريب
            labels: التصنيفات
            metadata: بيانات إضافية
        """
        if self.model is None:
            logger.warning("Model not initialized")
            return
        
        import uuid
        batch_id = str(uuid.uuid4())[:8]
        
        batch = TrainingBatch(
            id=batch_id,
            data=data,
            labels=labels,
            metadata=metadata or {}
        )
        
        self.training_batches.append(batch)
        
        # تحويل البيانات إلى مصفوفات
        X = np.array([list(d.values()) for d in data])
        y = np.array(labels)
        
        # تدريب النموذج على الدفعة
        history = self.model.fit(X, y, batch_size=self.batch_size, epochs=1, verbose=0)
        loss = history.history['loss'][0]
        accuracy = history.history['accuracy'][0]
        
        self.version += 1
        
        logger.debug(f"Trained batch {batch_id}: loss={loss:.4f}, accuracy={accuracy:.4f}")
    
    async def update_model(self, new_data: List[Dict], new_labels: List[Any]):
        """
        تحديث النموذج ببيانات جديدة
        
        Args:
            new_data: البيانات الجديدة
            new_labels: التصنيفات الجديدة
        """
        if self.model is None:
            logger.warning("Model not initialized")
            return
        
        # تدريب على البيانات الجديدة فقط
        X = np.array([list(d.values()) for d in new_data])
        y = np.array(new_labels)
        
        # تحديث النموذج مع معدل تعلم أقل للحفاظ على المعرفة السابقة
        original_lr = self.learning_rate
        self.learning_rate *= 0.5
        
        history = self.model.fit(X, y, batch_size=self.batch_size, epochs=1, verbose=0)
        loss = history.history['loss'][0]
        accuracy = history.history['accuracy'][0]
        
        self.learning_rate = original_lr
        self.version += 1
        
        logger.info(f"Model updated: loss={loss:.4f}, accuracy={accuracy:.4f}")
    
    async def predict(self, input_data: Dict) -> Any:
        """
        التنبؤ باستخدام النموذج الحالي
        
        Args:
            input_data: بيانات الإدخال
        
        Returns:
            التصنيف المتوقع
        """
        if self.model is None:
            return 0
        
        X = np.array([list(input_data.values())])
        predictions = self.model.predict(X, verbose=0)
        return np.argmax(predictions[0])
    
    async def get_model_version(self) -> int:
        """الحصول على إصدار النموذج الحالي"""
        return self.version
    
    async def get_performance_metrics(self) -> Dict:
        """الحصول على مقاييس أداء النموذج"""
        if not self.training_batches:
            return {"total_batches": 0}
        
        return {
            "total_batches": len(self.training_batches),
            "model_version": self.version,
            "learning_rate": self.learning_rate,
            "batch_size": self.batch_size
        }
    
    async def save_model(self, filepath: str):
        """حفظ النموذج"""
        if self.model:
            self.model.save(filepath)
            logger.info(f"Model saved to {filepath}")
    
    async def load_model(self, filepath: str):
        """تحميل النموذج"""
        try:
            import tensorflow as tf
            self.model = tf.keras.models.load_model(filepath)
            logger.info(f"Model loaded from {filepath}")
        except Exception as e:
            logger.error(f"Failed to load model: {e}")

