
import numpy as np
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from collections import deque

import logging

logger = logging.getLogger(__name__)


@dataclass
class Sequence:
    """تسلسل"""
    id: str
    events: List[Any]
    length: int
    frequency: int
    first_seen: datetime
    last_seen: datetime


class SequenceLearner:
    """
    متعلم التسلسلات المتقدم
    
    الميزات:
    - اكتشاف الأنماط المتكررة في التسلسلات
    - التنبؤ بالأحداث التالية
    - تحليل التسلسلات الزمنية
    - استخدام LSTM للتنبؤ
    """
    
    def __init__(self, max_sequence_length: int = 50):
        self.max_sequence_length = max_sequence_length
        self.sequences: List[Sequence] = []
        self.prediction_model = None
        self.sequence_buffer: deque = deque(maxlen=1000)
        
        logger.info(f"SequenceLearner initialized (max_length={max_sequence_length})")
    
    def _build_lstm_model(self, input_dim: int, hidden_dim: int = 64):
        """بناء نموذج LSTM للتنبؤ بالتسلسلات"""
        try:
            import tensorflow as tf
            from tensorflow.keras import layers, models
            
            model = models.Sequential([
                layers.LSTM(hidden_dim, input_shape=(self.max_sequence_length, input_dim), return_sequences=True),
                layers.LSTM(hidden_dim // 2),
                layers.Dense(hidden_dim // 4, activation='relu'),
                layers.Dense(input_dim, activation='softmax')
            ])
            
            model.compile(
                optimizer='adam',
                loss='categorical_crossentropy',
                metrics=['accuracy']
            )
            
            return model
        except ImportError:
            logger.warning("TensorFlow not available, using simplified predictor")
            return None
    
    async def add_event(self, event: Any):
        """
        إضافة حدث جديد إلى المخزن المؤقت
        
        Args:
            event: الحدث الجديد
        """
        self.sequence_buffer.append(event)
        
        # محاولة اكتشاف الأنماط
        await self._detect_patterns()
    
    async def _detect_patterns(self):
        """اكتشاف الأنماط المتكررة في التسلسلات"""
        if len(self.sequence_buffer) < 3:
            return
        
        # تحويل المخزن المؤقت إلى قائمة
        events = list(self.sequence_buffer)
        
        # البحث عن الأنماط المتكررة
        for length in range(2, min(10, len(events))):
            for i in range(len(events) - length):
                pattern = events[i:i+length]
                
                # حساب التكرار
                frequency = self._count_occurrences(events, pattern)
                
                if frequency >= 2:
                    # تحديث أو إضافة النمط
                    await self._update_sequence(pattern, frequency)
    
    def _count_occurrences(self, events: List, pattern: List) -> int:
        """حساب تكرار نمط في التسلسل"""
        count = 0
        pattern_len = len(pattern)
        
        for i in range(len(events) - pattern_len + 1):
            if events[i:i+pattern_len] == pattern:
                count += 1
        
        return count
    
    async def _update_sequence(self, pattern: List, frequency: int):
        """تحديث تسلسل موجود أو إضافة تسلسل جديد"""
        import uuid
        
        # البحث عن تسلسل مشابه
        existing = None
        for seq in self.sequences:
            if seq.events == pattern:
                existing = seq
                break
        
        if existing:
            existing.frequency = frequency
            existing.last_seen = datetime.now()
        else:
            new_seq = Sequence(
                id=str(uuid.uuid4())[:8],
                events=pattern,
                length=len(pattern),
                frequency=frequency,
                first_seen=datetime.now(),
                last_seen=datetime.now()
            )
            self.sequences.append(new_seq)
    
    async def predict_next(self, context: List[Any]) -> Optional[Any]:
        """
        التنبؤ بالحدث التالي بناءً على السياق
        
        Args:
            context: سياق الأحداث السابقة
        
        Returns:
            الحدث المتوقع أو None
        """
        if not self.sequences:
            return None
        
        # البحث عن أنماط مطابقة للسياق
        for seq in self.sequences:
            if len(seq.events) > len(context):
                # التحقق من تطابق بداية التسلسل مع السياق
                if seq.events[:len(context)] == context:
                    # إرجاع الحدث التالي في التسلسل
                    if len(seq.events) > len(context):
                        return seq.events[len(context)]
        
        # إذا لم يتم العثور على تطابق، إرجاع الحدث الأكثر تكراراً
        if self.sequences:
            most_frequent = max(self.sequences, key=lambda x: x.frequency)
            if most_frequent.events:
                return most_frequent.events[0]
        
        return None
    
    async def get_frequent_sequences(self, min_frequency: int = 2) -> List[Sequence]:
        """الحصول على التسلسلات المتكررة"""
        return [s for s in self.sequences if s.frequency >= min_frequency]
    
    async def get_longest_sequence(self) -> Optional[Sequence]:
        """الحصول على أطول تسلسل"""
        if not self.sequences:
            return None
        return max(self.sequences, key=lambda x: x.length)
    
    async def get_statistics(self) -> Dict:
        """إحصائيات المتعلم"""
        if not self.sequences:
            return {"total_sequences": 0}
        
        return {
            "total_sequences": len(self.sequences),
            "average_length": sum(s.length for s in self.sequences) / len(self.sequences),
            "max_length": max(s.length for s in self.sequences),
            "frequent_sequences": len([s for s in self.sequences if s.frequency >= 2]),
            "buffer_size": len(self.sequence_buffer),
            "max_sequence_length": self.max_sequence_length
        }

