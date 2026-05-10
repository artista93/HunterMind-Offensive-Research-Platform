
import numpy as np
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from collections import defaultdict

import logging

logger = logging.getLogger(__name__)


@dataclass
class BehaviorEvent:
    """حدث سلوكي"""
    timestamp: datetime
    event_type: str
    parameters: Dict[str, Any]
    confidence: float = 0.8


@dataclass
class BehaviorPrediction:
    """تنبؤ سلوكي"""
    event_type: str
    probability: float
    expected_time: Optional[datetime] = None
    confidence: float = 0.0


class BehaviorPredictor:
    """
    التنبؤ بالسلوك المتقدم
    
    الميزات:
    - تحليل أنماط السلوك التاريخية
    - التنبؤ بالأحداث المستقبلية
    - حساب احتمالية الأحداث
    - اكتشاف السلوك الشاذ
    """
    
    def __init__(self, history_size: int = 1000):
        self.history_size = history_size
        self.event_history: List[BehaviorEvent] = []
        self.event_counts: Dict[str, int] = defaultdict(int)
        self.transition_counts: Dict[Tuple[str, str], int] = defaultdict(int)
        
        logger.info(f"BehaviorPredictor initialized (history_size={history_size})")
    
    async def add_event(self, event: BehaviorEvent):
        """
        إضافة حدث سلوكي جديد
        
        Args:
            event: الحدث السلوكي
        """
        # إضافة إلى التاريخ
        self.event_history.append(event)
        
        # تحديث الإحصائيات
        self.event_counts[event.event_type] += 1
        
        # تحديث الانتقالات
        if len(self.event_history) >= 2:
            prev_event = self.event_history[-2].event_type
            curr_event = event.event_type
            self.transition_counts[(prev_event, curr_event)] += 1
        
        # الحفاظ على حجم التاريخ
        if len(self.event_history) > self.history_size:
            removed = self.event_history.pop(0)
            self.event_counts[removed.event_type] -= 1
    
    async def predict_next_event(self) -> List[BehaviorPrediction]:
        """
        التنبؤ بالحدث التالي بناءً على الأنماط التاريخية
        
        Returns:
            قائمة بالتنبؤات مرتبة حسب الاحتمالية
        """
        if len(self.event_history) < 2:
            return []
        
        last_event = self.event_history[-1].event_type
        
        # حساب احتمالية الانتقالات من آخر حدث
        predictions = []
        total = 0
        
        for (prev, next_event), count in self.transition_counts.items():
            if prev == last_event:
                total += count
        
        if total > 0:
            for (prev, next_event), count in self.transition_counts.items():
                if prev == last_event:
                    probability = count / total
                    predictions.append(
                        BehaviorPrediction(
                            event_type=next_event,
                            probability=probability,
                            confidence=min(0.9, probability + 0.1)
                        )
                    )
        
        # ترتيب حسب الاحتمالية
        predictions.sort(key=lambda x: x.probability, reverse=True)
        
        return predictions
    
    async def predict_event_time(
        self,
        event_type: str
    ) -> Optional[float]:
        """
        التنبؤ بالوقت المتوقع لحدوث حدث معين
        
        Args:
            event_type: نوع الحدث
        
        Returns:
            الوقت المتوقع (بالثواني) أو None
        """
        # جمع الفواصل الزمنية بين الأحداث من نفس النوع
        intervals = []
        last_time = None
        
        for event in self.event_history:
            if event.event_type == event_type:
                if last_time:
                    interval = (event.timestamp - last_time).total_seconds()
                    intervals.append(interval)
                last_time = event.timestamp
        
        if not intervals:
            return None
        
        # حساب متوسط الفاصل الزمني
        avg_interval = sum(intervals) / len(intervals)
        
        return avg_interval
    
    async def detect_anomaly(self, new_event: BehaviorEvent) -> float:
        """
        اكتشاف السلوك الشاذ
        
        Args:
            new_event: الحدث الجديد
        
        Returns:
            درجة الشذوذ (0-1، كلما زاد كلما كان أكثر شذوذاً)
        """
        # حساب احتمالية الحدث
        total_events = sum(self.event_counts.values())
        if total_events == 0:
            return 0.0
        
        event_probability = self.event_counts[new_event.event_type] / total_events
        
        # حساب انحراف الوقت (إذا كان لدينا تاريخ)
        expected_time = await self.predict_event_time(new_event.event_type)
        time_anomaly = 0.0
        
        if expected_time and len(self.event_history) >= 2:
            last_event = self.event_history[-1]
            actual_interval = (new_event.timestamp - last_event.timestamp).total_seconds()
            time_anomaly = min(1.0, abs(actual_interval - expected_time) / expected_time)
        
        # دمج الدرجات
        anomaly_score = (1 - event_probability) * 0.6 + time_anomaly * 0.4
        
        return anomaly_score
    
    async def get_event_statistics(self) -> Dict:
        """إحصائيات الأحداث"""
        if not self.event_history:
            return {"total_events": 0}
        
        # توزيع الأحداث
        event_distribution = dict(self.event_counts)
        
        # الأحداث الأكثر شيوعاً
        most_common = max(self.event_counts.items(), key=lambda x: x[1])[0] if self.event_counts else None
        
        return {
            "total_events": len(self.event_history),
            "unique_event_types": len(self.event_counts),
            "event_distribution": event_distribution,
            "most_common_event": most_common,
            "avg_events_per_time": len(self.event_history) / max(1, (self.event_history[-1].timestamp - self.event_history[0].timestamp).total_seconds())
        }

