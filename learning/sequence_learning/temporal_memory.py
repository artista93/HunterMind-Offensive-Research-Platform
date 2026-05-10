
import numpy as np
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from collections import defaultdict

import logging

logger = logging.getLogger(__name__)


@dataclass
class TemporalRecord:
    """سجل زمني"""
    timestamp: datetime
    value: Any
    importance: float = 1.0
    metadata: Dict[str, Any] = field(default_factory=dict)


class TemporalMemory:
    """
    الذاكرة الزمنية المتقدمة
    
    الميزات:
    - تخزين المعلومات مع الطوابع الزمنية
    - استرجاع المعلومات من نوافذ زمنية محددة
    - تحليل الاتجاهات الزمنية
    - نسيان المعلومات القديمة
    """
    
    def __init__(self, retention_days: int = 30):
        self.retention_days = retention_days
        self.records: Dict[str, List[TemporalRecord]] = defaultdict(list)
        self.trends: Dict[str, float] = {}
        
        logger.info(f"TemporalMemory initialized (retention={retention_days} days)")
    
    async def add_record(self, key: str, value: Any, importance: float = 1.0, metadata: Dict = None):
        """
        إضافة سجل زمني جديد
        
        Args:
            key: مفتاح السجل
            value: القيمة
            importance: الأهمية
            metadata: بيانات إضافية
        """
        record = TemporalRecord(
            timestamp=datetime.now(),
            value=value,
            importance=importance,
            metadata=metadata or {}
        )
        
        self.records[key].append(record)
        
        # تنظيف السجلات القديمة
        await self._cleanup_old_records(key)
        
        logger.debug(f"Temporal record added: {key}")
    
    async def get_records(
        self,
        key: str,
        start_time: datetime = None,
        end_time: datetime = None,
        limit: int = 100
    ) -> List[TemporalRecord]:
        """
        استرجاع السجلات في نطاق زمني
        
        Args:
            key: مفتاح السجل
            start_time: وقت البداية
            end_time: وقت النهاية
            limit: عدد النتائج
        
        Returns:
            قائمة بالسجلات الزمنية
        """
        records = self.records.get(key, [])
        
        if start_time:
            records = [r for r in records if r.timestamp >= start_time]
        
        if end_time:
            records = [r for r in records if r.timestamp <= end_time]
        
        # ترتيب حسب الوقت (الأحدث أولاً)
        records.sort(key=lambda x: x.timestamp, reverse=True)
        
        return records[:limit]
    
    async def get_latest(self, key: str) -> Optional[TemporalRecord]:
        """
        الحصول على أحدث سجل
        
        Args:
            key: مفتاح السجل
        
        Returns:
            أحدث سجل أو None
        """
        records = self.records.get(key, [])
        if not records:
            return None
        
        return max(records, key=lambda x: x.timestamp)
    
    async def get_values_in_window(
        self,
        key: str,
        window_hours: int = 24
    ) -> List[Any]:
        """
        الحصول على القيم في نافذة زمنية محددة
        
        Args:
            key: مفتاح السجل
            window_hours: حجم النافذة بالساعات
        
        Returns:
            قائمة بالقيم
        """
        cutoff = datetime.now() - timedelta(hours=window_hours)
        records = await self.get_records(key, start_time=cutoff)
        return [r.value for r in records]
    
    async def calculate_trend(self, key: str, hours: int = 24) -> float:
        """
        حساب اتجاه القيم في الفترة الزمنية
        
        Args:
            key: مفتاح السجل
            hours: عدد الساعات للتحليل
        
        Returns:
            اتجاه التغير (-1 إلى 1)
        """
        values = await self.get_values_in_window(key, hours)
        
        if len(values) < 2:
            return 0.0
        
        # حساب الانحدار الخطي البسيط
        x = list(range(len(values)))
        y = values
        
        n = len(x)
        sum_x = sum(x)
        sum_y = sum(y)
        sum_xy = sum(x[i] * y[i] for i in range(n))
        sum_x2 = sum(x[i] * x[i] for i in range(n))
        
        denominator = n * sum_x2 - sum_x * sum_x
        if denominator == 0:
            return 0.0
        
        slope = (n * sum_xy - sum_x * sum_y) / denominator
        
        # تطبيع الميل إلى المدى [-1, 1]
        trend = max(-1, min(1, slope / max(1, abs(slope))))
        
        self.trends[key] = trend
        return trend
    
    async def predict_next_value(self, key: str) -> Optional[float]:
        """
        التنبؤ بالقيمة التالية بناءً على الاتجاه
        
        Args:
            key: مفتاح السجل
        
        Returns:
            القيمة المتوقعة أو None
        """
        latest = await self.get_latest(key)
        if not latest:
            return None
        
        trend = await self.calculate_trend(key)
        
        # تنبؤ بسيط: آخر قيمة + متوسط التغير
        if isinstance(latest.value, (int, float)):
            # الحصول على متوسط التغير
            values = await self.get_values_in_window(key, 12)
            if len(values) >= 2:
                avg_change = sum(values[i] - values[i-1] for i in range(1, len(values))) / (len(values) - 1)
                next_value = latest.value + avg_change * trend
                return max(0, next_value)  # منع القيم السالبة
        
        return latest.value
    
    async def _cleanup_old_records(self, key: str):
        """تنظيف السجلات القديمة"""
        cutoff = datetime.now() - timedelta(days=self.retention_days)
        self.records[key] = [
            r for r in self.records[key]
            if r.timestamp >= cutoff
        ]
    
    async def forget_old_records(self, max_age_days: int = None):
        """نسيان جميع السجلات القديمة"""
        days = max_age_days or self.retention_days
        cutoff = datetime.now() - timedelta(days=days)
        
        for key in self.records:
            self.records[key] = [
                r for r in self.records[key]
                if r.timestamp >= cutoff
            ]
        
        logger.info(f"Forgot records older than {days} days")
    
    async def get_statistics(self) -> Dict:
        """إحصائيات الذاكرة"""
        total_records = sum(len(v) for v in self.records.values())
        
        return {
            "total_keys": len(self.records),
            "total_records": total_records,
            "avg_records_per_key": total_records / len(self.records) if self.records else 0,
            "trends": self.trends,
            "retention_days": self.retention_days,
            "oldest_record": min(
                (r.timestamp for records in self.records.values() for r in records),
                default=datetime.now()
            ).isoformat()
        }

