
import json
import asyncio
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from collections import defaultdict

import logging

logger = logging.getLogger(__name__)


class EventType(Enum):
    """أنواع الأحداث"""
    SYSTEM_START = "system_start"
    SYSTEM_STOP = "system_stop"
    COMPONENT_LOAD = "component_load"
    COMPONENT_UNLOAD = "component_unload"
    TASK_START = "task_start"
    TASK_COMPLETE = "task_complete"
    TASK_FAIL = "task_fail"
    DATA_RECEIVED = "data_received"
    DATA_SENT = "data_sent"
    CONNECTION_ESTABLISHED = "connection_established"
    CONNECTION_CLOSED = "connection_closed"
    CUSTOM = "custom"


@dataclass
class Event:
    """حدث"""
    id: str
    type: EventType
    source: str
    data: Any
    timestamp: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)


class EventLogger:
    """
    مسجل الأحداث المتقدم
    
    الميزات:
    - تسلسل الأحداث حسب الوقت
    - تتبع تدفق البيانات
    - تصفية الأحداث حسب النوع والمصدر
    - ردود فعل على الأحداث
    """
    
    def __init__(self, max_events: int = 10000):
        self.events: List[Event] = []
        self.max_events = max_events
        self.subscribers: Dict[EventType, List[Callable]] = defaultdict(list)
        self._lock = asyncio.Lock()
        
        logger.info(f"EventLogger initialized (max_events={max_events})")
    
    async def log_event(
        self,
        event_type: EventType,
        source: str,
        data: Any,
        metadata: Dict = None
    ) -> str:
        """
        تسجيل حدث جديد
        
        Args:
            event_type: نوع الحدث
            source: مصدر الحدث
            data: بيانات الحدث
            metadata: بيانات وصفية
        
        Returns:
            معرف الحدث
        """
        import uuid
        event_id = str(uuid.uuid4())[:8]
        
        event = Event(
            id=event_id,
            type=event_type,
            source=source,
            data=data,
            metadata=metadata or {}
        )
        
        async with self._lock:
            self.events.append(event)
            
            if len(self.events) > self.max_events:
                self.events = self.events[-self.max_events:]
        
        # إشعار المشتركين
        await self._notify_subscribers(event)
        
        logger.debug(f"Event logged: {event_type.value} from {source}")
        return event_id
    
    async def _notify_subscribers(self, event: Event):
        """إشعار المشتركين بالحدث"""
        for handler in self.subscribers.get(event.type, []):
            try:
                if asyncio.iscoroutinefunction(handler):
                    await handler(event)
                else:
                    handler(event)
            except Exception as e:
                logger.error(f"Event handler error: {e}")
    
    async def subscribe(self, event_type: EventType, handler: Callable):
        """الاشتراك في نوع حدث معين"""
        self.subscribers[event_type].append(handler)
        logger.debug(f"Subscribed to {event_type.value}")
    
    async def unsubscribe(self, event_type: EventType, handler: Callable):
        """إلغاء الاشتراك من نوع حدث معين"""
        if handler in self.subscribers[event_type]:
            self.subscribers[event_type].remove(handler)
            logger.debug(f"Unsubscribed from {event_type.value}")
    
    async def get_events(
        self,
        event_type: EventType = None,
        source: str = None,
        limit: int = 100,
        offset: int = 0
    ) -> List[Event]:
        """
        الحصول على الأحداث حسب المعايير
        
        Args:
            event_type: نوع الحدث (اختياري)
            source: المصدر (اختياري)
            limit: عدد النتائج
            offset: الإزاحة
        
        Returns:
            قائمة بالأحداث
        """
        async with self._lock:
            events = self.events
        
        if event_type:
            events = [e for e in events if e.type == event_type]
        
        if source:
            events = [e for e in events if e.source == source]
        
        events.sort(key=lambda x: x.timestamp, reverse=True)
        return events[offset:offset + limit]
    
    async def get_events_by_time_range(
        self,
        start_time: datetime,
        end_time: datetime,
        limit: int = 100
    ) -> List[Event]:
        """
        الحصول على الأحداث في نطاق زمني
        
        Args:
            start_time: وقت البدء
            end_time: وقت الانتهاء
            limit: عدد النتائج
        
        Returns:
            قائمة بالأحداث
        """
        async with self._lock:
            events = [
                e for e in self.events
                if start_time <= e.timestamp <= end_time
            ]
        
        events.sort(key=lambda x: x.timestamp)
        return events[-limit:]
    
    async def get_event_stream(self) -> List[Dict]:
        """
        الحصول على تدفق الأحداث (للواجهات في الوقت الفعلي)
        
        Returns:
            قائمة بالأحداث بتنسيق JSON
        """
        async with self._lock:
            return [
                {
                    "id": e.id,
                    "type": e.type.value,
                    "source": e.source,
                    "data": e.data,
                    "timestamp": e.timestamp.isoformat(),
                    "metadata": e.metadata
                }
                for e in self.events[-100:]
            ]
    
    async def clear_events(self):
        """مسح جميع الأحداث"""
        async with self._lock:
            self.events.clear()
            logger.info("Events cleared")
    
    async def get_statistics(self) -> Dict:
        """إحصائيات مسجل الأحداث"""
        async with self._lock:
            total = len(self.events)
            
            # إحصائيات حسب النوع
            by_type = defaultdict(int)
            for event in self.events:
                by_type[event.type.value] += 1
            
            # إحصائيات حسب المصدر
            by_source = defaultdict(int)
            for event in self.events:
                by_source[event.source] += 1
            
            return {
                "total_events": total,
                "by_type": dict(by_type),
                "by_source": dict(by_source),
                "subscribers_count": sum(len(v) for v in self.subscribers.values()),
                "max_events": self.max_events
            }


# نسخة عالمية
_default_event_logger = None


async def get_event_logger() -> EventLogger:
    """الحصول على نسخة عالمية من مسجل الأحداث"""
    global _default_event_logger
    if _default_event_logger is None:
        _default_event_logger = EventLogger()
    return _default_event_logger

