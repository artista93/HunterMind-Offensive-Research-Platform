
import asyncio
from typing import Dict, List, Optional, Any, Set, Callable
from dataclasses import dataclass, field
from datetime import datetime
from collections import defaultdict

import logging

logger = logging.getLogger(__name__)


@dataclass
class Event:
    """حدث"""
    type: str
    source: str
    data: Any
    timestamp: datetime = field(default_factory=datetime.now)
    id: str = ""


class EventBus:
    """
    ناقل الأحداث المتقدم
    
    الميزات:
    - نشر والاشتراك في الأحداث (Pub/Sub)
    - معالجة غير متزامنة
    - تصفية الأحداث
    - تتبع تاريخ الأحداث
    """
    
    def __init__(self, max_history: int = 1000):
        self.subscribers: Dict[str, List[Callable]] = defaultdict(list)
        self.event_history: List[Event] = []
        self.max_history = max_history
        self._lock = asyncio.Lock()
        
        logger.info("EventBus initialized")
    
    async def subscribe(self, event_type: str, handler: Callable):
        """
        الاشتراك في نوع حدث معين
        
        Args:
            event_type: نوع الحدث
            handler: دالة معالجة الحدث
        """
        async with self._lock:
            if handler not in self.subscribers[event_type]:
                self.subscribers[event_type].append(handler)
                logger.debug(f"Subscribed to {event_type}")
    
    async def unsubscribe(self, event_type: str, handler: Callable):
        """
        إلغاء الاشتراك في نوع حدث معين
        
        Args:
            event_type: نوع الحدث
            handler: دالة معالجة الحدث
        """
        async with self._lock:
            if handler in self.subscribers[event_type]:
                self.subscribers[event_type].remove(handler)
                logger.debug(f"Unsubscribed from {event_type}")
    
    async def publish(self, event: Event):
        """
        نشر حدث
        
        Args:
            event: الحدث المنشور
        """
        import uuid
        event.id = str(uuid.uuid4())[:8]
        
        # تخزين الحدث في التاريخ
        async with self._lock:
            self.event_history.append(event)
            if len(self.event_history) > self.max_history:
                self.event_history.pop(0)
        
        # توزيع الحدث على المشتركين
        handlers = self.subscribers.get(event.type, [])
        handlers.extend(self.subscribers.get("*", []))  # المشتركين في جميع الأحداث
        
        if not handlers:
            return
        
        # تنفيذ المعالجات بشكل متوازي
        tasks = []
        for handler in handlers:
            if asyncio.iscoroutinefunction(handler):
                tasks.append(handler(event))
            else:
                handler(event)
        
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        
        logger.debug(f"Event published: {event.type} from {event.source}")
    
    async def get_history(self, event_type: str = None, limit: int = 100) -> List[Event]:
        """
        الحصول على تاريخ الأحداث
        
        Args:
            event_type: نوع الحدث (اختياري)
            limit: عدد النتائج
        
        Returns:
            قائمة بالأحداث
        """
        async with self._lock:
            events = self.event_history
            if event_type:
                events = [e for e in events if e.type == event_type]
            return events[-limit:]
    
    async def clear_history(self):
        """مسح تاريخ الأحداث"""
        async with self._lock:
            self.event_history.clear()
            logger.info("Event history cleared")
    
    async def get_statistics(self) -> Dict:
        """إحصائيات ناقل الأحداث"""
        async with self._lock:
            event_types = defaultdict(int)
            for event in self.event_history:
                event_types[event.type] += 1
            
            return {
                "total_events": len(self.event_history),
                "unique_event_types": len(event_types),
                "event_type_distribution": dict(event_types),
                "total_subscribers": sum(len(h) for h in self.subscribers.values()),
                "max_history": self.max_history
            }

