"""
Event Bus - ناقل الأحداث
يدير توزيع الأحداث بين المكونات المختلفة في النظام
"""

import asyncio
import uuid
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
from datetime import datetime
from collections import defaultdict
from enum import Enum

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
    DATA_VULNERABILITY = "data_vulnerability"
    DATA_ENDPOINT = "data_endpoint"
    DATA_TECHNOLOGY = "data_technology"
    CONNECTION_ESTABLISHED = "connection_established"
    CONNECTION_CLOSED = "connection_closed"
    SCAN_STARTED = "scan_started"
    SCAN_COMPLETED = "scan_completed"
    SCAN_PAGE_COMPLETE = "scan_page_complete"
    VULNERABILITY_FOUND = "vulnerability_found"
    CUSTOM = "custom"


@dataclass
class Event:
    """حدث"""
    type: EventType
    source: str
    data: Any
    id: str = ""
    timestamp: datetime = field(default_factory=datetime.now)


class EventBus:
    """
    ناقل الأحداث المتقدم
    """
    
    def __init__(self, max_history: int = 1000):
        self.subscribers: Dict[EventType, List[Callable]] = defaultdict(list)
        self.event_history: List[Event] = []
        self.max_history = max_history
        self._lock = asyncio.Lock()
        
        logger.info(f"EventBus initialized (max_history={max_history})")
    
    async def subscribe(self, event_type: EventType, handler: Callable):
        """الاشتراك في نوع حدث معين"""
        async with self._lock:
            if handler not in self.subscribers[event_type]:
                self.subscribers[event_type].append(handler)
                logger.debug(f"Subscribed to {event_type.value}")
    
    async def unsubscribe(self, event_type: EventType, handler: Callable):
        """إلغاء الاشتراك في نوع حدث معين"""
        async with self._lock:
            if handler in self.subscribers[event_type]:
                self.subscribers[event_type].remove(handler)
                logger.debug(f"Unsubscribed from {event_type.value}")
    
    async def publish(self, event: Event):
        """
        نشر حدث
        
        Args:
            event: الحدث المنشور
        """
        event.id = str(uuid.uuid4())[:8]
        
        # تخزين الحدث في التاريخ
        async with self._lock:
            self.event_history.append(event)
            if len(self.event_history) > self.max_history:
                self.event_history.pop(0)
        
        # توزيع الحدث على المشتركين
        handlers = self.subscribers.get(event.type, [])
        handlers.extend(self.subscribers.get(EventType.CUSTOM, []))
        
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
        
        logger.debug(f"Event published: {event.type.value} from {event.source}")
    
    async def get_history(self, event_type: EventType = None, limit: int = 100) -> List[Event]:
        """الحصول على تاريخ الأحداث"""
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
                event_types[event.type.value] += 1
            
            return {
                "total_events": len(self.event_history),
                "unique_event_types": len(event_types),
                "event_type_distribution": dict(event_types),
                "total_subscribers": sum(len(h) for h in self.subscribers.values()),
                "max_history": self.max_history
            }


# نسخة عالمية
_default_event_bus = None


async def get_event_bus() -> EventBus:
    """الحصول على نسخة عالمية من ناقل الأحداث"""
    global _default_event_bus
    if _default_event_bus is None:
        _default_event_bus = EventBus()
    return _default_event_bus
