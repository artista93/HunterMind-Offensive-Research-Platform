
import asyncio
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from collections import OrderedDict

import logging

logger = logging.getLogger(__name__)


@dataclass
class WorkingMemoryItem:
    """عنصر في الذاكرة العاملة"""
    key: str
    value: Any
    timestamp: datetime = field(default_factory=datetime.now)
    ttl: Optional[float] = None  # Time To Live بالثواني
    priority: int = 0  # 0-10 (10 أعلى)
    metadata: Dict[str, Any] = field(default_factory=dict)


class WorkingMemory:
    """
    الذاكرة العاملة المتقدمة
    
    الميزات:
    - تخزين مؤقت للمعلومات الحالية
    - انتهاء صلاحية تلقائي (TTL)
    - أولويات للعناصر
    - قدرة محدودة (LIFO عند الامتلاء)
    """
    
    def __init__(self, capacity: int = 20):
        self._capacity = capacity
        self._items: OrderedDict[str, WorkingMemoryItem] = OrderedDict()
        self._cleanup_task: Optional[asyncio.Task] = None
        self._running = False
        
        logger.info(f"WorkingMemory initialized (capacity={capacity})")
    
    async def start(self):
        """بدء تشغيل الذاكرة"""
        if self._running:
            return
        
        self._running = True
        self._cleanup_task = asyncio.create_task(self._cleanup_loop())
        
        logger.info("WorkingMemory started")
    
    async def stop(self):
        """إيقاف تشغيل الذاكرة"""
        self._running = False
        
        if self._cleanup_task:
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass
        
        logger.info("WorkingMemory stopped")
    
    async def store(
        self,
        key: str,
        value: Any,
        ttl: float = None,
        priority: int = 0,
        metadata: Dict = None
    ):
        """
        تخزين عنصر في الذاكرة العاملة
        
        Args:
            key: المفتاح
            value: القيمة
            ttl: مدة الصلاحية بالثواني (اختياري)
            priority: الأولوية (0-10)
            metadata: بيانات إضافية
        """
        # إزالة العنصر القديم إذا كان موجوداً
        if key in self._items:
            del self._items[key]
        
        item = WorkingMemoryItem(
            key=key,
            value=value,
            ttl=ttl,
            priority=min(max(priority, 0), 10),
            metadata=metadata or {}
        )
        
        self._items[key] = item
        
        # نقل إلى النهاية (أحدث)
        self._items.move_to_end(key)
        
        # تطبيق السعة
        await self._enforce_capacity()
        
        logger.debug(f"Stored in working memory: {key} (priority={priority})")
    
    async def retrieve(self, key: str) -> Optional[Any]:
        """
        استرجاع عنصر من الذاكرة العاملة
        
        Args:
            key: المفتاح
        
        Returns:
            القيمة أو None
        """
        if key not in self._items:
            return None
        
        # تحديث وقت الوصول (نقل إلى النهاية)
        self._items.move_to_end(key)
        
        return self._items[key].value
    
    async def get_item(self, key: str) -> Optional[WorkingMemoryItem]:
        """الحصول على العنصر الكامل"""
        return self._items.get(key)
    
    async def delete(self, key: str) -> bool:
        """حذف عنصر من الذاكرة"""
        if key in self._items:
            del self._items[key]
            logger.debug(f"Deleted from working memory: {key}")
            return True
        return False
    
    async def clear(self):
        """مسح الذاكرة العاملة"""
        self._items.clear()
        logger.info("Working memory cleared")
    
    async def get_all(self) -> Dict[str, Any]:
        """الحصول على جميع العناصر (قيم فقط)"""
        return {key: item.value for key, item in self._items.items()}
    
    async def get_context(self) -> Dict[str, Any]:
        """الحصول على سياق الذاكرة الحالي (جميع العناصر مع البيانات الوصفية)"""
        return {
            key: {
                "value": item.value,
                "priority": item.priority,
                "timestamp": item.timestamp.isoformat(),
                "ttl": item.ttl,
                "metadata": item.metadata
            }
            for key, item in self._items.items()
        }
    
    async def _enforce_capacity(self):
        """تطبيق سعة الذاكرة"""
        while len(self._items) > self._capacity:
            # إزالة العنصر الأقل أولوية والأقدم
            # ترتيب حسب الأولوية (تنازلي) ثم حسب العمر (تصاعدي)
            items_list = list(self._items.items())
            items_list.sort(key=lambda x: (x[1].priority, -x[1].timestamp.timestamp()))
            
            oldest_lowest = items_list[0]
            del self._items[oldest_lowest[0]]
            
            logger.debug(f"Evicted from working memory: {oldest_lowest[0]}")
    
    async def _cleanup_loop(self):
        """حلقة تنظيف العناصر منتهية الصلاحية"""
        while self._running:
            await asyncio.sleep(5)  # فحص كل 5 ثواني
            await self._cleanup_expired()
    
    async def _cleanup_expired(self):
        """تنظيف العناصر منتهية الصلاحية"""
        now = datetime.now()
        expired_keys = []
        
        for key, item in self._items.items():
            if item.ttl:
                age = (now - item.timestamp).total_seconds()
                if age > item.ttl:
                    expired_keys.append(key)
        
        for key in expired_keys:
            del self._items[key]
        
        if expired_keys:
            logger.debug(f"Cleaned {len(expired_keys)} expired items from working memory")
    
    async def refresh(self, key: str) -> bool:
        """
        تحديث وقت العنصر (تمديد الصلاحية)
        
        Args:
            key: المفتاح
        
        Returns:
            نجاح العملية
        """
        if key not in self._items:
            return False
        
        self._items[key].timestamp = datetime.now()
        self._items.move_to_end(key)
        
        return True
    
    async def get_statistics(self) -> Dict:
        """إحصائيات الذاكرة"""
        if not self._items:
            return {"total_items": 0}
        
        # توزيع الأولويات
        priority_distribution = {}
        for item in self._items.values():
            priority_distribution[item.priority] = priority_distribution.get(item.priority, 0) + 1
        
        # عمر العناصر
        now = datetime.now()
        ages = [(now - item.timestamp).total_seconds() for item in self._items.values()]
        
        return {
            "total_items": len(self._items),
            "capacity": self._capacity,
            "usage_percentage": (len(self._items) / self._capacity) * 100,
            "priority_distribution": priority_distribution,
            "average_age_seconds": sum(ages) / len(ages) if ages else 0,
            "oldest_item_seconds": max(ages) if ages else 0,
            "running": self._running
        }

