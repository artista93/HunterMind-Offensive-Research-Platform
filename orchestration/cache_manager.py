"""
Cache Manager - مدير التخزين المؤقت
يدير التخزين المؤقت للبيانات لتحسين أداء النظام
"""

import asyncio
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from collections import OrderedDict

import logging

logger = logging.getLogger(__name__)


@dataclass
class CacheEntry:
    """عنصر في التخزين المؤقت"""
    key: str
    value: Any
    created_at: datetime = field(default_factory=datetime.now)
    expires_at: Optional[datetime] = None
    access_count: int = 0
    last_accessed: Optional[datetime] = None


class CacheManager:
    """
    مدير التخزين المؤقت المتقدم
    """
    
    def __init__(self, max_size: int = 1000, default_ttl: int = 3600, strategy: str = "lru"):
        self.max_size = max_size
        self.default_ttl = default_ttl
        self.strategy = strategy
        self.cache: Dict[str, CacheEntry] = {}
        self.access_order: List[str] = []  # لتتبع ترتيب الوصول (LRU)
        self._lock = asyncio.Lock()
        self._cleanup_task: Optional[asyncio.Task] = None
        self._running = False
        
        # إحصائيات
        self.hits = 0
        self.misses = 0
        
        logger.info(f"CacheManager initialized (max_size={max_size}, strategy={strategy})")
    
    async def start(self):
        """بدء تشغيل مدير التخزين المؤقت"""
        if self._running:
            return
        
        self._running = True
        self._cleanup_task = asyncio.create_task(self._cleanup_loop())
        logger.info("CacheManager started")
    
    async def stop(self):
        """إيقاف تشغيل مدير التخزين المؤقت"""
        self._running = False
        
        if self._cleanup_task:
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass
        
        logger.info("CacheManager stopped")
    
    async def get(self, key: str) -> Optional[Any]:
        """
        استرجاع قيمة من التخزين المؤقت
        
        Args:
            key: المفتاح
        
        Returns:
            القيمة أو None
        """
        async with self._lock:
            if key not in self.cache:
                self.misses += 1
                return None
            
            entry = self.cache[key]
            
            # التحقق من انتهاء الصلاحية
            if entry.expires_at and datetime.now() > entry.expires_at:
                del self.cache[key]
                if key in self.access_order:
                    self.access_order.remove(key)
                self.misses += 1
                return None
            
            # تحديث إحصائيات
            entry.access_count += 1
            entry.last_accessed = datetime.now()
            
            # تحديث ترتيب الوصول (LRU)
            if key in self.access_order:
                self.access_order.remove(key)
            self.access_order.append(key)
            
            self.hits += 1
            return entry.value
    
    async def set(self, key: str, value: Any, ttl: int = None):
        """
        تخزين قيمة في التخزين المؤقت
        
        Args:
            key: المفتاح
            value: القيمة
            ttl: مدة الصلاحية بالثواني
        """
        async with self._lock:
            expires_at = None
            if ttl or self.default_ttl:
                expires_at = datetime.now() + timedelta(seconds=ttl or self.default_ttl)
            
            entry = CacheEntry(
                key=key,
                value=value,
                expires_at=expires_at
            )
            
            # إزالة المفتاح القديم إذا كان موجوداً
            if key in self.cache:
                if key in self.access_order:
                    self.access_order.remove(key)
            
            self.cache[key] = entry
            self.access_order.append(key)
            
            # تطبيق استراتيجية الإخلاء
            await self._evict_if_needed()
            
            logger.debug(f"Cached: {key}")
    
    async def delete(self, key: str) -> bool:
        """
        حذف عنصر من التخزين المؤقت
        
        Args:
            key: المفتاح
        
        Returns:
            نجاح الحذف
        """
        async with self._lock:
            if key in self.cache:
                del self.cache[key]
                if key in self.access_order:
                    self.access_order.remove(key)
                logger.debug(f"Deleted from cache: {key}")
                return True
            return False
    
    async def clear(self):
        """مسح التخزين المؤقت بالكامل"""
        async with self._lock:
            self.cache.clear()
            self.access_order.clear()
            logger.info("Cache cleared")
    
    async def _evict_if_needed(self):
        """إخلاء عناصر إذا تجاوز الحجم"""
        while len(self.cache) > self.max_size:
            if self.strategy == "lru":
                # إزالة أقدم عنصر (LRU) - أول عنصر في قائمة الوصول
                if self.access_order:
                    oldest_key = self.access_order.pop(0)
                    del self.cache[oldest_key]
                    logger.debug(f"Evicted from cache (LRU): {oldest_key}")
            elif self.strategy == "lfu":
                # إزالة أقل عنصر استخداماً (LFU)
                min_key = min(self.cache.items(), key=lambda x: x[1].access_count)[0]
                del self.cache[min_key]
                if min_key in self.access_order:
                    self.access_order.remove(min_key)
                logger.debug(f"Evicted from cache (LFU): {min_key}")
            else:  # fifo
                if self.access_order:
                    oldest_key = self.access_order.pop(0)
                    del self.cache[oldest_key]
                    logger.debug(f"Evicted from cache (FIFO): {oldest_key}")
    
    async def _cleanup_loop(self):
        """حلقة تنظيف العناصر منتهية الصلاحية"""
        while self._running:
            await asyncio.sleep(60)  # كل دقيقة
            
            async with self._lock:
                now = datetime.now()
                expired_keys = [
                    key for key, entry in self.cache.items()
                    if entry.expires_at and entry.expires_at < now
                ]
                
                for key in expired_keys:
                    del self.cache[key]
                    if key in self.access_order:
                        self.access_order.remove(key)
                
                if expired_keys:
                    logger.debug(f"Cleaned {len(expired_keys)} expired cache entries")
    
    async def get_stats(self) -> Dict:
        """إحصائيات التخزين المؤقت"""
        total_requests = self.hits + self.misses
        
        return {
            "size": len(self.cache),
            "max_size": self.max_size,
            "usage_percent": (len(self.cache) / self.max_size) * 100 if self.max_size > 0 else 0,
            "hits": self.hits,
            "misses": self.misses,
            "hit_rate": self.hits / total_requests if total_requests > 0 else 0,
            "strategy": self.strategy,
            "default_ttl": self.default_ttl
        }
