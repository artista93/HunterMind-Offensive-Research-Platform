"""
Session Pool - تجمع الجلسات لإعادة الاستخدام
يدير pool من الجلسات لتقليل استهلاك الموارد وزيادة الأداء
"""

import asyncio
import random
import time
import uuid
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from collections import deque


class SessionStatus(Enum):
    """حالة الجلسة"""
    IDLE = "idle"           # جاهزة للاستخدام
    ACTIVE = "active"       # قيد الاستخدام
    EXPIRED = "expired"     # منتهية الصلاحية
    INVALID = "invalid"     # غير صالحة
    RECYCLING = "recycling" # قيد إعادة التدوير


@dataclass
class PooledSession:
    """جلسة في التجمع"""
    id: str
    session: Any  # aiohttp.ClientSession أو أي كائن جلسة
    created_at: float = field(default_factory=time.time)
    last_used: float = field(default_factory=time.time)
    usage_count: int = 0
    status: SessionStatus = SessionStatus.IDLE
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def use(self):
        """تسجيل استخدام الجلسة"""
        self.status = SessionStatus.ACTIVE
        self.last_used = time.time()
        self.usage_count += 1
    
    def release(self):
        """تحرير الجلسة"""
        self.status = SessionStatus.IDLE
        self.last_used = time.time()
    
    def mark_invalid(self):
        """تعليم الجلسة كغير صالحة"""
        self.status = SessionStatus.INVALID
    
    def is_expired(self, max_age: int = 300) -> bool:
        """هل انتهت صلاحية الجلسة؟"""
        return time.time() - self.created_at > max_age
    
    def is_idle_too_long(self, idle_timeout: int = 60) -> bool:
        """هل كانت خاملة لفترة طويلة؟"""
        return time.time() - self.last_used > idle_timeout


class SessionPool:
    """تجمع الجلسات المتقدم"""
    
    def __init__(
        self,
        pool_size: int = 10,
        max_age: int = 300,      # أقصى عمر للجلسة (ثواني)
        idle_timeout: int = 60,   # فترة الخمول قبل الإغلاق (ثواني)
        enable_ssl: bool = True,
        connector_limit: int = 100
    ):
        self.pool_size = pool_size
        self.max_age = max_age
        self.idle_timeout = idle_timeout
        self.enable_ssl = enable_ssl
        self.connector_limit = connector_limit
        
        self._sessions: Dict[str, PooledSession] = {}
        self._idle_queue: deque = deque()
        self._active_count = 0
        self._lock = asyncio.Lock()
        self._session_factory: Optional[Callable] = None
        self._cleanup_task: Optional[asyncio.Task] = None
        self._running = False
        
        self._stats = {
            "total_created": 0,
            "total_acquired": 0,
            "total_released": 0,
            "total_destroyed": 0,
            "total_timeouts": 0,
            "total_errors": 0
        }
    
    def set_session_factory(self, factory: Callable):
        """تعيين مصنع الجلسات"""
        self._session_factory = factory
    
    async def _create_session(self) -> PooledSession:
        """إنشاء جلسة جديدة"""
        import aiohttp
        
        if not self._session_factory:
            # مصنع افتراضي
            connector = aiohttp.TCPConnector(
                limit=self.connector_limit,
                limit_per_host=10,
                ttl_dns_cache=300,
                enable_cleanup_closed=True
            )
            
            timeout = aiohttp.ClientTimeout(
                total=30,
                connect=10,
                sock_read=20
            )
            
            session = aiohttp.ClientSession(
                connector=connector,
                timeout=timeout
            )
        else:
            session = await self._session_factory()
        
        session_id = str(uuid.uuid4())[:8]
        pooled = PooledSession(id=session_id, session=session)
        
        self._sessions[session_id] = pooled
        self._idle_queue.append(session_id)
        self._stats["total_created"] += 1
        
        return pooled
    
    async def _destroy_session(self, pooled: PooledSession):
        """تدمير جلسة"""
        try:
            if hasattr(pooled.session, 'close'):
                await pooled.session.close()
        except Exception:
            pass
        
        if pooled.id in self._sessions:
            del self._sessions[pooled.id]
        
        # إزالة من idle queue
        if pooled.id in self._idle_queue:
            self._idle_queue.remove(pooled.id)
        
        self._stats["total_destroyed"] += 1
    
    async def acquire(self, timeout: float = 10.0) -> Optional[PooledSession]:
        """الحصول على جلسة من التجمع"""
        start_time = time.time()
        
        async with self._lock:
            # البحث عن جلسة خاملة
            while self._idle_queue:
                session_id = self._idle_queue.popleft()
                pooled = self._sessions.get(session_id)
                
                if not pooled or pooled.status != SessionStatus.IDLE:
                    continue
                
                # التحقق من الصلاحية
                if pooled.is_expired(self.max_age):
                    await self._destroy_session(pooled)
                    continue
                
                # استخدام الجلسة
                pooled.use()
                self._active_count += 1
                self._stats["total_acquired"] += 1
                return pooled
            
            # إنشاء جلسة جديدة إذا كان التجمع لم يصل إلى الحد الأقصى
            if len(self._sessions) < self.pool_size:
                pooled = await self._create_session()
                pooled.use()
                self._active_count += 1
                self._stats["total_acquired"] += 1
                return pooled
        
        # انتظار جلسة متاحة
        while time.time() - start_time < timeout:
            await asyncio.sleep(0.1)
            
            async with self._lock:
                if self._idle_queue:
                    session_id = self._idle_queue.popleft()
                    pooled = self._sessions.get(session_id)
                    
                    if pooled and pooled.status == SessionStatus.IDLE:
                        pooled.use()
                        self._active_count += 1
                        self._stats["total_acquired"] += 1
                        return pooled
        
        self._stats["total_timeouts"] += 1
        return None
    
    async def release(self, pooled: PooledSession):
        """تحرير الجلسة إلى التجمع"""
        async with self._lock:
            if pooled.id not in self._sessions:
                return
            
            # التحقق من الصلاحية قبل الإعادة
            if pooled.is_expired(self.max_age) or pooled.is_idle_too_long(self.idle_timeout):
                await self._destroy_session(pooled)
            else:
                pooled.release()
                self._active_count -= 1
                self._idle_queue.append(pooled.id)
                self._stats["total_released"] += 1
    
    async def invalidate(self, pooled: PooledSession):
        """إبطال الجلسة (لن يتم إعادة استخدامها)"""
        async with self._lock:
            if pooled.id in self._sessions:
                await self._destroy_session(pooled)
                if pooled.status == SessionStatus.ACTIVE:
                    self._active_count -= 1
                self._stats["total_released"] += 1
    
    async def _cleanup_loop(self):
        """حلقة التنظيف الدورية"""
        while self._running:
            await asyncio.sleep(30)  # كل 30 ثانية
            
            async with self._lock:
                to_remove = []
                
                for session_id, pooled in self._sessions.items():
                    # حذف الجلسات منتهية الصلاحية
                    if pooled.status == SessionStatus.IDLE:
                        if pooled.is_expired(self.max_age) or pooled.is_idle_too_long(self.idle_timeout):
                            to_remove.append(session_id)
                
                for session_id in to_remove:
                    pooled = self._sessions.get(session_id)
                    if pooled:
                        await self._destroy_session(pooled)
    
    async def start(self):
        """بدء تجمع الجلسات"""
        self._running = True
        self._cleanup_task = asyncio.create_task(self._cleanup_loop())
    
    async def stop(self):
        """إيقاف تجمع الجلسات"""
        self._running = False
        
        if self._cleanup_task:
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass
        
        # إغلاق جميع الجلسات
        async with self._lock:
            for pooled in list(self._sessions.values()):
                await self._destroy_session(pooled)
    
    async def warmup(self, count: int = None):
        """تسخين التجمع (إنشاء جلسات مسبقاً)"""
        target = min(count or self.pool_size, self.pool_size)
        current = len(self._sessions)
        
        for _ in range(target - current):
            await self._create_session()
    
    def get_stats(self) -> Dict:
        """إحصائيات التجمع"""
        idle = sum(1 for p in self._sessions.values() if p.status == SessionStatus.IDLE)
        active = self._active_count
        expired = sum(1 for p in self._sessions.values() if p.is_expired(self.max_age))
        
        return {
            "total_sessions": len(self._sessions),
            "idle_sessions": idle,
            "active_sessions": active,
            "expired_sessions": expired,
            "pool_size": self.pool_size,
            "utilization": active / max(1, len(self._sessions)),
            "total_created": self._stats["total_created"],
            "total_acquired": self._stats["total_acquired"],
            "total_released": self._stats["total_released"],
            "total_destroyed": self._stats["total_destroyed"],
            "total_timeouts": self._stats["total_timeouts"],
            "total_errors": self._stats["total_errors"],
            "max_age": self.max_age,
            "idle_timeout": self.idle_timeout
        }
    
    async def health_check(self) -> bool:
        """فحص صحة التجمع"""
        try:
            session = await self.acquire(timeout=5.0)
            if session:
                await self.release(session)
                return True
        except Exception:
            pass
        return False


# نسخة عالمية
_default_session_pool = None


async def get_session_pool(
    pool_size: int = 10,
    max_age: int = 300,
    idle_timeout: int = 60
) -> SessionPool:
    """الحصول على نسخة عالمية من تجمع الجلسات"""
    global _default_session_pool
    if _default_session_pool is None:
        _default_session_pool = SessionPool(
            pool_size=pool_size,
            max_age=max_age,
            idle_timeout=idle_timeout
        )
        await _default_session_pool.start()
    return _default_session_pool


async def close_session_pool():
    """إغلاق تجمع الجلسات العالمي"""
    global _default_session_pool
    if _default_session_pool:
        await _default_session_pool.stop()
        _default_session_pool = None

