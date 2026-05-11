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

import logging

logger = logging.getLogger(__name__)


class SessionStatus(Enum):
    IDLE = "idle"
    ACTIVE = "active"
    EXPIRED = "expired"
    INVALID = "invalid"
    RECYCLING = "recycling"


@dataclass
class PooledSession:
    id: str
    session: Any
    created_at: float = field(default_factory=time.time)
    last_used: float = field(default_factory=time.time)
    usage_count: int = 0
    status: SessionStatus = SessionStatus.IDLE
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def use(self):
        self.status = SessionStatus.ACTIVE
        self.last_used = time.time()
        self.usage_count += 1
    
    def release(self):
        self.status = SessionStatus.IDLE
        self.last_used = time.time()
    
    def mark_invalid(self):
        self.status = SessionStatus.INVALID
    
    def is_expired(self, max_age: int = 300) -> bool:
        return time.time() - self.created_at > max_age
    
    def is_idle_too_long(self, idle_timeout: int = 60) -> bool:
        return time.time() - self.last_used > idle_timeout


class SessionPool:
    """تجمع الجلسات المتقدم"""
    
    def __init__(
        self,
        pool_size: int = 10,
        max_age: int = 300,
        idle_timeout: int = 60,
        enable_ssl: bool = True,
        connector_limit: int = 100,
        http_client=None
    ):
        self.pool_size = pool_size
        self.max_age = max_age
        self.idle_timeout = idle_timeout
        self.enable_ssl = enable_ssl
        self.connector_limit = connector_limit
        self._http_client = http_client
        
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
    
    def set_http_client(self, client):
        """تعيين عميل HTTP"""
        self._http_client = client
    
    def set_session_factory(self, factory: Callable):
        self._session_factory = factory
    
    async def _create_session(self) -> PooledSession:
        """إنشاء جلسة جديدة باستخدام httpx"""
        import httpx
        
        if self._session_factory:
            session = await self._session_factory()
        else:
            # مصنع افتراضي باستخدام httpx
            limits = httpx.Limits(
                max_keepalive_connections=self.connector_limit,
                max_connections=self.connector_limit,
                keepalive_expiry=60
            )
            
            timeout = httpx.Timeout(
                timeout=30.0,
                connect=10.0,
                read=20.0,
                write=10.0
            )
            
            session = httpx.AsyncClient(
                timeout=timeout,
                limits=limits,
                verify=self.enable_ssl,
                follow_redirects=True
            )
        
        session_id = str(uuid.uuid4())[:8]
        pooled = PooledSession(id=session_id, session=session)
        
        self._sessions[session_id] = pooled
        self._idle_queue.append(session_id)
        self._stats["total_created"] += 1
        
        return pooled
    
    async def _destroy_session(self, pooled: PooledSession):
        try:
            if hasattr(pooled.session, 'aclose'):
                await pooled.session.aclose()
            elif hasattr(pooled.session, 'close'):
                await pooled.session.close()
        except Exception as e:
            logger.debug(f"Error closing session: {e}")
        
        if pooled.id in self._sessions:
            del self._sessions[pooled.id]
        
        if pooled.id in self._idle_queue:
            try:
                self._idle_queue.remove(pooled.id)
            except ValueError:
                pass
        
        self._stats["total_destroyed"] += 1
    
    async def acquire(self, timeout: float = 10.0) -> Optional[PooledSession]:
        start_time = time.time()
        
        async with self._lock:
            while self._idle_queue:
                session_id = self._idle_queue.popleft()
                pooled = self._sessions.get(session_id)
                
                if not pooled or pooled.status != SessionStatus.IDLE:
                    continue
                
                if pooled.is_expired(self.max_age):
                    await self._destroy_session(pooled)
                    continue
                
                pooled.use()
                self._active_count += 1
                self._stats["total_acquired"] += 1
                return pooled
            
            if len(self._sessions) < self.pool_size:
                pooled = await self._create_session()
                pooled.use()
                self._active_count += 1
                self._stats["total_acquired"] += 1
                return pooled
        
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
        async with self._lock:
            if pooled.id not in self._sessions:
                return
            
            if pooled.is_expired(self.max_age) or pooled.is_idle_too_long(self.idle_timeout):
                await self._destroy_session(pooled)
            else:
                pooled.release()
                self._active_count -= 1
                self._idle_queue.append(pooled.id)
                self._stats["total_released"] += 1
    
    async def invalidate(self, pooled: PooledSession):
        async with self._lock:
            if pooled.id in self._sessions:
                await self._destroy_session(pooled)
                if pooled.status == SessionStatus.ACTIVE:
                    self._active_count -= 1
                self._stats["total_released"] += 1
    
    async def _cleanup_loop(self):
        while self._running:
            await asyncio.sleep(30)
            
            async with self._lock:
                to_remove = []
                
                for session_id, pooled in self._sessions.items():
                    if pooled.status == SessionStatus.IDLE:
                        if pooled.is_expired(self.max_age) or pooled.is_idle_too_long(self.idle_timeout):
                            to_remove.append(session_id)
                
                for session_id in to_remove:
                    pooled = self._sessions.get(session_id)
                    if pooled:
                        await self._destroy_session(pooled)
    
    async def start(self):
        self._running = True
        self._cleanup_task = asyncio.create_task(self._cleanup_loop())
        logger.info("SessionPool started")
    
    async def stop(self):
        self._running = False
        
        if self._cleanup_task:
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass
        
        async with self._lock:
            for pooled in list(self._sessions.values()):
                await self._destroy_session(pooled)
        
        logger.info("SessionPool stopped")
    
    async def warmup(self, count: int = None):
        target = min(count or self.pool_size, self.pool_size)
        current = len(self._sessions)
        
        for _ in range(max(0, target - current)):
            await self._create_session()
    
    def get_stats(self) -> Dict:
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
        try:
            session = await self.acquire(timeout=5.0)
            if session:
                await self.release(session)
                return True
        except Exception as e:
            logger.debug(f"Health check failed: {e}")
        return False
    
    async def close(self):
        """إغلاق التجمع"""
        await self.stop()
        self._http_client = None


_default_session_pool = None


async def get_session_pool(
    pool_size: int = 10,
    max_age: int = 300,
    idle_timeout: int = 60,
    http_client=None
) -> SessionPool:
    global _default_session_pool
    if _default_session_pool is None:
        _default_session_pool = SessionPool(
            pool_size=pool_size,
            max_age=max_age,
            idle_timeout=idle_timeout,
            http_client=http_client
        )
        await _default_session_pool.start()
    return _default_session_pool


async def close_session_pool():
    global _default_session_pool
    if _default_session_pool:
        await _default_session_pool.stop()
        _default_session_pool = None
