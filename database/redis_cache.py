"""Redis Cache - تخزين مؤقت احترافي"""
import json, logging
from typing import Dict, Optional, Any

try:
    import redis.asyncio as redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False

logger = logging.getLogger(__name__)

class RedisCache:
    def __init__(self, url: str = None):
        self.url = url or "redis://localhost:6379"
        self.client = None
    
    async def connect(self):
        if not REDIS_AVAILABLE:
            logger.warning("redis not installed - cache disabled")
            return
        try:
            self.client = redis.from_url(self.url, decode_responses=True)
            await self.client.ping()
            logger.info("Redis connected")
        except Exception as e:
            logger.warning(f"Redis unavailable: {e}")
            self.client = None
    
    async def get(self, key: str) -> Optional[Any]:
        if not self.client: return None
        try:
            value = await self.client.get(key)
            return json.loads(value) if value else None
        except Exception:
            return None
    
    async def set(self, key: str, value: Any, ttl: int = 300):
        if not self.client: return
        try:
            await self.client.set(key, json.dumps(value), ex=ttl)
        except Exception:
            pass
    
    async def delete(self, key: str):
        if self.client:
            await self.client.delete(key)
    
    async def close(self):
        if self.client:
            await self.client.close()
    
    def is_connected(self) -> bool:
        return self.client is not None

_default_cache = None

async def get_redis_cache() -> RedisCache:
    global _default_cache
    if _default_cache is None:
        _default_cache = RedisCache()
        await _default_cache.connect()
    return _default_cache
