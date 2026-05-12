import asyncio
import random
import time
import uuid
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict

import logging

logger = logging.getLogger(__name__)


class RoutingStrategy(Enum):
    ROUND_ROBIN = "round_robin"
    RANDOM = "random"
    WEIGHTED = "weighted"
    LEAST_LOADED = "least_loaded"
    FASTEST = "fastest"
    STICKY = "sticky"


@dataclass
class RouteTarget:
    id: str
    url: str
    weight: int = 1
    is_proxy: bool = True
    username: Optional[str] = None
    password: Optional[str] = None
    last_used: float = 0.0
    usage_count: int = 0
    success_count: int = 0
    fail_count: int = 0
    avg_response_time: float = 0.0
    is_healthy: bool = True
    last_check: float = 0.0
    
    @property
    def full_url(self) -> str:
        if self.username and self.password:
            if "://" in self.url:
                protocol, rest = self.url.split("://", 1)
                return f"{protocol}://{self.username}:{self.password}@{rest}"
            return f"http://{self.username}:{self.password}@{self.url}"
        return self.url
    
    @property
    def success_rate(self) -> float:
        total = self.success_count + self.fail_count
        if total == 0:
            return 1.0
        return self.success_count / total
    
    @property
    def load(self) -> float:
        if self.avg_response_time == 0:
            return 0
        return self.usage_count / max(1, self.avg_response_time)
    
    def record_success(self, response_time: float):
        self.success_count += 1
        self.usage_count += 1
        self.avg_response_time = (self.avg_response_time * 0.7 + response_time * 0.3)
        self.is_healthy = True
    
    def record_failure(self):
        self.fail_count += 1
        self.usage_count += 1
        if self.fail_count > 3:
            self.is_healthy = False
    
    def reset_health(self):
        self.is_healthy = True
        self.fail_count = 0


class RequestRouter:
    """موجه الطلبات الذكي"""
    
    def __init__(self, strategy: RoutingStrategy = RoutingStrategy.ROUND_ROBIN, http_client=None):
        self.strategy = strategy
        self._http_client = http_client
        self._targets: List[RouteTarget] = []
        self._targets_by_id: Dict[str, RouteTarget] = {}
        self._current_index = 0
        self._sticky_map: Dict[str, str] = {}
        self._lock = asyncio.Lock()
        
        self._stats = {
            "total_routes": 0,
            "successful_routes": 0,
            "failed_routes": 0,
            "strategy_changes": 0
        }
    
    def set_http_client(self, client):
        """تعيين عميل HTTP"""
        self._http_client = client
    
    async def _send_request_via_target(self, target: RouteTarget, test_url: str) -> tuple:
        """إرسال طلب اختبار عبر هدف"""
        if self._http_client and hasattr(self._http_client, 'send_request'):
            start = time.time()
            try:
                if target.is_proxy:
                    response = await self._http_client.send_request(
                        test_url, method="GET", proxy=target.full_url
                    )
                else:
                    response = await self._http_client.send_request(test_url, method="GET")
                elapsed = (time.time() - start) * 1000  # ms
                return response is not None, elapsed
            except Exception:
                return False, 0
        return False, 0
    
    def add_target(self, url: str, weight: int = 1, username: str = None, password: str = None, is_proxy: bool = True) -> str:
        target_id = str(uuid.uuid4())[:8]
        
        target = RouteTarget(
            id=target_id,
            url=url,
            weight=weight,
            is_proxy=is_proxy,
            username=username,
            password=password
        )
        
        self._targets.append(target)
        self._targets_by_id[target_id] = target
        return target_id
    
    def add_targets(self, targets: List[Dict]):
        for t in targets:
            self.add_target(
                url=t["url"],
                weight=t.get("weight", 1),
                username=t.get("username"),
                password=t.get("password"),
                is_proxy=t.get("is_proxy", True)
            )
    
    def remove_target(self, target_id: str) -> bool:
        if target_id not in self._targets_by_id:
            return False
        
        self._targets = [t for t in self._targets if t.id != target_id]
        del self._targets_by_id[target_id]
        
        self._sticky_map = {k: v for k, v in self._sticky_map.items() if v != target_id}
        
        return True
    
    def get_healthy_targets(self) -> List[RouteTarget]:
        return [t for t in self._targets if t.is_healthy]
    
    def _select_round_robin(self, targets: List[RouteTarget]) -> Optional[RouteTarget]:
        if not targets:
            return None
        target = targets[self._current_index % len(targets)]
        self._current_index += 1
        return target
    
    def _select_random(self, targets: List[RouteTarget]) -> Optional[RouteTarget]:
        if not targets:
            return None
        return random.choice(targets)
    
    def _select_weighted(self, targets: List[RouteTarget]) -> Optional[RouteTarget]:
        if not targets:
            return None
        
        total_weight = sum(t.weight for t in targets)
        if total_weight == 0:
            return random.choice(targets)
        
        r = random.randint(1, total_weight)
        cumulative = 0
        for target in targets:
            cumulative += target.weight
            if r <= cumulative:
                return target
        return targets[0]
    
    def _select_least_loaded(self, targets: List[RouteTarget]) -> Optional[RouteTarget]:
        if not targets:
            return None
        return min(targets, key=lambda t: t.load)
    
    def _select_fastest(self, targets: List[RouteTarget]) -> Optional[RouteTarget]:
        if not targets:
            return None
        
        valid = [t for t in targets if t.avg_response_time > 0]
        if not valid:
            return random.choice(targets)
        
        return min(valid, key=lambda t: t.avg_response_time)
    
    def _select_sticky(self, targets: List[RouteTarget], session_id: str = None) -> Optional[RouteTarget]:
        if not session_id:
            return self._select_round_robin(targets)
        
        if session_id in self._sticky_map:
            target_id = self._sticky_map[session_id]
            for target in targets:
                if target.id == target_id and target.is_healthy:
                    return target
        
        target = self._select_round_robin(targets)
        if target:
            self._sticky_map[session_id] = target.id
        return target
    
    async def get_target(self, session_id: str = None) -> Optional[RouteTarget]:
        async with self._lock:
            targets = self.get_healthy_targets()
            
            if not targets:
                targets = self._targets
                if not targets:
                    return None
            
            if self.strategy == RoutingStrategy.ROUND_ROBIN:
                target = self._select_round_robin(targets)
            elif self.strategy == RoutingStrategy.RANDOM:
                target = self._select_random(targets)
            elif self.strategy == RoutingStrategy.WEIGHTED:
                target = self._select_weighted(targets)
            elif self.strategy == RoutingStrategy.LEAST_LOADED:
                target = self._select_least_loaded(targets)
            elif self.strategy == RoutingStrategy.FASTEST:
                target = self._select_fastest(targets)
            elif self.strategy == RoutingStrategy.STICKY:
                target = self._select_sticky(targets, session_id)
            else:
                target = self._select_round_robin(targets)
            
            if target:
                target.last_used = time.time()
                self._stats["total_routes"] += 1
            
            return target
    
    async def record_result(self, target_id: str, success: bool, response_time: float = 0.0):
        async with self._lock:
            target = self._targets_by_id.get(target_id)
            if not target:
                return
            
            if success:
                target.record_success(response_time)
                self._stats["successful_routes"] += 1
            else:
                target.record_failure()
                self._stats["failed_routes"] += 1
    
    def set_strategy(self, strategy: RoutingStrategy):
        self.strategy = strategy
        self._stats["strategy_changes"] += 1
    
    async def health_check_all(self, test_url: str = "https://httpbin.org/ip"):
        async def check_target(target: RouteTarget) -> bool:
            try:
                success, response_time = await self._send_request_via_target(target, test_url)
                if success:
                    target.record_success(response_time)
                    return True
                else:
                    target.record_failure()
                    return False
            except Exception as e:
                logger.debug(f"Health check failed for {target.url}: {e}")
                target.record_failure()
                return False
        
        async with self._lock:
            tasks = [check_target(t) for t in self._targets]
            results = await asyncio.gather(*tasks)
            return sum(results)
    
    def get_stats(self) -> Dict:
        targets_stats = []
        for target in self._targets:
            targets_stats.append({
                "id": target.id,
                "url": target.url[:40] + "..." if len(target.url) > 40 else target.url,
                "weight": target.weight,
                "is_proxy": target.is_proxy,
                "success_rate": target.success_rate,
                "avg_response_time_ms": target.avg_response_time,
                "usage_count": target.usage_count,
                "is_healthy": target.is_healthy,
                "load": target.load
            })
        
        total = self._stats["total_routes"]
        success_rate = self._stats["successful_routes"] / max(1, total)
        
        return {
            "strategy": self.strategy.value,
            "total_targets": len(self._targets),
            "healthy_targets": len(self.get_healthy_targets()),
            "targets": targets_stats,
            "total_routes": total,
            "success_rate": success_rate,
            "sticky_sessions": len(self._sticky_map),
            "strategy_changes": self._stats["strategy_changes"]
        }
    
    def reset_stats(self):
        self._stats = {
            "total_routes": 0,
            "successful_routes": 0,
            "failed_routes": 0,
            "strategy_changes": 0
        }
    
    def clear(self):
        self._targets.clear()
        self._targets_by_id.clear()
        self._sticky_map.clear()
        self._current_index = 0
        self.reset_stats()
    
    async def close(self):
        """إغلاق الموجه"""
        self._http_client = None
        logger.info("RequestRouter closed")


def create_request_router(
    strategy: str = "round_robin",
    proxies: List[str] = None,
    http_client=None
) -> RequestRouter:
    strategy_map = {
        "round_robin": RoutingStrategy.ROUND_ROBIN,
        "random": RoutingStrategy.RANDOM,
        "weighted": RoutingStrategy.WEIGHTED,
        "least_loaded": RoutingStrategy.LEAST_LOADED,
        "fastest": RoutingStrategy.FASTEST,
        "sticky": RoutingStrategy.STICKY
    }
    
    router = RequestRouter(strategy=strategy_map.get(strategy, RoutingStrategy.ROUND_ROBIN), http_client=http_client)
    
    if proxies:
        for proxy in proxies:
            if isinstance(proxy, dict):
                router.add_target(**proxy)
            else:
                router.add_target(proxy)
    
    return router
