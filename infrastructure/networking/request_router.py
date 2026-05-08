
import asyncio
import random
import time
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict


class RoutingStrategy(Enum):
    """استراتيجية التوجيه"""
    ROUND_ROBIN = "round_robin"      # توزيع دوري
    RANDOM = "random"                 # عشوائي
    WEIGHTED = "weighted"            # حسب الوزن
    LEAST_LOADED = "least_loaded"    # أقل تحميل
    FASTEST = "fastest"              # الأسرع
    STICKY = "sticky"                # ثابت (لجلسة معينة)


@dataclass
class RouteTarget:
    """هدف التوجيه (Proxy أو عنوان مباشر)"""
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
        """URL الكامل مع المصادقة"""
        if self.username and self.password:
            if "://" in self.url:
                protocol, rest = self.url.split("://", 1)
                return f"{protocol}://{self.username}:{self.password}@{rest}"
            return f"http://{self.username}:{self.password}@{self.url}"
        return self.url
    
    @property
    def success_rate(self) -> float:
        """نسبة النجاح"""
        total = self.success_count + self.fail_count
        if total == 0:
            return 1.0
        return self.success_count / total
    
    @property
    def load(self) -> float:
        """التحميل الحالي (كلما زاد، زاد الاستخدام)"""
        if self.avg_response_time == 0:
            return 0
        return self.usage_count / max(1, self.avg_response_time)
    
    def record_success(self, response_time: float):
        """تسجيل نجاح"""
        self.success_count += 1
        self.usage_count += 1
        self.avg_response_time = (self.avg_response_time * 0.7 + response_time * 0.3)
        self.is_healthy = True
    
    def record_failure(self):
        """تسجيل فشل"""
        self.fail_count += 1
        self.usage_count += 1
        if self.fail_count > 3:
            self.is_healthy = False
    
    def reset_health(self):
        """إعادة تعيين حالة الصحة"""
        self.is_healthy = True
        self.fail_count = 0


class RequestRouter:
    """موجه الطلبات الذكي"""
    
    def __init__(self, strategy: RoutingStrategy = RoutingStrategy.ROUND_ROBIN):
        self.strategy = strategy
        self._targets: List[RouteTarget] = []
        self._targets_by_id: Dict[str, RouteTarget] = {}
        self._current_index = 0
        self._sticky_map: Dict[str, str] = {}  # session_id -> target_id
        self._lock = asyncio.Lock()
        
        # إحصائيات
        self._stats = {
            "total_routes": 0,
            "successful_routes": 0,
            "failed_routes": 0,
            "strategy_changes": 0
        }
    
    def add_target(self, url: str, weight: int = 1, username: str = None, password: str = None, is_proxy: bool = True) -> str:
        """إضافة هدف توجيه جديد"""
        import uuid
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
        """إضافة عدة أهداف"""
        for t in targets:
            self.add_target(
                url=t["url"],
                weight=t.get("weight", 1),
                username=t.get("username"),
                password=t.get("password"),
                is_proxy=t.get("is_proxy", True)
            )
    
    def remove_target(self, target_id: str) -> bool:
        """إزالة هدف"""
        if target_id not in self._targets_by_id:
            return False
        
        self._targets = [t for t in self._targets if t.id != target_id]
        del self._targets_by_id[target_id]
        
        # تنظيف sticky map
        self._sticky_map = {k: v for k, v in self._sticky_map.items() if v != target_id}
        
        return True
    
    def get_healthy_targets(self) -> List[RouteTarget]:
        """الحصول على الأهداف السليمة فقط"""
        return [t for t in self._targets if t.is_healthy]
    
    def _select_round_robin(self, targets: List[RouteTarget]) -> Optional[RouteTarget]:
        """اختيار هدف بطريقة Round Robin"""
        if not targets:
            return None
        target = targets[self._current_index % len(targets)]
        self._current_index += 1
        return target
    
    def _select_random(self, targets: List[RouteTarget]) -> Optional[RouteTarget]:
        """اختيار هدف عشوائي"""
        if not targets:
            return None
        return random.choice(targets)
    
    def _select_weighted(self, targets: List[RouteTarget]) -> Optional[RouteTarget]:
        """اختيار هدف حسب الوزن"""
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
        """اختيار هدف أقل تحميلاً"""
        if not targets:
            return None
        return min(targets, key=lambda t: t.load)
    
    def _select_fastest(self, targets: List[RouteTarget]) -> Optional[RouteTarget]:
        """اختيار أسرع هدف"""
        if not targets:
            return None
        
        # تجاهل الأهداف التي لم تقاس بعد
        valid = [t for t in targets if t.avg_response_time > 0]
        if not valid:
            return random.choice(targets)
        
        return min(valid, key=lambda t: t.avg_response_time)
    
    def _select_sticky(self, targets: List[RouteTarget], session_id: str = None) -> Optional[RouteTarget]:
        """اختيار هدف ثابت للجلسة"""
        if not session_id:
            return self._select_round_robin(targets)
        
        if session_id in self._sticky_map:
            target_id = self._sticky_map[session_id]
            for target in targets:
                if target.id == target_id and target.is_healthy:
                    return target
        
        # اختيار هدف جديد
        target = self._select_round_robin(targets)
        if target:
            self._sticky_map[session_id] = target.id
        return target
    
    async def get_target(self, session_id: str = None) -> Optional[RouteTarget]:
        """الحصول على هدف مناسب حسب الاستراتيجية"""
        async with self._lock:
            targets = self.get_healthy_targets()
            
            if not targets:
                # إذا لم يكن هناك أهداف سليمة، استخدم أي هدف
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
    
    def record_result(self, target_id: str, success: bool, response_time: float = 0.0):
        """تسجيل نتيجة استخدام هدف"""
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
        """تغيير استراتيجية التوجيه"""
        self.strategy = strategy
        self._stats["strategy_changes"] += 1
    
    async def health_check_all(self, test_url: str = "https://httpbin.org/ip"):
        """فحص صحة جميع الأهداف"""
        import aiohttp
        
        async def check_target(target: RouteTarget) -> bool:
            try:
                start = time.time()
                connector = aiohttp.TCPConnector()
                async with aiohttp.ClientSession(connector=connector) as session:
                    async with session.get(
                        test_url,
                        proxy=target.full_url if target.is_proxy else None,
                        timeout=aiohttp.ClientTimeout(total=10)
                    ) as response:
                        response_time = (time.time() - start) * 1000
                        if response.status == 200:
                            target.record_success(response_time)
                            return True
                        else:
                            target.record_failure()
                            return False
            except Exception:
                target.record_failure()
                return False
        
        async with self._lock:
            tasks = [check_target(t) for t in self._targets]
            results = await asyncio.gather(*tasks)
            return sum(results)
    
    def get_stats(self) -> Dict:
        """إحصائيات التوجيه"""
        targets_stats = []
        for target in self._targets:
            targets_stats.append({
                "id": target.id,
                "url": target.url[:40] + "...",
                "weight": target.weight,
                "is_proxy": target.is_proxy,
                "success_rate": target.success_rate,
                "avg_response_time_ms": target.avg_response_time,
                "usage_count": target.usage_count,
                "is_healthy": target.is_healthy,
                "load": target.load
            })
        
        return {
            "strategy": self.strategy.value,
            "total_targets": len(self._targets),
            "healthy_targets": len(self.get_healthy_targets()),
            "targets": targets_stats,
            "total_routes": self._stats["total_routes"],
            "success_rate": self._stats["successful_routes"] / max(1, self._stats["total_routes"]),
            "sticky_sessions": len(self._sticky_map),
            "strategy_changes": self._stats["strategy_changes"]
        }
    
    def reset_stats(self):
        """إعادة تعيين الإحصائيات"""
        self._stats = {
            "total_routes": 0,
            "successful_routes": 0,
            "failed_routes": 0,
            "strategy_changes": 0
        }
    
    def clear(self):
        """مسح جميع الأهداف"""
        self._targets.clear()
        self._targets_by_id.clear()
        self._sticky_map.clear()
        self._current_index = 0
        self.reset_stats()


def create_request_router(
    strategy: str = "round_robin",
    proxies: List[str] = None
) -> RequestRouter:
    """إنشاء موجه طلبات جديد"""
    strategy_map = {
        "round_robin": RoutingStrategy.ROUND_ROBIN,
        "random": RoutingStrategy.RANDOM,
        "weighted": RoutingStrategy.WEIGHTED,
        "least_loaded": RoutingStrategy.LEAST_LOADED,
        "fastest": RoutingStrategy.FASTEST,
        "sticky": RoutingStrategy.STICKY
    }
    
    router = RequestRouter(strategy=strategy_map.get(strategy, RoutingStrategy.ROUND_ROBIN))
    
    if proxies:
        for proxy in proxies:
            if isinstance(proxy, dict):
                router.add_target(**proxy)
            else:
                router.add_target(proxy)
    
    return router

