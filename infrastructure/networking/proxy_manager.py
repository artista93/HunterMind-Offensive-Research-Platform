"
import asyncio
import random
import aiohttp
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


class ProxyStatus(Enum):
    """حالة الـ Proxy"""
    ACTIVE = "active"
    INACTIVE = "inactive"
    CHECKING = "checking"
    FAILED = "failed"
    BANNED = "banned"


class ProxyRotationStrategy(Enum):
    """استراتيجية دوران الـ Proxies"""
    ROUND_ROBIN = "round_robin"      # توزيع دوري
    RANDOM = "random"                 # عشوائي
    LEAST_USED = "least_used"        # أقل استخداماً
    FASTEST = "fastest"              # الأسرع
    STICKY = "sticky"                # ثابت لكل جلسة


@dataclass
class ProxyInfo:
    """معلومات الـ Proxy"""
    url: str
    username: Optional[str] = None
    password: Optional[str] = None
    status: ProxyStatus = ProxyStatus.ACTIVE
    response_time: float = 0.0
    success_count: int = 0
    fail_count: int = 0
    last_used: Optional[datetime] = None
    last_check: Optional[datetime] = None
    country: Optional[str] = None
    protocol: str = "http"  # http, https, socks4, socks5
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    @property
    def full_url(self) -> str:
        """URL كامل مع المصادقة"""
        if self.username and self.password:
            # تحليل URL الأساسي
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
    
    def is_healthy(self) -> bool:
        """هل الـ Proxy سليم؟"""
        return self.status in [ProxyStatus.ACTIVE, ProxyStatus.INACTIVE] and self.success_rate > 0.5
    
    def record_success(self, response_time: float):
        """تسجيل نجاح"""
        self.success_count += 1
        self.response_time = (self.response_time * 0.7 + response_time * 0.3)
        self.last_used = datetime.now()
        self.status = ProxyStatus.ACTIVE
    
    def record_failure(self):
        """تسجيل فشل"""
        self.fail_count += 1
        if self.fail_count > 5:
            self.status = ProxyStatus.FAILED


class ProxyManager:
    """مدير الـ Proxies"""
    
    def __init__(
        self,
        rotation_strategy: ProxyRotationStrategy = ProxyRotationStrategy.ROUND_ROBIN,
        health_check_interval: int = 60,  # ثواني
        max_failures: int = 3
    ):
        self.rotation_strategy = rotation_strategy
        self.health_check_interval = health_check_interval
        self.max_failures = max_failures
        
        self.proxies: List[ProxyInfo] = []
        self._current_index = 0
        self._session_sticky: Dict[str, ProxyInfo] = {}
        self._health_check_task: Optional[asyncio.Task] = None
        self._running = False
        
        self._stats = {
            "total_requests": 0,
            "successful_requests": 0,
            "failed_requests": 0,
            "proxy_switches": 0
        }
    
    def add_proxy(self, proxy_url: str, username: str = None, password: str = None):
        """إضافة Proxy جديد"""
        proxy = ProxyInfo(
            url=proxy_url,
            username=username,
            password=password
        )
        self.proxies.append(proxy)
    
    def add_proxies(self, proxy_list: List[Dict]):
        """إضافة عدة Proxies"""
        for p in proxy_list:
            self.add_proxy(
                p.get("url"),
                p.get("username"),
                p.get("password")
            )
    
    def remove_proxy(self, proxy_url: str):
        """إزالة Proxy"""
        self.proxies = [p for p in self.proxies if p.url != proxy_url]
    
    def get_proxy(self, session_id: str = None) -> Optional[ProxyInfo]:
        """الحصول على Proxy حسب الاستراتيجية"""
        
        if not self.proxies:
            return None
        
        active_proxies = [p for p in self.proxies if p.is_healthy()]
        if not active_proxies:
            # إذا لم يكن هناك Proxies سليمة، نستخدم أي Proxy
            active_proxies = self.proxies
        
        # استراتيجية Sticky (ثابت لكل جلسة)
        if self.rotation_strategy == ProxyRotationStrategy.STICKY and session_id:
            if session_id in self._session_sticky:
                return self._session_sticky[session_id]
            else:
                proxy = self._get_by_strategy(active_proxies)
                self._session_sticky[session_id] = proxy
                return proxy
        
        return self._get_by_strategy(active_proxies)
    
    def _get_by_strategy(self, proxies: List[ProxyInfo]) -> ProxyInfo:
        """اختيار Proxy حسب الاستراتيجية"""
        
        if self.rotation_strategy == ProxyRotationStrategy.ROUND_ROBIN:
            proxy = proxies[self._current_index % len(proxies)]
            self._current_index += 1
            return proxy
        
        elif self.rotation_strategy == ProxyRotationStrategy.RANDOM:
            return random.choice(proxies)
        
        elif self.rotation_strategy == ProxyRotationStrategy.LEAST_USED:
            return min(proxies, key=lambda p: p.success_count + p.fail_count)
        
        elif self.rotation_strategy == ProxyRotationStrategy.FASTEST:
            # نرتب حسب أسرع وقت استجابة
            return min(proxies, key=lambda p: p.response_time if p.response_time > 0 else 9999)
        
        return proxies[0]
    
    async def check_proxy_health(self, proxy: ProxyInfo) -> bool:
        """فحص صحة Proxy"""
        proxy.status = ProxyStatus.CHECKING
        proxy.last_check = datetime.now()
        
        try:
            test_url = "https://httpbin.org/ip"
            start_time = asyncio.get_event_loop().time()
            
            connector = aiohttp.TCPConnector()
            async with aiohttp.ClientSession(connector=connector) as session:
                async with session.get(
                    test_url,
                    proxy=proxy.full_url,
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as response:
                    response_time = asyncio.get_event_loop().time() - start_time
                    if response.status == 200:
                        proxy.status = ProxyStatus.ACTIVE
                        proxy.response_time = response_time
                        return True
        except Exception:
            pass
        
        proxy.status = ProxyStatus.FAILED
        return False
    
    async def check_all_health(self):
        """فحص صحة جميع الـ Proxies"""
        tasks = [self.check_proxy_health(p) for p in self.proxies]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for proxy, result in zip(self.proxies, results):
            if not result:
                proxy.fail_count += 1
    
    async def _health_check_loop(self):
        """حلقة الفحص الدوري"""
        while self._running:
            await asyncio.sleep(self.health_check_interval)
            await self.check_all_health()
    
    async def start_health_check(self):
        """بدء الفحص الدوري"""
        self._running = True
        self._health_check_task = asyncio.create_task(self._health_check_loop())
    
    async def stop_health_check(self):
        """إيقاف الفحص الدوري"""
        self._running = False
        if self._health_check_task:
            self._health_check_task.cancel()
            try:
                await self._health_check_task
            except asyncio.CancelledError:
                pass
    
    def create_aiohttp_proxy(self, proxy: ProxyInfo) -> Dict:
        """إنشاء Proxy لـ aiohttp"""
        return {
            "proxy": proxy.full_url,
            "proxy_auth": aiohttp.BasicAuth(proxy.username, proxy.password) if proxy.username else None
        }
    
    def get_requests_proxy(self, proxy: ProxyInfo) -> Dict:
        """إنشاء Proxy لـ requests"""
        proxies = {
            "http": proxy.full_url,
            "https": proxy.full_url
        }
        return proxies
    
    async def test_proxy(self, proxy: ProxyInfo, test_url: str = "https://httpbin.org/ip") -> Tuple[bool, float]:
        """اختبار Proxy محدد"""
        try:
            start_time = asyncio.get_event_loop().time()
            connector = aiohttp.TCPConnector()
            async with aiohttp.ClientSession(connector=connector) as session:
                async with session.get(
                    test_url,
                    proxy=proxy.full_url,
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as response:
                    response_time = asyncio.get_event_loop().time() - start_time
                    return response.status == 200, response_time
        except Exception:
            return False, 0.0
    
    async def get_working_proxy(self, test_url: str = "https://httpbin.org/ip") -> Optional[ProxyInfo]:
        """الحصول على Proxy يعمل"""
        for proxy in self.proxies:
            success, _ = await self.test_proxy(proxy, test_url)
            if success:
                return proxy
        return None
    
    def record_request(self, proxy: ProxyInfo, success: bool, response_time: float = 0.0):
        """تسجيل طلب"""
        self._stats["total_requests"] += 1
        if success:
            self._stats["successful_requests"] += 1
            proxy.record_success(response_time)
        else:
            self._stats["failed_requests"] += 1
            proxy.record_failure()
    
    def rotate_proxy(self, session_id: str = None):
        """تغيير الـ Proxy"""
        if session_id and session_id in self._session_sticky:
            del self._session_sticky[session_id]
        self._stats["proxy_switches"] += 1
    
    def get_stats(self) -> Dict:
        """إحصائيات المدير"""
        return {
            **self._stats,
            "total_proxies": len(self.proxies),
            "active_proxies": sum(1 for p in self.proxies if p.status == ProxyStatus.ACTIVE),
            "failed_proxies": sum(1 for p in self.proxies if p.status == ProxyStatus.FAILED),
            "rotation_strategy": self.rotation_strategy.value,
            "health_check_interval": self.health_check_interval,
            "proxies": [
                {
                    "url": p.url[:20] + "...",
                    "status": p.status.value,
                    "success_rate": p.success_rate,
                    "response_time_ms": p.response_time * 1000
                }
                for p in self.proxies[:10]  # آخر 10 Proxies
            ]
        }
    
    def clear(self):
        """مسح جميع الـ Proxies"""
        self.proxies.clear()
        self._session_sticky.clear()
        self._current_index = 0
        self._stats = {
            "total_requests": 0,
            "successful_requests": 0,
            "failed_requests": 0,
            "proxy_switches": 0
        }


# Proxies افتراضية (للاختبار)
DEFAULT_PROXIES = [
    # يمكن إضافة Proxies حقيقية هنا
    # {"url": "http://proxy1.example.com:8080"},
    # {"url": "http://proxy2.example.com:8080", "username": "user", "password": "pass"},
]


def create_proxy_manager(
    proxies: List[Dict] = None,
    rotation_strategy: str = "round_robin",
    health_check_interval: int = 60
) -> ProxyManager:
    """إنشاء مدير Proxies جديد"""
    strategy_map = {
        "round_robin": ProxyRotationStrategy.ROUND_ROBIN,
        "random": ProxyRotationStrategy.RANDOM,
        "least_used": ProxyRotationStrategy.LEAST_USED,
        "fastest": ProxyRotationStrategy.FASTEST,
        "sticky": ProxyRotationStrategy.STICKY
    }
    
    manager = ProxyManager(
        rotation_strategy=strategy_map.get(rotation_strategy, ProxyRotationStrategy.ROUND_ROBIN),
        health_check_interval=health_check_interval
    )
    
    if proxies:
        manager.add_proxies(proxies)
    else:
        manager.add_proxies(DEFAULT_PROXIES)
    
    return manager

