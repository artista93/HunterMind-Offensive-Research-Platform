
import asyncio
import time
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
from collections import defaultdict
from enum import Enum


class RateLimitStrategy(Enum):
    """استراتيجية تحديد المعدل"""
    TOKEN_BUCKET = "token_bucket"      # دلو الرموز
    LEAKY_BUCKET = "leaky_bucket"      # دلو التسرب
    SLIDING_WINDOW = "sliding_window"  # نافذة منزلقة
    FIXED_WINDOW = "fixed_window"      # نافذة ثابتة


@dataclass
class RateLimitConfig:
    """إعدادات تحديد المعدل"""
    requests_per_second: float = 10.0
    burst_size: int = 5
    strategy: RateLimitStrategy = RateLimitStrategy.TOKEN_BUCKET
    adaptive: bool = True
    min_rate: float = 1.0
    max_rate: float = 50.0


class TokenBucket:
    """دلو الرموز - خوارزمية تحديد المعدل"""
    
    def __init__(self, rate: float, capacity: int):
        self.rate = rate  # رموز في الثانية
        self.capacity = capacity  # سعة الدلو
        self.tokens = capacity
        self.last_refill = time.time()
    
    def consume(self, tokens: int = 1) -> bool:
        """استهلاك الرموز"""
        self._refill()
        if self.tokens >= tokens:
            self.tokens -= tokens
            return True
        return False
    
    def _refill(self):
        """إعادة ملء الدلو"""
        now = time.time()
        elapsed = now - self.last_refill
        new_tokens = elapsed * self.rate
        self.tokens = min(self.capacity, self.tokens + new_tokens)
        self.last_refill = now
    
    def get_available(self) -> float:
        """الرموز المتاحة"""
        self._refill()
        return self.tokens
    
    def get_wait_time(self, tokens: int = 1) -> float:
        """وقت الانتظار للحصول على الرموز"""
        available = self.get_available()
        if available >= tokens:
            return 0.0
        needed = tokens - available
        return needed / self.rate


class LeakyBucket:
    """دلو التسرب - خوارزمية تحديد المعدل"""
    
    def __init__(self, rate: float, capacity: int):
        self.rate = rate  # معدل التسرب (طلبات في الثانية)
        self.capacity = capacity
        self.water = 0  # الماء الحالي في الدلو
        self.last_leak = time.time()
    
    def add(self, tokens: int = 1) -> bool:
        """إضافة طلب إلى الدلو"""
        self._leak()
        if self.water + tokens <= self.capacity:
            self.water += tokens
            return True
        return False
    
    def _leak(self):
        """تسرب الماء"""
        now = time.time()
        elapsed = now - self.last_leak
        leaked = elapsed * self.rate
        self.water = max(0, self.water - leaked)
        self.last_leak = now
    
    def get_wait_time(self, tokens: int = 1) -> float:
        """وقت الانتظار حتى يتسع الدلو"""
        self._leak()
        if self.water + tokens <= self.capacity:
            return 0.0
        needed = (self.water + tokens) - self.capacity
        return needed / self.rate


class SlidingWindow:
    """نافذة منزلقة - خوارزمية تحديد المعدل"""
    
    def __init__(self, rate: float, window_size: float = 1.0):
        self.rate = rate
        self.window_size = window_size
        self.requests: List[float] = []
    
    def allow(self) -> bool:
        """السماح بالطلب"""
        now = time.time()
        # إزالة الطلبات القديمة
        self.requests = [t for t in self.requests if now - t < self.window_size]
        
        if len(self.requests) < self.rate:
            self.requests.append(now)
            return True
        return False
    
    def get_wait_time(self) -> float:
        """وقت الانتظار حتى السماح بالطلب"""
        if self.allow():
            return 0.0
        if not self.requests:
            return 0.0
        oldest = min(self.requests)
        return self.window_size - (time.time() - oldest)


class FixedWindow:
    """نافذة ثابتة - خوارزمية تحديد المعدل"""
    
    def __init__(self, rate: float, window_size: float = 1.0):
        self.rate = rate
        self.window_size = window_size
        self.window_start = time.time()
        self.counter = 0
    
    def allow(self) -> bool:
        """السماح بالطلب"""
        now = time.time()
        if now - self.window_start >= self.window_size:
            self.window_start = now
            self.counter = 0
        
        if self.counter < self.rate:
            self.counter += 1
            return True
        return False
    
    def get_wait_time(self) -> float:
        """وقت الانتظار حتى النافذة التالية"""
        if self.allow():
            return 0.0
        elapsed = time.time() - self.window_start
        return self.window_size - elapsed


class AdaptiveRateController:
    """متحكم معدل متكيف - يضبط المعدل بناءً على الاستجابات"""
    
    def __init__(self, initial_rate: float = 10.0):
        self.current_rate = initial_rate
        self.min_rate = 1.0
        self.max_rate = 100.0
        self.success_count = 0
        self.failure_count = 0
        self.consecutive_failures = 0
        self.consecutive_successes = 0
        self.last_adjustment = time.time()
        self.adjustment_interval = 10.0  # ثواني
    
    def record_success(self):
        """تسجيل نجاح"""
        self.success_count += 1
        self.consecutive_failures = 0
        self.consecutive_successes += 1
        
        # زيادة المعدل إذا كان الأداء جيداً
        if self.consecutive_successes > 10:
            self._increase_rate()
    
    def record_failure(self):
        """تسجيل فشل (مثل 429, 503)"""
        self.failure_count += 1
        self.consecutive_successes = 0
        self.consecutive_failures += 1
        
        # تقليل المعدل إذا كان هناك فشل
        if self.consecutive_failures > 2:
            self._decrease_rate()
    
    def _increase_rate(self):
        """زيادة المعدل"""
        now = time.time()
        if now - self.last_adjustment >= self.adjustment_interval:
            self.current_rate = min(self.max_rate, self.current_rate * 1.2)
            self.last_adjustment = now
            self.consecutive_successes = 0
    
    def _decrease_rate(self):
        """تقليل المعدل"""
        now = time.time()
        if now - self.last_adjustment >= self.adjustment_interval:
            self.current_rate = max(self.min_rate, self.current_rate * 0.5)
            self.last_adjustment = now
            self.consecutive_failures = 0
    
    def get_current_rate(self) -> float:
        """المعدل الحالي"""
        return self.current_rate
    
    def get_stats(self) -> Dict:
        """إحصائيات التكيف"""
        total = self.success_count + self.failure_count
        return {
            "current_rate": self.current_rate,
            "success_rate": self.success_count / total if total > 0 else 1.0,
            "total_success": self.success_count,
            "total_failure": self.failure_count,
            "consecutive_failures": self.consecutive_failures
        }


class RateController:
    """متحكم المعدل الرئيسي - يدير جميع الاستراتيجيات"""
    
    def __init__(self, config: RateLimitConfig = None):
        self.config = config or RateLimitConfig()
        
        # معدل افتراضي لكل نطاق
        self._domain_limiters: Dict[str, Any] = {}
        self._global_limiter = self._create_limiter()
        
        # متحكم متكيف
        self._adaptive = AdaptiveRateController(self.config.requests_per_second)
        
        # إحصائيات
        self._stats = {
            "total_requests": 0,
            "total_delayed": 0,
            "total_rejected": 0,
            "domain_stats": defaultdict(lambda: {"requests": 0, "delayed": 0, "rejected": 0})
        }
    
    def _create_limiter(self, rate: float = None):
        """إنشاء محدد معدل حسب الاستراتيجية"""
        rate = rate or self.config.requests_per_second
        
        if self.config.strategy == RateLimitStrategy.TOKEN_BUCKET:
            return TokenBucket(rate, self.config.burst_size)
        elif self.config.strategy == RateLimitStrategy.LEAKY_BUCKET:
            return LeakyBucket(rate, self.config.burst_size)
        elif self.config.strategy == RateLimitStrategy.SLIDING_WINDOW:
            return SlidingWindow(rate)
        else:
            return FixedWindow(rate)
    
    def _get_domain(self, url: str) -> str:
        """استخراج النطاق من URL"""
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            return parsed.netloc or "global"
        except:
            return "global"
    
    def _get_limiter(self, domain: str) -> Any:
        """الحصول على محدد معدل للنطاق"""
        if domain not in self._domain_limiters:
            # استخدام معدل مخصص للنطاق إذا وجد
            self._domain_limiters[domain] = self._create_limiter()
        return self._domain_limiters[domain]
    
    async def acquire(self, url: str = None, tokens: int = 1) -> bool:
        """
        الحصول على إذن لإرسال طلب
        يعيد True إذا سمح، False إذا يجب الانتظار أو الرفض
        """
        domain = self._get_domain(url) if url else "global"
        self._stats["total_requests"] += 1
        self._stats["domain_stats"][domain]["requests"] += 1
        
        # المعدل المتكيف
        current_rate = self._adaptive.get_current_rate() if self.config.adaptive else self.config.requests_per_second
        
        # تحديث المحدد إذا تغير المعدل
        if self.config.adaptive and hasattr(self._global_limiter, 'rate') and self._global_limiter.rate != current_rate:
            self._global_limiter = self._create_limiter(current_rate)
        
        # التحقق من المحدد العالمي
        if not self._global_limiter.consume(tokens):
            wait_time = self._global_limiter.get_wait_time(tokens)
            self._stats["total_delayed"] += 1
            self._stats["domain_stats"][domain]["delayed"] += 1
            await asyncio.sleep(wait_time)
            # محاولة مرة أخرى
            return await self.acquire(url, tokens)
        
        # التحقق من المحدد لكل نطاق
        domain_limiter = self._get_limiter(domain)
        if not domain_limiter.consume(tokens):
            wait_time = domain_limiter.get_wait_time(tokens)
            self._stats["total_delayed"] += 1
            self._stats["domain_stats"][domain]["delayed"] += 1
            await asyncio.sleep(wait_time)
            return await self.acquire(url, tokens)
        
        return True
    
    def record_response(self, url: str, status_code: int):
        """تسجيل استجابة لتعديل المعدل بشكل متكيف"""
        if not self.config.adaptive:
            return
        
        if status_code in [429, 503, 504]:
            # طلب مرفوض بسبب المعدل
            self._adaptive.record_failure()
        elif status_code < 400:
            # نجاح
            self._adaptive.record_success()
    
    def record_failure(self, url: str, error: str = None):
        """تسجيل فشل"""
        if self.config.adaptive:
            self._adaptive.record_failure()
    
    def get_stats(self) -> Dict:
        """إحصائيات المتحكم"""
        domain_stats = {}
        for domain, stats in self._stats["domain_stats"].items():
            domain_stats[domain] = dict(stats)
        
        return {
            "total_requests": self._stats["total_requests"],
            "total_delayed": self._stats["total_delayed"],
            "total_rejected": self._stats["total_rejected"],
            "delay_rate": self._stats["total_delayed"] / max(1, self._stats["total_requests"]),
            "domain_stats": domain_stats,
            "adaptive": self._adaptive.get_stats() if self.config.adaptive else None,
            "strategy": self.config.strategy.value,
            "configured_rate": self.config.requests_per_second,
            "burst_size": self.config.burst_size
        }
    
    def reset(self):
        """إعادة تعيين الإحصائيات"""
        self._stats = {
            "total_requests": 0,
            "total_delayed": 0,
            "total_rejected": 0,
            "domain_stats": defaultdict(lambda: {"requests": 0, "delayed": 0, "rejected": 0})
        }
        self._domain_limiters.clear()
        self._adaptive = AdaptiveRateController(self.config.requests_per_second)


def create_rate_controller(
    requests_per_second: float = 10.0,
    burst_size: int = 5,
    strategy: str = "token_bucket",
    adaptive: bool = True
) -> RateController:
    """إنشاء متحكم معدل جديد"""
    strategy_map = {
        "token_bucket": RateLimitStrategy.TOKEN_BUCKET,
        "leaky_bucket": RateLimitStrategy.LEAKY_BUCKET,
        "sliding_window": RateLimitStrategy.SLIDING_WINDOW,
        "fixed_window": RateLimitStrategy.FIXED_WINDOW
    }
    
    config = RateLimitConfig(
        requests_per_second=requests_per_second,
        burst_size=burst_size,
        strategy=strategy_map.get(strategy, RateLimitStrategy.TOKEN_BUCKET),
        adaptive=adaptive
    )
    
    return RateController(config)

