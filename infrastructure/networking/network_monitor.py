
import asyncio
import time
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass, field
from datetime import datetime
from collections import defaultdict
from enum import Enum


class RequestMethod(Enum):
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    DELETE = "DELETE"
    PATCH = "PATCH"
    HEAD = "HEAD"
    OPTIONS = "OPTIONS"


class RequestStatus(Enum):
    PENDING = "pending"
    SUCCESS = "success"
    FAILED = "failed"
    TIMEOUT = "timeout"
    BLOCKED = "blocked"


@dataclass
class NetworkRequest:
    """طلب شبكة"""
    id: str
    url: str
    method: str
    start_time: float
    end_time: Optional[float] = None
    status_code: Optional[int] = None
    status: RequestStatus = RequestStatus.PENDING
    response_size: int = 0
    error_message: Optional[str] = None
    headers: Dict[str, str] = field(default_factory=dict)
    response_headers: Dict[str, str] = field(default_factory=dict)
    body: Optional[str] = None
    response_body: Optional[str] = None
    
    @property
    def duration_ms(self) -> float:
        if self.end_time:
            return (self.end_time - self.start_time) * 1000
        return 0.0
    
    def to_dict(self) -> Dict:
        return {
            "id": self.id,
            "url": self.url[:100],
            "method": self.method,
            "duration_ms": self.duration_ms,
            "status_code": self.status_code,
            "status": self.status.value,
            "response_size": self.response_size,
            "error": self.error_message
        }


@dataclass
class NetworkStats:
    """إحصائيات الشبكة"""
    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    blocked_requests: int = 0
    total_bytes: int = 0
    avg_response_time_ms: float = 0.0
    requests_per_second: float = 0.0
    errors_by_status: Dict[int, int] = field(default_factory=dict)
    endpoints_hit: Set[str] = field(default_factory=set)


class NetworkMonitor:
    """مراقب الشبكة المتقدم"""
    
    def __init__(self, max_requests: int = 1000):
        self.max_requests = max_requests
        self._requests: List[NetworkRequest] = []
        self._active_requests: Dict[str, NetworkRequest] = {}
        self._stats = NetworkStats()
        self._domain_stats: Dict[str, NetworkStats] = defaultdict(NetworkStats)
        self._method_stats: Dict[str, NetworkStats] = defaultdict(NetworkStats)
        self._start_time = time.time()
        self._lock = asyncio.Lock()
    
    def _add_request(self, request: NetworkRequest):
        """إضافة طلب إلى القائمة"""
        self._requests.append(request)
        if len(self._requests) > self.max_requests:
            self._requests = self._requests[-self.max_requests//2:]
    
    def start_request(self, url: str, method: str, headers: Dict = None, body: str = None) -> str:
        """بدء تتبع طلب جديد"""
        import uuid
        request_id = str(uuid.uuid4())[:8]
        
        request = NetworkRequest(
            id=request_id,
            url=url,
            method=method,
            start_time=time.time(),
            headers=headers or {},
            body=body[:500] if body else None
        )
        
        self._active_requests[request_id] = request
        return request_id
    
    def finish_request(
        self,
        request_id: str,
        status_code: int,
        response_headers: Dict = None,
        response_body: str = None,
        error: str = None
    ):
        """إنهاء تتبع الطلب"""
        request = self._active_requests.pop(request_id, None)
        if not request:
            return
        
        request.end_time = time.time()
        request.status_code = status_code
        
        if response_headers:
            request.response_headers = response_headers
            content_length = response_headers.get("content-length", "0")
            try:
                request.response_size = int(content_length)
            except:
                request.response_size = len(response_body or "")
        
        if response_body:
            request.response_body = response_body[:1000]
        
        if error:
            request.status = RequestStatus.FAILED
            request.error_message = error
            self._stats.failed_requests += 1
            domain = self._extract_domain(request.url)
            self._domain_stats[domain].failed_requests += 1
        elif status_code >= 400:
            if status_code == 429:
                request.status = RequestStatus.BLOCKED
                self._stats.blocked_requests += 1
            else:
                request.status = RequestStatus.FAILED
                self._stats.failed_requests += 1
            
            self._stats.errors_by_status[status_code] = self._stats.errors_by_status.get(status_code, 0) + 1
            domain = self._extract_domain(request.url)
            self._domain_stats[domain].errors_by_status[status_code] = \
                self._domain_stats[domain].errors_by_status.get(status_code, 0) + 1
        else:
            request.status = RequestStatus.SUCCESS
            self._stats.successful_requests += 1
            domain = self._extract_domain(request.url)
            self._domain_stats[domain].successful_requests += 1
        
        self._stats.total_requests += 1
        self._stats.total_bytes += request.response_size
        self._stats.endpoints_hit.add(request.url)
        
        # تحديث متوسط وقت الاستجابة
        current_avg = self._stats.avg_response_time_ms
        new_duration = request.duration_ms
        self._stats.avg_response_time_ms = (current_avg * 0.9 + new_duration * 0.1)
        
        # إحصائيات حسب النطاق
        domain = self._extract_domain(request.url)
        self._domain_stats[domain].total_requests += 1
        self._domain_stats[domain].total_bytes += request.response_size
        
        # إحصائيات حسب الطريقة
        self._method_stats[request.method].total_requests += 1
        
        self._add_request(request)
    
    def _extract_domain(self, url: str) -> str:
        """استخراج النطاق من URL"""
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            return parsed.netloc or "unknown"
        except:
            return "unknown"
    
    def get_requests(self, limit: int = 100, status: RequestStatus = None) -> List[Dict]:
        """الحصول على الطلبات الأخيرة"""
        requests = self._requests[-limit:]
        if status:
            requests = [r for r in requests if r.status == status]
        return [r.to_dict() for r in requests]
    
    def get_failed_requests(self, limit: int = 50) -> List[Dict]:
        """الحصول على الطلبات الفاشلة"""
        return self.get_requests(limit, RequestStatus.FAILED)
    
    def get_blocked_requests(self, limit: int = 50) -> List[Dict]:
        """الحصول على الطلبات المحظورة"""
        return self.get_requests(limit, RequestStatus.BLOCKED)
    
    def get_slow_requests(self, threshold_ms: float = 1000, limit: int = 20) -> List[Dict]:
        """الحصول على الطلبات البطيئة"""
        slow = [r for r in self._requests if r.duration_ms > threshold_ms]
        slow.sort(key=lambda x: x.duration_ms, reverse=True)
        return [r.to_dict() for r in slow[:limit]]
    
    def get_requests_by_method(self, method: str) -> List[Dict]:
        """الحصول على الطلبات حسب الطريقة"""
        return [r.to_dict() for r in self._requests if r.method == method]
    
    def get_requests_by_domain(self, domain: str) -> List[Dict]:
        """الحصول على الطلبات حسب النطاق"""
        return [r.to_dict() for r in self._requests if self._extract_domain(r.url) == domain]
    
    def get_stats(self) -> Dict:
        """إحصائيات الشبكة الكاملة"""
        elapsed = time.time() - self._start_time
        
        return {
            "total_requests": self._stats.total_requests,
            "successful_requests": self._stats.successful_requests,
            "failed_requests": self._stats.failed_requests,
            "blocked_requests": self._stats.blocked_requests,
            "success_rate": self._stats.successful_requests / max(1, self._stats.total_requests),
            "total_bytes": self._stats.total_bytes,
            "avg_response_time_ms": round(self._stats.avg_response_time_ms, 2),
            "requests_per_second": round(self._stats.total_requests / elapsed, 2),
            "unique_endpoints": len(self._stats.endpoints_hit),
            "errors_by_status": dict(self._stats.errors_by_status),
            "domains": {
                domain: {
                    "requests": stats.total_requests,
                    "success_rate": stats.successful_requests / max(1, stats.total_requests),
                    "errors": dict(stats.errors_by_status)
                }
                for domain, stats in self._domain_stats.items()
            },
            "methods": {
                method: {
                    "requests": stats.total_requests,
                    "success_rate": stats.successful_requests / max(1, stats.total_requests)
                }
                for method, stats in self._method_stats.items()
            }
        }
    
    def get_active_requests_count(self) -> int:
        """عدد الطلبات النشطة"""
        return len(self._active_requests)
    
    def clear(self):
        """مسح جميع البيانات"""
        self._requests.clear()
        self._active_requests.clear()
        self._stats = NetworkStats()
        self._domain_stats.clear()
        self._method_stats.clear()
        self._start_time = time.time()
    
    def get_summary(self) -> Dict:
        """ملخص سريع للشبكة"""
        return {
            "total": self._stats.total_requests,
            "success": self._stats.successful_requests,
            "failed": self._stats.failed_requests,
            "blocked": self._stats.blocked_requests,
            "success_rate": self._stats.successful_requests / max(1, self._stats.total_requests),
            "avg_response_ms": round(self._stats.avg_response_time_ms, 2),
            "active": len(self._active_requests)
        }


# نسخة عالمية
_default_monitor = None


def get_network_monitor() -> NetworkMonitor:
    """الحصول على نسخة عالمية من مراقب الشبكة"""
    global _default_monitor
    if _default_monitor is None:
        _default_monitor = NetworkMonitor()
    return _default_monitor

