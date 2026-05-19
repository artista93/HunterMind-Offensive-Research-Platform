"""
Base Scanner - الفاحص الأساسي (متصل بالبنية التحتية الاحترافية)
"""

import asyncio
import time
import random
import httpx
from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from urllib.parse import urlparse

import logging

logger = logging.getLogger(__name__)


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Confidence(Enum):
    CERTAIN = "certain"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    TENTATIVE = "tentative"


ScannerSeverity = Severity
ScannerConfidence = Confidence


@dataclass
class Finding:
    vulnerability_type: str
    severity: Severity
    confidence: Confidence
    url: str
    parameter: Optional[str] = None
    payload: Optional[str] = None
    evidence: Optional[str] = None
    description: str = ""
    remediation: str = ""
    cvss_score: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)
    discovered_at: datetime = field(default_factory=datetime.now)


@dataclass
class ScanTarget:
    url: str
    method: str = "GET"
    headers: Dict[str, str] = field(default_factory=dict)
    cookies: Dict[str, str] = field(default_factory=dict)
    params: Dict[str, str] = field(default_factory=dict)
    data: Optional[Dict[str, str]] = None
    follow_redirects: bool = True
    timeout: int = 30
    force_scan: bool = False


@dataclass
class ScanContext:
    target: ScanTarget
    depth: int = 0
    parent_url: Optional[str] = None
    visited_urls: set = field(default_factory=set)
    findings: List[Finding] = field(default_factory=list)
    start_time: datetime = field(default_factory=datetime.now)


class BaseScanner(ABC):
    """الفاحص الأساسي - متصل بالبنية التحتية الاحترافية"""
    
    # User-Agents احترافية
    USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.4; rv:125.0) Gecko/20100101 Firefox/125.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.82 Mobile Safari/537.36",
    ]
    
    def __init__(
        self,
        name: str,
        rate_limit: float = 2.0,
        timeout: int = 30,
        max_retries: int = 3,
        enabled: bool = True
    ):
        self.name = name
        self.rate_limit = rate_limit
        self.timeout = timeout
        self.max_retries = max_retries
        self.enabled = enabled
        
        self._total_requests = 0
        self._total_findings = 0
        self._last_request_time = 0
        
        # WorldState
        self._world_state = None
        self._world_state_manager = None
        
        # مكونات البنية التحتية (Lazy loading)
        self._rate_controller = None
        self._proxy_manager = None
        self._network_monitor = None
        self._session_manager = None
        self._traffic_analyzer = None
        self._session_pool = None
        
        # إعدادات التخفي
        self._stealth_mode = True
        self._last_ua_rotation = 0
        self._ua_rotation_interval = 30  # ثواني
        self._min_delay = 0.3
        self._max_delay = 2.0
        
        logger.info(f"Scanner initialized: {name}")
    
    async def _ensure_infrastructure(self):
        """تهيئة مكونات البنية التحتية"""
        try:
            if self._network_monitor is None:
                from infrastructure.networking.network_monitor import get_network_monitor
                self._network_monitor = get_network_monitor()
        except ImportError:
            pass
        
        try:
            if self._rate_controller is None:
                from infrastructure.networking.rate_controller import create_rate_controller
                self._rate_controller = create_rate_controller(
                    requests_per_second=self.rate_limit,
                    adaptive=True
                )
        except ImportError:
            pass
        
        try:
            if self._session_pool is None:
                from infrastructure.networking.session_pool import get_session_pool
                self._session_pool = await get_session_pool(pool_size=5)
        except ImportError:
            pass
    
    def set_world_state(self, world_state):
        self._world_state = world_state
    
    def set_world_state_manager(self, manager):
        self._world_state_manager = manager
        if manager and manager.state:
            self._world_state = manager.state
    
    def has_world_state(self) -> bool:
        return self._world_state is not None
    
    def _get_random_user_agent(self) -> str:
        """User-Agent عشوائي مع تدوير دوري"""
        now = time.time()
        if now - self._last_ua_rotation > self._ua_rotation_interval:
            self._last_ua_rotation = now
        return random.choice(self.USER_AGENTS)
    
    def _build_stealth_headers(self, url: str, extra_headers: Dict = None) -> Dict:
        """بناء headers احترافية"""
        parsed = urlparse(url)
        
        headers = {
            "User-Agent": self._get_random_user_agent(),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": random.choice(["en-US,en;q=0.9", "en-GB,en;q=0.9", "en;q=0.9"]),
            "Accept-Encoding": "gzip, deflate, br",
            "Cache-Control": "no-cache",
            "Sec-Fetch-Dest": random.choice(["document", "empty"]),
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
            "Upgrade-Insecure-Requests": "1",
            "Connection": "keep-alive",
        }
        
        if extra_headers:
            headers.update(extra_headers)
        
        return headers
    
    @abstractmethod
    async def scan(self, context: ScanContext) -> List[Finding]:
        pass
    
    @abstractmethod
    async def can_scan(self, context: ScanContext) -> bool:
        pass
    
    async def execute_scan(self, context: ScanContext) -> List[Finding]:
        if not self.enabled:
            return []
        
        if not context.target.force_scan:
            if not await self.can_scan(context):
                return []
        
        await self._ensure_infrastructure()
        
        findings = []
        retries = 0
        
        while retries <= self.max_retries:
            try:
                await self._apply_rate_limit(context.target.url)
                findings = await asyncio.wait_for(self.scan(context), timeout=self.timeout)
                self._total_findings += len(findings)
                break
            except asyncio.TimeoutError:
                retries += 1
                logger.warning(f"Scanner {self.name} timeout (attempt {retries}/{self.max_retries})")
            except Exception as e:
                retries += 1
                logger.error(f"Scanner {self.name} error: {e}")
                if retries > self.max_retries:
                    raise
        
        return findings
    
    async def _apply_rate_limit(self, url: str = None):
        """تطبيق rate limit مع delay عشوائي"""
        # Delay عشوائي للتخفي
        if self._stealth_mode:
            delay = self._min_delay + random.random() * (self._max_delay - self._min_delay)
            await asyncio.sleep(delay)
        
        # استخدام RateController إذا متاح
        if self._rate_controller:
            await self._rate_controller.acquire(url)
            return
        
        # Fallback: delay ثابت
        if self.rate_limit <= 0:
            return
        
        now = time.time()
        elapsed = now - self._last_request_time
        min_interval = 1.0 / self.rate_limit
        
        if elapsed < min_interval:
            await asyncio.sleep(min_interval - elapsed + random.uniform(0, 0.5))
        
        self._last_request_time = time.time()
    
    async def send_request(
        self,
        url: str,
        method: str = "GET",
        params: Dict = None,
        data: Dict = None,
        json_data: Dict = None,
        headers: Dict = None
    ) -> Optional[str]:
        """إرسال طلب HTTP احترافي"""
        request_id = None
        
        try:
            # بناء headers احترافية
            request_headers = self._build_stealth_headers(url, headers)
            
            # بدء تتبع الطلب
            if self._network_monitor:
                request_id = self._network_monitor.start_request(url, method, request_headers)
            
            # استخدام SessionPool إذا متاح
            if self._session_pool:
                pooled = await self._session_pool.acquire(timeout=5)
                if pooled:
                    client = pooled.session
                    try:
                        response = await client.request(
                            method=method, url=url,
                            headers=request_headers,
                            params=params, data=data, json=json_data,
                            timeout=self.timeout,
                            follow_redirects=True
                        )
                        
                        self._total_requests += 1
                        
                        # إنهاء التتبع
                        if self._network_monitor and request_id:
                            self._network_monitor.finish_request(
                                request_id, response.status_code,
                                dict(response.headers), response.text[:500]
                            )
                        
                        # تحديث RateController
                        if self._rate_controller:
                            self._rate_controller.record_response(url, response.status_code)
                        
                        await self._session_pool.release(pooled)
                        return response.text
                    except Exception:
                        await self._session_pool.invalidate(pooled)
            
            # Fallback: httpx مباشر
            async with httpx.AsyncClient(
                timeout=self.timeout,
                follow_redirects=True,
                verify=False
            ) as client:
                response = await client.request(
                    method=method, url=url,
                    headers=request_headers,
                    params=params, data=data, json=json_data
                )
                
                self._total_requests += 1
                
                if self._network_monitor and request_id:
                    self._network_monitor.finish_request(
                        request_id, response.status_code,
                        dict(response.headers), response.text[:500]
                    )
                
                if self._rate_controller:
                    self._rate_controller.record_response(url, response.status_code)
                
                return response.text
                
        except httpx.TimeoutException:
            logger.warning(f"Request timeout: {url}")
            if self._network_monitor and request_id:
                self._network_monitor.finish_request(request_id, 0, error="timeout")
            if self._rate_controller:
                self._rate_controller.record_failure(url, "timeout")
            return None
        except Exception as e:
            logger.debug(f"Request failed: {e}")
            if self._network_monitor and request_id:
                self._network_monitor.finish_request(request_id, 0, error=str(e))
            if self._rate_controller:
                self._rate_controller.record_failure(url, str(e))
            return None
    
    def add_finding(self, **kwargs) -> Finding:
        return Finding(discovered_at=datetime.now(), **kwargs)
    
    def get_statistics(self) -> Dict:
        return {
            "name": self.name,
            "enabled": self.enabled,
            "total_requests": self._total_requests,
            "total_findings": self._total_findings,
            "rate_limit": self.rate_limit,
            "timeout": self.timeout,
            "world_state_connected": self.has_world_state(),
            "stealth_mode": self._stealth_mode,
        }
    
    async def close(self):
        logger.info(f"Scanner closed: {self.name}")
