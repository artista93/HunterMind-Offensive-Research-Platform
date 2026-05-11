import asyncio
import time
import httpx
from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Any, Callable, Awaitable
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import logging

logger = logging.getLogger(__name__)


class Severity(Enum):
    """شدة الثغرة"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Confidence(Enum):
    """مستوى الثقة في اكتشاف الثغرة"""
    CERTAIN = "certain"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    TENTATIVE = "tentative"


@dataclass
class Finding:
    """نتيجة اكتشاف ثغرة"""
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
    """هدف الفحص"""
    url: str
    method: str = "GET"
    headers: Dict[str, str] = field(default_factory=dict)
    cookies: Dict[str, str] = field(default_factory=dict)
    params: Dict[str, str] = field(default_factory=dict)
    data: Optional[Dict[str, str]] = None
    follow_redirects: bool = True
    timeout: int = 30


@dataclass
class ScanContext:
    """سياق الفحص"""
    target: ScanTarget
    depth: int = 0
    parent_url: Optional[str] = None
    visited_urls: set = field(default_factory=set)
    findings: List[Finding] = field(default_factory=list)
    start_time: datetime = field(default_factory=datetime.now)


class BaseScanner(ABC):
    """
    الفاحص الأساسي لجميع فاحصات الثغرات
    
    الميزات:
    - إدارة دورة حياة الفحص
    - تقييد المعدل (Rate Limiting)
    - مهلات زمنية
    - إعادة المحاولة التلقائية
    - تسجيل النتائج
    - إرسال الطلبات HTTP الحقيقية
    """
    
    def __init__(
        self,
        name: str,
        rate_limit: float = 1.0,
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
        self._session = None
        
        logger.info(f"Scanner initialized: {name}")
    
    @abstractmethod
    async def scan(self, context: ScanContext) -> List[Finding]:
        pass
    
    @abstractmethod
    async def can_scan(self, context: ScanContext) -> bool:
        pass
    
    async def execute_scan(self, context: ScanContext) -> List[Finding]:
        if not self.enabled:
            logger.debug(f"Scanner {self.name} is disabled")
            return []
        
        if not await self.can_scan(context):
            logger.debug(f"Scanner {self.name} cannot scan target")
            return []
        
        findings = []
        retries = 0
        
        while retries <= self.max_retries:
            try:
                await self._apply_rate_limit()
                findings = await asyncio.wait_for(
                    self.scan(context),
                    timeout=self.timeout
                )
                self._total_findings += len(findings)
                break
                
            except asyncio.TimeoutError:
                retries += 1
                logger.warning(f"Scanner {self.name} timeout (attempt {retries}/{self.max_retries})")
                if retries > self.max_retries:
                    logger.error(f"Scanner {self.name} failed after {self.max_retries} retries")
                    
            except Exception as e:
                retries += 1
                logger.error(f"Scanner {self.name} error: {e} (attempt {retries}/{self.max_retries})")
                if retries > self.max_retries:
                    raise
        
        return findings
    
    async def _apply_rate_limit(self):
        if self.rate_limit <= 0:
            return
        
        now = time.time()
        elapsed = now - self._last_request_time
        min_interval = 1.0 / self.rate_limit
        
        if elapsed < min_interval:
            await asyncio.sleep(min_interval - elapsed)
        
        self._last_request_time = time.time()
        self._total_requests += 1
    
    async def send_request(
        self,
        url: str,
        method: str = "GET",
        params: Dict = None,
        data: Dict = None,
        headers: Dict = None
    ) -> Optional[str]:
        """
        إرسال طلب HTTP حقيقي
        
        Args:
            url: الرابط المستهدف
            method: طريقة الطلب (GET, POST, PUT, DELETE)
            params: معاملات URL
            data: بيانات POST
            headers: هيدرات إضافية
        
        Returns:
            نص الاستجابة أو None
        """
        try:
            async with httpx.AsyncClient(
                timeout=self.timeout,
                follow_redirects=True,
                verify=False
            ) as client:
                
                if method.upper() == "GET":
                    response = await client.get(url, params=params, headers=headers)
                elif method.upper() == "POST":
                    response = await client.post(url, params=params, data=data, headers=headers)
                elif method.upper() == "PUT":
                    response = await client.put(url, params=params, data=data, headers=headers)
                elif method.upper() == "DELETE":
                    response = await client.delete(url, params=params, headers=headers)
                else:
                    response = await client.request(method, url, params=params, data=data, headers=headers)
                
                self._total_requests += 1
                logger.debug(f"Request: {method} {url} -> {response.status_code}")
                return response.text
                
        except httpx.TimeoutException:
            logger.warning(f"Request timeout: {url}")
            return None
        except httpx.ConnectError:
            logger.warning(f"Connection error: {url}")
            return None
        except Exception as e:
            logger.debug(f"Request failed: {e}")
            return None
    
    def add_finding(
        self,
        vulnerability_type: str,
        severity: Severity,
        confidence: Confidence,
        url: str,
        parameter: str = None,
        payload: str = None,
        evidence: str = None,
        description: str = "",
        remediation: str = "",
        cvss_score: float = 0.0,
        metadata: Dict = None
    ) -> Finding:
        """إنشاء كائن Finding جديد"""
        return Finding(
            vulnerability_type=vulnerability_type,
            severity=severity,
            confidence=confidence,
            url=url,
            parameter=parameter,
            payload=payload,
            evidence=evidence,
            description=description,
            remediation=remediation,
            cvss_score=cvss_score,
            metadata=metadata or {},
            discovered_at=datetime.now()
        )
    
    def get_statistics(self) -> Dict:
        """الحصول على إحصائيات الفاحص"""
        return {
            "name": self.name,
            "enabled": self.enabled,
            "total_requests": self._total_requests,
            "total_findings": self._total_findings,
            "rate_limit": self.rate_limit,
            "timeout": self.timeout
        }
    
    async def close(self):
        """إغلاق الفاحص وتنظيف الموارد"""
        if self._session:
            await self._session.close()
        logger.info(f"Scanner closed: {self.name}")
