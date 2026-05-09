
import asyncio
import time
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
    CERTAIN = "certain"      # 100% - مؤكد
    HIGH = "high"            # 80-99%
    MEDIUM = "medium"        # 50-79%
    LOW = "low"              # 20-49%
    TENTATIVE = "tentative"  # <20%


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
    """
    
    def __init__(
        self,
        name: str,
        rate_limit: float = 1.0,  # طلب في الثانية
        timeout: int = 30,
        max_retries: int = 3,
        enabled: bool = True
    ):
        self.name = name
        self.rate_limit = rate_limit
        self.timeout = timeout
        self.max_retries = max_retries
        self.enabled = enabled
        
        # إحصائيات
        self._total_requests = 0
        self._total_findings = 0
        self._last_request_time = 0
        self._session = None
        
        logger.info(f"Scanner initialized: {name}")
    
    @abstractmethod
    async def scan(self, context: ScanContext) -> List[Finding]:
        """
        تنفيذ فحص الثغرات
        
        Args:
            context: سياق الفحص
        
        Returns:
            قائمة النتائج
        """
        pass
    
    @abstractmethod
    async def can_scan(self, context: ScanContext) -> bool:
        """
        التحقق مما إذا كان الفاحص يمكنه فحص الهدف
        
        Returns:
            True إذا كان الفحص ممكناً
        """
        pass
    
    async def execute_scan(self, context: ScanContext) -> List[Finding]:
        """
        تنفيذ الفحص مع إدارة الأخطاء والتكرار
        
        Args:
            context: سياق الفحص
        
        Returns:
            قائمة النتائج
        """
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
                # تطبيق تقييد المعدل
                await self._apply_rate_limit()
                
                # تنفيذ الفحص
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
        """تطبيق تقييد المعدل"""
        if self.rate_limit <= 0:
            return
        
        now = time.time()
        elapsed = now - self._last_request_time
        min_interval = 1.0 / self.rate_limit
        
        if elapsed < min_interval:
            await asyncio.sleep(min_interval - elapsed)
        
        self._last_request_time = time.time()
        self._total_requests += 1
    
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

