from enum import Enum
from typing import List, Dict, Any, Optional, Set
from dataclasses import dataclass, field
from datetime import datetime
from .vulnerability import Vulnerability, Severity


class ScanPhase(Enum):
    """مراحل المسح"""
    IDLE = "idle"
    INITIALIZING = "initializing"
    RECONNAISSANCE = "reconnaissance"
    CRAWLING = "crawling"
    ANALYSIS = "analysis"
    SCANNING = "scanning"
    EXPLOITATION = "exploitation"
    REPORTING = "reporting"
    COMPLETED = "completed"
    ERROR = "error"


class TargetStatus(Enum):
    """حالة الهدف"""
    UNKNOWN = "unknown"
    ALIVE = "alive"
    RESPONSIVE = "responsive"
    SLOW = "slow"
    UNSTABLE = "unstable"
    BLOCKING = "blocking"
    DOWN = "down"


class WAFType(Enum):
    """أنظمة حماية التطبيقات"""
    NONE = "none"
    CLOUDFLARE = "cloudflare"
    AWS_WAF = "aws_waf"
    MODSECURITY = "modsecurity"
    IMPERVA = "imperva"
    F5_ASM = "f5_asm"
    AKAMAI = "akamai"
    FORTINET = "fortinet"
    UNKNOWN = "unknown"


class AuthLevel(Enum):
    """مستوى المصادقة"""
    NONE = "none"
    GUEST = "guest"
    USER = "user"
    ADMIN = "admin"
    SYSTEM = "system"


class StealthLevel(Enum):
    """مستوى التخفي"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    MAXIMUM = "maximum"


@dataclass
class DiscoveredEndpoint:
    """Endpoint مكتشف"""
    url: str
    method: str = "GET"
    parameters: List[str] = field(default_factory=list)
    forms: List[Dict] = field(default_factory=list)
    response_time: float = 0.0
    status_code: int = 0
    content_type: str = ""
    discovered_at: datetime = field(default_factory=datetime.now)
    last_seen: datetime = field(default_factory=datetime.now)
    visit_count: int = 1
    
    def to_dict(self) -> Dict:
        return {
            "url": self.url,
            "method": self.method,
            "parameters": self.parameters,
            "forms_count": len(self.forms),
            "response_time": self.response_time,
            "status_code": self.status_code,
            "visit_count": self.visit_count
        }


@dataclass
class DiscoveredTechnology:
    """تقنية مكتشفة"""
    name: str
    version: Optional[str] = None
    category: str = "unknown"
    confidence: float = 0.7
    discovered_at: datetime = field(default_factory=datetime.now)


@dataclass
class ScanStatistics:
    """إحصائيات المسح"""
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    pages_crawled: int = 0
    requests_sent: int = 0
    requests_failed: int = 0
    endpoints_discovered: int = 0
    forms_discovered: int = 0
    js_files_analyzed: int = 0
    api_endpoints_found: int = 0
    vulnerabilities_found: int = 0
    false_positives: int = 0
    
    @property
    def duration_seconds(self) -> float:
        if self.start_time and self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        return 0.0
    
    @property
    def success_rate(self) -> float:
        if self.requests_sent == 0:
            return 0.0
        return (self.requests_sent - self.requests_failed) / self.requests_sent
    
    def to_dict(self) -> Dict:
        return {
            "duration_seconds": self.duration_seconds,
            "pages_crawled": self.pages_crawled,
            "requests_sent": self.requests_sent,
            "requests_failed": self.requests_failed,
            "endpoints_discovered": self.endpoints_discovered,
            "vulnerabilities_found": self.vulnerabilities_found,
            "success_rate": self.success_rate
        }


@dataclass
class WorldState:
    """حالة العالم - تمثل الوضع الحالي للنظام والهدف"""
    
    target_url: str = ""
    target_status: TargetStatus = TargetStatus.UNKNOWN
    target_host: str = ""
    target_ip: Optional[str] = None
    
    phase: ScanPhase = ScanPhase.IDLE
    started_at: Optional[datetime] = None
    current_step: str = ""
    
    waf_detected: bool = False
    waf_type: WAFType = WAFType.NONE
    rate_limited: bool = False
    rate_limit_count: int = 0
    
    auth_level: AuthLevel = AuthLevel.NONE
    authenticated: bool = False
    auth_tokens: List[str] = field(default_factory=list)
    
    stealth_level: StealthLevel = StealthLevel.MEDIUM
    stealth_score: float = 0.5
    detection_risk: float = 0.0
    
    discovered_endpoints: Dict[str, DiscoveredEndpoint] = field(default_factory=dict)
    discovered_technologies: List[DiscoveredTechnology] = field(default_factory=list)
    crawled_urls: Set[str] = field(default_factory=set)
    pending_urls: Set[str] = field(default_factory=set)
    
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    
    statistics: ScanStatistics = field(default_factory=ScanStatistics)
    
    temp_data: Dict[str, Any] = field(default_factory=dict)
    
    last_update: datetime = field(default_factory=datetime.now)
    
    def update(self, **kwargs):
        """تحديث الحالة"""
        for key, value in kwargs.items():
            if hasattr(self, key):
                setattr(self, key, value)
        self.last_update = datetime.now()
    
    def add_endpoint(self, url: str, method: str = "GET", parameters: List[str] = None) -> DiscoveredEndpoint:
        """إضافة endpoint مكتشف"""
        # التحقق من عدم التكرار
        if url in self.discovered_endpoints:
            endpoint = self.discovered_endpoints[url]
            endpoint.last_seen = datetime.now()
            endpoint.visit_count += 1
            # تحديث المعاملات لو فيه جديدة
            if parameters:
                for p in parameters:
                    if p not in endpoint.parameters:
                        endpoint.parameters.append(p)
            return endpoint
        
        # إنشاء endpoint جديد
        endpoint = DiscoveredEndpoint(
            url=url,
            method=method,
            parameters=parameters or []
        )
        self.discovered_endpoints[url] = endpoint
        self.statistics.endpoints_discovered = len(self.discovered_endpoints)
        return endpoint
    
    def add_technology(self, name: str, version: str = None, category: str = "unknown", confidence: float = 0.7):
        """إضافة تقنية مكتشفة"""
        for tech in self.discovered_technologies:
            if tech.name == name and tech.version == version:
                tech.confidence = max(tech.confidence, confidence)
                tech.discovered_at = datetime.now()
                return
        
        self.discovered_technologies.append(DiscoveredTechnology(
            name=name,
            version=version,
            category=category,
            confidence=confidence
        ))
    
    def add_vulnerability(self, vulnerability: Vulnerability):
        """إضافة ثغرة مكتشفة"""
        # التحقق من نوع المدخلات
        if vulnerability is None:
            return
        if isinstance(vulnerability, str):
            # لا نضيف string - نتجاهل
            return
        self.vulnerabilities.append(vulnerability)
        self.statistics.vulnerabilities_found = len(self.vulnerabilities)
    
    def add_crawled_url(self, url: str):
        """إضافة URL تم زحفه"""
        self.crawled_urls.add(url)
        if url in self.pending_urls:
            self.pending_urls.discard(url)
        self.statistics.pages_crawled = len(self.crawled_urls)
    
    def add_pending_url(self, url: str):
        """إضافة URL معلق للزحف"""
        if url not in self.crawled_urls:
            self.pending_urls.add(url)
    
    def get_unvisited_endpoints(self) -> List[str]:
        """الحصول على الـ endpoints غير المزورة"""
        return [url for url in self.discovered_endpoints if url not in self.crawled_urls]
    
    def get_vulnerabilities_by_severity(self, severity: Severity) -> List[Vulnerability]:
        """الحصول على الثغرات حسب الخطورة"""
        return [v for v in self.vulnerabilities if v.severity == severity]
    
    def get_critical_vulnerabilities(self) -> List[Vulnerability]:
        return self.get_vulnerabilities_by_severity(Severity.CRITICAL)
    
    def get_high_vulnerabilities(self) -> List[Vulnerability]:
        return self.get_vulnerabilities_by_severity(Severity.HIGH)
    
    def has_waf(self) -> bool:
        return self.waf_detected
    
    def is_authenticated(self) -> bool:
        return self.authenticated
    
    def get_attack_surface_score(self) -> float:
        score = 0.0
        score += min(0.3, len(self.discovered_endpoints) / 100)
        api_count = sum(1 for e in self.discovered_endpoints.values() if "/api/" in e.url)
        score += min(0.2, api_count / 20)
        score += min(0.2, len(self.discovered_technologies) / 10)
        score += min(0.3, len(self.vulnerabilities) / 10)
        return min(1.0, score)
    
    def get_progress_percentage(self) -> float:
        total = len(self.discovered_endpoints)
        crawled = len(self.crawled_urls)
        if total == 0:
            return 0.0
        return (crawled / total) * 100
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "target_url": self.target_url,
            "target_status": self.target_status.value,
            "phase": self.phase.value,
            "authenticated": self.authenticated,
            "waf_detected": self.waf_detected,
            "waf_type": self.waf_type.value,
            "endpoints_total": len(self.discovered_endpoints),
            "endpoints_crawled": len(self.crawled_urls),
            "technologies": [{"name": t.name, "version": t.version} for t in self.discovered_technologies],
            "vulnerabilities_found": len(self.vulnerabilities),
            "statistics": self.statistics.to_dict(),
            "attack_surface_score": self.get_attack_surface_score(),
            "progress": self.get_progress_percentage()
        }
    
    def reset(self):
        self.discovered_endpoints.clear()
        self.discovered_technologies.clear()
        self.crawled_urls.clear()
        self.pending_urls.clear()
        self.vulnerabilities.clear()
        self.statistics = ScanStatistics()
        self.phase = ScanPhase.IDLE
        self.authenticated = False
        self.waf_detected = False
        self.last_update = datetime.now()


def create_initial_state(target_url: str) -> WorldState:
    """إنشاء حالة أولية لهدف جديد"""
    from urllib.parse import urlparse
    
    parsed = urlparse(target_url)
    
    state = WorldState(
        target_url=target_url,
        target_host=parsed.netloc,
        phase=ScanPhase.INITIALIZING,
        started_at=datetime.now()
    )
    
    state.add_endpoint(target_url)
    state.add_pending_url(target_url)
    
    return state
