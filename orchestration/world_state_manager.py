"""
WorldState Manager - مدير حالة العالم المركزي

يدير WorldState كذاكرة مركزية حية لجميع مكونات المنصة
"""

import asyncio
from typing import Dict, List, Optional, Any, Set
from datetime import datetime
from urllib.parse import urlparse

from schemas.world_state import (
    WorldState, ScanPhase, TargetStatus, WAFType, AuthLevel, StealthLevel,
    DiscoveredEndpoint, DiscoveredTechnology, ScanStatistics,
    create_initial_state
)
from schemas.vulnerability import Vulnerability

import logging

logger = logging.getLogger(__name__)


class WorldStateManager:
    """
    مدير حالة العالم المركزي
    
    المسؤوليات:
    - تهيئة وإدارة WorldState
    - تتبع مراحل المسح (phase transitions)
    - إدارة الـ endpoints المكتشفة
    - كشف WAF والتقنيات
    - تجميع الإحصائيات
    - توفير وصول موحد لكل المكونات
    """
    
    def __init__(self):
        self._state: Optional[WorldState] = None
        self._phase_history: List[tuple] = []  # (phase, timestamp)
        self._lock = asyncio.Lock()
        self._waf_detection_attempted = False
        
        logger.info("WorldStateManager initialized")
    
    @property
    def state(self) -> Optional[WorldState]:
        """الحصول على WorldState الحالي"""
        return self._state
    
    @property
    def is_initialized(self) -> bool:
        """هل تمت التهيئة؟"""
        return self._state is not None
    
    async def initialize(self, target_url: str) -> WorldState:
        """
        تهيئة WorldState لهدف جديد
        
        Args:
            target_url: رابط الهدف
        
        Returns:
            WorldState المُهيأ
        """
        async with self._lock:
            self._state = create_initial_state(target_url)
            self._phase_history = [(ScanPhase.INITIALIZING, datetime.now())]
            self._waf_detection_attempted = False
            
            logger.info(f"WorldState initialized for {target_url}")
            return self._state
    
    async def transition_phase(self, new_phase: ScanPhase) -> ScanPhase:
        """
        الانتقال إلى مرحلة جديدة
        
        Args:
            new_phase: المرحلة الجديدة
        
        Returns:
            المرحلة الحالية بعد الانتقال
        """
        async with self._lock:
            if self._state is None:
                raise ValueError("WorldState not initialized")
            
            old_phase = self._state.phase
            self._state.phase = new_phase
            self._state.last_update = datetime.now()
            
            self._phase_history.append((new_phase, datetime.now()))
            
            logger.info(f"Phase transition: {old_phase.value} → {new_phase.value}")
            return new_phase
    
    async def get_current_phase(self) -> Optional[ScanPhase]:
        """الحصول على المرحلة الحالية"""
        if self._state:
            return self._state.phase
        return None
    
    async def get_phase_history(self) -> List[Dict]:
        """الحصول على تاريخ انتقالات المراحل"""
        return [
            {"phase": phase.value, "timestamp": ts.isoformat()}
            for phase, ts in self._phase_history
        ]
    
    async def add_endpoint(
        self,
        url: str,
        method: str = "GET",
        parameters: List[str] = None,
        response_time: float = 0.0,
        status_code: int = 0,
        content_type: str = ""
    ) -> Optional[DiscoveredEndpoint]:
        """
        إضافة endpoint مكتشف
        
        Args:
            url: رابط الـ endpoint
            method: طريقة HTTP
            parameters: قائمة المعاملات
            response_time: زمن الاستجابة
            status_code: كود الحالة
            content_type: نوع المحتوى
        
        Returns:
            DiscoveredEndpoint المضاف
        """
        async with self._lock:
            if self._state is None:
                return None
            
            # استخدام الدالة الموجودة في WorldState
            endpoint = self._state.add_endpoint(url, method, parameters or [])
            
            # تحديث معلومات إضافية
            if endpoint:
                endpoint.response_time = response_time
                endpoint.status_code = status_code
                endpoint.content_type = content_type
                endpoint.last_seen = datetime.now()
            
            self._state.last_update = datetime.now()
            
            logger.debug(f"Endpoint added: {method} {url}")
            return endpoint
    
    async def add_technology(
        self,
        name: str,
        version: Optional[str] = None,
        category: str = "unknown",
        confidence: float = 0.7
    ):
        """
        إضافة تقنية مكتشفة
        
        Args:
            name: اسم التقنية
            version: الإصدار
            category: الفئة (framework, server, database, cms)
            confidence: درجة الثقة
        """
        async with self._lock:
            if self._state is None:
                return
            
            self._state.add_technology(name, version, category, confidence)
            self._state.last_update = datetime.now()
            
            logger.debug(f"Technology added: {name} {version or ''}")
    
    async def detect_waf(self, response_headers: Dict[str, str]) -> Optional[WAFType]:
        """
        كشف WAF من headers الاستجابة
        
        Args:
            response_headers: headers الاستجابة
        
        Returns:
            نوع WAF أو None
        """
        if self._waf_detection_attempted:
            return self._state.waf_type if self._state else None
        
        waf_signatures = {
            WAFType.CLOUDFLARE: [
                ("server", "cloudflare"),
                ("cf-ray", ""),
            ],
            WAFType.AWS_WAF: [
                ("x-amzn-requestid", ""),
                ("x-amz-cf-id", ""),
            ],
            WAFType.MODSECURITY: [
                ("server", "mod_security"),
                ("x-mod-security", ""),
            ],
            WAFType.IMPERVA: [
                ("x-iinfo", ""),
                ("x-cdn", "imperva"),
            ],
            WAFType.AKAMAI: [
                ("x-akamai-transformed", ""),
                ("server", "akamai"),
            ],
            WAFType.FORTINET: [
                ("server", "fortiwaf"),
                ("x-fortinet", ""),
            ],
        }
        
        headers_lower = {k.lower(): v.lower() for k, v in response_headers.items()}
        
        for waf_type, signatures in waf_signatures.items():
            for header_key, header_value in signatures:
                if header_key in headers_lower:
                    if not header_value or header_value in headers_lower[header_key]:
                        async with self._lock:
                            if self._state:
                                self._state.waf_detected = True
                                self._state.waf_type = waf_type
                                self._state.last_update = datetime.now()
                        
                        self._waf_detection_attempted = True
                        logger.info(f"WAF detected: {waf_type.value}")
                        return waf_type
        
        self._waf_detection_attempted = True
        return None
    
    async def add_vulnerability(self, vulnerability: Vulnerability):
        """
        إضافة ثغرة مكتشفة
        
        Args:
            vulnerability: الثغرة
        """
        async with self._lock:
            if self._state is None:
                return
            
            self._state.add_vulnerability(vulnerability)
            self._state.last_update = datetime.now()
            
            logger.debug(f"Vulnerability added: {vulnerability.id}")
    
    async def update_target_status(self, status: TargetStatus):
        """تحديث حالة الهدف"""
        async with self._lock:
            if self._state:
                self._state.target_status = status
                self._state.last_update = datetime.now()
    
    async def update_auth_level(self, level: AuthLevel):
        """تحديث مستوى المصادقة"""
        async with self._lock:
            if self._state:
                self._state.auth_level = level
                self._state.authenticated = level in [AuthLevel.USER, AuthLevel.ADMIN]
                self._state.last_update = datetime.now()
    
    async def update_stealth_level(self, level: StealthLevel):
        """تحديث مستوى التخفي"""
        async with self._lock:
            if self._state:
                self._state.stealth_level = level
                self._state.last_update = datetime.now()
    
    async def increment_requests(self, success: bool = True):
        """زيادة عداد الطلبات"""
        async with self._lock:
            if self._state:
                self._state.statistics.requests_sent += 1
                if not success:
                    self._state.statistics.requests_failed += 1
    
    async def get_unscanned_endpoints(self) -> List[str]:
        """الحصول على الـ endpoints اللي لسه متفحصتش"""
        if self._state:
            return self._state.get_unvisited_endpoints()
        return []
    
    async def get_endpoints_by_method(self, method: str) -> List[DiscoveredEndpoint]:
        """الحصول على endpoints حسب الطريقة"""
        if not self._state:
            return []
        
        return [
            ep for ep in self._state.discovered_endpoints.values()
            if ep.method.upper() == method.upper()
        ]
    
    async def get_endpoints_with_params(self) -> List[DiscoveredEndpoint]:
        """الحصول على endpoints اللي فيها parameters"""
        if not self._state:
            return []
        
        return [
            ep for ep in self._state.discovered_endpoints.values()
            if ep.parameters
        ]
    
    async def get_technologies_by_category(self, category: str) -> List[DiscoveredTechnology]:
        """الحصول على تقنيات حسب الفئة"""
        if not self._state:
            return []
        
        return [
            tech for tech in self._state.discovered_technologies
            if tech.category == category
        ]
    
    async def get_vulnerabilities_by_severity(self, min_severity: str = "MEDIUM") -> List[Vulnerability]:
        """الحصول على ثغرات حسب الحد الأدنى للخطورة"""
        if not self._state:
            return []
        
        from schemas.vulnerability import Severity
        severity_levels = {
            "CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4
        }
        
        min_level = severity_levels.get(min_severity.upper(), 4)
        
        filtered = []
        for vuln in self._state.vulnerabilities:
            vuln_level = severity_levels.get(vuln.severity.name, 4)
            if vuln_level <= min_level:
                filtered.append(vuln)
        
        return filtered
    
    async def get_statistics(self) -> Dict:
        """الحصول على إحصائيات شاملة"""
        if not self._state:
            return {"error": "WorldState not initialized"}
        
        return {
            "phase": self._state.phase.value,
            "target_url": self._state.target_url,
            "target_status": self._state.target_status.value,
            "waf_detected": self._state.waf_detected,
            "waf_type": self._state.waf_type.value,
            "authenticated": self._state.authenticated,
            "auth_level": self._state.auth_level.value,
            "stealth_level": self._state.stealth_level.value,
            "detection_risk": self._state.detection_risk,
            "endpoints_discovered": len(self._state.discovered_endpoints),
            "endpoints_crawled": len(self._state.crawled_urls),
            "endpoints_pending": len(self._state.pending_urls),
            "technologies_discovered": len(self._state.discovered_technologies),
            "vulnerabilities_found": len(self._state.vulnerabilities),
            "attack_surface_score": self._state.get_attack_surface_score(),
            "progress_percentage": self._state.get_progress_percentage(),
            "statistics": self._state.statistics.to_dict(),
            "phase_history": await self.get_phase_history(),
        }
    
    async def get_summary(self) -> Dict:
        """ملخص سريع للحالة"""
        if not self._state:
            return {"phase": "not_initialized"}
        
        return {
            "phase": self._state.phase.value,
            "target": self._state.target_url,
            "waf": self._state.waf_type.value,
            "endpoints": len(self._state.discovered_endpoints),
            "vulnerabilities": len(self._state.vulnerabilities),
            "progress": f"{self._state.get_progress_percentage():.1f}%",
            "attack_surface": f"{self._state.get_attack_surface_score():.2f}",
        }
    
    async def to_dict(self) -> Dict:
        """تحويل كامل للحالة إلى قاموس"""
        if not self._state:
            return {}
        return self._state.to_dict()
    
    async def reset(self):
        """إعادة تعيين الحالة"""
        async with self._lock:
            if self._state:
                self._state.reset()
                self._phase_history = []
                self._waf_detection_attempted = False
                logger.info("WorldState reset")


# نسخة عالمية
_default_world_state_manager = None


def get_world_state_manager() -> WorldStateManager:
    """الحصول على نسخة عالمية من مدير WorldState"""
    global _default_world_state_manager
    if _default_world_state_manager is None:
        _default_world_state_manager = WorldStateManager()
    return _default_world_state_manager
