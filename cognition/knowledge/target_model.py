
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime

import logging

logger = logging.getLogger(__name__)


@dataclass
class ServiceInfo:
    """معلومات خدمة"""
    name: str
    version: Optional[str] = None
    port: Optional[int] = None
    protocol: str = "tcp"
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class TechnologyInfo:
    """معلومات تقنية"""
    name: str
    category: str  # language, framework, database, server, waf
    version: Optional[str] = None
    confidence: float = 0.8
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class EndpointInfo:
    """معلومات نقطة نهاية"""
    path: str
    method: str
    parameters: List[str]
    authenticated: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)


class TargetModel:
    """
    نموذج الهدف المتقدم
    
    الميزات:
    - تخزين معلومات الهدف (الخدمات، التقنيات، نقاط النهاية)
    - تحديث المعلومات ديناميكياً
    - تحليل المخاطر
    - تصدير واستيراد النموذج
    """
    
    def __init__(self, target_id: str, base_url: str):
        self.target_id = target_id
        self.base_url = base_url
        self.created_at = datetime.now()
        self.updated_at = datetime.now()
        
        self._services: Dict[str, ServiceInfo] = {}
        self._technologies: Dict[str, TechnologyInfo] = {}
        self._endpoints: Dict[str, EndpointInfo] = {}
        self._vulnerabilities: List[Dict] = []
        self._metadata: Dict[str, Any] = {}
        
        logger.info(f"TargetModel created for {base_url} ({target_id})")
    
    async def add_service(
        self,
        name: str,
        version: str = None,
        port: int = None,
        protocol: str = "tcp",
        metadata: Dict = None
    ):
        """إضافة خدمة مكتشفة"""
        service = ServiceInfo(
            name=name,
            version=version,
            port=port,
            protocol=protocol,
            metadata=metadata or {}
        )
        self._services[name] = service
        self.updated_at = datetime.now()
        
        logger.debug(f"Service added: {name} (v{version})")
    
    async def add_technology(
        self,
        name: str,
        category: str,
        version: str = None,
        confidence: float = 0.8,
        metadata: Dict = None
    ):
        """إضافة تقنية مكتشفة"""
        tech = TechnologyInfo(
            name=name,
            category=category,
            version=version,
            confidence=confidence,
            metadata=metadata or {}
        )
        
        # تحديث إذا كان الاسم موجوداً وذو ثقة أعلى
        if name in self._technologies:
            if confidence > self._technologies[name].confidence:
                self._technologies[name] = tech
        else:
            self._technologies[name] = tech
        
        self.updated_at = datetime.now()
        logger.debug(f"Technology added: {name} ({category})")
    
    async def add_endpoint(
        self,
        path: str,
        method: str = "GET",
        parameters: List[str] = None,
        authenticated: bool = False,
        metadata: Dict = None
    ):
        """إضافة نقطة نهاية"""
        endpoint_key = f"{method}:{path}"
        
        endpoint = EndpointInfo(
            path=path,
            method=method,
            parameters=parameters or [],
            authenticated=authenticated,
            metadata=metadata or {}
        )
        
        self._endpoints[endpoint_key] = endpoint
        self.updated_at = datetime.now()
        
        logger.debug(f"Endpoint added: {method} {path}")
    
    async def add_vulnerability(
        self,
        vuln_id: str,
        name: str,
        severity: str,
        location: str,
        evidence: str = None,
        metadata: Dict = None
    ):
        """إضافة ثغرة مكتشفة"""
        vulnerability = {
            "id": vuln_id,
            "name": name,
            "severity": severity,
            "location": location,
            "evidence": evidence,
            "metadata": metadata or {},
            "discovered_at": datetime.now().isoformat()
        }
        
        self._vulnerabilities.append(vulnerability)
        self.updated_at = datetime.now()
        
        logger.info(f"Vulnerability added: {name} ({severity})")
    
    async def get_services(self) -> Dict[str, ServiceInfo]:
        """الحصول على جميع الخدمات"""
        return self._services
    
    async def get_technologies(self) -> Dict[str, TechnologyInfo]:
        """الحصول على جميع التقنيات"""
        return self._technologies
    
    async def get_endpoints(self) -> Dict[str, EndpointInfo]:
        """الحصول على جميع نقاط النهاية"""
        return self._endpoints
    
    async def get_vulnerabilities(self) -> List[Dict]:
        """الحصول على جميع الثغرات"""
        return self._vulnerabilities
    
    async def get_risk_score(self) -> float:
        """
        حساب درجة المخاطر للهدف
        
        Returns:
            درجة المخاطر (0-100)
        """
        score = 0.0
        
        # ثغرات حرجة
        critical_vulns = [v for v in self._vulnerabilities if v["severity"] == "critical"]
        high_vulns = [v for v in self._vulnerabilities if v["severity"] == "high"]
        
        score += len(critical_vulns) * 20
        score += len(high_vulns) * 10
        score += len(self._vulnerabilities) * 2
        
        # خدمات معروفة بثغرات (محاكاة)
        for service in self._services.values():
            if service.name in ["Apache", "nginx", "MySQL", "PostgreSQL"] and not service.version:
                score += 5
        
        return min(score, 100.0)
    
    async def get_summary(self) -> Dict:
        """ملخص الهدف"""
        return {
            "target_id": self.target_id,
            "base_url": self.base_url,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "services_count": len(self._services),
            "technologies_count": len(self._technologies),
            "endpoints_count": len(self._endpoints),
            "vulnerabilities_count": len(self._vulnerabilities),
            "risk_score": await self.get_risk_score(),
            "critical_vulns": len([v for v in self._vulnerabilities if v["severity"] == "critical"]),
            "high_vulns": len([v for v in self._vulnerabilities if v["severity"] == "high"])
        }
    
    async def export(self) -> Dict:
        """تصدير النموذج إلى قاموس"""
        return {
            "target_id": self.target_id,
            "base_url": self.base_url,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "services": {
                name: {
                    "version": s.version,
                    "port": s.port,
                    "protocol": s.protocol,
                    "metadata": s.metadata
                }
                for name, s in self._services.items()
            },
            "technologies": {
                name: {
                    "category": t.category,
                    "version": t.version,
                    "confidence": t.confidence,
                    "metadata": t.metadata
                }
                for name, t in self._technologies.items()
            },
            "endpoints": {
                key: {
                    "path": e.path,
                    "method": e.method,
                    "parameters": e.parameters,
                    "authenticated": e.authenticated,
                    "metadata": e.metadata
                }
                for key, e in self._endpoints.items()
            },
            "vulnerabilities": self._vulnerabilities,
            "metadata": self._metadata
        }
    
    async def import_from_dict(self, data: Dict):
        """استيراد النموذج من قاموس"""
        self.target_id = data.get("target_id", self.target_id)
        self.base_url = data.get("base_url", self.base_url)
        self.created_at = datetime.fromisoformat(data.get("created_at")) if data.get("created_at") else self.created_at
        self.updated_at = datetime.fromisoformat(data.get("updated_at")) if data.get("updated_at") else self.updated_at
        
        self._services = {}
        for name, sdata in data.get("services", {}).items():
            self._services[name] = ServiceInfo(
                name=name,
                version=sdata.get("version"),
                port=sdata.get("port"),
                protocol=sdata.get("protocol", "tcp"),
                metadata=sdata.get("metadata", {})
            )
        
        self._technologies = {}
        for name, tdata in data.get("technologies", {}).items():
            self._technologies[name] = TechnologyInfo(
                name=name,
                category=tdata.get("category", "unknown"),
                version=tdata.get("version"),
                confidence=tdata.get("confidence", 0.8),
                metadata=tdata.get("metadata", {})
            )
        
        self._endpoints = {}
        for key, edata in data.get("endpoints", {}).items():
            self._endpoints[key] = EndpointInfo(
                path=edata.get("path", ""),
                method=edata.get("method", "GET"),
                parameters=edata.get("parameters", []),
                authenticated=edata.get("authenticated", False),
                metadata=edata.get("metadata", {})
            )
        
        self._vulnerabilities = data.get("vulnerabilities", [])
        self._metadata = data.get("metadata", {})
        
        logger.info(f"TargetModel imported for {self.base_url}")

