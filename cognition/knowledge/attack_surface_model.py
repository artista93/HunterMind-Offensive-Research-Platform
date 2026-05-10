
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from collections import defaultdict

import logging

logger = logging.getLogger(__name__)


@dataclass
class EntryPoint:
    """نقطة دخول للهجوم"""
    url: str
    method: str
    parameters: List[str]
    type: str  # form, api, parameter, file_upload, login
    risk_level: str  # high, medium, low
    authenticated: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AttackVector:
    """متجه هجومي"""
    name: str
    entry_points: List[EntryPoint]
    vulnerability_type: str
    likelihood: float
    impact: str
    metadata: Dict[str, Any] = field(default_factory=dict)


class AttackSurfaceModel:
    """
    نموذج سطح الهجوم المتقدم
    
    الميزات:
    - تجميع نقاط الدخول للهجوم
    - تحليل المخاطر لكل نقطة دخول
    - تحديد متجهات الهجوم المحتملة
    - تقييم سطح الهجوم الكلي
    """
    
    def __init__(self, target_url: str):
        self.target_url = target_url
        self.created_at = datetime.now()
        self.updated_at = datetime.now()
        
        self._entry_points: List[EntryPoint] = []
        self._attack_vectors: List[AttackVector] = []
        self._exposed_apis: Set[str] = set()
        self._admin_endpoints: Set[str] = set()
        
        logger.info(f"AttackSurfaceModel created for {target_url}")
    
    async def add_entry_point(
        self,
        url: str,
        method: str,
        parameters: List[str],
        ep_type: str,
        risk_level: str = "medium",
        authenticated: bool = False,
        metadata: Dict = None
    ):
        """
        إضافة نقطة دخول جديدة
        
        Args:
            url: الرابط
            method: طريقة الطلب
            parameters: المعاملات
            ep_type: نوع نقطة الدخول
            risk_level: مستوى المخاطر
            authenticated: هل تتطلب مصادقة؟
            metadata: بيانات إضافية
        """
        entry = EntryPoint(
            url=url,
            method=method,
            parameters=parameters,
            type=ep_type,
            risk_level=risk_level,
            authenticated=authenticated,
            metadata=metadata or {}
        )
        
        self._entry_points.append(entry)
        self.updated_at = datetime.now()
        
        # تحديث الفهارس الخاصة
        if "api" in ep_type.lower():
            self._exposed_apis.add(url)
        
        if "admin" in url.lower():
            self._admin_endpoints.add(url)
        
        logger.debug(f"Entry point added: {method} {url} ({ep_type})")
    
    async def add_attack_vector(
        self,
        name: str,
        vulnerability_type: str,
        likelihood: float,
        impact: str,
        entry_points: List[EntryPoint] = None,
        metadata: Dict = None
    ):
        """
        إضافة متجه هجومي
        
        Args:
            name: اسم المتجه
            vulnerability_type: نوع الثغرة
            likelihood: احتمالية النجاح
            impact: التأثير
            entry_points: نقاط الدخول المرتبطة
            metadata: بيانات إضافية
        """
        vector = AttackVector(
            name=name,
            entry_points=entry_points or [],
            vulnerability_type=vulnerability_type,
            likelihood=likelihood,
            impact=impact,
            metadata=metadata or {}
        )
        
        self._attack_vectors.append(vector)
        self.updated_at = datetime.now()
        
        logger.info(f"Attack vector added: {name} ({vulnerability_type})")
    
    async def get_high_risk_points(self) -> List[EntryPoint]:
        """الحصول على نقاط الدخول عالية المخاطر"""
        return [ep for ep in self._entry_points if ep.risk_level == "high"]
    
    async def get_unauthenticated_points(self) -> List[EntryPoint]:
        """الحصول على نقاط الدخول التي لا تتطلب مصادقة"""
        return [ep for ep in self._entry_points if not ep.authenticated]
    
    async def get_api_endpoints(self) -> List[EntryPoint]:
        """الحصول على نقاط نهاية API"""
        return [ep for ep in self._entry_points if "api" in ep.type.lower()]
    
    async def get_admin_endpoints(self) -> List[str]:
        """الحصول على نقاط نهاية الإدارة"""
        return list(self._admin_endpoints)
    
    async def calculate_surface_score(self) -> float:
        """
        حساب درجة سطح الهجوم (كلما زادت، زادت قابلية الهجوم)
        
        Returns:
            درجة سطح الهجوم (0-100)
        """
        score = 0.0
        
        # نقاط الدخول عالية المخاطر
        high_risk_count = len(await self.get_high_risk_points())
        score += high_risk_count * 5
        
        # نقاط الدخول غير المحمية
        unauth_count = len(await self.get_unauthenticated_points())
        score += unauth_count * 3
        
        # واجهات API مكشوفة
        api_count = len(self._exposed_apis)
        score += api_count * 4
        
        # نقاط إدارة
        admin_count = len(self._admin_endpoints)
        score += admin_count * 8
        
        # متجهات الهجوم
        high_likelihood = sum(1 for v in self._attack_vectors if v.likelihood > 0.7)
        score += high_likelihood * 10
        
        return min(score, 100.0)
    
    async def get_top_attack_vectors(self, limit: int = 5) -> List[AttackVector]:
        """الحصول على أفضل متجهات الهجوم (حسب احتمالية النجاح)"""
        sorted_vectors = sorted(
            self._attack_vectors,
            key=lambda x: x.likelihood,
            reverse=True
        )
        return sorted_vectors[:limit]
    
    async def get_summary(self) -> Dict:
        """ملخص سطح الهجوم"""
        return {
            "target_url": self.target_url,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "total_entry_points": len(self._entry_points),
            "high_risk_points": len(await self.get_high_risk_points()),
            "unauthenticated_points": len(await self.get_unauthenticated_points()),
            "api_endpoints": len(self._exposed_apis),
            "admin_endpoints": len(self._admin_endpoints),
            "attack_vectors_count": len(self._attack_vectors),
            "surface_score": await self.calculate_surface_score(),
            "top_attack_vectors": [
                {
                    "name": v.name,
                    "vulnerability_type": v.vulnerability_type,
                    "likelihood": v.likelihood,
                    "impact": v.impact
                }
                for v in await self.get_top_attack_vectors(5)
            ]
        }
    
    async def export(self) -> Dict:
        """تصدير النموذج إلى قاموس"""
        return {
            "target_url": self.target_url,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "entry_points": [
                {
                    "url": ep.url,
                    "method": ep.method,
                    "parameters": ep.parameters,
                    "type": ep.type,
                    "risk_level": ep.risk_level,
                    "authenticated": ep.authenticated,
                    "metadata": ep.metadata
                }
                for ep in self._entry_points
            ],
            "attack_vectors": [
                {
                    "name": v.name,
                    "vulnerability_type": v.vulnerability_type,
                    "likelihood": v.likelihood,
                    "impact": v.impact,
                    "entry_points": [
                        {"url": ep.url, "method": ep.method}
                        for ep in v.entry_points
                    ],
                    "metadata": v.metadata
                }
                for v in self._attack_vectors
            ],
            "exposed_apis": list(self._exposed_apis),
            "admin_endpoints": list(self._admin_endpoints)
        }
    
    async def import_from_dict(self, data: Dict):
        """استيراد النموذج من قاموس"""
        self.target_url = data.get("target_url", self.target_url)
        self.created_at = datetime.fromisoformat(data.get("created_at")) if data.get("created_at") else self.created_at
        self.updated_at = datetime.fromisoformat(data.get("updated_at")) if data.get("updated_at") else self.updated_at
        
        self._entry_points = []
        for ep_data in data.get("entry_points", []):
            self._entry_points.append(EntryPoint(
                url=ep_data["url"],
                method=ep_data["method"],
                parameters=ep_data["parameters"],
                type=ep_data["type"],
                risk_level=ep_data["risk_level"],
                authenticated=ep_data["authenticated"],
                metadata=ep_data.get("metadata", {})
            ))
        
        self._attack_vectors = []
        for v_data in data.get("attack_vectors", []):
            # إعادة بناء نقاط الدخول المرتبطة
            entry_points = []
            for ep_ref in v_data.get("entry_points", []):
                for ep in self._entry_points:
                    if ep.url == ep_ref["url"] and ep.method == ep_ref["method"]:
                        entry_points.append(ep)
                        break
            
            self._attack_vectors.append(AttackVector(
                name=v_data["name"],
                entry_points=entry_points,
                vulnerability_type=v_data["vulnerability_type"],
                likelihood=v_data["likelihood"],
                impact=v_data["impact"],
                metadata=v_data.get("metadata", {})
            ))
        
        self._exposed_apis = set(data.get("exposed_apis", []))
        self._admin_endpoints = set(data.get("admin_endpoints", []))
        
        logger.info(f"AttackSurfaceModel imported for {self.target_url}")

