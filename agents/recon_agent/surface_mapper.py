
import asyncio
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from collections import defaultdict

import logging

logger = logging.getLogger(__name__)


@dataclass
class AttackSurfaceComponent:
    """مكون من سطح الهجوم"""
    name: str
    type: str  # endpoint, parameter, form, api, file
    location: str
    risk_level: str  # high, medium, low
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SurfaceMappingResult:
    """نتيجة تخطيط سطح الهجوم"""
    target_url: str
    timestamp: datetime
    components: List[AttackSurfaceComponent] = field(default_factory=list)
    attack_vectors: List[Dict] = field(default_factory=list)
    entry_points: List[Dict] = field(default_factory=list)
    exposed_data: List[Dict] = field(default_factory=list)
    summary: Dict[str, Any] = field(default_factory=dict)


class SurfaceMapper:
    """
    Mapper سطح الهجوم المتقدم
    
    الميزات:
    - تخطيط جميع نقاط الدخول
    - تحديد مسارات الهجوم المحتملة
    - تحليل التعقيد
    - تحديد الثغرات المحتملة
    - إعطاء أولوية لنقاط الهجوم
    """
    
    def __init__(self):
        self._results: Dict[str, SurfaceMappingResult] = {}
        
        logger.info("SurfaceMapper initialized")
    
    async def map_surface(
        self,
        urls: List[str],
        analyzed_at: datetime,
        technologies: List[Dict],
        entry_points: List[Dict],
        api_endpoints: List[Dict],
        forms: List[Dict]
    ) -> SurfaceMappingResult:
        """
        تخطيط سطح الهجوم
        
        Args:
            urls: قائمة الروابط المكتشفة
            analyzed_at: وقت التحليل
            technologies: التقنيات المكتشفة
            entry_points: نقاط الدخول
            api_endpoints: واجهات API
            forms: النماذج
        
        Returns:
            نتيجة تخطيط سطح الهجوم
        """
        result = SurfaceMappingResult(
            target_url=urls[0] if urls else "",
            timestamp=analyzed_at
        )
        
        # 1. تخطيط المكونات
        result.components = await self._map_components(
            urls, entry_points, api_endpoints, forms
        )
        
        # 2. تحديد مسارات الهجوم
        result.attack_vectors = await self._identify_attack_vectors(
            technologies, entry_points, api_endpoints
        )
        
        # 3. تحديد نقاط الدخول
        result.entry_points = await self._prioritize_entry_points(entry_points)
        
        # 4. كشف البيانات المكشوفة
        result.exposed_data = await self._detect_exposed_data(technologies)
        
        # 5. إنشاء الملخص
        result.summary = await self._create_summary(result)
        
        return result
    
    async def _map_components(
        self,
        urls: List[str],
        entry_points: List[Dict],
        api_endpoints: List[Dict],
        forms: List[Dict]
    ) -> List[AttackSurfaceComponent]:
        """تخطيط مكونات سطح الهجوم"""
        components = []
        
        # نقاط النهاية
        for url in urls[:100]:  # حد أقصى 100 رابط
            component = AttackSurfaceComponent(
                name=url,
                type="endpoint",
                location=url,
                risk_level="medium",
                details={"method": "GET", "depth": url.count('/')}
            )
            components.append(component)
        
        # واجهات API
        for api in api_endpoints[:50]:
            component = AttackSurfaceComponent(
                name=api.get("path", ""),
                type="api",
                location=api.get("full_url", ""),
                risk_level="high",
                details={"method": api.get("method", "GET")}
            )
            components.append(component)
        
        # نقاط الدخول
        for ep in entry_points[:50]:
            component = AttackSurfaceComponent(
                name=ep.get("parameter", ""),
                type="parameter",
                location=ep.get("url", ""),
                risk_level="high" if ep.get("type") == "login" else "medium",
                details={"method": ep.get("method", "GET")}
            )
            components.append(component)
        
        # النماذج
        for form in forms[:50]:
            component = AttackSurfaceComponent(
                name=form.get("action", ""),
                type="form",
                location=form.get("action", ""),
                risk_level="high" if form.get("has_file_upload") else "medium",
                details={"method": form.get("method", "POST")}
            )
            components.append(component)
        
        return components
    
    async def _identify_attack_vectors(
        self,
        technologies: List[Dict],
        entry_points: List[Dict],
        api_endpoints: List[Dict]
    ) -> List[Dict]:
        """تحديد مسارات الهجوم المحتملة"""
        attack_vectors = []
        
        # مسارات بناءً على التقنيات
        for tech in technologies:
            tech_name = tech.get("name", "").lower()
            
            if "xss" in tech_name or "javascript" in tech_name:
                attack_vectors.append({
                    "type": "XSS",
                    "targets": [ep["url"] for ep in entry_points[:5]],
                    "likelihood": 0.7,
                    "impact": "medium"
                })
            
            if "sqli" in tech_name or "sql" in tech_name or "database" in tech_name:
                attack_vectors.append({
                    "type": "SQL Injection",
                    "targets": [ep["url"] for ep in entry_points if ep.get("parameter")],
                    "likelihood": 0.6,
                    "impact": "high"
                })
            
            if "api" in tech_name:
                attack_vectors.append({
                    "type": "API Abuse",
                    "targets": [api["full_url"] for api in api_endpoints[:10]],
                    "likelihood": 0.5,
                    "impact": "high"
                })
        
        # مسارات إضافية
        attack_vectors.append({
            "type": "Authentication Bypass",
            "targets": [ep["url"] for ep in entry_points if ep.get("type") == "login"],
            "likelihood": 0.4,
            "impact": "critical"
        })
        
        attack_vectors.append({
            "type": "IDOR",
            "targets": [ep["url"] for ep in entry_points if "user" in ep.get("url", "").lower() or "id" in ep.get("url", "").lower()],
            "likelihood": 0.6,
            "impact": "high"
        })
        
        return attack_vectors
    
    async def _prioritize_entry_points(self, entry_points: List[Dict]) -> List[Dict]:
        """ترتيب نقاط الدخول حسب الأولوية"""
        prioritized = []
        
        for ep in entry_points:
            score = 0
            
            # نقاط دخول عالية المخاطر
            if ep.get("type") == "login":
                score += 30
            if ep.get("type") == "file_upload":
                score += 25
            if ep.get("type") == "api":
                score += 20
            
            # معاملات حساسة
            param = ep.get("parameter", "")
            if param and any(word in param.lower() for word in ["id", "user", "admin", "password"]):
                score += 15
            
            # طريقة POST
            if ep.get("method") == "POST":
                score += 10
            
            prioritized.append({
                **ep,
                "priority_score": score,
                "priority": "high" if score >= 30 else "medium" if score >= 15 else "low"
            })
        
        # ترتيب حسب الدرجة
        prioritized.sort(key=lambda x: x["priority_score"], reverse=True)
        
        return prioritized
    
    async def _detect_exposed_data(self, technologies: List[Dict]) -> List[Dict]:
        """كشف البيانات المكشوفة"""
        exposed = []
        
        for tech in technologies:
            tech_name = tech.get("name", "").lower()
            
            if "version" in tech_name:
                exposed.append({
                    "type": "Version Disclosure",
                    "data": tech.get("evidence", ""),
                    "severity": "low"
                })
            
            if "debug" in tech_name or "dev" in tech_name:
                exposed.append({
                    "type": "Development Information",
                    "data": tech.get("evidence", ""),
                    "severity": "medium"
                })
        
        return exposed
    
    async def _create_summary(self, result: SurfaceMappingResult) -> Dict[str, Any]:
        """إنشاء ملخص لسطح الهجوم"""
        # توزيع المخاطر
        risk_distribution = defaultdict(int)
        for comp in result.components:
            risk_distribution[comp.risk_level] += 1
        
        # أنواع المكونات
        component_types = defaultdict(int)
        for comp in result.components:
            component_types[comp.type] += 1
        
        # مسارات الهجوم حسب النوع
        attack_types = defaultdict(int)
        for av in result.attack_vectors:
            attack_types[av["type"]] += 1
        
        return {
            "total_components": len(result.components),
            "risk_distribution": dict(risk_distribution),
            "component_types": dict(component_types),
            "attack_vectors_count": len(result.attack_vectors),
            "attack_types": dict(attack_types),
            "entry_points_count": len(result.entry_points),
            "high_priority_entry_points": len([ep for ep in result.entry_points if ep.get("priority") == "high"]),
            "exposed_data_count": len(result.exposed_data),
            "estimated_attack_complexity": "medium",
            "recommended_approach": "Start with high-priority entry points and authentication bypass vectors."
        }
    
    async def save_result(self, result: SurfaceMappingResult, target_url: str):
        """حفظ نتيجة التخطيط"""
        self._results[target_url] = result
        logger.info(f"Saved surface mapping result for {target_url}")
    
    async def get_result(self, target_url: str) -> Optional[SurfaceMappingResult]:
        """الحصول على نتيجة التخطيط لهدف معين"""
        return self._results.get(target_url)
    
    async def get_all_results(self) -> List[SurfaceMappingResult]:
        """الحصول على جميع النتائج"""
        return list(self._results.values())
    
    async def clear_results(self):
        """مسح جميع النتائج"""
        self._results.clear()
        logger.info("All surface mapping results cleared")
    
    async def get_statistics(self) -> Dict:
        """إحصائيات الـ mapper"""
        if not self._results:
            return {"total_mappings": 0}
        
        total_components = sum(len(r.components) for r in self._results.values())
        total_vectors = sum(len(r.attack_vectors) for r in self._results.values())
        
        return {
            "total_mappings": len(self._results),
            "total_components": total_components,
            "avg_components_per_target": total_components / len(self._results),
            "total_attack_vectors": total_vectors,
            "avg_vectors_per_target": total_vectors / len(self._results),
            "targets": list(self._results.keys())
        }

