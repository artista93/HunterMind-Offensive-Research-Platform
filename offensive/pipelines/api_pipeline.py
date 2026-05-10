
import asyncio
import json
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass, field
from datetime import datetime
from urllib.parse import urlparse, parse_qs

from ..scanners.api_scanner import APIScanner, Finding
from ..scanners.base_scanner import ScanContext, ScanTarget, Severity, Confidence
from ..recon.api_collector import APICollector, APIEndpoint
from ..payloads.payload_generator import PayloadType, get_payload_generator
from ..exploitation.exploit_orchestrator import ExploitTarget, get_exploit_orchestrator
from ..exploitation.exploit_memory import get_exploit_memory

import logging

logger = logging.getLogger(__name__)


@dataclass
class APIPipelineResult:
    """نتائج خط أنابيب API"""
    target_url: str
    start_time: datetime
    end_time: Optional[datetime] = None
    discovered_endpoints: List[APIEndpoint] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    exploited: List[Dict] = field(default_factory=list)
    total_endpoints: int = 0
    total_findings: int = 0
    exploited_count: int = 0
    authenticated_endpoints: int = 0
    unauthenticated_endpoints: int = 0
    status: str = "pending"
    error: Optional[str] = None


class APIPipeline:
    """
    خط أنابيب هجمات API المتكامل
    
    الميزات:
    - اكتشاف نقاط نهاية API تلقائياً
    - فحص ثغرات API (IDOR, Auth, Mass Assignment)
    - استغلال تلقائي للثغرات
    - تحليل المصادقة
    - تكامل مع ذاكرة الاستغلال
    - دعم GraphQL و REST APIs
    """
    
    def __init__(self):
        self._scanner = APIScanner()
        self._api_collector = APICollector()
        self._generator = get_payload_generator()
        self._orchestrator = get_exploit_orchestrator()
        self._memory = get_exploit_memory()
        
        self._active_pipelines: Dict[str, APIPipelineResult] = {}
        
        logger.info("APIPipeline initialized")
    
    async def run(
        self,
        target_url: str,
        headers: Dict[str, str] = None,
        auth_token: str = None,
        max_endpoints: int = 50,
        auto_exploit: bool = True,
        test_idor: bool = True,
        test_auth: bool = True
    ) -> APIPipelineResult:
        """
        تنفيذ خط أنابيب API كامل
        
        Args:
            target_url: الرابط المستهدف (نقطة نهاية API الأساسية)
            headers: هيدرات مخصصة
            auth_token: توكن المصادقة (Bearer)
            max_endpoints: الحد الأقصى لنقاط النهاية
            auto_exploit: استغلال تلقائي للثغرات
            test_idor: اختبار IDOR
            test_auth: اختبار المصادقة
        
        Returns:
            نتائج خط الأنابيب
        """
        pipeline_id = f"api_{target_url}_{int(datetime.now().timestamp())}"
        
        result = APIPipelineResult(
            target_url=target_url,
            start_time=datetime.now()
        )
        
        self._active_pipelines[pipeline_id] = result
        
        logger.info(f"Starting API pipeline for {target_url}")
        
        try:
            # 1. اكتشاف نقاط نهاية API
            if auth_token:
                headers = headers or {}
                headers["Authorization"] = f"Bearer {auth_token}"
            
            # جمع نقاط النهاية من HTML و JS
            all_endpoints = await self._discover_api_endpoints(target_url, headers)
            result.discovered_endpoints = all_endpoints[:max_endpoints]
            result.total_endpoints = len(result.discovered_endpoints)
            
            # 2. تحليل المصادقة
            for endpoint in result.discovered_endpoints:
                if endpoint.auth_required:
                    result.authenticated_endpoints += 1
                else:
                    result.unauthenticated_endpoints += 1
            
            logger.info(f"Discovered {result.total_endpoints} API endpoints ({result.authenticated_endpoints} authenticated)")
            
            # 3. فحص كل نقطة نهاية
            all_findings = []
            
            for endpoint in result.discovered_endpoints[:max_endpoints]:
                # إنشاء سياق فحص
                context = ScanContext(
                    target=ScanTarget(
                        url=endpoint.full_url,
                        headers=headers or {},
                        method=endpoint.method
                    )
                )
                
                # فحص النقطة
                if await self._scanner.can_scan(context):
                    findings = await self._scanner.scan(context)
                    all_findings.extend(findings)
                    
                    # تحديث الإحصائيات
                    for finding in findings:
                        result.total_findings += 1
                        
                        # تخزين في الذاكرة
                        self._memory.store_exploit(
                            name=f"API_{endpoint.path}_{finding.parameter if finding.parameter else 'general'}",
                            target_type="api",
                            vulnerability_type=finding.vulnerability_type,
                            payload=finding.payload or "",
                            encoding="none",
                            success=True,
                            context=endpoint.path,
                            metadata={
                                "url": endpoint.full_url,
                                "method": endpoint.method,
                                "endpoint": endpoint.path
                            }
                        )
                        
                        # استغلال تلقائي
                        if auto_exploit:
                            exploit_result = await self._exploit_endpoint(endpoint, finding)
                            if exploit_result:
                                result.exploited.append(exploit_result)
                                result.exploited_count += 1
            
            result.findings = all_findings
            result.status = "completed"
            
        except Exception as e:
            logger.error(f"API pipeline failed: {e}")
            result.status = "failed"
            result.error = str(e)
        
        finally:
            result.end_time = datetime.now()
            await self._scanner.close()
            await self._api_collector.close()
        
        logger.info(f"API pipeline completed: {result.total_endpoints} endpoints, {result.total_findings} findings, {result.exploited_count} exploited")
        
        return result
    
    async def _discover_api_endpoints(
        self,
        base_url: str,
        headers: Dict[str, str] = None
    ) -> List[APIEndpoint]:
        """
        اكتشاف نقاط نهاية API
        
        Args:
            base_url: الرابط الأساسي
            headers: هيدرات مخصصة
        
        Returns:
            قائمة بنقاط النهاية
        """
        all_endpoints = []
        
        # جمع من HTML (محاكاة)
        # في الواقع، سيتم جمع من HTML الفعلي
        
        # نقاط نهاية افتراضية للاختبار
        common_endpoints = [
            "/api/users",
            "/api/user/1",
            "/api/profile",
            "/api/orders",
            "/api/products",
            "/api/auth/login",
            "/api/auth/register",
            "/api/admin/users",
            "/api/config",
            "/api/metrics",
            "/graphql",
            "/swagger.json",
            "/openapi.json",
        ]
        
        for endpoint_path in common_endpoints:
            full_url = base_url.rstrip('/') + endpoint_path
            
            endpoint = APIEndpoint(
                path=endpoint_path,
                method="GET",
                full_url=full_url,
                discovered_from="common",
                auth_required="/admin/" in endpoint_path or "/auth/" in endpoint_path
            )
            all_endpoints.append(endpoint)
        
        return all_endpoints
    
    async def _exploit_endpoint(
        self,
        endpoint: APIEndpoint,
        finding: Finding
    ) -> Optional[Dict]:
        """
        استغلال نقطة نهاية API
        
        Args:
            endpoint: نقطة النهاية
            finding: نتيجة الفحص
        
        Returns:
            نتيجة الاستغلال
        """
        # إنشاء هدف الاستغلال
        exploit_target = ExploitTarget(
            url=endpoint.full_url,
            vulnerability_type=finding.vulnerability_type,
            parameter=finding.parameter,
            method=endpoint.method
        )
        
        # تنفيذ الاستغلال
        result = await self._orchestrator._exploit_target(exploit_target, None)
        
        if result and result.status.value == "success":
            return {
                "endpoint": endpoint.path,
                "method": endpoint.method,
                "vulnerability": finding.vulnerability_type,
                "parameter": finding.parameter,
                "payload": finding.payload[:100] if finding.payload else "",
                "response": result.output[:500] if result.output else "",
                "status_code": result.metadata.get("status_code", 200) if result.metadata else 200,
                "execution_time": result.execution_time
            }
        
        return None
    
    async def test_endpoint_security(
        self,
        endpoint_url: str,
        method: str = "GET",
        headers: Dict[str, str] = None
    ) -> Dict:
        """
        اختبار أمان نقطة نهاية واحدة
        
        Args:
            endpoint_url: رابط نقطة النهاية
            method: طريقة الطلب
            headers: هيدرات مخصصة
        
        Returns:
            نتائج اختبار الأمان
        """
        result = {
            "url": endpoint_url,
            "method": method,
            "authenticated_access": None,
            "authorization_bypass": None,
            "rate_limiting": None,
            "findings": []
        }
        
        # اختبار الوصول بدون مصادقة
        context = ScanContext(
            target=ScanTarget(
                url=endpoint_url,
                headers=headers or {},
                method=method
            )
        )
        
        if await self._scanner.can_scan(context):
            findings = await self._scanner.scan(context)
            result["findings"] = [f.__dict__ for f in findings]
            
            # كشف مشاكل المصادقة
            for finding in findings:
                if "Authentication" in finding.vulnerability_type or "Unauthenticated" in finding.vulnerability_type:
                    result["authenticated_access"] = True
                if "IDOR" in finding.vulnerability_type:
                    result["authorization_bypass"] = True
        
        return result
    
    async def generate_postman_collection(self, endpoints: List[APIEndpoint]) -> Dict:
        """
        توليد مجموعة Postman لنقاط النهاية المكتشفة
        
        Args:
            endpoints: قائمة نقاط النهاية
        
        Returns:
            مجموعة Postman بصيغة JSON
        """
        collection = {
            "info": {
                "name": "HunterMind API Collection",
                "description": "Automatically discovered API endpoints",
                "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"
            },
            "item": []
        }
        
        for endpoint in endpoints:
            item = {
                "name": f"{endpoint.method} {endpoint.path}",
                "request": {
                    "method": endpoint.method,
                    "header": [],
                    "url": {
                        "raw": endpoint.full_url,
                        "protocol": "https",
                        "host": [endpoint.full_url.split("//")[1].split("/")[0]] if "//" in endpoint.full_url else [],
                        "path": endpoint.path.strip("/").split("/")
                    }
                }
            }
            collection["item"].append(item)
        
        return collection
    
    async def get_result(self, pipeline_id: str) -> Optional[APIPipelineResult]:
        """الحصول على نتيجة خط الأنابيب"""
        return self._active_pipelines.get(pipeline_id)
    
    async def get_summary(self) -> Dict:
        """ملخص خطوط الأنابيب النشطة"""
        return {
            "active_pipelines": len(self._active_pipelines),
            "completed": sum(1 for r in self._active_pipelines.values() if r.status == "completed"),
            "failed": sum(1 for r in self._active_pipelines.values() if r.status == "failed"),
            "total_endpoints": sum(r.total_endpoints for r in self._active_pipelines.values()),
            "total_findings": sum(r.total_findings for r in self._active_pipelines.values()),
            "total_exploited": sum(r.exploited_count for r in self._active_pipelines.values()),
            "authenticated_endpoints": sum(r.authenticated_endpoints for r in self._active_pipelines.values()),
            "unauthenticated_endpoints": sum(r.unauthenticated_endpoints for r in self._active_pipelines.values())
        }
    
    async def close(self):
        """إغلاق الخط الأنابيب"""
        await self._scanner.close()
        await self._api_collector.close()
        logger.info("APIPipeline closed")


# نسخة عالمية
async def get_api_pipeline() -> APIPipeline:
    """الحصول على نسخة من خط أنابيب API"""
    return APIPipeline()

