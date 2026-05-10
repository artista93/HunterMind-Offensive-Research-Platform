
import asyncio
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass, field
from datetime import datetime

from ..scanners.xss_scanner import XSSScanner, Finding, Severity, Confidence
from ..scanners.base_scanner import ScanContext, ScanTarget
from ..payloads.payload_generator import PayloadType, get_payload_generator
from ..payloads.payload_encoder import get_payload_encoder
from ..payloads.payload_ranker import get_payload_ranker
from ..exploitation.exploit_orchestrator import ExploitTarget, get_exploit_orchestrator
from ..exploitation.exploit_memory import get_exploit_memory

import logging

logger = logging.getLogger(__name__)


@dataclass
class XSSPipelineResult:
    """نتائج خط أنابيب XSS"""
    target_url: str
    start_time: datetime
    end_time: Optional[datetime] = None
    findings: List[Finding] = field(default_factory=list)
    exploited: List[Dict] = field(default_factory=list)
    total_requests: int = 0
    total_findings: int = 0
    exploited_count: int = 0
    status: str = "pending"
    error: Optional[str] = None


class XSSPipeline:
    """
    خط أنابيب هجمات XSS المتكامل
    
    الميزات:
    - فحص XSS متقدم
    - توليد حمولات مخصصة
    - استغلال تلقائي للثغرات
    - تكامل مع ذاكرة الاستغلال
    - ترتيب الحمولات حسب الفعالية
    - تقارير مفصلة
    """
    
    def __init__(self):
        self._scanner = XSSScanner()
        self._generator = get_payload_generator()
        self._encoder = get_payload_encoder()
        self._ranker = get_payload_ranker()
        self._orchestrator = get_exploit_orchestrator()
        self._memory = get_exploit_memory()
        
        self._active_pipelines: Dict[str, XSSPipelineResult] = {}
        
        logger.info("XSSPipeline initialized")
    
    async def run(
        self,
        target_url: str,
        params: Dict[str, str] = None,
        headers: Dict[str, str] = None,
        max_payloads: int = 100,
        auto_exploit: bool = True
    ) -> XSSPipelineResult:
        """
        تنفيذ خط أنابيب XSS كامل
        
        Args:
            target_url: الرابط المستهدف
            params: معاملات إضافية
            headers: هيدرات مخصصة
            max_payloads: الحد الأقصى للحمولات
            auto_exploit: استغلال تلقائي للثغرات
        
        Returns:
            نتائج خط الأنابيب
        """
        pipeline_id = f"xss_{target_url}_{int(datetime.now().timestamp())}"
        
        result = XSSPipelineResult(
            target_url=target_url,
            start_time=datetime.now()
        )
        
        self._active_pipelines[pipeline_id] = result
        
        logger.info(f"Starting XSS pipeline for {target_url}")
        
        try:
            # 1. تحضير السياق
            context = ScanContext(
                target=ScanTarget(
                    url=target_url,
                    headers=headers or {},
                    params=params or {}
                )
            )
            
            # 2. البحث عن استغلالات سابقة مشابهة
            similar_exploits = self._memory.find_similar_exploits(
                vulnerability_type="XSS",
                min_success_rate=0.6,
                limit=10
            )
            
            if similar_exploits:
                logger.info(f"Found {len(similar_exploits)} similar exploits in memory")
            
            # 3. توليد الحمولات (بما في ذلك المستفادة من الذاكرة)
            payloads = self._generator.generate_xss_payloads(max_payloads=max_payloads)
            
            # إضافة حمولات من الذاكرة
            for exploit in similar_exploits:
                from ..payloads.payload_generator import Payload
                memory_payload = Payload(
                    id=exploit.id,
                    name=exploit.name,
                    type=PayloadType.XSS,
                    payload=exploit.payload,
                    description=f"From memory: {exploit.name}",
                    tags=["memory", "reused"]
                )
                payloads.append(memory_payload)
            
            # 4. ترتيب الحمولات حسب الفعالية المتوقعة
            scored_payloads = self._ranker.rank_payloads(payloads, context={"has_waf": False})
            
            # 5. تنفيذ الفحص
            all_findings = []
            
            for scored in scored_payloads[:max_payloads]:
                # استخدام الحمولة في الفحص
                payload = self._get_payload_from_scored(scored)
                
                # ترميز الحمولة
                encoded_payloads = self._encoder.encode_all(payload, max_encodings=3)
                
                for encoded in encoded_payloads[:5]:  # حد أقصى 5 ترميزات لكل حمولة
                    # إدراج الحمولة في الفحص
                    finding = await self._scanner._test_payload(
                        context=context,
                        url=target_url,
                        param_name=params.keys()[0] if params else "q",
                        payload=encoded.encoded,
                        method="GET"
                    )
                    
                    if finding:
                        all_findings.append(finding)
                        result.total_findings += 1
                        
                        # تخزين الاستغلال الناجح في الذاكرة
                        self._memory.store_exploit(
                            name=f"XSS_{target_url}_{finding.parameter}",
                            target_type="web",
                            vulnerability_type="XSS",
                            payload=payload.payload,
                            encoding=encoded.encoding.value if encoded.encoding else "none",
                            success=True,
                            context=finding.parameter,
                            metadata={
                                "url": target_url,
                                "confidence": finding.confidence.value,
                                "severity": finding.severity.value
                            }
                        )
                        
                        logger.info(f"Found XSS vulnerability: {finding.parameter} - {finding.payload[:50]}")
                        
                        # 6. استغلال تلقائي (إذا كان مطلوباً)
                        if auto_exploit:
                            exploit_result = await self._exploit_vulnerability(target_url, finding)
                            if exploit_result:
                                result.exploited.append(exploit_result)
                                result.exploited_count += 1
                        
                        break  # توقف عند أول نجاح لهذا المعامل
                
                if len(all_findings) >= 10:  # حد أقصى 10 نتائج
                    break
            
            result.findings = all_findings
            result.total_requests = self._scanner._total_requests
            result.status = "completed"
            
        except Exception as e:
            logger.error(f"XSS pipeline failed: {e}")
            result.status = "failed"
            result.error = str(e)
        
        finally:
            result.end_time = datetime.now()
            await self._scanner.close()
        
        logger.info(f"XSS pipeline completed: {len(result.findings)} findings, {result.exploited_count} exploited")
        
        return result
    
    async def _exploit_vulnerability(
        self,
        target_url: str,
        finding: Finding
    ) -> Optional[Dict]:
        """
        استغلال ثغرة XSS
        
        Args:
            target_url: الرابط المستهدف
            finding: نتيجة الفحص
        
        Returns:
            نتيجة الاستغلال
        """
        # إنشاء هدف الاستغلال
        exploit_target = ExploitTarget(
            url=target_url,
            vulnerability_type="XSS",
            parameter=finding.parameter,
            method="GET"
        )
        
        # تنفيذ الاستغلال باستخدام المنسق
        result = await self._orchestrator._exploit_target(exploit_target, None)
        
        if result and result.status.value == "success":
            return {
                "parameter": finding.parameter,
                "payload": finding.payload,
                "output": result.output[:200] if result.output else "",
                "execution_time": result.execution_time
            }
        
        return None
    
    def _get_payload_from_scored(self, scored) -> Any:
        """استخراج الحمولة من الكائن المقيم"""
        from ..payloads.payload_generator import Payload
        
        if hasattr(scored, 'payload_id'):
            # إنشاء Payload من المعرف
            return Payload(
                id=scored.payload_id,
                name=scored.payload_name,
                type=PayloadType.XSS,
                payload="<script>alert('XSS')</script>",  # مؤقت
                description="XSS payload"
            )
        return scored
    
    async def get_result(self, pipeline_id: str) -> Optional[XSSPipelineResult]:
        """الحصول على نتيجة خط الأنابيب"""
        return self._active_pipelines.get(pipeline_id)
    
    async def get_summary(self) -> Dict:
        """ملخص خطوط الأنابيب النشطة"""
        return {
            "active_pipelines": len(self._active_pipelines),
            "completed": sum(1 for r in self._active_pipelines.values() if r.status == "completed"),
            "failed": sum(1 for r in self._active_pipelines.values() if r.status == "failed"),
            "total_findings": sum(r.total_findings for r in self._active_pipelines.values()),
            "total_exploited": sum(r.exploited_count for r in self._active_pipelines.values())
        }
    
    async def close(self):
        """إغلاق الخط الأنابيب"""
        await self._scanner.close()
        logger.info("XSSPipeline closed")


# نسخة عالمية
async def get_xss_pipeline() -> XSSPipeline:
    """الحصول على نسخة من خط أنابيب XSS"""
    return XSSPipeline()

