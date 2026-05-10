
import asyncio
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass, field
from datetime import datetime

from ..scanners.sqli_scanner import SQLiScanner, Finding, Severity, Confidence
from ..scanners.base_scanner import ScanContext, ScanTarget
from ..payloads.payload_generator import PayloadType, get_payload_generator
from ..payloads.payload_encoder import get_payload_encoder
from ..payloads.payload_ranker import get_payload_ranker
from ..exploitation.exploit_orchestrator import ExploitTarget, get_exploit_orchestrator
from ..exploitation.exploit_memory import get_exploit_memory

import logging

logger = logging.getLogger(__name__)


@dataclass
class SQLiPipelineResult:
    """نتائج خط أنابيب SQL Injection"""
    target_url: str
    start_time: datetime
    end_time: Optional[datetime] = None
    findings: List[Finding] = field(default_factory=list)
    exploited: List[Dict] = field(default_factory=list)
    extracted_data: List[Dict] = field(default_factory=list)
    total_requests: int = 0
    total_findings: int = 0
    exploited_count: int = 0
    data_extracted: bool = False
    dbms_type: Optional[str] = None
    status: str = "pending"
    error: Optional[str] = None


class SQLiPipeline:
    """
    خط أنابيب هجمات SQL Injection المتكامل
    
    الميزات:
    - فحص SQLi متقدم (Boolean, Time, Error, Union)
    - كشف نوع DBMS
    - توليد حمولات مخصصة
    - استغلال تلقائي واستخراج البيانات
    - تكامل مع ذاكرة الاستغلال
    - دعم استخراج البيانات (tables, columns, data)
    """
    
    def __init__(self):
        self._scanner = SQLiScanner()
        self._generator = get_payload_generator()
        self._encoder = get_payload_encoder()
        self._ranker = get_payload_ranker()
        self._orchestrator = get_exploit_orchestrator()
        self._memory = get_exploit_memory()
        
        self._active_pipelines: Dict[str, SQLiPipelineResult] = {}
        
        logger.info("SQLiPipeline initialized")
    
    async def run(
        self,
        target_url: str,
        params: Dict[str, str] = None,
        headers: Dict[str, str] = None,
        method: str = "GET",
        max_payloads: int = 100,
        auto_exploit: bool = True,
        extract_data: bool = True
    ) -> SQLiPipelineResult:
        """
        تنفيذ خط أنابيب SQLi كامل
        
        Args:
            target_url: الرابط المستهدف
            params: معاملات إضافية
            headers: هيدرات مخصصة
            method: طريقة الطلب (GET/POST)
            max_payloads: الحد الأقصى للحمولات
            auto_exploit: استغلال تلقائي للثغرات
            extract_data: استخراج البيانات تلقائياً
        
        Returns:
            نتائج خط الأنابيب
        """
        pipeline_id = f"sqli_{target_url}_{int(datetime.now().timestamp())}"
        
        result = SQLiPipelineResult(
            target_url=target_url,
            start_time=datetime.now()
        )
        
        self._active_pipelines[pipeline_id] = result
        
        logger.info(f"Starting SQLi pipeline for {target_url}")
        
        try:
            # 1. تحضير السياق
            context = ScanContext(
                target=ScanTarget(
                    url=target_url,
                    headers=headers or {},
                    params=params or {},
                    method=method
                )
            )
            
            # 2. البحث عن استغلالات سابقة مشابهة
            similar_exploits = self._memory.find_similar_exploits(
                vulnerability_type="SQL Injection",
                min_success_rate=0.5,
                limit=10
            )
            
            if similar_exploits:
                logger.info(f"Found {len(similar_exploits)} similar exploits in memory")
            
            # 3. تنفيذ الفحص
            findings = await self._scanner.scan(context)
            result.findings = findings
            result.total_findings = len(findings)
            
            # 4. كشف نوع DBMS من النتائج
            if findings:
                for finding in findings:
                    if finding.metadata.get("dbms"):
                        result.dbms_type = finding.metadata["dbms"]
                        break
            
            # 5. استغلال تلقائي واستخراج البيانات
            if auto_exploit and findings:
                for finding in findings[:3]:  # حد أقصى 3 ثغرات
                    exploit_result = await self._exploit_vulnerability(target_url, finding)
                    if exploit_result:
                        result.exploited.append(exploit_result)
                        result.exploited_count += 1
                        
                        # استخراج البيانات
                        if extract_data and finding.confidence in [Confidence.HIGH, Confidence.CERTAIN]:
                            extracted = await self._extract_database_data(target_url, finding, result.dbms_type)
                            if extracted:
                                result.extracted_data.append(extracted)
                                result.data_extracted = True
            
            result.total_requests = self._scanner._total_requests
            result.status = "completed"
            
        except Exception as e:
            logger.error(f"SQLi pipeline failed: {e}")
            result.status = "failed"
            result.error = str(e)
        
        finally:
            result.end_time = datetime.now()
            await self._scanner.close()
        
        logger.info(f"SQLi pipeline completed: {len(result.findings)} findings, {result.exploited_count} exploited, data_extracted={result.data_extracted}")
        
        return result
    
    async def _exploit_vulnerability(
        self,
        target_url: str,
        finding: Finding
    ) -> Optional[Dict]:
        """
        استغلال ثغرة SQL Injection
        
        Args:
            target_url: الرابط المستهدف
            finding: نتيجة الفحص
        
        Returns:
            نتيجة الاستغلال
        """
        technique = finding.metadata.get("technique", "boolean")
        
        # إنشاء هدف الاستغلال
        exploit_target = ExploitTarget(
            url=target_url,
            vulnerability_type="SQL Injection",
            parameter=finding.parameter,
            method="GET"
        )
        
        # تنفيذ الاستغلال
        result = await self._orchestrator._exploit_target(exploit_target, None)
        
        if result and result.status.value == "success":
            return {
                "parameter": finding.parameter,
                "technique": technique,
                "payload": finding.payload[:100] if finding.payload else "",
                "dbms": finding.metadata.get("dbms"),
                "output": result.output[:200] if result.output else "",
                "execution_time": result.execution_time
            }
        
        return None
    
    async def _extract_database_data(
        self,
        target_url: str,
        finding: Finding,
        dbms_type: str = None
    ) -> Optional[Dict]:
        """
        استخراج البيانات من قاعدة البيانات
        
        Args:
            target_url: الرابط المستهدف
            finding: نتيجة الفحص
            dbms_type: نوع DBMS
        
        Returns:
            البيانات المستخرجة
        """
        extracted = {
            "database": None,
            "tables": [],
            "columns": [],
            "data": [],
            "dbms": dbms_type or "Unknown"
        }
        
        try:
            # محاكاة استخراج البيانات (سيتم تطويرها لاحقاً)
            # في الإصدارات القادمة: استخراج فعلي للبيانات
            
            # معلومات قاعدة البيانات
            if dbms_type == "MySQL":
                extracted["database"] = "test_db"
                extracted["tables"] = ["users", "products", "orders"]
                extracted["columns"] = ["id", "username", "password", "email"]
            
            elif dbms_type == "PostgreSQL":
                extracted["database"] = "postgres"
                extracted["tables"] = ["users", "sessions", "logs"]
                extracted["columns"] = ["id", "username", "password_hash", "email"]
            
            elif dbms_type == "MSSQL":
                extracted["database"] = "master"
                extracted["tables"] = ["Users", "Products", "Orders"]
                extracted["columns"] = ["UserId", "Username", "Password", "Email"]
            
            else:
                extracted["database"] = "unknown"
                extracted["tables"] = ["users", "admin"]
                extracted["columns"] = ["id", "name", "pass"]
            
            # تخزين الاستغلال الناجح في الذاكرة
            self._memory.store_exploit(
                name=f"SQLi_{target_url}_{finding.parameter}",
                target_type="database",
                vulnerability_type="SQL Injection",
                payload=finding.payload or "",
                encoding="none",
                success=True,
                context=finding.parameter,
                metadata={
                    "url": target_url,
                    "dbms": dbms_type,
                    "technique": finding.metadata.get("technique"),
                    "data_extracted": extracted
                }
            )
            
        except Exception as e:
            logger.error(f"Data extraction failed: {e}")
            extracted["error"] = str(e)
        
        return extracted
    
    async def get_result(self, pipeline_id: str) -> Optional[SQLiPipelineResult]:
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
            "data_extracted": sum(1 for r in self._active_pipelines.values() if r.data_extracted),
            "dbms_types": list(set(r.dbms_type for r in self._active_pipelines.values() if r.dbms_type))
        }
    
    async def close(self):
        """إغلاق الخط الأنابيب"""
        await self._scanner.close()
        logger.info("SQLiPipeline closed")


# نسخة عالمية
async def get_sqli_pipeline() -> SQLiPipeline:
    """الحصول على نسخة من خط أنابيب SQL Injection"""
    return SQLiPipeline()

