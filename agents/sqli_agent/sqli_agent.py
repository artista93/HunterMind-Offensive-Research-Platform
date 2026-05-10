
import asyncio
from typing import Dict, List, Optional, Any, Set, Tuple
from datetime import datetime

from ..base.base_agent import BaseAgent, AgentPriority, AgentMessage
from ..base.agent_state import AgentStateEnum
from ...offensive.scanners.sqli_scanner import SQLiScanner, Finding, Severity, Confidence
from ...offensive.scanners.base_scanner import ScanContext, ScanTarget
from ...offensive.payloads.payload_generator import get_payload_generator, PayloadType
from ...offensive.exploitation.exploit_orchestrator import ExploitTarget, get_exploit_orchestrator
from ...offensive.exploitation.exploit_memory import get_exploit_memory

import logging

logger = logging.getLogger(__name__)


class SQLiAgent(BaseAgent):
    """
    وكيل هجمات SQL Injection المتقدم
    
    الميزات:
    - فحص SQLi متقدم (Boolean, Time, Error, Union)
    - كشف نوع DBMS (MySQL, PostgreSQL, MSSQL, Oracle, SQLite)
    - استغلال تلقائي للثغرات
    - استخراج البيانات من قاعدة البيانات
    - تكامل مع ذاكرة الاستغلال
    - توليد تقارير مفصلة
    """
    
    def __init__(
        self,
        name: str = "SQLiAgent",
        priority: AgentPriority = AgentPriority.HIGH,
        rate_limit: float = 1.0,
        timeout: int = 30,
        boolean_threshold: float = 0.2,
        time_threshold: float = 4.0
    ):
        super().__init__(name, priority)
        
        self._rate_limit = rate_limit
        self._timeout = timeout
        self._boolean_threshold = boolean_threshold
        self._time_threshold = time_threshold
        
        # مكونات SQLi
        self._scanner = SQLiScanner(
            rate_limit=rate_limit,
            timeout=timeout,
            boolean_threshold=boolean_threshold,
            time_threshold=time_threshold
        )
        self._generator = get_payload_generator()
        self._orchestrator = get_exploit_orchestrator()
        self._memory = get_exploit_memory()
        
        # نتائج الفحص
        self._scan_results: Dict[str, List[Finding]] = {}
        self._active_scans: Set[str] = set()
        self._extracted_data: Dict[str, Dict] = {}
        
        logger.info(f"SQLiAgent initialized: {name}")
    
    async def _on_initialize(self):
        """تهيئة الوكيل"""
        logger.info("Initializing SQLiAgent components...")
    
    async def _on_start(self):
        """بدء تشغيل الوكيل"""
        logger.info("SQLiAgent started")
    
    async def _on_stop(self):
        """إيقاف تشغيل الوكيل"""
        # إلغاء الفحوصات النشطة
        for scan_id in list(self._active_scans):
            await self.stop_scan(scan_id)
        
        await self._scanner.close()
        logger.info("SQLiAgent stopped")
    
    async def _handle_message(self, message: AgentMessage) -> Optional[AgentMessage]:
        """
        معالجة الرسائل الواردة
        
        أنواع الرسائل المدعومة:
        - start_scan: بدء فحص SQLi
        - stop_scan: إيقاف فحص
        - get_findings: الحصول على النتائج
        - exploit_finding: استغلال ثغرة محددة
        - extract_data: استخراج البيانات
        """
        if message.type == "start_scan":
            result = await self.start_scan(message.content)
            return AgentMessage(
                id="",
                sender=self.name,
                receiver=message.sender,
                type="scan_started",
                content={"scan_id": result.get("scan_id")}
            )
        
        elif message.type == "stop_scan":
            success = await self.stop_scan(message.content.get("scan_id"))
            return AgentMessage(
                id="",
                sender=self.name,
                receiver=message.sender,
                type="scan_stopped",
                content={"success": success}
            )
        
        elif message.type == "get_findings":
            findings = await self.get_findings(message.content.get("scan_id"))
            return AgentMessage(
                id="",
                sender=self.name,
                receiver=message.sender,
                type="findings",
                content={"findings": [self._finding_to_dict(f) for f in findings]}
            )
        
        elif message.type == "exploit_finding":
            result = await self.exploit_finding(message.content)
            return AgentMessage(
                id="",
                sender=self.name,
                receiver=message.sender,
                type="exploit_result",
                content=result
            )
        
        elif message.type == "extract_data":
            result = await self.extract_database_data(message.content)
            return AgentMessage(
                id="",
                sender=self.name,
                receiver=message.sender,
                type="extracted_data",
                content=result
            )
        
        return await super()._handle_message(message)
    
    async def start_scan(
        self,
        target_url: str,
        params: Dict[str, str] = None,
        headers: Dict[str, str] = None,
        method: str = "GET",
        options: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """
        بدء فحص SQLi جديد
        
        Args:
            target_url: الرابط المستهدف
            params: معاملات إضافية
            headers: هيدرات مخصصة
            method: طريقة الطلب (GET/POST)
            options: خيارات إضافية
        
        Returns:
            معلومات الفحص
        """
        # تحديث الحالة
        self._state_manager.transition_to(
            AgentStateEnum.BUSY,
            reason=f"Starting SQLi scan of {target_url}"
        )
        
        # إنشاء معرف الفحص
        import uuid
        scan_id = str(uuid.uuid4())[:8]
        
        # إنشاء سياق الفحص
        context = ScanContext(
            target=ScanTarget(
                url=target_url,
                headers=headers or {},
                params=params or {},
                method=method
            )
        )
        
        self._active_scans.add(scan_id)
        
        try:
            # تنفيذ الفحص
            findings = await self._scanner.scan(context)
            
            # تخزين النتائج
            self._scan_results[scan_id] = findings
            
            # تحديث الإحصائيات
            self._context.tasks_completed += 1
            
            # تخزين الاستغلالات الناجحة في الذاكرة
            for finding in findings:
                if finding.confidence in [Confidence.HIGH, Confidence.CERTAIN]:
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
                            "severity": finding.severity.value,
                            "confidence": finding.confidence.value,
                            "technique": finding.metadata.get("technique", ""),
                            "dbms": finding.metadata.get("dbms", "")
                        }
                    )
            
            logger.info(f"SQLi scan completed: {target_url} - {len(findings)} findings")
            
            return {
                "scan_id": scan_id,
                "status": "completed",
                "findings_count": len(findings),
                "high_confidence": len([f for f in findings if f.confidence == Confidence.HIGH or f.confidence == Confidence.CERTAIN]),
                "url": target_url
            }
            
        except Exception as e:
            logger.error(f"SQLi scan failed: {e}")
            self._context.tasks_failed += 1
            raise
            
        finally:
            self._active_scans.discard(scan_id)
            self._state_manager.transition_to(AgentStateEnum.IDLE, reason="Scan completed")
    
    async def stop_scan(self, scan_id: str) -> bool:
        """
        إيقاف فحص قيد التنفيذ
        
        Args:
            scan_id: معرف الفحص
        
        Returns:
            نجاح الإيقاف
        """
        if scan_id not in self._active_scans:
            logger.warning(f"Scan {scan_id} not active")
            return False
        
        await self._scanner.close()
        self._active_scans.discard(scan_id)
        
        logger.info(f"Scan {scan_id} stopped")
        return True
    
    async def get_findings(self, scan_id: str = None) -> List[Finding]:
        """
        الحصول على نتائج الفحص
        
        Args:
            scan_id: معرف الفحص (آخر فحص إذا None)
        
        Returns:
            قائمة بالثغرات المكتشفة
        """
        if scan_id and scan_id in self._scan_results:
            return self._scan_results[scan_id]
        
        # آخر فحص
        if self._scan_results:
            last_id = list(self._scan_results.keys())[-1]
            return self._scan_results.get(last_id, [])
        
        return []
    
    async def exploit_finding(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        استغلال ثغرة SQLi محددة
        
        Args:
            data: معلومات الثغرة (scan_id, finding_index, إلخ)
        
        Returns:
            نتيجة الاستغلال
        """
        scan_id = data.get("scan_id")
        finding_index = data.get("finding_index", 0)
        
        findings = await self.get_findings(scan_id)
        
        if not findings or finding_index >= len(findings):
            return {"success": False, "error": "Finding not found"}
        
        finding = findings[finding_index]
        
        # إنشاء هدف الاستغلال
        exploit_target = ExploitTarget(
            url=finding.url,
            vulnerability_type="SQL Injection",
            parameter=finding.parameter,
            method="GET"
        )
        
        # تنفيذ الاستغلال
        result = await self._orchestrator._exploit_target(exploit_target, None)
        
        if result and result.status.value == "success":
            return {
                "success": True,
                "url": finding.url,
                "parameter": finding.parameter,
                "technique": finding.metadata.get("technique", ""),
                "dbms": finding.metadata.get("dbms", ""),
                "payload": finding.payload[:100] if finding.payload else "",
                "output": result.output[:500] if result.output else "",
                "execution_time": result.execution_time
            }
        
        return {"success": False, "error": "Exploitation failed"}
    
    async def extract_database_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        استخراج البيانات من قاعدة البيانات
        
        Args:
            data: معلومات الثغرة (scan_id, finding_index, إلخ)
        
        Returns:
            البيانات المستخرجة
        """
        scan_id = data.get("scan_id")
        finding_index = data.get("finding_index", 0)
        
        findings = await self.get_findings(scan_id)
        
        if not findings or finding_index >= len(findings):
            return {"success": False, "error": "Finding not found"}
        
        finding = findings[finding_index]
        dbms = finding.metadata.get("dbms", "Unknown")
        
        # محاكاة استخراج البيانات (سيتم تطويرها لاحقاً)
        extracted = {
            "success": True,
            "dbms": dbms,
            "database": "target_db",
            "tables": ["users", "products", "orders"],
            "columns": ["id", "username", "password", "email"],
            "sample_data": [
                {"id": 1, "username": "admin", "password": "***", "email": "admin@example.com"},
                {"id": 2, "username": "user", "password": "***", "email": "user@example.com"}
            ]
        }
        
        # تخزين البيانات المستخرجة
        extraction_key = f"{scan_id}_{finding_index}"
        self._extracted_data[extraction_key] = extracted
        
        return extracted
    
    async def get_dbms_type(self, scan_id: str = None) -> Optional[str]:
        """
        الحصول على نوع DBMS من نتائج الفحص
        
        Args:
            scan_id: معرف الفحص
        
        Returns:
            نوع DBMS أو None
        """
        findings = await self.get_findings(scan_id)
        
        for finding in findings:
            if finding.metadata.get("dbms"):
                return finding.metadata["dbms"]
        
        return None
    
    async def generate_report(self, scan_id: str = None, format: str = "json") -> str:
        """
        توليد تقرير عن نتائج الفحص
        
        Args:
            scan_id: معرف الفحص
            format: صيغة التقرير (json, markdown)
        
        Returns:
            التقرير كنص
        """
        findings = await self.get_findings(scan_id)
        
        if format == "json":
            import json
            return json.dumps({
                "scan_id": scan_id or "latest",
                "timestamp": datetime.now().isoformat(),
                "total_findings": len(findings),
                "findings": [self._finding_to_dict(f) for f in findings]
            }, indent=2)
        
        elif format == "markdown":
            report = f"""# SQL Injection Scan Report

**Scan ID:** {scan_id or 'latest'}
**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**Total Findings:** {len(findings)}

## Findings

"""
            for i, finding in enumerate(findings, 1):
                report += f"### {i}. {finding.vulnerability_type}\n"
                report += f"- **Severity:** {finding.severity.value}\n"
                report += f"- **Confidence:** {finding.confidence.value}\n"
                report += f"- **URL:** {finding.url}\n"
                report += f"- **Parameter:** {finding.parameter}\n"
                report += f"- **Technique:** {finding.metadata.get('technique', 'unknown')}\n"
                report += f"- **DBMS:** {finding.metadata.get('dbms', 'unknown')}\n"
                if finding.payload:
                    report += f"- **Payload:** `{finding.payload[:100]}`\n"
                report += f"- **Description:** {finding.description}\n"
                report += f"- **Remediation:** {finding.remediation}\n\n"
            
            return report
        
        return "Unsupported format"
    
    def _finding_to_dict(self, finding: Finding) -> Dict:
        """تحويل Finding إلى قاموس"""
        return {
            "type": finding.vulnerability_type,
            "severity": finding.severity.value,
            "confidence": finding.confidence.value,
            "url": finding.url,
            "parameter": finding.parameter,
            "payload": finding.payload,
            "evidence": finding.evidence,
            "technique": finding.metadata.get("technique", ""),
            "dbms": finding.metadata.get("dbms", ""),
            "description": finding.description,
            "remediation": finding.remediation,
            "cvss_score": finding.cvss_score
        }
    
    async def get_summary(self) -> Dict:
        """ملخص الفحوصات"""
        return {
            "total_scans": len(self._scan_results),
            "active_scans": len(self._active_scans),
            "total_findings": sum(len(f) for f in self._scan_results.values()),
            "high_confidence_findings": sum(
                1 for findings in self._scan_results.values()
                for f in findings
                if f.confidence in [Confidence.HIGH, Confidence.CERTAIN]
            ),
            "targets_scanned": list(self._scan_results.keys()),
            "extracted_data_count": len(self._extracted_data)
        }
    
    async def get_statistics(self) -> Dict:
        """إحصائيات الوكيل"""
        base_stats = await super().get_statistics()
        
        return {
            **base_stats,
            "sqli_specific": await self.get_summary()
        }
    
    async def clear_results(self):
        """مسح جميع نتائج الفحص"""
        self._scan_results.clear()
        self._extracted_data.clear()
        logger.info("All SQLi scan results cleared")


# نسخة عالمية
_default_sqli_agent = None


async def get_sqli_agent() -> SQLiAgent:
    """الحصول على نسخة من وكيل SQL Injection"""
    global _default_sqli_agent
    if _default_sqli_agent is None:
        _default_sqli_agent = SQLiAgent()
        await _default_sqli_agent.initialize()
        await _default_sqli_agent.start()
    return _default_sqli_agent

