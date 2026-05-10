
import asyncio
import re
from typing import Dict, List, Optional, Any, Set, Tuple
from datetime import datetime

from ..base.base_agent import BaseAgent, AgentPriority, AgentMessage
from ..base.agent_state import AgentStateEnum
from ...offensive.scanners.idor_scanner import IDORScanner, Finding, Severity, Confidence
from ...offensive.scanners.base_scanner import ScanContext, ScanTarget
from ...offensive.exploitation.exploit_orchestrator import ExploitTarget, get_exploit_orchestrator
from ...offensive.exploitation.exploit_memory import get_exploit_memory

import logging

logger = logging.getLogger(__name__)


class IDORAgent(BaseAgent):
    """
    وكيل هجمات IDOR المتقدم
    
    الميزات:
    - فحص IDOR متقدم لكشف المعرفات القابلة للتخمين
    - اختبار الوصول الأفقي والعمودي
    - استغلال تلقائي للثغرات
    - كشف البيانات الحساسة
    - تكامل مع ذاكرة الاستغلال
    - توليد تقارير مفصلة
    """
    
    def __init__(
        self,
        name: str = "IDORAgent",
        priority: AgentPriority = AgentPriority.HIGH,
        rate_limit: float = 2.0,
        timeout: int = 30,
        test_increment: bool = True,
        test_decrement: bool = True
    ):
        super().__init__(name, priority)
        
        self._rate_limit = rate_limit
        self._timeout = timeout
        self._test_increment = test_increment
        self._test_decrement = test_decrement
        
        # مكونات IDOR
        self._scanner = IDORScanner(
            rate_limit=rate_limit,
            timeout=timeout,
            test_increment=test_increment,
            test_decrement=test_decrement
        )
        self._orchestrator = get_exploit_orchestrator()
        self._memory = get_exploit_memory()
        
        # نتائج الفحص
        self._scan_results: Dict[str, List[Finding]] = {}
        self._active_scans: Set[str] = set()
        self._accessed_resources: Dict[str, List[Dict]] = {}
        
        logger.info(f"IDORAgent initialized: {name}")
    
    async def _on_initialize(self):
        """تهيئة الوكيل"""
        logger.info("Initializing IDORAgent components...")
    
    async def _on_start(self):
        """بدء تشغيل الوكيل"""
        logger.info("IDORAgent started")
    
    async def _on_stop(self):
        """إيقاف تشغيل الوكيل"""
        # إلغاء الفحوصات النشطة
        for scan_id in list(self._active_scans):
            await self.stop_scan(scan_id)
        
        await self._scanner.close()
        logger.info("IDORAgent stopped")
    
    async def _handle_message(self, message: AgentMessage) -> Optional[AgentMessage]:
        """
        معالجة الرسائل الواردة
        
        أنواع الرسائل المدعومة:
        - start_scan: بدء فحص IDOR
        - stop_scan: إيقاف فحص
        - get_findings: الحصول على النتائج
        - exploit_finding: استغلال ثغرة محددة
        - get_accessed_resources: الحصول على الموارد التي تم الوصول إليها
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
        
        elif message.type == "get_accessed_resources":
            resources = await self.get_accessed_resources(message.content.get("scan_id"))
            return AgentMessage(
                id="",
                sender=self.name,
                receiver=message.sender,
                type="accessed_resources",
                content={"resources": resources}
            )
        
        return await super()._handle_message(message)
    
    async def start_scan(
        self,
        target_url: str,
        params: Dict[str, str] = None,
        headers: Dict[str, str] = None,
        cookies: Dict[str, str] = None,
        options: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """
        بدء فحص IDOR جديد
        
        Args:
            target_url: الرابط المستهدف
            params: معاملات إضافية
            headers: هيدرات مخصصة
            cookies: كوكيز للمصادقة
            options: خيارات إضافية
        
        Returns:
            معلومات الفحص
        """
        # تحديث الحالة
        self._state_manager.transition_to(
            AgentStateEnum.BUSY,
            reason=f"Starting IDOR scan of {target_url}"
        )
        
        # إنشاء معرف الفحص
        import uuid
        scan_id = str(uuid.uuid4())[:8]
        
        # تحديث الخيارات
        max_ids_to_test = options.get("max_ids_to_test", 20) if options else 20
        
        # إنشاء سياق الفحص
        context = ScanContext(
            target=ScanTarget(
                url=target_url,
                headers=headers or {},
                params=params or {},
                cookies=cookies or {}
            )
        )
        
        # تحديث إعدادات الماسح
        self._scanner._max_ids_to_test = max_ids_to_test
        
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
                        name=f"IDOR_{target_url}_{finding.parameter}",
                        target_type="web_api",
                        vulnerability_type="IDOR",
                        payload=finding.payload or "",
                        encoding="none",
                        success=True,
                        context=finding.parameter,
                        metadata={
                            "url": target_url,
                            "severity": finding.severity.value,
                            "confidence": finding.confidence.value,
                            "original_id": finding.metadata.get("original_id", ""),
                            "modified_id": finding.metadata.get("modified_id", "")
                        }
                    )
            
            logger.info(f"IDOR scan completed: {target_url} - {len(findings)} findings")
            
            return {
                "scan_id": scan_id,
                "status": "completed",
                "findings_count": len(findings),
                "high_confidence": len([f for f in findings if f.confidence == Confidence.HIGH or f.confidence == Confidence.CERTAIN]),
                "url": target_url
            }
            
        except Exception as e:
            logger.error(f"IDOR scan failed: {e}")
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
        استغلال ثغرة IDOR محددة
        
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
        
        # استخراج المعرفات من الأدلة
        evidence = finding.evidence or ""
        original_id = None
        modified_id = None
        
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
            # تسجيل المورد الذي تم الوصول إليه
            if scan_id not in self._accessed_resources:
                self._accessed_resources[scan_id] = []
            
            self._accessed_resources[scan_id].append({
                "url": finding.url,
                "parameter": finding.parameter,
                "original_id": original_id,
                "modified_id": modified_id,
                "response_preview": result.output[:500] if result.output else "",
                "timestamp": datetime.now().isoformat()
            })
            
            return {
                "success": True,
                "url": finding.url,
                "parameter": finding.parameter,
                "original_id": original_id,
                "modified_id": modified_id,
                "response_preview": result.output[:500] if result.output else "",
                "execution_time": result.execution_time
            }
        
        return {"success": False, "error": "Exploitation failed"}
    
    async def get_accessed_resources(self, scan_id: str = None) -> List[Dict]:
        """
        الحصول على الموارد التي تم الوصول إليها
        
        Args:
            scan_id: معرف الفحص
        
        Returns:
            قائمة بالموارد
        """
        if scan_id:
            return self._accessed_resources.get(scan_id, [])
        
        # جميع الموارد من جميع الفحوصات
        all_resources = []
        for resources in self._accessed_resources.values():
            all_resources.extend(resources)
        return all_resources
    
    async def extract_ids_from_url(self, url: str) -> List[str]:
        """
        استخراج المعرفات من URL
        
        Args:
            url: الرابط
        
        Returns:
            قائمة المعرفات
        """
        ids = []
        
        # أرقام
        numbers = re.findall(r'\b\d{3,}\b', url)
        ids.extend(numbers)
        
        # UUIDs
        uuids = re.findall(r'\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b', url, re.I)
        ids.extend(uuids)
        
        return ids
    
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
        resources = await self.get_accessed_resources(scan_id)
        
        if format == "json":
            import json
            return json.dumps({
                "scan_id": scan_id or "latest",
                "timestamp": datetime.now().isoformat(),
                "total_findings": len(findings),
                "findings": [self._finding_to_dict(f) for f in findings],
                "accessed_resources": resources
            }, indent=2)
        
        elif format == "markdown":
            report = f"""# IDOR Scan Report

**Scan ID:** {scan_id or 'latest'}
**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**Total Findings:** {len(findings)}
**Resources Accessed:** {len(resources)}

## Findings

"""
            for i, finding in enumerate(findings, 1):
                report += f"### {i}. {finding.vulnerability_type}\n"
                report += f"- **Severity:** {finding.severity.value}\n"
                report += f"- **Confidence:** {finding.confidence.value}\n"
                report += f"- **URL:** {finding.url}\n"
                report += f"- **Parameter:** {finding.parameter}\n"
                if finding.payload:
                    report += f"- **Payload:** `{finding.payload[:100]}`\n"
                report += f"- **Description:** {finding.description}\n"
                report += f"- **Remediation:** {finding.remediation}\n\n"
            
            if resources:
                report += "## Accessed Resources\n\n"
                for resource in resources[:20]:
                    report += f"- **URL:** {resource['url']}\n"
                    report += f"  - Parameter: {resource['parameter']}\n"
                    report += f"  - Modified ID: {resource['modified_id']}\n\n"
            
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
            "original_id": finding.metadata.get("original_id", ""),
            "modified_id": finding.metadata.get("modified_id", ""),
            "description": finding.description,
            "remediation": finding.remediation,
            "cvss_score": finding.cvss_score
        }
    
    async def get_summary(self) -> Dict:
        """ملخص الفحوصات"""
        total_accessed = sum(len(r) for r in self._accessed_resources.values())
        
        return {
            "total_scans": len(self._scan_results),
            "active_scans": len(self._active_scans),
            "total_findings": sum(len(f) for f in self._scan_results.values()),
            "high_confidence_findings": sum(
                1 for findings in self._scan_results.values()
                for f in findings
                if f.confidence in [Confidence.HIGH, Confidence.CERTAIN]
            ),
            "total_accessed_resources": total_accessed,
            "targets_scanned": list(self._scan_results.keys())
        }
    
    async def get_statistics(self) -> Dict:
        """إحصائيات الوكيل"""
        base_stats = await super().get_statistics()
        
        return {
            **base_stats,
            "idor_specific": await self.get_summary()
        }
    
    async def clear_results(self):
        """مسح جميع نتائج الفحص"""
        self._scan_results.clear()
        self._accessed_resources.clear()
        logger.info("All IDOR scan results cleared")


# نسخة عالمية
_default_idor_agent = None


async def get_idor_agent() -> IDORAgent:
    """الحصول على نسخة من وكيل IDOR"""
    global _default_idor_agent
    if _default_idor_agent is None:
        _default_idor_agent = IDORAgent()
        await _default_idor_agent.initialize()
        await _default_idor_agent.start()
    return _default_idor_agent

