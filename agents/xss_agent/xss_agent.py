
import asyncio
from typing import Dict, List, Optional, Any, Set, Tuple
from datetime import datetime

from ..base.base_agent import BaseAgent, AgentPriority, AgentMessage
from ..base.agent_state import AgentStateEnum
from offensive.scanners.xss_scanner import XSSScanner, Finding, Severity, Confidence
from offensive.scanners.base_scanner import ScanContext, ScanTarget
from offensive.payloads.payload_generator import get_payload_generator, PayloadType
from offensive.payloads.payload_encoder import get_payload_encoder
from offensive.payloads.payload_ranker import get_payload_ranker
from offensive.exploitation.exploit_orchestrator import ExploitTarget, get_exploit_orchestrator
from offensive.exploitation.exploit_memory import get_exploit_memory

import logging

logger = logging.getLogger(__name__)


class XSSAgent(BaseAgent):
    """
    وكيل هجمات XSS المتقدم
    
    الميزات:
    - فحص XSS متقدم مع 20+ حمولة
    - تحليل سياق التنفيذ
    - استغلال تلقائي للثغرات
    - تكامل مع ذاكرة الاستغلال
    - توليد حمولات مخصصة
    - تقارير مفصلة
    """
    
    def __init__(
        self,
        name: str = "XSSAgent",
        priority: AgentPriority = AgentPriority.HIGH,
        rate_limit: float = 2.0,
        timeout: int = 30
    ):
        super().__init__(name, priority)
        
        self._rate_limit = rate_limit
        self._timeout = timeout
        
        # مكونات XSS
        self._scanner = XSSScanner(rate_limit=rate_limit, timeout=timeout)
        self._generator = get_payload_generator()
        self._encoder = get_payload_encoder()
        self._ranker = get_payload_ranker()
        self._orchestrator = get_exploit_orchestrator()
        self._memory = get_exploit_memory()
        
        # نتائج الفحص
        self._scan_results: Dict[str, List[Finding]] = {}
        self._active_scans: Set[str] = set()
        
        logger.info(f"XSSAgent initialized: {name}")
    
    async def _on_initialize(self):
        """تهيئة الوكيل"""
        logger.info("Initializing XSSAgent components...")
    
    async def _on_start(self):
        """بدء تشغيل الوكيل"""
        logger.info("XSSAgent started")
    
    async def _on_stop(self):
        """إيقاف تشغيل الوكيل"""
        # إلغاء الفحوصات النشطة
        for scan_id in list(self._active_scans):
            await self.stop_scan(scan_id)
        
        await self._scanner.close()
        logger.info("XSSAgent stopped")
    
    async def _handle_message(self, message: AgentMessage) -> Optional[AgentMessage]:
        """
        معالجة الرسائل الواردة
        
        أنواع الرسائل المدعومة:
        - start_scan: بدء فحص XSS
        - stop_scan: إيقاف فحص
        - get_findings: الحصول على النتائج
        - exploit_finding: استغلال ثغرة محددة
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
        
        return await super()._handle_message(message)
    
    async def start_scan(
        self,
        target_url: str,
        params: Dict[str, str] = None,
        headers: Dict[str, str] = None,
        options: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """
        بدء فحص XSS جديد
        
        Args:
            target_url: الرابط المستهدف
            params: معاملات إضافية
            headers: هيدرات مخصصة
            options: خيارات إضافية (max_payloads, إلخ)
        
        Returns:
            معلومات الفحص
        """
        # تحديث الحالة
        self._state_manager.transition_to(
            AgentStateEnum.BUSY,
            reason=f"Starting XSS scan of {target_url}"
        )
        
        # إنشاء معرف الفحص
        import uuid
        scan_id = str(uuid.uuid4())[:8]
        
        # تحديث الخيارات
        max_payloads = options.get("max_payloads", 100) if options else 100
        
        # إنشاء سياق الفحص
        context = ScanContext(
            target=ScanTarget(
                url=target_url,
                headers=headers or {},
                params=params or {}
            )
        )
        
        self._active_scans.add(scan_id)
        
        try:
            # تنفيذ الفحص
            findings = await self._scanner.execute_scan(context)
            
            # تخزين النتائج
            self._scan_results[scan_id] = findings
            
            # تحديث الإحصائيات
            self._context.tasks_completed += 1
            
            # تخزين الاستغلالات الناجحة في الذاكرة
            for finding in findings:
                if finding.confidence in [Confidence.HIGH, Confidence.CERTAIN]:
                    self._memory.store_exploit(
                        name=f"XSS_{target_url}_{finding.parameter}",
                        target_type="web",
                        vulnerability_type="XSS",
                        payload=finding.payload or "",
                        encoding="none",
                        success=True,
                        context=finding.parameter,
                        metadata={
                            "url": target_url,
                            "severity": finding.severity.value,
                            "confidence": finding.confidence.value
                        }
                    )
            
            logger.info(f"XSS scan completed: {target_url} - {len(findings)} findings")
            
            return {
                "scan_id": scan_id,
                "status": "completed",
                "findings_count": len(findings),
                "high_confidence": len([f for f in findings if f.confidence == Confidence.HIGH or f.confidence == Confidence.CERTAIN]),
                "url": target_url
            }
            
        except Exception as e:
            logger.error(f"XSS scan failed: {e}")
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
        استغلال ثغرة XSS محددة
        
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
            vulnerability_type="XSS",
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
                "payload": finding.payload,
                "output": result.output[:500] if result.output else "",
                "execution_time": result.execution_time
            }
        
        return {"success": False, "error": "Exploitation failed"}
    
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
            report = f"""# XSS Scan Report

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
            "targets_scanned": list(self._scan_results.keys())
        }
    
    async def get_statistics(self) -> Dict:
        """إحصائيات الوكيل"""
        base_stats = await super().get_statistics()
        
        return {
            **base_stats,
            "xss_specific": await self.get_summary()
        }
    
    async def clear_results(self):
        """مسح جميع نتائج الفحص"""
        self._scan_results.clear()
        logger.info("All XSS scan results cleared")


# نسخة عالمية
_default_xss_agent = None


async def get_xss_agent() -> XSSAgent:
    """الحصول على نسخة من وكيل XSS"""
    global _default_xss_agent
    if _default_xss_agent is None:
        _default_xss_agent = XSSAgent()
        await _default_xss_agent.initialize()
        await _default_xss_agent.start()
    return _default_xss_agent

