
import numpy as np
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from collections import defaultdict

import logging

logger = logging.getLogger(__name__)


@dataclass
class FailureIncident:
    """حادثة فشل"""
    id: str
    timestamp: datetime
    failure_type: str
    context: Dict[str, Any]
    root_cause: Optional[str] = None
    resolved: bool = False
    resolution: Optional[str] = None


class FailureAnalyzer:
    """
    محلل الفشل المتقدم
    
    الميزات:
    - تحليل أسباب الفشل في الوقت الفعلي
    - اكتشاف أنماط الفشل المتكررة
    - اقتراح إجراءات تصحيحية
    - تتبع معدلات الفشل
    """
    
    def __init__(self):
        self.failures: List[FailureIncident] = []
        self.failure_patterns: Dict[str, int] = defaultdict(int)
        self.corrections: Dict[str, List[str]] = {}
        
        # تهيئة الإجراءات التصحيحية
        self._init_corrections()
        
        logger.info("FailureAnalyzer initialized")
    
    def _init_corrections(self):
        """تهيئة الإجراءات التصحيحية"""
        
        self.corrections = {
            "timeout": [
                "Increase timeout value",
                "Optimize request processing",
                "Implement retry mechanism"
            ],
            "connection_error": [
                "Check network connectivity",
                "Use connection pooling",
                "Implement automatic reconnection"
            ],
            "parsing_error": [
                "Improve error handling",
                "Validate response format",
                "Add fallback parser"
            ],
            "rate_limit": [
                "Reduce request rate",
                "Implement exponential backoff",
                "Use proxy rotation"
            ],
            "authentication_error": [
                "Refresh authentication token",
                "Check credentials",
                "Implement token renewal"
            ]
        }
    
    async def report_failure(
        self,
        failure_type: str,
        context: Dict[str, Any],
        root_cause: str = None
    ) -> str:
        """
        الإبلاغ عن فشل جديد
        
        Args:
            failure_type: نوع الفشل
            context: سياق الفشل
            root_cause: السبب الجذري (اختياري)
        
        Returns:
            معرف حادثة الفشل
        """
        import uuid
        incident_id = str(uuid.uuid4())[:8]
        
        incident = FailureIncident(
            id=incident_id,
            timestamp=datetime.now(),
            failure_type=failure_type,
            context=context,
            root_cause=root_cause
        )
        
        self.failures.append(incident)
        self.failure_patterns[failure_type] += 1
        
        logger.warning(f"Failure reported: {failure_type} ({incident_id})")
        return incident_id
    
    async def analyze_patterns(self) -> Dict[str, Any]:
        """
        تحليل أنماط الفشل
        
        Returns:
            تحليل الأنماط
        """
        if not self.failures:
            return {"has_data": False}
        
        total = len(self.failures)
        
        # أكثر أنواع الفشل شيوعاً
        most_common = max(self.failure_patterns.items(), key=lambda x: x[1])[0] if self.failure_patterns else None
        
        # اتجاه الفشل
        recent = len([f for f in self.failures if (datetime.now() - f.timestamp).seconds < 3600])
        
        return {
            "has_data": True,
            "total_failures": total,
            "failure_types": dict(self.failure_patterns),
            "most_common_failure": most_common,
            "recent_failures": recent,
            "failure_rate": len(self.failures) / max(1, total) * 100
        }
    
    async def suggest_correction(self, failure_type: str) -> List[str]:
        """
        اقتراح إجراءات تصحيحية لنوع فشل معين
        
        Args:
            failure_type: نوع الفشل
        
        Returns:
            قائمة بالإجراءات المقترحة
        """
        if failure_type in self.corrections:
            return self.corrections[failure_type]
        
        # إجراءات عامة
        return [
            "Investigate root cause",
            "Check system logs",
            "Implement monitoring",
            "Review error handling"
        ]
    
    async def mark_resolved(self, incident_id: str, resolution: str) -> bool:
        """
        تعليم حادثة فشل كـ"تم حلها"
        
        Args:
            incident_id: معرف الحادثة
            resolution: وصف الحل
        
        Returns:
            نجاح العملية
        """
        for incident in self.failures:
            if incident.id == incident_id:
                incident.resolved = True
                incident.resolution = resolution
                logger.info(f"Failure {incident_id} marked as resolved")
                return True
        
        return False
    
    async def get_unresolved_failures(self) -> List[FailureIncident]:
        """الحصول على حوادث الفشل غير المحلولة"""
        return [f for f in self.failures if not f.resolved]
    
    async def get_statistics(self) -> Dict:
        """إحصائيات المحلل"""
        total = len(self.failures)
        resolved = len([f for f in self.failures if f.resolved])
        
        return {
            "total_failures": total,
            "resolved_failures": resolved,
            "resolution_rate": resolved / total if total > 0 else 0,
            "failure_patterns": dict(self.failure_patterns),
            "unresolved_count": len(await self.get_unresolved_failures()),
            "available_corrections": len(self.corrections)
        }

