
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from collections import defaultdict

import logging

logger = logging.getLogger(__name__)


@dataclass
class FailureRecord:
    """سجل فشل"""
    id: str
    failure_type: str
    description: str
    timestamp: datetime
    severity: str  # critical, high, medium, low
    root_cause: Optional[str] = None
    lessons: List[str] = field(default_factory=list)
    resolved: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class FailurePattern:
    """نمط فشل متكرر"""
    pattern: str
    count: int
    severity: str
    common_causes: List[str]
    recommendations: List[str]
    last_seen: datetime


class FailureAnalysis:
    """
    تحليل الفشل المتقدم
    
    الميزات:
    - تسجيل حالات الفشل
    - تحليل الأسباب الجذرية
    - اكتشاف أنماط الفشل المتكررة
    - اقتراح إجراءات وقائية
    """
    
    def __init__(self):
        self._failures: List[FailureRecord] = []
        self._patterns: Dict[str, FailurePattern] = {}
        
        logger.info("FailureAnalysis initialized")
    
    async def record_failure(
        self,
        failure_type: str,
        description: str,
        severity: str,
        root_cause: str = None,
        metadata: Dict = None
    ) -> str:
        """
        تسجيل حالة فشل جديدة
        
        Args:
            failure_type: نوع الفشل
            description: وصف الفشل
            severity: شدة الفشل
            root_cause: السبب الجذري (اختياري)
            metadata: بيانات إضافية
        
        Returns:
            معرف سجل الفشل
        """
        import uuid
        failure_id = str(uuid.uuid4())[:8]
        
        failure = FailureRecord(
            id=failure_id,
            failure_type=failure_type,
            description=description,
            timestamp=datetime.now(),
            severity=severity,
            root_cause=root_cause,
            metadata=metadata or {}
        )
        
        self._failures.append(failure)
        
        # تحديث أنماط الفشل
        await self._update_patterns(failure)
        
        logger.warning(f"Failure recorded: {failure_type} ({severity})")
        return failure_id
    
    async def _update_patterns(self, failure: FailureRecord):
        """تحديث أنماط الفشل"""
        pattern_key = failure.failure_type
        
        if pattern_key in self._patterns:
            pattern = self._patterns[pattern_key]
            pattern.count += 1
            pattern.last_seen = failure.timestamp
            
            if failure.root_cause and failure.root_cause not in pattern.common_causes:
                pattern.common_causes.append(failure.root_cause)
        else:
            pattern = FailurePattern(
                pattern=pattern_key,
                count=1,
                severity=failure.severity,
                common_causes=[failure.root_cause] if failure.root_cause else [],
                recommendations=await self._generate_recommendations(pattern_key),
                last_seen=failure.timestamp
            )
            self._patterns[pattern_key] = pattern
    
    async def _generate_recommendations(self, failure_type: str) -> List[str]:
        """توليد توصيات لمنع تكرار الفشل"""
        recommendations = {
            "timeout": [
                "Increase timeout values",
                "Implement retry mechanism",
                "Optimize slow operations"
            ],
            "connection_error": [
                "Check network connectivity",
                "Implement connection pooling",
                "Add automatic reconnection"
            ],
            "parsing_error": [
                "Improve error handling",
                "Validate input format",
                "Add fallback parser"
            ],
            "memory_error": [
                "Reduce memory usage",
                "Implement pagination",
                "Add memory monitoring"
            ],
            "rate_limit": [
                "Reduce request rate",
                "Implement exponential backoff",
                "Use distributed requests"
            ]
        }
        
        return recommendations.get(failure_type, [
            "Investigate root cause",
            "Add monitoring",
            "Implement automated recovery"
        ])
    
    async def analyze_root_causes(self) -> Dict[str, List[str]]:
        """
        تحليل الأسباب الجذرية للفشل
        
        Returns:
            قاموس بنوع الفشل وقائمة الأسباب الجذرية
        """
        root_causes = defaultdict(list)
        
        for failure in self._failures:
            if failure.root_cause:
                root_causes[failure.failure_type].append(failure.root_cause)
        
        # إزالة التكرارات
        for failure_type in root_causes:
            root_causes[failure_type] = list(set(root_causes[failure_type]))
        
        return dict(root_causes)
    
    async def get_failure_patterns(self) -> List[FailurePattern]:
        """الحصول على أنماط الفشل المتكررة"""
        patterns = list(self._patterns.values())
        patterns.sort(key=lambda x: x.count, reverse=True)
        return patterns
    
    async def get_failures_by_type(
        self,
        failure_type: str = None,
        severity: str = None,
        resolved: bool = None,
        limit: int = 50
    ) -> List[FailureRecord]:
        """
        الحصول على سجلات الفشل حسب المعايير
        
        Args:
            failure_type: نوع الفشل
            severity: شدة الفشل
            resolved: حالة الحل
            limit: عدد النتائج
        
        Returns:
            قائمة بسجلات الفشل
        """
        failures = self._failures
        
        if failure_type:
            failures = [f for f in failures if f.failure_type == failure_type]
        
        if severity:
            failures = [f for f in failures if f.severity == severity]
        
        if resolved is not None:
            failures = [f for f in failures if f.resolved == resolved]
        
        failures.sort(key=lambda x: x.timestamp, reverse=True)
        
        return failures[:limit]
    
    async def mark_resolved(self, failure_id: str, resolution_notes: str = None) -> bool:
        """
        تعليم فشل كـ"تم حله"
        
        Args:
            failure_id: معرف سجل الفشل
            resolution_notes: ملاحظات الحل
        
        Returns:
            نجاح العملية
        """
        for failure in self._failures:
            if failure.id == failure_id:
                failure.resolved = True
                if resolution_notes:
                    failure.metadata["resolution_notes"] = resolution_notes
                logger.info(f"Failure {failure_id} marked as resolved")
                return True
        return False
    
    async def get_risk_assessment(self) -> Dict:
        """
        تقييم المخاطر بناءً على أنماط الفشل
        
        Returns:
            تقييم المخاطر
        """
        patterns = await self.get_failure_patterns()
        
        risk_score = 0.0
        critical_patterns = []
        
        for pattern in patterns:
            if pattern.severity == "critical":
                critical_patterns.append(pattern.pattern)
                risk_score += pattern.count * 10
            elif pattern.severity == "high":
                risk_score += pattern.count * 5
            elif pattern.severity == "medium":
                risk_score += pattern.count * 2
        
        return {
            "risk_score": min(risk_score, 100),
            "critical_patterns": critical_patterns,
            "total_failures": len(self._failures),
            "unresolved_failures": len([f for f in self._failures if not f.resolved]),
            "most_common_failure": patterns[0].pattern if patterns else None,
            "recommendations": [
                rec for pattern in patterns[:3]
                for rec in pattern.recommendations
            ][:5]
        }
    
    async def get_statistics(self) -> Dict:
        """إحصائيات تحليل الفشل"""
        failures_by_type = defaultdict(int)
        failures_by_severity = defaultdict(int)
        
        for failure in self._failures:
            failures_by_type[failure.failure_type] += 1
            failures_by_severity[failure.severity] += 1
        
        return {
            "total_failures": len(self._failures),
            "resolved_failures": len([f for f in self._failures if f.resolved]),
            "resolution_rate": len([f for f in self._failures if f.resolved]) / len(self._failures) if self._failures else 0,
            "failures_by_type": dict(failures_by_type),
            "failures_by_severity": dict(failures_by_severity),
            "total_patterns": len(self._patterns),
            "most_frequent_pattern": max(self._patterns.values(), key=lambda x: x.count).pattern if self._patterns else None
        }

