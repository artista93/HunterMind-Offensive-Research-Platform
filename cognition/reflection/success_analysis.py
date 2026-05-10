
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from collections import defaultdict

import logging

logger = logging.getLogger(__name__)


@dataclass
class SuccessRecord:
    """سجل نجاح"""
    id: str
    success_type: str
    description: str
    timestamp: datetime
    impact: str  # critical, high, medium, low
    contributing_factors: List[str]
    metrics: Dict[str, float]
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SuccessPattern:
    """نمط نجاح متكرر"""
    pattern: str
    count: int
    impact: str
    common_factors: List[str]
    best_practices: List[str]
    last_seen: datetime


class SuccessAnalysis:
    """
    تحليل النجاح المتقدم
    
    الميزات:
    - تسجيل حالات النجاح
    - تحليل العوامل المساهمة
    - اكتشاف أنماط النجاح المتكررة
    - استخلاص أفضل الممارسات
    """
    
    def __init__(self):
        self._successes: List[SuccessRecord] = []
        self._patterns: Dict[str, SuccessPattern] = {}
        
        logger.info("SuccessAnalysis initialized")
    
    async def record_success(
        self,
        success_type: str,
        description: str,
        impact: str,
        contributing_factors: List[str],
        metrics: Dict = None,
        metadata: Dict = None
    ) -> str:
        """
        تسجيل حالة نجاح جديدة
        
        Args:
            success_type: نوع النجاح
            description: وصف النجاح
            impact: تأثير النجاح
            contributing_factors: العوامل المساهمة
            metrics: مقاييس الأداء
            metadata: بيانات إضافية
        
        Returns:
            معرف سجل النجاح
        """
        import uuid
        success_id = str(uuid.uuid4())[:8]
        
        success = SuccessRecord(
            id=success_id,
            success_type=success_type,
            description=description,
            timestamp=datetime.now(),
            impact=impact,
            contributing_factors=contributing_factors,
            metrics=metrics or {},
            metadata=metadata or {}
        )
        
        self._successes.append(success)
        
        # تحديث أنماط النجاح
        await self._update_patterns(success)
        
        logger.info(f"Success recorded: {success_type} ({impact})")
        return success_id
    
    async def _update_patterns(self, success: SuccessRecord):
        """تحديث أنماط النجاح"""
        pattern_key = success.success_type
        
        if pattern_key in self._patterns:
            pattern = self._patterns[pattern_key]
            pattern.count += 1
            pattern.last_seen = success.timestamp
            
            for factor in success.contributing_factors:
                if factor not in pattern.common_factors:
                    pattern.common_factors.append(factor)
        else:
            pattern = SuccessPattern(
                pattern=pattern_key,
                count=1,
                impact=success.impact,
                common_factors=success.contributing_factors,
                best_practices=await self._extract_best_practices(success),
                last_seen=success.timestamp
            )
            self._patterns[pattern_key] = pattern
    
    async def _extract_best_practices(self, success: SuccessRecord) -> List[str]:
        """استخلاص أفضل الممارسات من النجاح"""
        best_practices = {
            "detection": [
                "Use multiple payload types",
                "Implement context-aware scanning",
                "Verify findings automatically"
            ],
            "exploitation": [
                "Start with simple payloads",
                "Use encoding for WAF bypass",
                "Implement retry with backoff"
            ],
            "reconnaissance": [
                "Crawl JavaScript files",
                "Analyze API endpoints",
                "Check common directories"
            ],
            "bypass": [
                "Test multiple encoding techniques",
                "Use case variation",
                "Insert comments in payloads"
            ]
        }
        
        return best_practices.get(success.success_type, [
            "Document successful approach",
            "Share knowledge with team",
            "Automate successful pattern"
        ])
    
    async def analyze_success_factors(self) -> Dict[str, List[str]]:
        """
        تحليل العوامل المساهمة في النجاح
        
        Returns:
            قاموس بنوع النجاح وقائمة العوامل المساهمة
        """
        factors = defaultdict(list)
        
        for success in self._successes:
            factors[success.success_type].extend(success.contributing_factors)
        
        # إزالة التكرارات
        for success_type in factors:
            factors[success_type] = list(set(factors[success_type]))
        
        return dict(factors)
    
    async def get_success_patterns(self) -> List[SuccessPattern]:
        """الحصول على أنماط النجاح المتكررة"""
        patterns = list(self._patterns.values())
        patterns.sort(key=lambda x: x.count, reverse=True)
        return patterns
    
    async def get_successes_by_type(
        self,
        success_type: str = None,
        impact: str = None,
        limit: int = 50
    ) -> List[SuccessRecord]:
        """
        الحصول على سجلات النجاح حسب المعايير
        
        Args:
            success_type: نوع النجاح
            impact: تأثير النجاح
            limit: عدد النتائج
        
        Returns:
            قائمة بسجلات النجاح
        """
        successes = self._successes
        
        if success_type:
            successes = [s for s in successes if s.success_type == success_type]
        
        if impact:
            successes = [s for s in successes if s.impact == impact]
        
        successes.sort(key=lambda x: x.timestamp, reverse=True)
        
        return successes[:limit]
    
    async def get_best_practices(self, success_type: str = None) -> List[str]:
        """
        الحصول على أفضل الممارسات
        
        Args:
            success_type: نوع النجاح (اختياري)
        
        Returns:
            قائمة بأفضل الممارسات
        """
        if success_type and success_type in self._patterns:
            return self._patterns[success_type].best_practices
        
        # دمج أفضل الممارسات من جميع الأنماط
        all_practices = set()
        for pattern in self._patterns.values():
            all_practices.update(pattern.best_practices)
        
        return list(all_practices)
    
    async def get_metrics_summary(self) -> Dict:
        """
        ملخص مقاييس النجاح
        
        Returns:
            ملخص المقاييس
        """
        if not self._successes:
            return {"total_successes": 0}
        
        # تجميع المقاييس حسب النوع
        metrics_by_type = defaultdict(list)
        for success in self._successes:
            for key, value in success.metrics.items():
                metrics_by_type[key].append(value)
        
        # حساب المتوسطات
        averages = {}
        for key, values in metrics_by_type.items():
            averages[key] = sum(values) / len(values)
        
        return {
            "total_successes": len(self._successes),
            "high_impact_successes": len([s for s in self._successes if s.impact == "critical"]),
            "average_metrics": averages,
            "best_success": max(self._successes, key=lambda x: x.metrics.get("success_rate", 0)).description if self._successes else None,
            "most_common_type": max(self._patterns.values(), key=lambda x: x.count).pattern if self._patterns else None
        }
    
    async def get_statistics(self) -> Dict:
        """إحصائيات تحليل النجاح"""
        successes_by_type = defaultdict(int)
        successes_by_impact = defaultdict(int)
        
        for success in self._successes:
            successes_by_type[success.success_type] += 1
            successes_by_impact[success.impact] += 1
        
        return {
            "total_successes": len(self._successes),
            "successes_by_type": dict(successes_by_type),
            "successes_by_impact": dict(successes_by_impact),
            "total_patterns": len(self._patterns),
            "most_frequent_pattern": max(self._patterns.values(), key=lambda x: x.count).pattern if self._patterns else None,
            "average_contributing_factors": sum(len(s.contributing_factors) for s in self._successes) / len(self._successes) if self._successes else 0
        }

