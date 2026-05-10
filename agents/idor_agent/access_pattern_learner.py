
import re
import json
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from collections import defaultdict, deque
import random

import logging

logger = logging.getLogger(__name__)


@dataclass
class AccessEvent:
    """حدث وصول إلى مورد"""
    user_id: str
    resource_type: str
    resource_id: str
    url: str
    timestamp: datetime = field(default_factory=datetime.now)
    success: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AccessPattern:
    """نمط وصول"""
    resource_type: str
    user_ids: List[str]
    resource_ids: List[str]
    frequency: int
    last_seen: datetime
    confidence: float = 0.0


class AccessPatternLearner:
    """
    متعلم أنماط الوصول المتقدم
    
    الميزات:
    - تسجيل أحداث الوصول
    - تعلم أنماط الوصول الطبيعية
    - اكتشاف السلوكيات الشاذة
    - تحديد الموارد التي يمكن الوصول إليها عبر IDOR
    - تحليل سلاسل الوصول
    """
    
    def __init__(self, max_history: int = 10000, pattern_window: int = 100):
        self._access_history: deque = deque(maxlen=max_history)
        self._user_access: Dict[str, List[AccessEvent]] = defaultdict(list)
        self._resource_access: Dict[str, List[AccessEvent]] = defaultdict(list)
        self._patterns: List[AccessPattern] = []
        self._anomalies: List[AccessEvent] = []
        self._pattern_window = pattern_window
        
        logger.info("AccessPatternLearner initialized")
    
    async def record_access(
        self,
        user_id: str,
        resource_type: str,
        resource_id: str,
        url: str,
        success: bool = True,
        metadata: Dict = None
    ):
        """
        تسجيل حدث وصول
        
        Args:
            user_id: معرف المستخدم
            resource_type: نوع المورد
            resource_id: معرف المورد
            url: الرابط
            success: نجاح الوصول
            metadata: بيانات إضافية
        """
        event = AccessEvent(
            user_id=user_id,
            resource_type=resource_type,
            resource_id=resource_id,
            url=url,
            timestamp=datetime.now(),
            success=success,
            metadata=metadata or {}
        )
        
        self._access_history.append(event)
        self._user_access[user_id].append(event)
        self._resource_access[f"{resource_type}:{resource_id}"].append(event)
        
        # تحديث الأنماط
        await self._update_patterns()
        
        # كشف الشذوذ
        await self._detect_anomaly(event)
    
    async def _update_patterns(self):
        """تحديث أنماط الوصول"""
        # تجميع حسب نوع المورد
        resource_groups = defaultdict(lambda: defaultdict(set))
        
        for event in list(self._access_history)[-self._pattern_window:]:
            resource_groups[event.resource_type][event.user_id].add(event.resource_id)
        
        # إنشاء أنماط جديدة
        new_patterns = []
        for resource_type, user_resources in resource_groups.items():
            for user_id, resource_ids in user_resources.items():
                if len(resource_ids) >= 2:  # على الأقل موردين
                    pattern = AccessPattern(
                        resource_type=resource_type,
                        user_ids=[user_id],
                        resource_ids=list(resource_ids),
                        frequency=len(resource_ids),
                        last_seen=datetime.now(),
                        confidence=min(0.5 + len(resource_ids) * 0.1, 1.0)
                    )
                    new_patterns.append(pattern)
        
        # دمج مع الأنماط الحالية
        self._patterns = new_patterns
    
    async def _detect_anomaly(self, event: AccessEvent):
        """
        كشف السلوك الشاذ
        
        Args:
            event: حدث الوصول
        """
        # التحقق من وصول المستخدم إلى موارد لم يصل إليها سابقاً
        user_resources = set()
        for e in self._user_access[event.user_id]:
            user_resources.add(f"{e.resource_type}:{e.resource_id}")
        
        current_resource = f"{event.resource_type}:{event.resource_id}"
        
        if current_resource not in user_resources and len(user_resources) > 5:
            # مستخدم يصل إلى مورد جديد
            self._anomalies.append(event)
            logger.warning(f"Anomaly detected: User {event.user_id} accessed new resource {current_resource}")
        
        # التحقق من وصول مورد إلى مستخدمين مختلفين
        resource_events = self._resource_access[current_resource]
        unique_users = set(e.user_id for e in resource_events)
        
        if len(unique_users) > 1 and len(resource_events) > 3:
            # مورد يصل إليه عدة مستخدمين (قد يكون IDOR)
            anomaly_event = AccessEvent(
                user_id=event.user_id,
                resource_type=event.resource_type,
                resource_id=event.resource_id,
                url=event.url,
                metadata={"reason": "resource_accessed_by_multiple_users", "user_count": len(unique_users)}
            )
            self._anomalies.append(anomaly_event)
            logger.info(f"Potential IDOR: Resource {current_resource} accessed by {len(unique_users)} users")
    
    async def get_user_access_pattern(
        self,
        user_id: str
    ) -> Dict[str, Any]:
        """
        الحصول على نمط وصول مستخدم محدد
        
        Args:
            user_id: معرف المستخدم
        
        Returns:
            نمط الوصول
        """
        events = self._user_access.get(user_id, [])
        
        if not events:
            return {"has_data": False}
        
        # تجميع حسب نوع المورد
        resource_types = defaultdict(set)
        for event in events:
            resource_types[event.resource_type].add(event.resource_id)
        
        # حساب التكرار الزمني
        if len(events) >= 2:
            time_diffs = []
            for i in range(1, len(events)):
                diff = (events[i].timestamp - events[i-1].timestamp).total_seconds()
                time_diffs.append(diff)
            avg_gap = sum(time_diffs) / len(time_diffs) if time_diffs else 0
        else:
            avg_gap = 0
        
        return {
            "has_data": True,
            "total_access": len(events),
            "resource_types": {rt: len(rids) for rt, rids in resource_types.items()},
            "unique_resources": sum(len(rids) for rids in resource_types.values()),
            "success_rate": sum(1 for e in events if e.success) / len(events),
            "avg_time_between_access": avg_gap,
            "last_access": events[-1].timestamp.isoformat() if events else None
        }
    
    async def get_resource_access_pattern(
        self,
        resource_type: str,
        resource_id: str
    ) -> Dict[str, Any]:
        """
        الحصول على نمط وصول مورد محدد
        
        Args:
            resource_type: نوع المورد
            resource_id: معرف المورد
        
        Returns:
            نمط الوصول
        """
        key = f"{resource_type}:{resource_id}"
        events = self._resource_access.get(key, [])
        
        if not events:
            return {"has_data": False}
        
        unique_users = set(e.user_id for e in events)
        
        return {
            "has_data": True,
            "total_access": len(events),
            "unique_users": len(unique_users),
            "users": list(unique_users),
            "success_rate": sum(1 for e in events if e.success) / len(events),
            "first_access": events[0].timestamp.isoformat(),
            "last_access": events[-1].timestamp.isoformat()
        }
    
    async def get_potential_idor_targets(self) -> List[Dict]:
        """
        الحصول على الأهداف المحتملة لثغرات IDOR
        
        Returns:
            قائمة بالموارد التي قد تكون عرضة لـ IDOR
        """
        targets = []
        
        for key, events in self._resource_access.items():
            unique_users = set(e.user_id for e in events)
            
            # إذا وصل إلى المورد أكثر من مستخدم واحد
            if len(unique_users) >= 2:
                resource_type, resource_id = key.split(':', 1)
                
                # التحقق من أن المستخدمين ليسوا جميعاً من نفس الدور
                targets.append({
                    "resource_type": resource_type,
                    "resource_id": resource_id,
                    "url": events[0].url if events else "",
                    "accessed_by": len(unique_users),
                    "users": list(unique_users),
                    "first_access": events[0].timestamp.isoformat(),
                    "last_access": events[-1].timestamp.isoformat(),
                    "total_access": len(events)
                })
        
        # ترتيب حسب عدد المستخدمين
        targets.sort(key=lambda x: x["accessed_by"], reverse=True)
        
        return targets
    
    async def get_access_sequence(
        self,
        user_id: str,
        limit: int = 50
    ) -> List[Dict]:
        """
        الحصول على تسلسل الوصول لمستخدم محدد
        
        Args:
            user_id: معرف المستخدم
            limit: الحد الأقصى للنتائج
        
        Returns:
            تسلسل الوصول
        """
        events = self._user_access.get(user_id, [])
        
        return [
            {
                "timestamp": e.timestamp.isoformat(),
                "resource_type": e.resource_type,
                "resource_id": e.resource_id,
                "url": e.url,
                "success": e.success
            }
            for e in events[-limit:]
        ]
    
    async def get_anomalies(self, limit: int = 50) -> List[Dict]:
        """
        الحصول على السلوكيات الشاذة المكتشفة
        
        Args:
            limit: الحد الأقصى للنتائج
        
        Returns:
            قائمة بالسلوكيات الشاذة
        """
        return [
            {
                "timestamp": a.timestamp.isoformat(),
                "user_id": a.user_id,
                "resource_type": a.resource_type,
                "resource_id": a.resource_id,
                "url": a.url,
                "reason": a.metadata.get("reason", "unknown")
            }
            for a in self._anomalies[-limit:]
        ]
    
    async def get_patterns(self) -> List[Dict]:
        """الحصول على أنماط الوصول المكتشفة"""
        return [
            {
                "resource_type": p.resource_type,
                "users": p.user_ids,
                "resources_count": len(p.resource_ids),
                "frequency": p.frequency,
                "confidence": p.confidence,
                "last_seen": p.last_seen.isoformat()
            }
            for p in self._patterns
        ]
    
    async def generate_learning_report(self) -> str:
        """
        توليد تقرير تعلم أنماط الوصول
        
        Returns:
            تقرير Markdown
        """
        report = f"""# Access Pattern Learning Report

**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## Statistics

| Metric | Value |
|--------|-------|
| Total Access Events | {len(self._access_history)} |
| Unique Users | {len(self._user_access)} |
| Unique Resources | {len(self._resource_access)} |
| Detected Patterns | {len(self._patterns)} |
| Anomalies Found | {len(self._anomalies)} |

## Potential IDOR Targets ({len(await self.get_potential_idor_targets())})

"""
        targets = await self.get_potential_idor_targets()
        for target in targets[:10]:
            report += f"- **{target['resource_type']}** `{target['resource_id']}`\n"
            report += f"  - Accessed by {target['accessed_by']} users\n"
            report += f"  - Total accesses: {target['total_access']}\n"
        
        if len(targets) > 10:
            report += f"\n*... and {len(targets) - 10} more targets*\n"
        
        anomalies = await self.get_anomalies()
        if anomalies:
            report += f"\n## Recent Anomalies ({len(anomalies)})\n\n"
            for anomaly in anomalies[:10]:
                report += f"- **User:** {anomaly['user_id']}\n"
                report += f"  - Resource: {anomaly['resource_type']}:{anomaly['resource_id']}\n"
                report += f"  - URL: {anomaly['url']}\n"
                report += f"  - Reason: {anomaly['reason']}\n"
        
        return report
    
    async def get_statistics(self) -> Dict:
        """إحصائيات المتعلم"""
        return {
            "total_access_events": len(self._access_history),
            "unique_users": len(self._user_access),
            "unique_resources": len(self._resource_access),
            "patterns_detected": len(self._patterns),
            "anomalies_detected": len(self._anomalies),
            "potential_idor_targets": len(await self.get_potential_idor_targets()),
            "max_history": self._access_history.maxlen,
            "pattern_window": self._pattern_window
        }
    
    async def clear_history(self):
        """مسح سجل الوصول"""
        self._access_history.clear()
        self._user_access.clear()
        self._resource_access.clear()
        self._patterns.clear()
        self._anomalies.clear()
        logger.info("Access pattern history cleared")

