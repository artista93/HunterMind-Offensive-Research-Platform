
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime
from collections import defaultdict

from .metrics_engine import get_metrics_engine

import logging

logger = logging.getLogger(__name__)


@dataclass
class AttackRecord:
    """سجل هجوم"""
    attack_id: str
    attack_type: str
    target: str
    success: bool
    duration: float
    payload_size: int
    timestamp: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)


class AttackMetrics:
    """
    مقاييس الهجمات المتقدمة
    
    الميزات:
    - تسجيل مقاييس الهجمات
    - تحليل معدلات النجاح
    - إحصائيات أوقات الاستجابة
    - تقارير أداء الهجمات
    """
    
    def __init__(self):
        self.attacks: List[AttackRecord] = []
        self.metrics_engine = None
        self._lock = asyncio.Lock()
        
        logger.info("AttackMetrics initialized")
    
    async def initialize(self):
        """تهيئة مقاييس الهجمات"""
        self.metrics_engine = await get_metrics_engine()
        logger.info("AttackMetrics connected to metrics engine")
    
    async def record_attack(
        self,
        attack_id: str,
        attack_type: str,
        target: str,
        success: bool,
        duration: float,
        payload_size: int,
        metadata: Dict = None
    ):
        """
        تسجيل هجوم
        
        Args:
            attack_id: معرف الهجوم
            attack_type: نوع الهجوم
            target: الهدف
            success: نجاح الهجوم
            duration: مدة الهجوم
            payload_size: حجم الحمولة
            metadata: بيانات إضافية
        """
        record = AttackRecord(
            attack_id=attack_id,
            attack_type=attack_type,
            target=target,
            success=success,
            duration=duration,
            payload_size=payload_size,
            metadata=metadata or {}
        )
        
        async with self._lock:
            self.attacks.append(record)
            
            # الاحتفاظ بآخر 10000 سجل فقط
            if len(self.attacks) > 10000:
                self.attacks = self.attacks[-10000:]
        
        # تسجيل المقاييس
        if self.metrics_engine:
            await self.metrics_engine.increment_counter(
                f"attack.total",
                labels={"type": attack_type}
            )
            
            if success:
                await self.metrics_engine.increment_counter(
                    f"attack.success",
                    labels={"type": attack_type}
                )
            else:
                await self.metrics_engine.increment_counter(
                    f"attack.failed",
                    labels={"type": attack_type}
                )
            
            await self.metrics_engine.record_timer(
                f"attack.duration",
                duration,
                labels={"type": attack_type}
            )
            
            await self.metrics_engine.record_histogram(
                f"attack.payload_size",
                payload_size,
                labels={"type": attack_type}
            )
        
        logger.debug(f"Attack recorded: {attack_type} - {'SUCCESS' if success else 'FAIL'}")
    
    async def get_success_rate(self, attack_type: str = None) -> float:
        """
        حساب معدل النجاح
        
        Args:
            attack_type: نوع الهجوم (الكل إذا None)
        
        Returns:
            معدل النجاح (0-1)
        """
        attacks = self.attacks
        if attack_type:
            attacks = [a for a in attacks if a.attack_type == attack_type]
        
        if not attacks:
            return 0.0
        
        successful = len([a for a in attacks if a.success])
        return successful / len(attacks)
    
    async def get_average_duration(self, attack_type: str = None) -> float:
        """
        حساب متوسط مدة الهجوم
        
        Args:
            attack_type: نوع الهجوم (الكل إذا None)
        
        Returns:
            متوسط المدة بالثواني
        """
        attacks = self.attacks
        if attack_type:
            attacks = [a for a in attacks if a.attack_type == attack_type]
        
        if not attacks:
            return 0.0
        
        return sum(a.duration for a in attacks) / len(attacks)
    
    async def get_attack_statistics(self) -> Dict:
        """الحصول على إحصائيات الهجمات"""
        if not self.attacks:
            return {"total_attacks": 0}
        
        # إحصائيات حسب النوع
        by_type = defaultdict(lambda: {
            "total": 0,
            "successful": 0,
            "failed": 0,
            "total_duration": 0.0,
            "total_payload": 0
        })
        
        for attack in self.attacks:
            stats = by_type[attack.attack_type]
            stats["total"] += 1
            if attack.success:
                stats["successful"] += 1
            else:
                stats["failed"] += 1
            stats["total_duration"] += attack.duration
            stats["total_payload"] += attack.payload_size
        
        # حساب المتوسطات
        for attack_type, stats in by_type.items():
            stats["success_rate"] = stats["successful"] / stats["total"] if stats["total"] > 0 else 0
            stats["avg_duration"] = stats["total_duration"] / stats["total"] if stats["total"] > 0 else 0
            stats["avg_payload"] = stats["total_payload"] / stats["total"] if stats["total"] > 0 else 0
        
        return {
            "total_attacks": len(self.attacks),
            "successful_attacks": len([a for a in self.attacks if a.success]),
            "failed_attacks": len([a for a in self.attacks if not a.success]),
            "overall_success_rate": await self.get_success_rate(),
            "average_duration": await self.get_average_duration(),
            "by_type": dict(by_type),
            "recent_attacks": [
                {
                    "id": a.attack_id,
                    "type": a.attack_type,
                    "target": a.target,
                    "success": a.success,
                    "duration": a.duration,
                    "timestamp": a.timestamp.isoformat()
                }
                for a in self.attacks[-20:]
            ]
        }
    
    async def get_attack_trends(self, hours: int = 24) -> Dict:
        """
        تحليل اتجاهات الهجمات
        
        Args:
            hours: عدد الساعات للتحليل
        
        Returns:
            تحليل الاتجاهات
        """
        cutoff = datetime.now().timestamp() - (hours * 3600)
        recent_attacks = [a for a in self.attacks if a.timestamp.timestamp() > cutoff]
        
        if not recent_attacks:
            return {"has_data": False}
        
        # تجميع حسب الساعة
        hourly = defaultdict(lambda: {"total": 0, "successful": 0})
        
        for attack in recent_attacks:
            hour = attack.timestamp.strftime("%Y-%m-%d %H:00")
            hourly[hour]["total"] += 1
            if attack.success:
                hourly[hour]["successful"] += 1
        
        return {
            "has_data": True,
            "hours_analyzed": hours,
            "total_attacks": len(recent_attacks),
            "hourly_data": dict(hourly),
            "peak_hour": max(hourly.items(), key=lambda x: x[1]["total"])[0] if hourly else None,
            "trend": "increasing" if len(recent_attacks) > len(self.attacks) // 2 else "stable"
        }


# نسخة عالمية
_default_metrics = None


async def get_attack_metrics() -> AttackMetrics:
    """الحصول على نسخة عالمية من مقاييس الهجمات"""
    global _default_metrics
    if _default_metrics is None:
        _default_metrics = AttackMetrics()
        await _default_metrics.initialize()
    return _default_metrics

