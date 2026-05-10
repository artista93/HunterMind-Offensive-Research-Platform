
import asyncio
import random
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from collections import defaultdict

from .bypass_generator import BypassTechnique, BypassGenerator
from .payload_obfuscator import ObfuscationMethod, PayloadObfuscator

import logging

logger = logging.getLogger(__name__)


class EvasionState(Enum):
    """حالة التهرب"""
    LEARNING = "learning"
    TESTING = "testing"
    ADAPTING = "adapting"
    SUCCESS = "success"
    FAILED = "failed"


@dataclass
class EvasionAttempt:
    """محاولة تهرب"""
    technique: str
    payload: str
    success: bool
    response_time: float
    status_code: int
    timestamp: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class TechniqueStats:
    """إحصائيات تقنية التهرب"""
    attempts: int = 0
    successes: int = 0
    avg_response_time: float = 0.0
    last_used: Optional[datetime] = None
    success_rate: float = 0.0


class AdaptiveEvasion:
    """
    التهرب التكيفي من WAF المتقدم
    
    الميزات:
    - تعلم من نجاحات وفشل التقنيات
    - تكيف ديناميكي مع سلوك WAF
    - خوارزميات تحسين Bayesian
    - تبديل ذكي للتقنيات
    - تقييد معدل التكيف
    """
    
    def __init__(self):
        self._bypass_gen = BypassGenerator()
        self._obfuscator = PayloadObfuscator()
        
        self._technique_stats: Dict[str, TechniqueStats] = defaultdict(TechniqueStats)
        self._evasion_history: List[EvasionAttempt] = []
        self._state = EvasionState.LEARNING
        self._active_evasions: Set[str] = set()
        
        # أوزان التقنيات (تتحدث ديناميكياً)
        self._technique_weights: Dict[str, float] = {
            t.value: 1.0 for t in BypassTechnique
        }
        
        logger.info("AdaptiveEvasion initialized")
    
    async def evade(
        self,
        original_payload: str,
        waf_type: str = None,
    ) -> Tuple[str, str, float]:
        """
        تهرب تكيفي من WAF
        
        Args:
            original_payload: الحمولة الأصلية
            waf_type: نوع WAF (اختياري)
        
        Returns:
            (modified_payload, technique_used, confidence)
        """
        evasion_id = f"evasion_{datetime.now().timestamp()}"
        self._active_evasions.add(evasion_id)
        
        try:
            # اختيار أفضل تقنية بناءً على الإحصائيات
            technique = await self._select_best_technique(waf_type)
            
            # توليد حمولة متجاوزة
            bypass_result = await self._bypass_gen.generate_bypass(
                original_payload,
                BypassTechnique(technique),
                waf_type
            )
            
            modified_payload = bypass_result.modified_payload
            
            # تطبيق إبهام إضافي إذا لزم الأمر
            if random.random() > 0.7:
                obf_method = random.choice(list(ObfuscationMethod))
                obf_result = await self._obfuscator.obfuscate(
                    modified_payload,
                    obf_method,
                    layers=random.randint(1, 2)
                )
                modified_payload = obf_result.obfuscated
            
            # تحديث الإحصائيات
            self._technique_stats[technique].last_used = datetime.now()
            
            logger.debug(f"Evasion technique selected: {technique}")
            
            return modified_payload, technique, self._technique_weights[technique]
            
        finally:
            self._active_evasions.discard(evasion_id)
    
    async def _select_best_technique(self, waf_type: str = None) -> str:
        """
        اختيار أفضل تقنية تهرب
        
        Args:
            waf_type: نوع WAF
        
        Returns:
            اسم التقنية المختارة
        """
        # إذا كان WAF معروفاً، استخدم التقنيات المخصصة
        if waf_type:
            waf_specific = self._bypass_gen.WAF_SPECIFIC_BYPASS.get(waf_type, [])
            if waf_specific:
                # اختيار من التقنيات المخصصة
                available = [t for t in waf_specific if t in self._technique_weights]
                if available:
                    return random.choice(available)
        
        # اختيار بناءً على الأوزان
        total_weight = sum(self._technique_weights.values())
        if total_weight == 0:
            return random.choice(list(self._technique_weights.keys()))
        
        rand = random.random() * total_weight
        cumulative = 0.0
        
        for technique, weight in self._technique_weights.items():
            cumulative += weight
            if rand <= cumulative:
                return technique
        
        return list(self._technique_weights.keys())[0]
    
    async def record_result(
        self,
        technique: str,
        success: bool,
        response_time: float,
        status_code: int,
        metadata: Dict = None
    ):
        """
        تسجيل نتيجة محاولة تهرب
        
        Args:
            technique: التقنية المستخدمة
            success: نجاح التهرب
            response_time: وقت الاستجابة
            status_code: كود الحالة
            metadata: بيانات إضافية
        """
        attempt = EvasionAttempt(
            technique=technique,
            payload="",
            success=success,
            response_time=response_time,
            status_code=status_code,
            metadata=metadata or {}
        )
        
        self._evasion_history.append(attempt)
        
        # تحديث إحصائيات التقنية
        stats = self._technique_stats[technique]
        stats.attempts += 1
        if success:
            stats.successes += 1
        
        # تحديث متوسط وقت الاستجابة
        stats.avg_response_time = (
            (stats.avg_response_time * (stats.attempts - 1) + response_time) 
            / stats.attempts
        )
        
        # تحديث معدل النجاح
        stats.success_rate = stats.successes / stats.attempts
        
        # تحديث وزن التقنية (Bayesian optimization)
        await self._update_technique_weight(technique, success)
        
        # تحديث الحالة
        await self._update_state()
        
        logger.debug(f"Evasion result recorded: {technique} - {'SUCCESS' if success else 'FAIL'}")
    
    async def _update_technique_weight(self, technique: str, success: bool):
        """
        تحديث وزن التقنية باستخدام تحسين Bayesian
        
        Args:
            technique: التقنية المستخدمة
            success: نجاح التهرب
        """
        stats = self._technique_stats[technique]
        
        # حساب الوزن الجديد
        if stats.attempts < 5:
            # مرحلة الاستكشاف: وزن أعلى للتقنيات غير المجربة
            weight = 1.5
        else:
            # مرحلة الاستغلال: وزن يعتمد على معدل النجاح
            base_weight = stats.success_rate * 2.0
            
            # مكافأة زمنية (التقنيات الأسرع تحصل على وزن أعلى)
            time_bonus = max(0, 1.0 - (stats.avg_response_time / 10.0)) * 0.5
            
            # عقوبة للمحاولات الفاشلة المتكررة
            if stats.successes == 0 and stats.attempts > 3:
                penalty = 0.3
            else:
                penalty = 1.0
            
            weight = (base_weight + time_bonus) * penalty
        
        # تحديث الوزن (مع حدود)
        self._technique_weights[technique] = max(0.1, min(weight, 3.0))
    
    async def _update_state(self):
        """تحديث حالة التهرب"""
        total_attempts = sum(s.attempts for s in self._technique_stats.values())
        total_successes = sum(s.successes for s in self._technique_stats.values())
        
        if total_attempts < 10:
            self._state = EvasionState.LEARNING
        elif total_successes > 0:
            self._state = EvasionState.SUCCESS
        elif total_attempts > 50 and total_successes == 0:
            self._state = EvasionState.FAILED
        else:
            self._state = EvasionState.ADAPTING
    
    async def get_best_techniques(self, limit: int = 5) -> List[Tuple[str, float]]:
        """
        الحصول على أفضل التقنيات حسب معدل النجاح
        
        Args:
            limit: عدد النتائج
        
        Returns:
            قائمة (التقنية, معدل النجاح)
        """
        techniques = []
        for technique, stats in self._technique_stats.items():
            if stats.attempts >= 3:  # على الأقل 3 محاولات
                techniques.append((technique, stats.success_rate))
        
        techniques.sort(key=lambda x: x[1], reverse=True)
        return techniques[:limit]
    
    async def get_technique_stats(self) -> Dict[str, Dict]:
        """الحصول على إحصائيات جميع التقنيات"""
        return {
            technique: {
                "attempts": stats.attempts,
                "successes": stats.successes,
                "success_rate": stats.success_rate,
                "avg_response_time": stats.avg_response_time,
                "weight": self._technique_weights.get(technique, 1.0),
                "last_used": stats.last_used.isoformat() if stats.last_used else None
            }
            for technique, stats in self._technique_stats.items()
        }
    
    async def get_evasion_history(self, limit: int = 100) -> List[Dict]:
        """الحصول على تاريخ محاولات التهرب"""
        return [
            {
                "technique": a.technique,
                "success": a.success,
                "response_time": a.response_time,
                "status_code": a.status_code,
                "timestamp": a.timestamp.isoformat()
            }
            for a in self._evasion_history[-limit:]
        ]
    
    async def get_state(self) -> Dict:
        """الحصول على حالة التهرب"""
        total_attempts = sum(s.attempts for s in self._technique_stats.values())
        total_successes = sum(s.successes for s in self._technique_stats.values())
        
        return {
            "state": self._state.value,
            "total_attempts": total_attempts,
            "total_successes": total_successes,
            "overall_success_rate": total_successes / total_attempts if total_attempts > 0 else 0,
            "active_evasions": len(self._active_evasions),
            "techniques_tested": len(self._technique_stats),
            "best_techniques": await self.get_best_techniques()
        }
    
    async def reset_learning(self):
        """إعادة تعلم الإحصائيات"""
        self._technique_stats.clear()
        self._evasion_history.clear()
        self._state = EvasionState.LEARNING
        
        # إعادة تعيين الأوزان
        for technique in self._technique_weights:
            self._technique_weights[technique] = 1.0
        
        logger.info("Evasion learning reset")
    
    async def get_statistics(self) -> Dict:
        """إحصائيات التهرب التكيفي"""
        return {
            "techniques_count": len(self._technique_stats),
            "evasion_history": len(self._evasion_history),
            "current_state": self._state.value,
            "technique_weights": self._technique_weights,
            "active_evasions": len(self._active_evasions)
        }

