
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

import logging

logger = logging.getLogger(__name__)


class RiskLevel(Enum):
    """مستويات المخاطر"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NEGLIGIBLE = "negligible"


@dataclass
class RiskAssessment:
    """تقييم المخاطر"""
    level: RiskLevel
    score: float  # 0-100
    factors: List[str]
    mitigation: List[str]
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class RiskFactor:
    """عامل خطر"""
    name: str
    weight: float
    current_value: float
    threshold: float
    impact: str


class RiskEngine:
    """
    محرك المخاطر المتقدم
    
    الميزات:
    - تقييم المخاطر للقرارات والخطط
    - تحديد عوامل الخطر
    - اقتراح استراتيجيات التخفيف
    - تتبع تاريخ المخاطر
    """
    
    def __init__(self):
        self._risk_factors: Dict[str, RiskFactor] = {}
        self._assessments: List[RiskAssessment] = []
        
        # تهيئة عوامل الخطر الافتراضية
        self._init_default_risk_factors()
        
        logger.info("RiskEngine initialized")
    
    def _init_default_risk_factors(self):
        """تهيئة عوامل الخطر الافتراضية"""
        
        self._risk_factors = {
            "detection_risk": RiskFactor(
                name="Detection Risk",
                weight=0.3,
                current_value=0.5,
                threshold=0.7,
                impact="High"
            ),
            "data_loss_risk": RiskFactor(
                name="Data Loss Risk",
                weight=0.25,
                current_value=0.3,
                threshold=0.6,
                impact="Critical"
            ),
            "system_damage_risk": RiskFactor(
                name="System Damage Risk",
                weight=0.2,
                current_value=0.2,
                threshold=0.5,
                impact="High"
            ),
            "legal_risk": RiskFactor(
                name="Legal Risk",
                weight=0.15,
                current_value=0.4,
                threshold=0.6,
                impact="Critical"
            ),
            "reputational_risk": RiskFactor(
                name="Reputational Risk",
                weight=0.1,
                current_value=0.3,
                threshold=0.7,
                impact="Medium"
            )
        }
    
    async def assess_risk(
        self,
        action_type: str,
        context: Dict[str, Any] = None
    ) -> RiskAssessment:
        """
        تقييم المخاطر لعملية معينة
        
        Args:
            action_type: نوع العملية
            context: سياق العملية
        
        Returns:
            تقييم المخاطر
        """
        total_score = 0.0
        factors = []
        
        for factor in self._risk_factors.values():
            # حساب مساهمة هذا العامل في المخاطر
            contribution = factor.weight * factor.current_value * 100
            total_score += contribution
            
            if factor.current_value > factor.threshold:
                factors.append(f"{factor.name} exceeds threshold ({factor.current_value:.2f} > {factor.threshold})")
        
        # تحديث بعض العوامل بناءً على السياق
        if context:
            if context.get("stealth_required", False):
                self._risk_factors["detection_risk"].current_value = 0.8
                factors.append("Stealth required - increased detection risk")
            
            if context.get("critical_target", False):
                self._risk_factors["legal_risk"].current_value = 0.7
                factors.append("Critical target - increased legal risk")
        
        # تحديد مستوى المخاطر
        if total_score >= 80:
            level = RiskLevel.CRITICAL
        elif total_score >= 60:
            level = RiskLevel.HIGH
        elif total_score >= 40:
            level = RiskLevel.MEDIUM
        elif total_score >= 20:
            level = RiskLevel.LOW
        else:
            level = RiskLevel.NEGLIGIBLE
        
        # اقتراح استراتيجيات التخفيف
        mitigation = await self._suggest_mitigation(level, factors)
        
        assessment = RiskAssessment(
            level=level,
            score=total_score,
            factors=factors,
            mitigation=mitigation
        )
        
        self._assessments.append(assessment)
        
        logger.info(f"Risk assessment: {level.value} (score={total_score:.1f})")
        return assessment
    
    async def _suggest_mitigation(
        self,
        level: RiskLevel,
        factors: List[str]
    ) -> List[str]:
        """اقتراح استراتيجيات تخفيف المخاطر"""
        mitigation = []
        
        if level in [RiskLevel.CRITICAL, RiskLevel.HIGH]:
            mitigation.append("Stop operation and review before proceeding")
            mitigation.append("Implement additional security measures")
        
        if any("detection" in f.lower() for f in factors):
            mitigation.append("Use stealth techniques to avoid detection")
            mitigation.append("Implement traffic obfuscation")
        
        if any("legal" in f.lower() for f in factors):
            mitigation.append("Ensure proper authorization")
            mitigation.append("Document all actions for legal review")
        
        if any("data" in f.lower() for f in factors):
            mitigation.append("Create backup before operations")
            mitigation.append("Implement rollback procedures")
        
        if not mitigation:
            mitigation.append("Monitor operation closely")
            mitigation.append("Have incident response plan ready")
        
        return mitigation
    
    async def update_risk_factor(
        self,
        factor_name: str,
        new_value: float
    ) -> bool:
        """
        تحديث قيمة عامل خطر
        
        Args:
            factor_name: اسم عامل الخطر
            new_value: القيمة الجديدة
        
        Returns:
            نجاح العملية
        """
        if factor_name in self._risk_factors:
            self._risk_factors[factor_name].current_value = new_value
            logger.debug(f"Risk factor {factor_name} updated to {new_value}")
            return True
        return False
    
    async def get_current_risk_profile(self) -> Dict:
        """الحصول على ملف المخاطر الحالي"""
        return {
            "risk_factors": {
                name: {
                    "current_value": factor.current_value,
                    "threshold": factor.threshold,
                    "weight": factor.weight,
                    "impact": factor.impact,
                    "status": "exceeded" if factor.current_value > factor.threshold else "normal"
                }
                for name, factor in self._risk_factors.items()
            },
            "overall_score": sum(f.weight * f.current_value * 100 for f in self._risk_factors.values()),
            "highest_risk_factor": max(
                self._risk_factors.items(),
                key=lambda x: x[1].current_value,
                default=(None, None)
            )[0]
        }
    
    async def get_assessment_history(self, limit: int = 10) -> List[Dict]:
        """الحصول على تاريخ تقييمات المخاطر"""
        return [
            {
                "level": a.level.value,
                "score": a.score,
                "factors": a.factors,
                "mitigation": a.mitigation,
                "timestamp": a.timestamp.isoformat()
            }
            for a in self._assessments[-limit:]
        ]
    
    async def get_statistics(self) -> Dict:
        """إحصائيات المحرك"""
        if not self._assessments:
            return {"total_assessments": 0}
        
        level_counts = {
            RiskLevel.CRITICAL: 0,
            RiskLevel.HIGH: 0,
            RiskLevel.MEDIUM: 0,
            RiskLevel.LOW: 0,
            RiskLevel.NEGLIGIBLE: 0
        }
        
        for assessment in self._assessments:
            level_counts[assessment.level] += 1
        
        return {
            "total_assessments": len(self._assessments),
            "risk_level_distribution": {k.value: v for k, v in level_counts.items()},
            "average_risk_score": sum(a.score for a in self._assessments) / len(self._assessments),
            "highest_risk_score": max(a.score for a in self._assessments),
            "lowest_risk_score": min(a.score for a in self._assessments)
        }

