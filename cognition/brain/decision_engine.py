
import asyncio
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

import logging

logger = logging.getLogger(__name__)


class DecisionType(Enum):
    """أنواع القرارات"""
    ATTACK = "attack"
    DEFEND = "defend"
    RECON = "recon"
    LEARN = "learn"
    ADAPT = "adapt"
    STOP = "stop"


@dataclass
class DecisionOption:
    """خيار قرار"""
    type: DecisionType
    action: str
    confidence: float
    expected_impact: float
    risk_level: str
    resources_needed: List[str]
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Decision:
    """قرار متخذ"""
    id: str
    timestamp: datetime
    selected_option: DecisionOption
    alternatives: List[DecisionOption]
    reasoning: str
    metadata: Dict[str, Any] = field(default_factory=dict)


class DecisionEngine:
    """
    محرك القرارات المتقدم
    
    الميزات:
    - تقييم الخيارات المتعددة
    - موازنة المخاطر والمكافآت
    - تعلم من القرارات السابقة
    - تكامل مع نظام المكافآت
    - دعم القرارات الجماعية
    """
    
    def __init__(self):
        self._decision_history: List[Decision] = []
        self._decision_cache: Dict[str, DecisionOption] = {}
        
        logger.info("DecisionEngine initialized")
    
    async def evaluate_options(
        self,
        options: List[DecisionOption],
        context: Dict[str, Any] = None
    ) -> Decision:
        """
        تقييم الخيارات واختيار الأفضل
        
        Args:
            options: قائمة الخيارات المتاحة
            context: سياق القرار (الأولويات، القيود، إلخ)
        
        Returns:
            القرار المتخذ
        """
        import uuid
        decision_id = str(uuid.uuid4())[:8]
        
        # حساب درجة كل خيار
        scored_options = []
        for option in options:
            score = await self._calculate_score(option, context)
            scored_options.append((score, option))
        
        # ترتيب حسب الدرجة
        scored_options.sort(key=lambda x: x[0], reverse=True)
        
        best_option = scored_options[0][1] if scored_options else None
        alternatives = [opt for _, opt in scored_options[1:4]] if len(scored_options) > 1 else []
        
        # بناء التبرير
        reasoning = await self._generate_reasoning(best_option, scored_options, context)
        
        decision = Decision(
            id=decision_id,
            timestamp=datetime.now(),
            selected_option=best_option,
            alternatives=alternatives,
            reasoning=reasoning
        )
        
        self._decision_history.append(decision)
        
        logger.info(f"Decision made: {best_option.type.value} - {best_option.action} (confidence={best_option.confidence})")
        
        return decision
    
    async def _calculate_score(
        self,
        option: DecisionOption,
        context: Dict = None
    ) -> float:
        """
        حساب درجة الخيار
        
        Args:
            option: الخيار
            context: سياق القرار
        
        Returns:
            الدرجة (0-100)
        """
        score = 0.0
        
        # الثقة
        score += option.confidence * 30
        
        # التأثير المتوقع
        score += option.expected_impact * 30
        
        # المخاطر
        risk_multiplier = {
            "low": 1.0,
            "medium": 0.8,
            "high": 0.5,
            "critical": 0.2
        }.get(option.risk_level, 0.5)
        score += 20 * risk_multiplier
        
        # الموارد المتاحة
        if context and "available_resources" in context:
            available = set(context["available_resources"])
            required = set(option.resources_needed)
            if required.issubset(available):
                score += 20
            else:
                missing = len(required - available)
                score += max(0, 20 - missing * 5)
        
        return min(score, 100.0)
    
    async def _generate_reasoning(
        self,
        best_option: DecisionOption,
        scored_options: List[Tuple[float, DecisionOption]],
        context: Dict = None
    ) -> str:
        """توليد تبرير للقرار"""
        reasons = []
        
        best_score = scored_options[0][0]
        second_score = scored_options[1][0] if len(scored_options) > 1 else 0
        
        reasons.append(f"Selected option has highest score ({best_score:.1f})")
        
        if second_score > 0:
            reasons.append(f"Second best option scored {second_score:.1f} ({best_score - second_score:.1f} difference)")
        
        reasons.append(f"Action: {best_option.action}")
        reasons.append(f"Risk level: {best_option.risk_level}")
        
        return "; ".join(reasons)
    
    async def get_decision_history(self, limit: int = 50) -> List[Decision]:
        """الحصول على تاريخ القرارات"""
        return self._decision_history[-limit:]
    
    async def get_statistics(self) -> Dict:
        """إحصائيات المحرك"""
        if not self._decision_history:
            return {"total_decisions": 0}
        
        # توزيع أنواع القرارات
        type_distribution = {}
        for decision in self._decision_history:
            dec_type = decision.selected_option.type.value
            type_distribution[dec_type] = type_distribution.get(dec_type, 0) + 1
        
        # متوسط الثقة
        avg_confidence = sum(d.selected_option.confidence for d in self._decision_history) / len(self._decision_history)
        
        # توزيع المخاطر
        risk_distribution = {}
        for decision in self._decision_history:
            risk = decision.selected_option.risk_level
            risk_distribution[risk] = risk_distribution.get(risk, 0) + 1
        
        return {
            "total_decisions": len(self._decision_history),
            "type_distribution": type_distribution,
            "average_confidence": avg_confidence,
            "risk_distribution": risk_distribution,
            "most_common_decision": max(type_distribution, key=type_distribution.get) if type_distribution else None
        }

