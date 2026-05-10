
import asyncio
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from collections import defaultdict

import logging

logger = logging.getLogger(__name__)


@dataclass
class DecisionProposal:
    """مقترح قرار من مصدر"""
    source: str
    action: str
    confidence: float
    reasoning: str
    timestamp: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class FusedDecision:
    """قرار مدمج"""
    action: str
    confidence: float
    sources: List[str]
    reasoning: List[str]
    timestamp: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)


class DecisionFusion:
    """
    دمج القرارات المتقدم
    
    الميزات:
    - جمع القرارات من مصادر متعددة
    - حل التعارضات بين القرارات
    - حساب الثقة الإجمالية
    - توليد قرار موحد
    """
    
    def __init__(self):
        self._proposals: List[DecisionProposal] = []
        self._fused_decisions: List[FusedDecision] = []
        
        logger.info("DecisionFusion initialized")
    
    async def add_proposal(
        self,
        source: str,
        action: str,
        confidence: float,
        reasoning: str,
        metadata: Dict = None
    ):
        """
        إضافة مقترح قرار من مصدر
        
        Args:
            source: المصدر
            action: الإجراء المقترح
            confidence: مستوى الثقة (0-1)
            reasoning: تبرير القرار
            metadata: بيانات إضافية
        """
        proposal = DecisionProposal(
            source=source,
            action=action,
            confidence=confidence,
            reasoning=reasoning,
            metadata=metadata or {}
        )
        
        self._proposals.append(proposal)
        
        logger.debug(f"Proposal added from {source}: {action} (confidence={confidence})")
    
    async def fuse(self) -> Optional[FusedDecision]:
        """
        دمج جميع المقترحات في قرار واحد
        
        Returns:
            القرار المدمج
        """
        if not self._proposals:
            return None
        
        # تجميع المقترحات حسب الإجراء
        grouped = defaultdict(list)
        for proposal in self._proposals:
            grouped[proposal.action].append(proposal)
        
        # حساب درجة كل إجراء
        action_scores = {}
        action_confidences = {}
        action_sources = {}
        action_reasoning = {}
        
        for action, proposals in grouped.items():
            total_confidence = sum(p.confidence for p in proposals)
            avg_confidence = total_confidence / len(proposals)
            
            # وزن حسب عدد المصادر
            source_weight = min(1.0, len(proposals) / 5.0)
            final_score = avg_confidence * (0.7 + 0.3 * source_weight)
            
            action_scores[action] = final_score
            action_confidences[action] = avg_confidence
            action_sources[action] = [p.source for p in proposals]
            action_reasoning[action] = [p.reasoning for p in proposals]
        
        # اختيار الإجراء بأعلى درجة
        best_action = max(action_scores, key=action_scores.get)
        
        fused = FusedDecision(
            action=best_action,
            confidence=action_confidences[best_action],
            sources=action_sources[best_action],
            reasoning=action_reasoning[best_action],
            metadata={
                "alternatives": {
                    action: {
                        "score": score,
                        "confidence": action_confidences[action],
                        "sources": action_sources[action]
                    }
                    for action, score in action_scores.items()
                    if action != best_action
                }
            }
        )
        
        self._fused_decisions.append(fused)
        
        # تنظيف المقترحات المؤقتة
        self._proposals.clear()
        
        logger.info(f"Decision fused: {best_action} (confidence={fused.confidence:.2f}, sources={len(fused.sources)})")
        
        return fused
    
    async def get_fusion_history(self, limit: int = 20) -> List[FusedDecision]:
        """الحصول على تاريخ القرارات المدمجة"""
        return self._fused_decisions[-limit:]
    
    async def get_statistics(self) -> Dict:
        """إحصائيات دمج القرارات"""
        if not self._fused_decisions:
            return {"total_fusions": 0}
        
        # توزيع أنواع القرارات
        action_distribution = {}
        for decision in self._fused_decisions:
            action_distribution[decision.action] = action_distribution.get(decision.action, 0) + 1
        
        # متوسط عدد المصادر
        avg_sources = sum(len(d.sources) for d in self._fused_decisions) / len(self._fused_decisions)
        
        return {
            "total_fusions": len(self._fused_decisions),
            "action_distribution": action_distribution,
            "average_sources_per_decision": avg_sources,
            "average_confidence": sum(d.confidence for d in self._fused_decisions) / len(self._fused_decisions),
            "pending_proposals": len(self._proposals)
        }

