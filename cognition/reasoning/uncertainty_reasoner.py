
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime
import random

import logging

logger = logging.getLogger(__name__)


@dataclass
class UncertainFact:
    """حقيقة غير مؤكدة"""
    statement: str
    confidence: float  # 0-1
    source: str
    timestamp: datetime = field(default_factory=datetime.now)
    evidence: List[str] = field(default_factory=list)


@dataclass
class Belief:
    """اعتقاد"""
    statement: str
    probability: float
    confidence_interval: Tuple[float, float]  # (lower, upper)
    last_updated: datetime = field(default_factory=datetime.now)


class UncertaintyReasoner:
    """
    مفكر عدم اليقين المتقدم
    
    الميزات:
    - تمثيل المعلومات غير المؤكدة
    - حساب الثقة في الاستنتاجات
    - دمج الأدلة من مصادر متعددة
    - تحديث المعتقدات بناءً على أدلة جديدة
    """
    
    def __init__(self):
        self._facts: List[UncertainFact] = []
        self._beliefs: Dict[str, Belief] = {}
        
        logger.info("UncertaintyReasoner initialized")
    
    async def add_fact(
        self,
        statement: str,
        confidence: float,
        source: str,
        evidence: List[str] = None
    ):
        """
        إضافة حقيقة غير مؤكدة
        
        Args:
            statement: العبارة
            confidence: مستوى الثقة (0-1)
            source: مصدر الحقيقة
            evidence: الأدلة
        """
        fact = UncertainFact(
            statement=statement,
            confidence=confidence,
            source=source,
            evidence=evidence or []
        )
        
        self._facts.append(fact)
        
        # تحديث الاعتقادات
        await self._update_belief(statement, confidence)
        
        logger.debug(f"Fact added: {statement[:50]}... (confidence={confidence})")
    
    async def _update_belief(self, statement: str, new_confidence: float):
        """
        تحديث الاعتقاد بناءً على حقيقة جديدة
        
        Args:
            statement: العبارة
            new_confidence: الثقة الجديدة
        """
        if statement in self._beliefs:
            belief = self._beliefs[statement]
            
            # دمج الثقة الجديدة مع الثقة الحالية (Bayesian updating)
            old_prob = belief.probability
            new_prob = (old_prob * new_confidence) / (old_prob * new_confidence + (1 - old_prob) * (1 - new_confidence))
            
            belief.probability = new_prob
            belief.last_updated = datetime.now()
            
            # تحديث فاصل الثقة
            margin = 1.96 * (new_prob * (1 - new_prob) / (len(self._facts) + 1)) ** 0.5
            belief.confidence_interval = (max(0, new_prob - margin), min(1, new_prob + margin))
        else:
            # اعتقاد جديد
            margin = 1.96 * (new_confidence * (1 - new_confidence)) ** 0.5
            belief = Belief(
                statement=statement,
                probability=new_confidence,
                confidence_interval=(max(0, new_confidence - margin), min(1, new_confidence + margin))
            )
            self._beliefs[statement] = belief
    
    async def get_confidence(self, statement: str) -> float:
        """
        الحصول على مستوى الثقة في عبارة معينة
        
        Args:
            statement: العبارة
        
        Returns:
            مستوى الثقة (0-1)
        """
        if statement in self._beliefs:
            return self._beliefs[statement].probability
        
        # حساب الثقة من الحقائق المرتبطة
        related_facts = [f for f in self._facts if statement in f.statement]
        if related_facts:
            avg_confidence = sum(f.confidence for f in related_facts) / len(related_facts)
            return avg_confidence
        
        return 0.5  # ثقة افتراضية
    
    async def combine_evidence(
        self,
        statement: str,
        evidences: List[Tuple[str, float]]
    ) -> float:
        """
        دمج الأدلة من مصادر متعددة
        
        Args:
            statement: العبارة
            evidences: قائمة (دليل, ثقة)
        
        Returns:
            الثقة المدمجة
        """
        if not evidences:
            return 0.5
        
        # صيغة دمج الأدلة (Dempster-Shafer)
        product = 1.0
        for _, conf in evidences:
            product *= conf
        
        # تطبيع
        combined = product / (product + (1 - product))
        
        # تحديث الاعتقاد
        await self._update_belief(statement, combined)
        
        return combined
    
    async def get_high_confidence_facts(self, threshold: float = 0.8) -> List[UncertainFact]:
        """الحصول على الحقائق عالية الثقة"""
        return [f for f in self._facts if f.confidence >= threshold]
    
    async def get_low_confidence_facts(self, threshold: float = 0.3) -> List[UncertainFact]:
        """الحصول على الحقائق منخفضة الثقة"""
        return [f for f in self._facts if f.confidence <= threshold]
    
    async def get_contradictions(self) -> List[Tuple[str, str, float]]:
        """
        كشف التناقضات بين الحقائق
        
        Returns:
            قائمة (عبارة1, عبارة2, درجة التناقض)
        """
        contradictions = []
        
        for i, fact1 in enumerate(self._facts):
            for fact2 in self._facts[i+1:]:
                if self._are_contradictory(fact1.statement, fact2.statement):
                    # حساب درجة التناقض
                    contradiction_score = (fact1.confidence + fact2.confidence) / 2
                    contradictions.append((fact1.statement, fact2.statement, contradiction_score))
        
        return contradictions
    
    def _are_contradictory(self, statement1: str, statement2: str) -> bool:
        """التحقق من تناقض عبارتين"""
        # بحث بسيط عن نفي
        if "not " in statement2.lower() and statement1.lower().replace("not ", "") in statement2.lower():
            return True
        if "not " in statement1.lower() and statement2.lower().replace("not ", "") in statement1.lower():
            return True
        return False
    
    async def get_beliefs_summary(self) -> Dict:
        """ملخص المعتقدات"""
        return {
            "total_beliefs": len(self._beliefs),
            "average_probability": sum(b.probability for b in self._beliefs.values()) / len(self._beliefs) if self._beliefs else 0,
            "high_confidence_beliefs": sum(1 for b in self._beliefs.values() if b.probability >= 0.8),
            "low_confidence_beliefs": sum(1 for b in self._beliefs.values() if b.probability <= 0.3),
            "beliefs": [
                {
                    "statement": b.statement[:100],
                    "probability": b.probability,
                    "confidence_interval": b.confidence_interval
                }
                for b in list(self._beliefs.values())[:10]
            ]
        }
    
    async def get_statistics(self) -> Dict:
        """إحصائيات المفكر"""
        return {
            "total_facts": len(self._facts),
            "total_beliefs": len(self._beliefs),
            "average_confidence": sum(f.confidence for f in self._facts) / len(self._facts) if self._facts else 0,
            "high_confidence_facts": len(await self.get_high_confidence_facts()),
            "low_confidence_facts": len(await self.get_low_confidence_facts()),
            "contradictions_found": len(await self.get_contradictions()),
            "unique_sources": len(set(f.source for f in self._facts))
        }

