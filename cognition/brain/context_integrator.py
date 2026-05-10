
import asyncio
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from collections import defaultdict

import logging

logger = logging.getLogger(__name__)


@dataclass
class ContextFragment:
    """جزء سياقي"""
    source: str
    data: Dict[str, Any]
    timestamp: datetime
    confidence: float
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class IntegratedContext:
    """سياق مدمج"""
    timestamp: datetime
    fragments: List[ContextFragment]
    synthesized_data: Dict[str, Any]
    confidence: float
    metadata: Dict[str, Any] = field(default_factory=dict)


class ContextIntegrator:
    """
    دمج السياق المتقدم
    
    الميزات:
    - جمع المعلومات من مصادر متعددة
    - دمج البيانات في سياق واحد
    - حل التعارضات
    - تحديث السياق ديناميكياً
    """
    
    def __init__(self):
        self._fragments: List[ContextFragment] = []
        self._integrated_context: Optional[IntegratedContext] = None
        self._source_weights: Dict[str, float] = defaultdict(lambda: 0.5)
        
        logger.info("ContextIntegrator initialized")
    
    async def add_fragment(
        self,
        source: str,
        data: Dict[str, Any],
        confidence: float = 0.8,
        metadata: Dict = None
    ):
        """
        إضافة جزء سياقي جديد
        
        Args:
            source: المصدر
            data: البيانات
            confidence: مستوى الثقة
            metadata: بيانات إضافية
        """
        fragment = ContextFragment(
            source=source,
            data=data,
            timestamp=datetime.now(),
            confidence=confidence,
            metadata=metadata or {}
        )
        
        self._fragments.append(fragment)
        
        # تحديث وزن المصدر بناءً على الثقة
        self._source_weights[source] = confidence
        
        # إعادة دمج السياق
        await self._integrate()
        
        logger.debug(f"Fragment added from {source} (confidence={confidence})")
    
    async def _integrate(self):
        """دمج جميع الأجزاء في سياق واحد"""
        if not self._fragments:
            return
        
        # تجميع البيانات حسب المفتاح
        aggregated = defaultdict(list)
        
        for fragment in self._fragments:
            weight = self._source_weights[fragment.source]
            for key, value in fragment.data.items():
                aggregated[key].append({
                    "value": value,
                    "weight": weight,
                    "confidence": fragment.confidence
                })
        
        # دمج القيم (اختيار القيمة ذات الثقة الأعلى)
        synthesized = {}
        overall_confidence = 0.0
        total_weight = 0
        
        for key, values in aggregated.items():
            # اختيار القيمة ذات الثقة الأعلى
            best = max(values, key=lambda x: x["confidence"])
            synthesized[key] = best["value"]
            overall_confidence += best["confidence"] * best["weight"]
            total_weight += best["weight"]
        
        if total_weight > 0:
            overall_confidence /= total_weight
        
        self._integrated_context = IntegratedContext(
            timestamp=datetime.now(),
            fragments=self._fragments.copy(),
            synthesized_data=synthesized,
            confidence=overall_confidence
        )
        
        logger.info(f"Context integrated: {len(synthesized)} keys, confidence={overall_confidence:.2f}")
    
    async def get_context(self) -> Optional[IntegratedContext]:
        """الحصول على السياق المدمج الحالي"""
        return self._integrated_context
    
    async def get_value(self, key: str, default: Any = None) -> Any:
        """
        الحصول على قيمة محددة من السياق
        
        Args:
            key: المفتاح
            default: القيمة الافتراضية
        
        Returns:
            القيمة أو القيمة الافتراضية
        """
        if not self._integrated_context:
            return default
        
        return self._integrated_context.synthesized_data.get(key, default)
    
    async def clear_old_fragments(self, max_age_seconds: int = 3600):
        """
        تنظيف الأجزاء القديمة
        
        Args:
            max_age_seconds: الحد الأقصى للعمر بالثواني
        """
        cutoff = datetime.now().timestamp() - max_age_seconds
        
        self._fragments = [
            f for f in self._fragments
            if f.timestamp.timestamp() > cutoff
        ]
        
        await self._integrate()
        
        logger.info(f"Cleared fragments older than {max_age_seconds}s")
    
    async def get_statistics(self) -> Dict:
        """إحصائيات الدامج"""
        return {
            "total_fragments": len(self._fragments),
            "sources_count": len(self._source_weights),
            "source_weights": dict(self._source_weights),
            "has_integrated_context": self._integrated_context is not None,
            "integrated_keys": len(self._integrated_context.synthesized_data) if self._integrated_context else 0,
            "context_confidence": self._integrated_context.confidence if self._integrated_context else 0.0
        }

