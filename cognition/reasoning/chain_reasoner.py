
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from collections import defaultdict

import logging

logger = logging.getLogger(__name__)


@dataclass
class ChainEvent:
    """حدث في السلسلة"""
    id: str
    description: str
    timestamp: datetime
    confidence: float
    previous_events: List[str]  # معرفات الأحداث السابقة
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class LogicChain:
    """سلسلة منطقية"""
    id: str
    events: List[ChainEvent]
    conclusion: str
    confidence: float
    created_at: datetime = field(default_factory=datetime.now)


class ChainReasoner:
    """
    مفكر السلاسل المتقدم
    
    الميزات:
    - ربط الأحداث المنطقية في سلاسل
    - استنتاج العلاقات بين الأحداث
    - تتبع التسلسل الزمني
    - بناء سلاسل استدلالية معقدة
    """
    
    def __init__(self):
        self._chains: Dict[str, LogicChain] = {}
        self._event_index: Dict[str, List[str]] = defaultdict(list)  # نوع الحدث -> معرفات الأحداث
        
        logger.info("ChainReasoner initialized")
    
    async def add_event(
        self,
        description: str,
        event_type: str,
        confidence: float = 0.8,
        previous_events: List[str] = None,
        metadata: Dict = None
    ) -> str:
        """
        إضافة حدث جديد إلى السلسلة
        
        Args:
            description: وصف الحدث
            event_type: نوع الحدث
            confidence: مستوى الثقة
            previous_events: الأحداث السابقة المرتبطة
            metadata: بيانات إضافية
        
        Returns:
            معرف الحدث
        """
        import uuid
        event_id = str(uuid.uuid4())[:8]
        
        event = ChainEvent(
            id=event_id,
            description=description,
            timestamp=datetime.now(),
            confidence=confidence,
            previous_events=previous_events or [],
            metadata=metadata or {}
        )
        
        # إضافة إلى فهرس الأحداث
        self._event_index[event_type].append(event_id)
        
        logger.debug(f"Event added: {event_type} - {description[:50]}...")
        return event_id
    
    async def create_chain(
        self,
        event_ids: List[str],
        conclusion: str,
        chain_id: str = None
    ) -> LogicChain:
        """
        إنشاء سلسلة منطقية من مجموعة أحداث
        
        Args:
            event_ids: قائمة معرفات الأحداث
            conclusion: الاستنتاج النهائي
            chain_id: معرف السلسلة (اختياري)
        
        Returns:
            السلسلة المنطقية
        """
        import uuid
        if not chain_id:
            chain_id = str(uuid.uuid4())[:8]
        
        events = []
        total_confidence = 0.0
        
        for eid in event_ids:
            event = await self.get_event(eid)
            if event:
                events.append(event)
                total_confidence += event.confidence
        
        avg_confidence = total_confidence / len(events) if events else 0.0
        
        chain = LogicChain(
            id=chain_id,
            events=events,
            conclusion=conclusion,
            confidence=avg_confidence
        )
        
        self._chains[chain_id] = chain
        
        logger.info(f"Chain created: {chain_id} with {len(events)} events")
        return chain
    
    async def get_event(self, event_id: str) -> Optional[ChainEvent]:
        """الحصول على حدث بالمعرف"""
        for event_type, event_ids in self._event_index.items():
            if event_id in event_ids:
                # البحث عن الحدث الفعلي (محاكاة)
                # في الإصدار الكامل، سيتم استرجاع الحدث من قاعدة البيانات
                pass
        return None
    
    async def get_chain(self, chain_id: str) -> Optional[LogicChain]:
        """الحصول على سلسلة منطقية"""
        return self._chains.get(chain_id)
    
    async def get_events_by_type(self, event_type: str) -> List[str]:
        """الحصول على أحداث حسب النوع"""
        return self._event_index.get(event_type, [])
    
    async def trace_chain(self, event_id: str) -> List[ChainEvent]:
        """
        تتبع السلسلة من حدث معين إلى الأحداث السابقة
        
        Args:
            event_id: معرف حدث البداية
        
        Returns:
            قائمة بالأحداث في السلسلة
        """
        event = await self.get_event(event_id)
        if not event:
            return []
        
        chain = [event]
        
        # تتبع الأحداث السابقة بشكل متكرر
        for prev_id in event.previous_events:
            prev_chain = await self.trace_chain(prev_id)
            chain.extend(prev_chain)
        
        return chain
    
    async def find_chains_by_conclusion(self, conclusion: str) -> List[LogicChain]:
        """البحث عن سلاسل حسب الاستنتاج"""
        return [c for c in self._chains.values() if c.conclusion == conclusion]
    
    async def get_statistics(self) -> Dict:
        """إحصائيات المفكر"""
        total_events = sum(len(ids) for ids in self._event_index.values())
        total_chains = len(self._chains)
        
        # توزيع أنواع الأحداث
        event_types = {etype: len(ids) for etype, ids in self._event_index.items()}
        
        # متوسط الثقة
        avg_confidence = sum(c.confidence for c in self._chains.values()) / total_chains if total_chains > 0 else 0
        
        return {
            "total_events": total_events,
            "total_chains": total_chains,
            "event_types": event_types,
            "average_chain_confidence": avg_confidence,
            "unique_event_types": len(self._event_index)
        }

