
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime

from .episodic_memory import EpisodicMemory
from .semantic_memory import SemanticMemory
from .working_memory import WorkingMemory
from .procedural_memory import ProceduralMemory
from .vector_memory import VectorMemory
from .attack_memory import AttackMemory

import logging

logger = logging.getLogger(__name__)


@dataclass
class MemoryQuery:
    """استعلام ذاكرة"""
    query_text: str
    memory_types: List[str]  # episodic, semantic, working, procedural, attack
    filters: Dict[str, Any] = field(default_factory=dict)
    limit: int = 10


@dataclass
class MemoryResult:
    """نتيجة استرجاع"""
    source: str
    data: Any
    relevance: float
    timestamp: datetime = field(default_factory=datetime.now)


class MemoryRetriever:
    """
    مسترجع الذاكرة المتقدم
    
    الميزات:
    - استرجاع من أنواع متعددة من الذاكرة
    - دمج النتائج من مصادر مختلفة
    - ترتيب حسب الأهمية
    - استعلامات موحدة
    """
    
    def __init__(
        self,
        episodic: EpisodicMemory,
        semantic: SemanticMemory,
        working: WorkingMemory,
        procedural: ProceduralMemory,
        vector: VectorMemory,
        attack: AttackMemory
    ):
        self._episodic = episodic
        self._semantic = semantic
        self._working = working
        self._procedural = procedural
        self._vector = vector
        self._attack = attack
        
        logger.info("MemoryRetriever initialized")
    
    async def query(
        self,
        query: MemoryQuery
    ) -> List[MemoryResult]:
        """
        تنفيذ استعلام على أنواع الذاكرة
        
        Args:
            query: استعلام الذاكرة
        
        Returns:
            قائمة بالنتائج المرتبة حسب الأهمية
        """
        results = []
        
        # استعلام من الذاكرة العرضية
        if "episodic" in query.memory_types:
            episodic_results = await self._query_episodic(query)
            results.extend(episodic_results)
        
        # استعلام من الذاكرة الدلالية
        if "semantic" in query.memory_types:
            semantic_results = await self._query_semantic(query)
            results.extend(semantic_results)
        
        # استعلام من الذاكرة العاملة
        if "working" in query.memory_types:
            working_results = await self._query_working(query)
            results.extend(working_results)
        
        # استعلام من الذاكرة الإجرائية
        if "procedural" in query.memory_types:
            procedural_results = await self._query_procedural(query)
            results.extend(procedural_results)
        
        # استعلام من ذاكرة الهجمات
        if "attack" in query.memory_types:
            attack_results = await self._query_attack(query)
            results.extend(attack_results)
        
        # ترتيب حسب الأهمية
        results.sort(key=lambda x: x.relevance, reverse=True)
        
        return results[:query.limit]
    
    async def _query_episodic(
        self,
        query: MemoryQuery
    ) -> List[MemoryResult]:
        """استعلام من الذاكرة العرضية"""
        results = []
        
        # البحث حسب النوع
        if "event_type" in query.filters:
            episodes = await self._episodic.retrieve_by_type(
                query.filters["event_type"],
                limit=query.limit
            )
            for episode in episodes:
                results.append(MemoryResult(
                    source="episodic",
                    data=episode,
                    relevance=episode.importance
                ))
        
        # البحث حسب السياق المشابه
        if "context" in query.filters:
            episodes = await self._episodic.retrieve_by_similar_context(
                query.filters["context"],
                limit=query.limit
            )
            for episode in episodes:
                results.append(MemoryResult(
                    source="episodic",
                    data=episode,
                    relevance=episode.importance * 0.8
                ))
        
        return results
    
    async def _query_semantic(
        self,
        query: MemoryQuery
    ) -> List[MemoryResult]:
        """استعلام من الذاكرة الدلالية"""
        results = []
        
        # البحث عن مفاهيم مشابهة
        similar = await self._semantic.find_similar_concepts(
            query.query_text,
            limit=query.limit
        )
        
        for name, score in similar:
            concept = await self._semantic.get_concept(name)
            if concept:
                results.append(MemoryResult(
                    source="semantic",
                    data=concept,
                    relevance=score
                ))
        
        return results
    
    async def _query_working(
        self,
        query: MemoryQuery
    ) -> List[MemoryResult]:
        """استعلام من الذاكرة العاملة"""
        results = []
        
        # الحصول على جميع العناصر
        all_items = await self._working.get_all()
        
        for key, value in all_items.items():
            relevance = 0.5
            
            # تطابق المفتاح مع نص الاستعلام
            if query.query_text.lower() in key.lower():
                relevance = 0.8
            
            # تصفية حسب الأولوية
            item_data = await self._working.get_item(key)
            if item_data and "min_priority" in query.filters:
                if item_data.priority < query.filters["min_priority"]:
                    continue
            
            results.append(MemoryResult(
                source="working",
                data={"key": key, "value": value},
                relevance=relevance
            ))
        
        return results
    
    async def _query_procedural(
        self,
        query: MemoryQuery
    ) -> List[MemoryResult]:
        """استعلام من الذاكرة الإجرائية"""
        results = []
        
        # البحث عن إجراءات حسب العلامات
        tags = query.filters.get("tags", [])
        if tags:
            procedures = await self._procedural.find_by_tags(tags)
            
            for proc in procedures:
                results.append(MemoryResult(
                    source="procedural",
                    data=proc,
                    relevance=0.7
                ))
        
        # اقتراح أفضل إجراء
        best = await self._procedural.suggest_best_procedure(
            query.query_text,
            tags
        )
        
        if best:
            results.append(MemoryResult(
                source="procedural",
                data=best,
                relevance=0.9
            ))
        
        return results
    
    async def _query_attack(
        self,
        query: MemoryQuery
    ) -> List[MemoryResult]:
        """استعلام من ذاكرة الهجمات"""
        results = []
        
        # الحصول على الهجمات الناجحة
        vuln_type = query.filters.get("vulnerability_type")
        attacks = await self._attack.get_successful_attacks(
            vulnerability_type=vuln_type,
            limit=query.limit
        )
        
        for attack in attacks:
            results.append(MemoryResult(
                source="attack",
                data=attack,
                relevance=0.8 if attack.success else 0.3
            ))
        
        # الحصول على أفضل الحمولات
        if vuln_type:
            best_payloads = await self._attack.get_best_payloads(
                vuln_type,
                limit=3
            )
            
            for payload, rate in best_payloads:
                results.append(MemoryResult(
                    source="attack",
                    data={"payload": payload, "success_rate": rate},
                    relevance=rate
                ))
        
        return results
    
    async def get_all_memories_summary(self) -> Dict:
        """ملخص جميع أنواع الذاكرة"""
        return {
            "episodic": await self._episodic.get_statistics(),
            "semantic": await self._semantic.get_statistics(),
            "working": await self._working.get_statistics(),
            "procedural": await self._procedural.get_statistics(),
            "attack": await self._attack.get_statistics()
        }

