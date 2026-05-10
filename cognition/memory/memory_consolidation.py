
import asyncio
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from .episodic_memory import EpisodicMemory
from .semantic_memory import SemanticMemory
from .attack_memory import AttackMemory

import logging

logger = logging.getLogger(__name__)


@dataclass
class ConsolidationStats:
    """إحصائيات الدمج"""
    episodes_consolidated: int
    concepts_generalized: int
    attacks_patterns_updated: int
    timestamp: datetime = field(default_factory=datetime.now)


class MemoryConsolidation:
    """
    دمج الذاكرة المتقدم
    
    الميزات:
    - دمج الذكريات المتشابهة
    - استخلاص أنماط عامة من الذكريات الفردية
    - تحديث نماذج الهجوم بناءً على الخبرة
    - جدولة دورية للدمج
    """
    
    def __init__(
        self,
        episodic: EpisodicMemory,
        semantic: SemanticMemory,
        attack: AttackMemory,
        consolidation_interval: int = 3600  # ساعة واحدة
    ):
        self._episodic = episodic
        self._semantic = semantic
        self._attack = attack
        self._consolidation_interval = consolidation_interval
        self._consolidation_task: Optional[asyncio.Task] = None
        self._running = False
        self._stats: List[ConsolidationStats] = []
        
        logger.info("MemoryConsolidation initialized")
    
    async def start(self):
        """بدء الدمج الدوري"""
        if self._running:
            return
        
        self._running = True
        self._consolidation_task = asyncio.create_task(self._consolidation_loop())
        
        logger.info("MemoryConsolidation started")
    
    async def stop(self):
        """إيقاف الدمج الدوري"""
        self._running = False
        
        if self._consolidation_task:
            self._consolidation_task.cancel()
            try:
                await self._consolidation_task
            except asyncio.CancelledError:
                pass
        
        logger.info("MemoryConsolidation stopped")
    
    async def _consolidation_loop(self):
        """حلقة الدمج الدورية"""
        while self._running:
            await asyncio.sleep(self._consolidation_interval)
            await self.consolidate()
    
    async def consolidate(self) -> ConsolidationStats:
        """
        تنفيذ عملية الدمج الكاملة
        """
        stats = ConsolidationStats(
            episodes_consolidated=0,
            concepts_generalized=0,
            attacks_patterns_updated=0
        )
        
        # 1. دمج الذكريات العرضية المتشابهة
        stats.episodes_consolidated = await self._consolidate_episodic()
        
        # 2. استخلاص مفاهيم عامة من الذكريات
        stats.concepts_generalized = await self._generalize_concepts()
        
        # 3. تحديث أنماط الهجوم
        stats.attacks_patterns_updated = await self._update_attack_patterns()
        
        self._stats.append(stats)
        
        # الاحتفاظ بآخر 100 إحصائية فقط
        if len(self._stats) > 100:
            self._stats.pop(0)
        
        logger.info(f"Memory consolidation completed: {stats}")
        
        return stats
    
    async def _consolidate_episodic(self) -> int:
        """دمج الذكريات العرضية المتشابهة"""
        consolidated = 0
        
        # الحصول على جميع الذكريات العرضية (محاكاة)
        # في الإصدار الكامل، سيتم استرجاعها من episodic memory
        
        return consolidated
    
    async def _generalize_concepts(self) -> int:
        """
        استخلاص مفاهيم عامة من الذكريات الفردية
        """
        generalized = 0
        
        # تحليل أنماط النجاح من الذاكرة العرضية
        successful_episodes = await self._episodic.retrieve_successful(limit=50)
        
        # تجميع حسب نوع الحدث
        events_by_type = {}
        for episode in successful_episodes:
            if episode.event_type not in events_by_type:
                events_by_type[episode.event_type] = []
            events_by_type[episode.event_type].append(episode)
        
        # استخلاص مفاهيم عامة لكل نوع
        for event_type, episodes in events_by_type.items():
            if len(episodes) >= 3:
                # استخلاص الخصائص المشتركة
                common_context = {}
                for episode in episodes[:5]:
                    for key, value in episode.context.items():
                        if key not in common_context:
                            common_context[key] = []
                        common_context[key].append(value)
                
                # حساب التكرار
                for key, values in common_context.items():
                    if len(values) >= 3 and len(set(str(v) for v in values)) == 1:
                        # إنشاء مفهوم جديد
                        concept_name = f"successful_{event_type}_{key}"
                        
                        await self._semantic.add_concept(
                            name=concept_name,
                            category=event_type,
                            properties={key: values[0]},
                            relationships=[],
                            confidence=0.7
                        )
                        generalized += 1
        
        return generalized
    
    async def _update_attack_patterns(self) -> int:
        """
        تحديث أنماط الهجوم بناءً على الخبرة الجديدة
        """
        updated = 0
        
        # الحصول على الهجمات الناجحة الحديثة
        successful_attacks = await self._attack.get_successful_attacks(limit=50)
        
        # تجميع حسب نوع الثغرة
        attacks_by_type = {}
        for attack in successful_attacks:
            if attack.vulnerability_type not in attacks_by_type:
                attacks_by_type[attack.vulnerability_type] = []
            attacks_by_type[attack.vulnerability_type].append(attack)
        
        # تحديث الأنماط لكل نوع
        for vuln_type, attacks in attacks_by_type.items():
            if len(attacks) >= 5:
                # حساب معدل نجاح جديد
                total = len(attacks)
                successful = sum(1 for a in attacks if a.success)
                new_rate = successful / total if total > 0 else 0
                
                # تحديث النمط
                patterns = await self._attack.get_patterns()
                for pattern in patterns:
                    if pattern.vulnerability_type == vuln_type:
                        pattern.success_rate = (pattern.success_rate + new_rate) / 2
                        updated += 1
        
        return updated
    
    async def get_statistics(self) -> Dict:
        """إحصائيات الدمج"""
        recent_stats = self._stats[-5:] if self._stats else []
        
        return {
            "total_consolidations": len(self._stats),
            "recent_consolidations": [
                {
                    "episodes_consolidated": s.episodes_consolidated,
                    "concepts_generalized": s.concepts_generalized,
                    "attacks_patterns_updated": s.attacks_patterns_updated,
                    "timestamp": s.timestamp.isoformat()
                }
                for s in recent_stats
            ],
            "consolidation_interval": self._consolidation_interval,
            "running": self._running
        }

