
import json
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from collections import deque

import logging

logger = logging.getLogger(__name__)


@dataclass
class Episode:
    """حدث/تجربة مخزنة"""
    id: str
    timestamp: datetime
    event_type: str
    description: str
    outcome: str
    success: bool
    context: Dict[str, Any]
    metadata: Dict[str, Any] = field(default_factory=dict)
    importance: float = 0.5


class EpisodicMemory:
    """
    الذاكرة العرضية المتقدمة
    
    الميزات:
    - تخزين الأحداث والتجارب
    - استرجاع التجارب حسب النوع أو السياق
    - تصنيف حسب الأهمية
    - تحليل أنماط النجاح والفشل
    - نسيان الأحداث القديمة غير المهمة
    """
    
    def __init__(self, max_size: int = 1000):
        self._episodes: Dict[str, Episode] = {}
        self._episodes_by_type: Dict[str, List[str]] = {}
        self._episodes_by_outcome: Dict[str, List[str]] = {}
        self._max_size = max_size
        
        logger.info(f"EpisodicMemory initialized (max_size={max_size})")
    
    async def store_episode(
        self,
        event_type: str,
        description: str,
        outcome: str,
        success: bool,
        context: Dict,
        metadata: Dict = None,
        importance: float = 0.5
    ) -> str:
        """
        تخزين حدث جديد
        
        Args:
            event_type: نوع الحدث
            description: وصف الحدث
            outcome: نتيجة الحدث
            success: نجاح/فشل
            context: سياق الحدث
            metadata: بيانات إضافية
            importance: أهمية الحدث
        
        Returns:
            معرف الحدث
        """
        import uuid
        episode_id = str(uuid.uuid4())[:8]
        
        episode = Episode(
            id=episode_id,
            timestamp=datetime.now(),
            event_type=event_type,
            description=description,
            outcome=outcome,
            success=success,
            context=context,
            metadata=metadata or {},
            importance=importance
        )
        
        self._episodes[episode_id] = episode
        
        # فهرسة حسب النوع
        if event_type not in self._episodes_by_type:
            self._episodes_by_type[event_type] = []
        self._episodes_by_type[event_type].append(episode_id)
        
        # فهرسة حسب النتيجة
        outcome_key = "success" if success else "failure"
        if outcome_key not in self._episodes_by_outcome:
            self._episodes_by_outcome[outcome_key] = []
        self._episodes_by_outcome[outcome_key].append(episode_id)
        
        # تنظيف إذا تجاوز الحجم
        if len(self._episodes) > self._max_size:
            await self._forget_least_important()
        
        logger.debug(f"Episode stored: {event_type} ({episode_id})")
        return episode_id
    
    async def retrieve_by_type(
        self,
        event_type: str,
        limit: int = 10
    ) -> List[Episode]:
        """
        استرجاع الأحداث حسب النوع
        
        Args:
            event_type: نوع الحدث
            limit: عدد النتائج
        
        Returns:
            قائمة بالأحداث
        """
        episode_ids = self._episodes_by_type.get(event_type, [])
        episodes = [self._episodes[eid] for eid in episode_ids if eid in self._episodes]
        
        # ترتيب حسب الأهمية والأحدث
        episodes.sort(key=lambda x: (x.importance, x.timestamp.timestamp()), reverse=True)
        
        return episodes[:limit]
    
    async def retrieve_by_similar_context(
        self,
        context: Dict,
        limit: int = 10
    ) -> List[Episode]:
        """
        استرجاع الأحداث ذات السياق المشابه
        
        Args:
            context: السياق للمقارنة
            limit: عدد النتائج
        
        Returns:
            قائمة بالأحداث
        """
        episodes = list(self._episodes.values())
        
        # حساب التشابه مع السياق
        scored_episodes = []
        for episode in episodes:
            similarity = self._calculate_similarity(context, episode.context)
            scored_episodes.append((similarity, episode))
        
        scored_episodes.sort(key=lambda x: x[0], reverse=True)
        
        return [ep for _, ep in scored_episodes[:limit]]
    
    async def retrieve_successful(self, limit: int = 10) -> List[Episode]:
        """استرجاع الأحداث الناجحة فقط"""
        episode_ids = self._episodes_by_outcome.get("success", [])
        episodes = [self._episodes[eid] for eid in episode_ids if eid in self._episodes]
        episodes.sort(key=lambda x: (x.importance, x.timestamp.timestamp()), reverse=True)
        return episodes[:limit]
    
    async def retrieve_failed(self, limit: int = 10) -> List[Episode]:
        """استرجاع الأحداث الفاشلة فقط"""
        episode_ids = self._episodes_by_outcome.get("failure", [])
        episodes = [self._episodes[eid] for eid in episode_ids if eid in self._episodes]
        episodes.sort(key=lambda x: (x.importance, x.timestamp.timestamp()), reverse=True)
        return episodes[:limit]
    
    def _calculate_similarity(self, context1: Dict, context2: Dict) -> float:
        """حساب التشابه بين سياقين"""
        if not context1 or not context2:
            return 0.0
        
        common_keys = set(context1.keys()) & set(context2.keys())
        if not common_keys:
            return 0.0
        
        matches = 0
        for key in common_keys:
            if context1.get(key) == context2.get(key):
                matches += 1
        
        return matches / len(common_keys)
    
    async def _forget_least_important(self):
        """نسيان أقل الأحداث أهمية"""
        if len(self._episodes) <= self._max_size:
            return
        
        # ترتيب حسب الأهمية
        episodes = list(self._episodes.values())
        episodes.sort(key=lambda x: (x.importance, x.timestamp.timestamp()))
        
        # حذف أقدم 10% من الأقل أهمية
        to_forget = episodes[:int(self._max_size * 0.1)]
        
        for episode in to_forget:
            await self.delete_episode(episode.id)
        
        logger.info(f"Forgot {len(to_forget)} least important episodes")
    
    async def delete_episode(self, episode_id: str) -> bool:
        """حذف حدث"""
        if episode_id not in self._episodes:
            return False
        
        episode = self._episodes[episode_id]
        
        # إزالة من الفهارس
        if episode.event_type in self._episodes_by_type:
            self._episodes_by_type[episode.event_type] = [
                eid for eid in self._episodes_by_type[episode.event_type]
                if eid != episode_id
            ]
        
        outcome_key = "success" if episode.success else "failure"
        if outcome_key in self._episodes_by_outcome:
            self._episodes_by_outcome[outcome_key] = [
                eid for eid in self._episodes_by_outcome[outcome_key]
                if eid != episode_id
            ]
        
        del self._episodes[episode_id]
        
        return True
    
    async def get_statistics(self) -> Dict:
        """إحصائيات الذاكرة"""
        total = len(self._episodes)
        successful = len(self._episodes_by_outcome.get("success", []))
        failed = len(self._episodes_by_outcome.get("failure", []))
        
        # توزيع أنواع الأحداث
        type_distribution = {
            event_type: len(ids)
            for event_type, ids in self._episodes_by_type.items()
        }
        
        return {
            "total_episodes": total,
            "successful_episodes": successful,
            "failed_episodes": failed,
            "success_rate": successful / total if total > 0 else 0,
            "type_distribution": type_distribution,
            "unique_event_types": len(self._episodes_by_type),
            "max_size": self._max_size
        }

