
import numpy as np
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from collections import deque

import logging

logger = logging.getLogger(__name__)


@dataclass
class KnowledgeChunk:
    """جزء من المعرفة"""
    id: str
    data: Dict[str, Any]
    importance: float
    timestamp: datetime = field(default_factory=datetime.now)
    access_count: int = 0


class ContinualLearner:
    """
    التعلم المستمر المتقدم
    
    الميزات:
    - تعلم من البيانات الجديدة دون نسيان القديم
    - استراتيجيات لتجنب الانتحال (Catastrophic Forgetting)
    - إدارة الذاكرة بأهمية المعرفة
    - إعادة تشغيل التجارب القديمة
    """
    
    def __init__(self, memory_size: int = 1000):
        self.memory_size = memory_size
        self.knowledge_base: Dict[str, KnowledgeChunk] = {}
        self.task_history: List[Dict] = []
        self.importance_threshold = 0.3
        
        logger.info(f"ContinualLearner initialized (memory_size={memory_size})")
    
    async def learn(self, task_data: Dict[str, Any], importance: float = 0.5):
        """
        تعلم مهمة جديدة
        
        Args:
            task_data: بيانات المهمة الجديدة
            importance: أهمية المهمة
        """
        import uuid
        chunk_id = str(uuid.uuid4())[:8]
        
        # إنشاء جزء معرفة جديد
        chunk = KnowledgeChunk(
            id=chunk_id,
            data=task_data,
            importance=importance
        )
        
        # تخزين المعرفة الجديدة
        self.knowledge_base[chunk_id] = chunk
        
        # تسجيل المهمة
        self.task_history.append({
            "id": chunk_id,
            "timestamp": datetime.now().isoformat(),
            "importance": importance
        })
        
        # إدارة الذاكرة
        await self._consolidate_memory()
        
        logger.info(f"Learned new task: {chunk_id} (importance={importance})")
    
    async def _consolidate_memory(self):
        """دمج وتنظيم الذاكرة"""
        if len(self.knowledge_base) <= self.memory_size:
            return
        
        # ترتيب المعرفة حسب الأهمية وعدد الوصولات
        sorted_chunks = sorted(
            self.knowledge_base.values(),
            key=lambda x: (x.importance, x.access_count),
            reverse=True
        )
        
        # الاحتفاظ بأهم المعرفة فقط
        keep_ids = {c.id for c in sorted_chunks[:self.memory_size]}
        
        # حذف المعرفة الأقل أهمية
        removed = 0
        for chunk_id in list(self.knowledge_base.keys()):
            if chunk_id not in keep_ids:
                del self.knowledge_base[chunk_id]
                removed += 1
        
        if removed:
            logger.info(f"Consolidated memory: removed {removed} less important items")
    
    async def recall(self, query: Dict[str, Any]) -> List[Tuple[KnowledgeChunk, float]]:
        """
        استرجاع المعرفة ذات الصلة
        
        Args:
            query: استعلام البحث
        
        Returns:
            قائمة بالمعرفة المسترجعة مع درجات الصلة
        """
        results = []
        
        for chunk in self.knowledge_base.values():
            # حساب الصلة (محاكاة بسيطة)
            relevance = await self._compute_relevance(query, chunk.data)
            
            if relevance > self.importance_threshold:
                results.append((chunk, relevance))
                chunk.access_count += 1
        
        # ترتيب حسب الصلة
        results.sort(key=lambda x: x[1], reverse=True)
        
        return results
    
    async def _compute_relevance(self, query: Dict, knowledge: Dict) -> float:
        """حساب الصلة بين الاستعلام والمعرفة"""
        if not query or not knowledge:
            return 0.0
        
        # حساب التشابه البسيط
        common_keys = set(query.keys()) & set(knowledge.keys())
        if not common_keys:
            return 0.0
        
        matches = 0
        for key in common_keys:
            if query[key] == knowledge[key]:
                matches += 1
        
        return matches / len(common_keys)
    
    async def replay_experiences(self, num_experiences: int = 10):
        """
        إعادة تشغيل تجارب سابقة لمنع النسيان
        
        Args:
            num_experiences: عدد التجارب لإعادة التشغيل
        """
        if not self.task_history:
            return
        
        # اختيار تجارب عشوائية
        import random
        experiences = random.sample(self.task_history, min(num_experiences, len(self.task_history)))
        
        for exp in experiences:
            chunk = self.knowledge_base.get(exp["id"])
            if chunk:
                # تحديث أهمية المعرفة
                chunk.importance = min(1.0, chunk.importance + 0.05)
                chunk.access_count += 1
                logger.debug(f"Replayed experience: {exp['id']}")
    
    async def get_knowledge_summary(self) -> Dict:
        """ملخص المعرفة"""
        if not self.knowledge_base:
            return {"total_items": 0}
        
        chunks = list(self.knowledge_base.values())
        
        return {
            "total_items": len(self.knowledge_base),
            "memory_usage": len(self.knowledge_base) / self.memory_size,
            "average_importance": sum(c.importance for c in chunks) / len(chunks),
            "average_access_count": sum(c.access_count for c in chunks) / len(chunks),
            "oldest_knowledge": min(c.timestamp for c in chunks).isoformat(),
            "newest_knowledge": max(c.timestamp for c in chunks).isoformat()
        }
    
    async def get_statistics(self) -> Dict:
        """إحصائيات المتعلم المستمر"""
        return {
            "memory_size": self.memory_size,
            "knowledge_items": len(self.knowledge_base),
            "total_tasks": len(self.task_history),
            "importance_threshold": self.importance_threshold,
            **await self.get_knowledge_summary()
        }

