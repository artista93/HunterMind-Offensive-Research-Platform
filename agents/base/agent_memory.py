
import asyncio
import json
from typing import Dict, List, Optional, Any, Deque
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

import logging

logger = logging.getLogger(__name__)


class MemoryType(Enum):
    """نوع الذاكرة"""
    WORKING = "working"      # ذاكرة عاملة (حالية)
    EPISODIC = "episodic"    # ذاكرة تجارب (أحداث)
    SEMANTIC = "semantic"    # ذاكرة معرفية (حقائق)
    PROCEDURAL = "procedural"  # ذاكرة إجرائية (مهارات)


class MemoryImportance(Enum):
    """أهمية الذاكرة"""
    CRITICAL = 1.0
    HIGH = 0.8
    MEDIUM = 0.5
    LOW = 0.3
    TRIVIAL = 0.1


@dataclass
class MemoryItem:
    """عنصر ذاكرة"""
    id: str
    content: Any
    type: MemoryType
    importance: MemoryImportance
    timestamp: datetime
    access_count: int = 0
    last_accessed: Optional[datetime] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    expires_at: Optional[datetime] = None


@dataclass
class MemoryQuery:
    """استعلام ذاكرة"""
    query: str
    memory_type: Optional[MemoryType] = None
    min_importance: MemoryImportance = MemoryImportance.LOW
    limit: int = 10
    time_range: Optional[tuple] = None  # (start, end)
    tags: List[str] = field(default_factory=list)


class AgentMemory:
    """
    ذاكرة الوكيل المتقدمة
    
    الميزات:
    - أنواع متعددة من الذاكرة (عاملة، تجارب، معرفية، إجرائية)
    - تخزين واسترجاع الذاكرة
    - أهمية الذاكرة (للحفاظ على الذكريات المهمة)
    - انتهاء صلاحية الذاكرة
    - بحث متقدم في الذاكرة
    - دمج الذكريات المشابهة
    """
    
    def __init__(
        self,
        agent_id: str,
        working_memory_size: int = 10,
        episodic_memory_size: int = 1000,
        semantic_memory_size: int = 10000,
        procedural_memory_size: int = 500
    ):
        self._agent_id = agent_id
        
        # ذاكرة عاملة (حجم محدود)
        self._working_memory: Deque[MemoryItem] = deque(maxlen=working_memory_size)
        
        # ذاكرة تجارب
        self._episodic_memory: Dict[str, MemoryItem] = {}
        self._episodic_memory_size = episodic_memory_size
        
        # ذاكرة معرفية
        self._semantic_memory: Dict[str, MemoryItem] = {}
        self._semantic_memory_size = semantic_memory_size
        
        # ذاكرة إجرائية
        self._procedural_memory: Dict[str, MemoryItem] = {}
        self._procedural_memory_size = procedural_memory_size
        
        # فهارس للبحث السريع
        self._tag_index: Dict[str, List[str]] = {}
        
        self._lock = asyncio.Lock()
        
        logger.info(f"AgentMemory initialized for {agent_id}")
    
    async def store(
        self,
        content: Any,
        memory_type: MemoryType = MemoryType.EPISODIC,
        importance: MemoryImportance = MemoryImportance.MEDIUM,
        metadata: Dict = None,
        ttl_seconds: int = None,
        tags: List[str] = None
    ) -> str:
        """
        تخزين ذاكرة جديدة
        
        Args:
            content: محتوى الذاكرة
            memory_type: نوع الذاكرة
            importance: الأهمية
            metadata: بيانات إضافية
            ttl_seconds: مدة الصلاحية بالثواني
            tags: علامات للتصنيف
        
        Returns:
            معرف الذاكرة
        """
        import uuid
        memory_id = str(uuid.uuid4())[:8]
        now = datetime.now()
        
        memory = MemoryItem(
            id=memory_id,
            content=content,
            type=memory_type,
            importance=importance,
            timestamp=now,
            metadata=metadata or {},
            expires_at=datetime.fromtimestamp(now.timestamp() + ttl_seconds) if ttl_seconds else None
        )
        
        # إضافة علامات
        if tags:
            memory.metadata["tags"] = tags
            for tag in tags:
                if tag not in self._tag_index:
                    self._tag_index[tag] = []
                self._tag_index[tag].append(memory_id)
        
        async with self._lock:
            if memory_type == MemoryType.WORKING:
                self._working_memory.append(memory)
            
            elif memory_type == MemoryType.EPISODIC:
                self._episodic_memory[memory_id] = memory
                await self._enforce_size_limit(memory_type)
            
            elif memory_type == MemoryType.SEMANTIC:
                self._semantic_memory[memory_id] = memory
                await self._enforce_size_limit(memory_type)
            
            elif memory_type == MemoryType.PROCEDURAL:
                self._procedural_memory[memory_id] = memory
                await self._enforce_size_limit(memory_type)
        
        logger.debug(f"Memory stored: {memory_type.value} ({memory_id})")
        return memory_id
    
    async def retrieve(
        self,
        memory_id: str,
        memory_type: MemoryType = None
    ) -> Optional[MemoryItem]:
        """
        استرجاع ذاكرة بالمعرف
        
        Args:
            memory_id: معرف الذاكرة
            memory_type: نوع الذاكرة (لتحسين الأداء)
        
        Returns:
            عنصر الذاكرة أو None
        """
        async with self._lock:
            memory = None
            
            if memory_type == MemoryType.WORKING or not memory_type:
                for m in self._working_memory:
                    if m.id == memory_id:
                        memory = m
                        break
            
            if (not memory and (memory_type == MemoryType.EPISODIC or not memory_type)):
                memory = self._episodic_memory.get(memory_id)
            
            if (not memory and (memory_type == MemoryType.SEMANTIC or not memory_type)):
                memory = self._semantic_memory.get(memory_id)
            
            if (not memory and (memory_type == MemoryType.PROCEDURAL or not memory_type)):
                memory = self._procedural_memory.get(memory_id)
            
            if memory:
                memory.access_count += 1
                memory.last_accessed = datetime.now()
            
            return memory
    
    async def search(
        self,
        query: str,
        query_type: MemoryType = None,
        min_importance: MemoryImportance = MemoryImportance.LOW,
        limit: int = 10,
        tags: List[str] = None
    ) -> List[MemoryItem]:
        """
        البحث في الذاكرة
        
        Args:
            query: نص البحث
            query_type: نوع الذاكرة للبحث
            min_importance: الحد الأدنى للأهمية
            limit: الحد الأقصى للنتائج
            tags: تصفية حسب العلامات
        
        Returns:
            قائمة بعناصر الذاكرة المطابقة
        """
        results = []
        
        async with self._lock:
            # اختيار الذاكرة المناسبة
            memories = []
            
            if query_type == MemoryType.WORKING or not query_type:
                memories.extend(self._working_memory)
            if query_type == MemoryType.EPISODIC or not query_type:
                memories.extend(self._episodic_memory.values())
            if query_type == MemoryType.SEMANTIC or not query_type:
                memories.extend(self._semantic_memory.values())
            if query_type == MemoryType.PROCEDURAL or not query_type:
                memories.extend(self._procedural_memory.values())
            
            # تصفية وتقييم
            for memory in memories:
                # التحقق من الأهمية
                if memory.importance.value < min_importance.value:
                    continue
                
                # التحقق من الصلاحية
                if memory.expires_at and memory.expires_at < datetime.now():
                    continue
                
                # التحقق من العلامات
                if tags:
                    memory_tags = memory.metadata.get("tags", [])
                    if not any(tag in memory_tags for tag in tags):
                        continue
                
                # البحث النصي البسيط
                score = self._calculate_relevance(query, memory)
                if score > 0:
                    results.append((score, memory))
            
            # ترتيب حسب الصلة
            results.sort(key=lambda x: x[0], reverse=True)
            
            return [memory for _, memory in results[:limit]]
    
    def _calculate_relevance(self, query: str, memory: MemoryItem) -> float:
        """حساب صلة الذاكرة بالاستعلام"""
        score = 0.0
        
        # أهمية الذاكرة
        score += memory.importance.value * 0.3
        
        # عدد مرات الوصول (الذاكرة الشائعة)
        recency = 1.0 / (1.0 + (datetime.now() - memory.timestamp).total_seconds() / 3600)
        score += recency * 0.2
        
        # البحث النصي (إذا كان المحتوى نصياً)
        if isinstance(memory.content, str):
            if query.lower() in memory.content.lower():
                score += 0.5
        
        return min(score, 1.0)
    
    async def consolidate(self):
        """
        دمج الذكريات المتشابهة لتقليل التكرار
        """
        async with self._lock:
            # دمج الذكريات في الذاكرة المعرفية
            semantic_items = list(self._semantic_memory.items())
            
            for i in range(len(semantic_items)):
                for j in range(i + 1, len(semantic_items)):
                    id1, mem1 = semantic_items[i]
                    id2, mem2 = semantic_items[j]
                    
                    # إذا كان المحتوى متشابهاً
                    if isinstance(mem1.content, str) and isinstance(mem2.content, str):
                        if self._are_similar(mem1.content, mem2.content):
                            # دمج مع الاحتفاظ بالأهمية الأعلى
                            if mem1.importance.value >= mem2.importance.value:
                                # تحديث محتوى الذاكرة الأولى
                                mem1.metadata["merged_with"] = mem1.metadata.get("merged_with", []) + [id2]
                                mem1.metadata["merged_content"] = mem2.content
                                del self._semantic_memory[id2]
                            else:
                                mem2.metadata["merged_with"] = mem2.metadata.get("merged_with", []) + [id1]
                                mem2.metadata["merged_content"] = mem1.content
                                del self._semantic_memory[id1]
                                break
        
        logger.debug(f"Memory consolidation completed")
    
    def _are_similar(self, text1: str, text2: str, threshold: float = 0.8) -> bool:
        """التحقق من تشابه النصوص (محاكاة بسيطة)"""
        # في الإنتاج، يمكن استخدام embeddings
        return text1 == text2
    
    async def forget(self, memory_id: str, memory_type: MemoryType = None) -> bool:
        """
        نسيان ذاكرة محددة
        
        Args:
            memory_id: معرف الذاكرة
            memory_type: نوع الذاكرة
        
        Returns:
            نجاح العملية
        """
        async with self._lock:
            if memory_type == MemoryType.WORKING or not memory_type:
                for i, m in enumerate(self._working_memory):
                    if m.id == memory_id:
                        # إزالة من deque
                        self._working_memory = deque(
                            [m for m in self._working_memory if m.id != memory_id],
                            maxlen=self._working_memory.maxlen
                        )
                        return True
            
            if (memory_type == MemoryType.EPISODIC or not memory_type) and memory_id in self._episodic_memory:
                del self._episodic_memory[memory_id]
                return True
            
            if (memory_type == MemoryType.SEMANTIC or not memory_type) and memory_id in self._semantic_memory:
                del self._semantic_memory[memory_id]
                return True
            
            if (memory_type == MemoryType.PROCEDURAL or not memory_type) and memory_id in self._procedural_memory:
                del self._procedural_memory[memory_id]
                return True
        
        return False
    
    async def forget_old(self, max_age_seconds: int = 86400):
        """
        نسيان الذكريات القديمة
        
        Args:
            max_age_seconds: الحد الأقصى للعمر بالثواني
        """
        now = datetime.now()
        cutoff = datetime.fromtimestamp(now.timestamp() - max_age_seconds)
        
        async with self._lock:
            # الذاكرة التجريبية
            old_ids = [
                mid for mid, mem in self._episodic_memory.items()
                if mem.timestamp < cutoff and mem.importance != MemoryImportance.CRITICAL
            ]
            for mid in old_ids:
                del self._episodic_memory[mid]
            
            # الذاكرة المعرفية (القديمة)
            old_semantic = [
                mid for mid, mem in self._semantic_memory.items()
                if mem.timestamp < cutoff and mem.importance != MemoryImportance.CRITICAL
            ]
            for mid in old_semantic:
                del self._semantic_memory[mid]
        
        logger.info(f"Forgot {len(old_ids)} episodic and {len(old_semantic)} semantic memories")
    
    async def clear(self, memory_type: MemoryType = None):
        """
        مسح الذاكرة
        
        Args:
            memory_type: نوع الذاكرة للمسح (الكل إذا None)
        """
        async with self._lock:
            if not memory_type or memory_type == MemoryType.WORKING:
                self._working_memory.clear()
            
            if not memory_type or memory_type == MemoryType.EPISODIC:
                self._episodic_memory.clear()
            
            if not memory_type or memory_type == MemoryType.SEMANTIC:
                self._semantic_memory.clear()
            
            if not memory_type or memory_type == MemoryType.PROCEDURAL:
                self._procedural_memory.clear()
        
        logger.info(f"Memory cleared for type: {memory_type.value if memory_type else 'all'}")
    
    async def _enforce_size_limit(self, memory_type: MemoryType):
        """تطبيق حدود حجم الذاكرة"""
        if memory_type == MemoryType.EPISODIC and len(self._episodic_memory) > self._episodic_memory_size:
            # حذف الأقل أهمية
            sorted_items = sorted(
                self._episodic_memory.items(),
                key=lambda x: x[1].importance.value
            )
            to_delete = len(self._episodic_memory) - self._episodic_memory_size
            for mid, _ in sorted_items[:to_delete]:
                del self._episodic_memory[mid]
        
        elif memory_type == MemoryType.SEMANTIC and len(self._semantic_memory) > self._semantic_memory_size:
            sorted_items = sorted(
                self._semantic_memory.items(),
                key=lambda x: x[1].importance.value
            )
            to_delete = len(self._semantic_memory) - self._semantic_memory_size
            for mid, _ in sorted_items[:to_delete]:
                del self._semantic_memory[mid]
    
    async def get_statistics(self) -> Dict:
        """إحصائيات الذاكرة"""
        return {
            "working_memory_size": len(self._working_memory),
            "episodic_memory_size": len(self._episodic_memory),
            "semantic_memory_size": len(self._semantic_memory),
            "procedural_memory_size": len(self._procedural_memory),
            "total_memories": len(self._working_memory) + len(self._episodic_memory) + 
                              len(self._semantic_memory) + len(self._procedural_memory),
            "tag_count": len(self._tag_index),
            "memory_types": {
                "working": len(self._working_memory),
                "episodic": len(self._episodic_memory),
                "semantic": len(self._semantic_memory),
                "procedural": len(self._procedural_memory)
            }
        }

