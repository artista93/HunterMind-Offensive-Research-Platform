
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from collections import defaultdict

import logging

logger = logging.getLogger(__name__)


@dataclass
class KnowledgeTransfer:
    """نقل معرفة"""
    source_task: str
    target_task: str
    transferred_knowledge: Dict[str, Any]
    effectiveness: float
    timestamp: datetime = field(default_factory=datetime.now)


class TransferLearning:
    """
    التعلم النقلي المتقدم
    
    الميزات:
    - نقل المعرفة بين المهام المتشابهة
    - تكييف المعرفة للسياق الجديد
    - تقييم فعالية النقل
    - تجميع المعرفة من مهام متعددة
    """
    
    def __init__(self):
        self._knowledge_base: Dict[str, Dict[str, Any]] = {}
        self._transfers: List[KnowledgeTransfer] = []
        self._task_similarities: Dict[Tuple[str, str], float] = {}
        
        logger.info("TransferLearning initialized")
    
    async def store_knowledge(
        self,
        task_id: str,
        knowledge: Dict[str, Any],
        metadata: Dict = None
    ):
        """
        تخزين معرفة من مهمة مكتملة
        
        Args:
            task_id: معرف المهمة
            knowledge: المعرفة المكتسبة
            metadata: بيانات إضافية
        """
        self._knowledge_base[task_id] = {
            "knowledge": knowledge,
            "metadata": metadata or {},
            "stored_at": datetime.now()
        }
        
        logger.info(f"Knowledge stored for task {task_id}")
    
    async def transfer_to_task(
        self,
        source_task: str,
        target_task: str,
        context: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """
        نقل المعرفة من مهمة إلى أخرى
        
        Args:
            source_task: معرف المهمة المصدر
            target_task: معرف المهمة الهدف
            context: سياق المهمة الهدف
        
        Returns:
            المعرفة المنقولة والمكيفة
        """
        if source_task not in self._knowledge_base:
            logger.warning(f"Source task {source_task} not found")
            return {}
        
        source_knowledge = self._knowledge_base[source_task]["knowledge"]
        
        # حساب التشابه بين المهمتين
        similarity = await self._compute_task_similarity(source_task, target_task, context)
        
        # تكييف المعرفة للسياق الجديد
        transferred = await self._adapt_knowledge(source_knowledge, similarity, context)
        
        # تسجيل النقل
        transfer = KnowledgeTransfer(
            source_task=source_task,
            target_task=target_task,
            transferred_knowledge=transferred,
            effectiveness=similarity
        )
        self._transfers.append(transfer)
        
        logger.info(f"Knowledge transferred from {source_task} to {target_task} (similarity={similarity:.2f})")
        
        return transferred
    
    async def transfer_from_multiple(
        self,
        source_tasks: List[str],
        target_task: str,
        context: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """
        نقل المعرفة من مهام متعددة
        
        Args:
            source_tasks: قائمة معرفات المهام المصدر
            target_task: معرف المهمة الهدف
            context: سياق المهمة الهدف
        
        Returns:
            المعرفة المدمجة من جميع المصادر
        """
        if not source_tasks:
            return {}
        
        combined_knowledge = {}
        total_weight = 0.0
        
        for source_task in source_tasks:
            transferred = await self.transfer_to_task(source_task, target_task, context)
            similarity = await self._compute_task_similarity(source_task, target_task, context)
            
            if transferred:
                weight = similarity
                total_weight += weight
                
                for key, value in transferred.items():
                    if key not in combined_knowledge:
                        combined_knowledge[key] = 0.0
                    combined_knowledge[key] += value * weight
        
        # تطبيع القيم
        if total_weight > 0:
            for key in combined_knowledge:
                combined_knowledge[key] /= total_weight
        
        return combined_knowledge
    
    async def _compute_task_similarity(
        self,
        source_task: str,
        target_task: str,
        context: Dict = None
    ) -> float:
        """حساب التشابه بين مهمتين"""
        cache_key = (source_task, target_task)
        
        if cache_key in self._task_similarities:
            return self._task_similarities[cache_key]
        
        # محاكاة حساب التشابه
        # في الإصدار الكامل، سيتم استخدام مقاييس أكثر تعقيداً
        similarity = 0.5
        
        if context and "task_type" in context:
            source_meta = self._knowledge_base.get(source_task, {}).get("metadata", {})
            if source_meta.get("task_type") == context["task_type"]:
                similarity += 0.3
        
        similarity = min(1.0, similarity)
        self._task_similarities[cache_key] = similarity
        
        return similarity
    
    async def _adapt_knowledge(
        self,
        knowledge: Dict[str, Any],
        similarity: float,
        context: Dict = None
    ) -> Dict[str, Any]:
        """تكييف المعرفة للسياق الجديد"""
        adapted = {}
        
        for key, value in knowledge.items():
            if isinstance(value, (int, float)):
                # تكييف القيم الرقمية
                adapted_value = value * similarity
                
                # تعديل حسب السياق
                if context:
                    if key == "learning_rate" and context.get("need_fast_learning", False):
                        adapted_value *= 1.5
                    elif key == "exploration_rate" and context.get("need_exploration", False):
                        adapted_value *= 1.2
                
                adapted[key] = adapted_value
            elif isinstance(value, dict):
                # تكييف القواميس بشكل متكرر
                adapted[key] = await self._adapt_knowledge(value, similarity, context)
            else:
                # نقل القيم غير الرقمية كما هي
                adapted[key] = value
        
        return adapted
    
    async def get_most_similar_task(
        self,
        target_task: str,
        context: Dict = None
    ) -> Optional[str]:
        """الحصول على أكثر مهمة مشابهة لمهمة معينة"""
        best_task = None
        best_similarity = -1.0
        
        for source_task in self._knowledge_base.keys():
            if source_task == target_task:
                continue
            
            similarity = await self._compute_task_similarity(source_task, target_task, context)
            if similarity > best_similarity:
                best_similarity = similarity
                best_task = source_task
        
        return best_task
    
    async def get_transfer_effectiveness(self) -> Dict:
        """الحصول على فعالية عمليات النقل"""
        if not self._transfers:
            return {"total_transfers": 0}
        
        effectiveness = [t.effectiveness for t in self._transfers]
        
        return {
            "total_transfers": len(self._transfers),
            "average_effectiveness": sum(effectiveness) / len(effectiveness),
            "max_effectiveness": max(effectiveness),
            "min_effectiveness": min(effectiveness),
            "transfers_by_source": {
                source: len([t for t in self._transfers if t.source_task == source])
                for source in set(t.source_task for t in self._transfers)
            }
        }
    
    async def get_statistics(self) -> Dict:
        """إحصائيات التعلم النقلي"""
        return {
            "total_tasks": len(self._knowledge_base),
            "total_transfers": len(self._transfers),
            "transfer_effectiveness": await self.get_transfer_effectiveness(),
            "task_similarities": len(self._task_similarities)
        }

