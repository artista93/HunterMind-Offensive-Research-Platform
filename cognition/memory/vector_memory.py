
import numpy as np
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime

import logging

logger = logging.getLogger(__name__)


@dataclass
class VectorItem:
    """عنصر متجهي"""
    id: str
    vector: np.ndarray
    metadata: Dict[str, Any]
    timestamp: datetime = field(default_factory=datetime.now)


class VectorMemory:
    """
    الذاكرة المتجهية المتقدمة
    
    الميزات:
    - تخزين التمثيلات المتجهية
    - بحث دلالي باستخدام التشابه (cosine similarity)
    - دمج المتجهات
    - تطبيع المتجهات
    """
    
    def __init__(self, dimension: int = 768):
        self._dimension = dimension
        self._items: Dict[str, VectorItem] = {}
        self._index: Optional[np.ndarray] = None
        self._id_to_index: Dict[str, int] = {}
        
        logger.info(f"VectorMemory initialized (dimension={dimension})")
    
    async def add_item(
        self,
        item_id: str,
        vector: List[float],
        metadata: Dict = None
    ):
        """
        إضافة عنصر متجهي جديد
        
        Args:
            item_id: معرف العنصر
            vector: المتجه
            metadata: بيانات وصفية
        """
        if len(vector) != self._dimension:
            raise ValueError(f"Vector dimension mismatch: expected {self._dimension}, got {len(vector)}")
        
        # تطبيع المتجه
        normalized = await self._normalize_vector(np.array(vector))
        
        item = VectorItem(
            id=item_id,
            vector=normalized,
            metadata=metadata or {}
        )
        
        self._items[item_id] = item
        await self._rebuild_index()
        
        logger.debug(f"Vector item added: {item_id}")
    
    async def search(
        self,
        query_vector: List[float],
        top_k: int = 10,
        filter_metadata: Dict = None
    ) -> List[Tuple[str, float, Dict]]:
        """
        بحث دلالي باستخدام المتجه
        
        Args:
            query_vector: متجه الاستعلام
            top_k: عدد النتائج
            filter_metadata: تصفية حسب البيانات الوصفية
        
        Returns:
            قائمة (معرف العنصر, درجة التشابه, البيانات الوصفية)
        """
        if not self._items:
            return []
        
        if len(query_vector) != self._dimension:
            raise ValueError(f"Query dimension mismatch: expected {self._dimension}, got {len(query_vector)}")
        
        query_norm = await self._normalize_vector(np.array(query_vector))
        
        # حساب التشابه (cosine similarity)
        similarities = np.dot(self._index, query_norm)
        
        # ترتيب النتائج
        indices = np.argsort(similarities)[::-1][:top_k]
        
        results = []
        for idx in indices:
            item_id = list(self._items.keys())[idx]
            item = self._items[item_id]
            
            # تصفية حسب البيانات الوصفية
            if filter_metadata:
                match = all(
                    item.metadata.get(key) == value
                    for key, value in filter_metadata.items()
                )
                if not match:
                    continue
            
            results.append((item_id, float(similarities[idx]), item.metadata))
        
        return results
    
    async def search_by_text(
        self,
        text: str,
        embedder: callable,
        top_k: int = 10,
        filter_metadata: Dict = None
    ) -> List[Tuple[str, float, Dict]]:
        """
        بحث دلالي باستخدام نص
        
        Args:
            text: نص الاستعلام
            embedder: دالة لتحويل النص إلى متجه
            top_k: عدد النتائج
            filter_metadata: تصفية حسب البيانات الوصفية
        
        Returns:
            قائمة (معرف العنصر, درجة التشابه, البيانات الوصفية)
        """
        query_vector = await embedder(text)
        return await self.search(query_vector, top_k, filter_metadata)
    
    async def merge_vectors(
        self,
        vector1: List[float],
        vector2: List[float],
        weight1: float = 0.5,
        weight2: float = 0.5
    ) -> List[float]:
        """
        دمج متجهين
        
        Args:
            vector1: المتجه الأول
            vector2: المتجه الثاني
            weight1: وزن المتجه الأول
            weight2: وزن المتجه الثاني
        
        Returns:
            المتجه المدمج
        """
        if len(vector1) != self._dimension or len(vector2) != self._dimension:
            raise ValueError("Vector dimension mismatch")
        
        v1 = np.array(vector1)
        v2 = np.array(vector2)
        
        merged = (v1 * weight1 + v2 * weight2) / (weight1 + weight2)
        
        return merged.tolist()
    
    async def get_item(self, item_id: str) -> Optional[VectorItem]:
        """الحصول على عنصر بالمعرف"""
        return self._items.get(item_id)
    
    async def delete_item(self, item_id: str) -> bool:
        """حذف عنصر"""
        if item_id not in self._items:
            return False
        
        del self._items[item_id]
        await self._rebuild_index()
        
        logger.debug(f"Vector item deleted: {item_id}")
        return True
    
    async def update_metadata(
        self,
        item_id: str,
        metadata: Dict
    ) -> bool:
        """تحديث البيانات الوصفية لعنصر"""
        if item_id not in self._items:
            return False
        
        self._items[item_id].metadata.update(metadata)
        return True
    
    async def _rebuild_index(self):
        """إعادة بناء فهرس المتجهات"""
        if not self._items:
            self._index = None
            return
        
        vectors = [item.vector for item in self._items.values()]
        self._index = np.vstack(vectors)
    
    async def _normalize_vector(self, vector: np.ndarray) -> np.ndarray:
        """تطبيع المتجه"""
        norm = np.linalg.norm(vector)
        if norm > 0:
            return vector / norm
        return vector
    
    async def get_similar_items(
        self,
        item_id: str,
        top_k: int = 5
    ) -> List[Tuple[str, float]]:
        """
        الحصول على عناصر مشابهة لعنصر معين
        
        Args:
            item_id: معرف العنصر
            top_k: عدد النتائج
        
        Returns:
            قائمة (معرف العنصر, درجة التشابه)
        """
        if item_id not in self._items:
            return []
        
        item_vector = self._items[item_id].vector.tolist()
        results = await self.search(item_vector, top_k + 1)
        
        # استبعاد العنصر نفسه
        return [(cid, score) for cid, score, _ in results if cid != item_id][:top_k]
    
    async def get_statistics(self) -> Dict:
        """إحصائيات الذاكرة"""
        total_items = len(self._items)
        
        return {
            "total_items": total_items,
            "dimension": self._dimension,
            "index_built": self._index is not None,
            "memory_usage_bytes": self._index.nbytes if self._index is not None else 0,
            "items": list(self._items.keys())[:10]  # عرض أول 10 عناصر فقط
        }

