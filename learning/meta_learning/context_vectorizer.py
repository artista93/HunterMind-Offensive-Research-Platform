
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime
import numpy as np

import logging

logger = logging.getLogger(__name__)


@dataclass
class ContextFeature:
    """سمة سياقية"""
    name: str
    value: Any
    weight: float = 1.0
    normalized_value: float = 0.0


class ContextVectorizer:
    """
    متجه السياق المتقدم
    
    الميزات:
    - تحويل السياق إلى متجهات رقمية
    - تطبيع السمات
    - حساب التشابه بين السياقات
    - تجميع السياقات المتشابهة
    """
    
    def __init__(self, dimension: int = 64):
        self._dimension = dimension
        self._feature_names: List[str] = []
        self._feature_ranges: Dict[str, Tuple[float, float]] = {}
        
        # تهيئة السمات الافتراضية
        self._init_default_features()
        
        logger.info(f"ContextVectorizer initialized (dimension={dimension})")
    
    def _init_default_features(self):
        """تهيئة السمات الافتراضية"""
        
        self._feature_names = [
            "target_complexity",
            "waf_detected",
            "auth_required",
            "vulnerability_count",
            "network_latency",
            "has_api",
            "has_forms",
            "has_js",
            "target_size",
            "response_time"
        ]
        
        self._feature_ranges = {
            "target_complexity": (0.0, 1.0),
            "waf_detected": (0.0, 1.0),
            "auth_required": (0.0, 1.0),
            "vulnerability_count": (0.0, 100.0),
            "network_latency": (0.0, 500.0),
            "has_api": (0.0, 1.0),
            "has_forms": (0.0, 1.0),
            "has_js": (0.0, 1.0),
            "target_size": (0.0, 10000.0),
            "response_time": (0.0, 10.0)
        }
    
    async def vectorize(self, context: Dict[str, Any]) -> np.ndarray:
        """
        تحويل السياق إلى متجه
        
        Args:
            context: قاموس السياق
        
        Returns:
            متجه numpy بالأبعاد المحددة
        """
        vector = np.zeros(self._dimension)
        
        for i, feature_name in enumerate(self._feature_names):
            if i >= self._dimension:
                break
            
            value = context.get(feature_name, 0)
            normalized = await self._normalize_feature(feature_name, value)
            vector[i] = normalized
        
        logger.debug(f"Context vectorized: {len(vector)} dimensions")
        return vector
    
    async def _normalize_feature(self, feature_name: str, value: Any) -> float:
        """
        تطبيع سمة
        
        Args:
            feature_name: اسم السمة
            value: قيمة السمة
        
        Returns:
            القيمة الطبيعية (0-1)
        """
        if feature_name in self._feature_ranges:
            min_val, max_val = self._feature_ranges[feature_name]
            if max_val > min_val:
                return (value - min_val) / (max_val - min_val)
        
        # تطبيع تلقائي للقيم المنطقية
        if isinstance(value, bool):
            return 1.0 if value else 0.0
        
        # محاولة تحويل إلى رقم
        try:
            num_value = float(value)
            # تطبيع افتراضي (افتراض أن المدى 0-100)
            return min(1.0, num_value / 100.0)
        except (ValueError, TypeError):
            return 0.0
    
    async def compute_similarity(
        self,
        context1: Dict[str, Any],
        context2: Dict[str, Any]
    ) -> float:
        """
        حساب التشابه بين سياقين
        
        Args:
            context1: السياق الأول
            context2: السياق الثاني
        
        Returns:
            درجة التشابه (0-1)
        """
        vec1 = await self.vectorize(context1)
        vec2 = await self.vectorize(context2)
        
        # Cosine similarity
        norm1 = np.linalg.norm(vec1)
        norm2 = np.linalg.norm(vec2)
        
        if norm1 == 0 or norm2 == 0:
            return 0.0
        
        similarity = np.dot(vec1, vec2) / (norm1 * norm2)
        return max(0.0, min(1.0, similarity))
    
    async def find_similar_contexts(
        self,
        query_context: Dict[str, Any],
        contexts: List[Dict[str, Any]],
        threshold: float = 0.7,
        limit: int = 10
    ) -> List[Tuple[Dict[str, Any], float]]:
        """
        البحث عن سياقات مشابهة
        
        Args:
            query_context: سياق الاستعلام
            contexts: قائمة السياقات للبحث
            threshold: عتبة التشابه
            limit: عدد النتائج
        
        Returns:
            قائمة بالسياقات المشابهة مع درجات التشابه
        """
        similarities = []
        
        for ctx in contexts:
            similarity = await self.compute_similarity(query_context, ctx)
            if similarity >= threshold:
                similarities.append((ctx, similarity))
        
        similarities.sort(key=lambda x: x[1], reverse=True)
        return similarities[:limit]
    
    async def add_feature(self, name: str, min_value: float = 0.0, max_value: float = 1.0):
        """
        إضافة سمة جديدة
        
        Args:
            name: اسم السمة
            min_value: الحد الأدنى
            max_value: الحد الأقصى
        """
        if name not in self._feature_names:
            self._feature_names.append(name)
            self._feature_ranges[name] = (min_value, max_value)
            logger.info(f"Feature added: {name}")
    
    async def get_feature_names(self) -> List[str]:
        """الحصول على أسماء السمات"""
        return self._feature_names.copy()
    
    async def get_statistics(self) -> Dict:
        """إحصائيات المتجه"""
        return {
            "dimension": self._dimension,
            "total_features": len(self._feature_names),
            "features": self._feature_names,
            "feature_ranges": self._feature_ranges
        }

