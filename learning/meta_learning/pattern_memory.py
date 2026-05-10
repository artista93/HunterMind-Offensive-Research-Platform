
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from collections import defaultdict

import logging

logger = logging.getLogger(__name__)


@dataclass
class Pattern:
    """نمط متكرر"""
    id: str
    name: str
    features: Dict[str, Any]
    frequency: int
    success_rate: float
    first_seen: datetime
    last_seen: datetime
    examples: List[Dict] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PatternMatch:
    """تطابق نمط"""
    pattern: Pattern
    similarity: float
    confidence: float


class PatternMemory:
    """
    ذاكرة الأنماط المتقدمة
    
    الميزات:
    - تخزين الأنماط المتكررة
    - استخراج الأنماط من البيانات
    - مطابقة الأنماط الجديدة
    - تحديث إحصائيات الأنماط
    """
    
    def __init__(self, similarity_threshold: float = 0.7):
        self._patterns: Dict[str, Pattern] = {}
        self._pattern_index: Dict[str, List[str]] = defaultdict(list)  # feature -> pattern ids
        self._similarity_threshold = similarity_threshold
        
        logger.info("PatternMemory initialized")
    
    async def add_pattern(
        self,
        name: str,
        features: Dict[str, Any],
        success: bool,
        example: Dict = None
    ) -> str:
        """
        إضافة نمط جديد أو تحديث موجود
        
        Args:
            name: اسم النمط
            features: خصائص النمط
            success: نجاح النمط
            example: مثال توضيحي
        
        Returns:
            معرف النمط
        """
        import uuid
        pattern_id = str(uuid.uuid4())[:8]
        
        # البحث عن أنماط مشابهة
        existing = await self.find_matching_patterns(features)
        
        if existing:
            # تحديث النمط الموجود
            best_match = existing[0]
            pattern = best_match.pattern
            pattern.frequency += 1
            pattern.last_seen = datetime.now()
            
            # تحديث معدل النجاح
            total = pattern.frequency
            success_count = pattern.success_rate * (total - 1) + (1 if success else 0)
            pattern.success_rate = success_count / total
            
            if example:
                pattern.examples.append(example)
                if len(pattern.examples) > 10:
                    pattern.examples.pop(0)
            
            return pattern.id
        
        # إنشاء نمط جديد
        pattern = Pattern(
            id=pattern_id,
            name=name,
            features=features,
            frequency=1,
            success_rate=1.0 if success else 0.0,
            first_seen=datetime.now(),
            last_seen=datetime.now(),
            examples=[example] if example else []
        )
        
        self._patterns[pattern_id] = pattern
        
        # فهرسة الخصائص
        for key, value in features.items():
            index_key = f"{key}:{value}"
            self._pattern_index[index_key].append(pattern_id)
        
        logger.info(f"Pattern added: {name} (id={pattern_id})")
        return pattern_id
    
    async def find_matching_patterns(
        self,
        features: Dict[str, Any],
        limit: int = 5
    ) -> List[PatternMatch]:
        """
        البحث عن أنماط مطابقة
        
        Args:
            features: خصائص للبحث
            limit: عدد النتائج
        
        Returns:
            قائمة بالأنماط المطابقة
        """
        matches = []
        
        for pattern in self._patterns.values():
            similarity = await self._compute_similarity(features, pattern.features)
            
            if similarity >= self._similarity_threshold:
                matches.append(PatternMatch(
                    pattern=pattern,
                    similarity=similarity,
                    confidence=pattern.success_rate * similarity
                ))
        
        matches.sort(key=lambda x: x.confidence, reverse=True)
        return matches[:limit]
    
    async def _compute_similarity(
        self,
        features1: Dict[str, Any],
        features2: Dict[str, Any]
    ) -> float:
        """حساب التشابه بين مجموعتين من الخصائص"""
        if not features1 or not features2:
            return 0.0
        
        common_keys = set(features1.keys()) & set(features2.keys())
        
        if not common_keys:
            return 0.0
        
        matches = 0
        for key in common_keys:
            if features1[key] == features2[key]:
                matches += 1
        
        return matches / len(common_keys)
    
    async def get_pattern(self, pattern_id: str) -> Optional[Pattern]:
        """الحصول على نمط بالمعرف"""
        return self._patterns.get(pattern_id)
    
    async def get_patterns_by_feature(self, feature_key: str, feature_value: Any) -> List[Pattern]:
        """الحصول على الأنماط حسب خاصية معينة"""
        index_key = f"{feature_key}:{feature_value}"
        pattern_ids = self._pattern_index.get(index_key, [])
        return [self._patterns[pid] for pid in pattern_ids if pid in self._patterns]
    
    async def get_frequent_patterns(self, min_frequency: int = 5) -> List[Pattern]:
        """الحصول على الأنماط المتكررة"""
        return [p for p in self._patterns.values() if p.frequency >= min_frequency]
    
    async def get_high_success_patterns(self, min_success_rate: float = 0.7) -> List[Pattern]:
        """الحصول على الأنماط عالية النجاح"""
        return [p for p in self._patterns.values() if p.success_rate >= min_success_rate]
    
    async def update_pattern_success(self, pattern_id: str, success: bool) -> bool:
        """
        تحديث معدل نجاح النمط
        
        Args:
            pattern_id: معرف النمط
            success: نجاح النمط
        
        Returns:
            نجاح العملية
        """
        if pattern_id not in self._patterns:
            return False
        
        pattern = self._patterns[pattern_id]
        pattern.frequency += 1
        
        success_count = pattern.success_rate * (pattern.frequency - 1) + (1 if success else 0)
        pattern.success_rate = success_count / pattern.frequency
        pattern.last_seen = datetime.now()
        
        return True
    
    async def get_statistics(self) -> Dict:
        """إحصائيات الذاكرة"""
        if not self._patterns:
            return {"total_patterns": 0}
        
        frequencies = [p.frequency for p in self._patterns.values()]
        success_rates = [p.success_rate for p in self._patterns.values()]
        
        return {
            "total_patterns": len(self._patterns),
            "average_frequency": sum(frequencies) / len(frequencies),
            "max_frequency": max(frequencies),
            "average_success_rate": sum(success_rates) / len(success_rates),
            "frequent_patterns": len([p for p in self._patterns.values() if p.frequency >= 5]),
            "high_success_patterns": len([p for p in self._patterns.values() if p.success_rate >= 0.7]),
            "unique_features": len(self._pattern_index)
        }

