
import json
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from collections import defaultdict

import logging

logger = logging.getLogger(__name__)


@dataclass
class Concept:
    """مفهوم معرفي"""
    name: str
    category: str
    properties: Dict[str, Any]
    relationships: List[Tuple[str, str, float]]  # (target, relation_type, weight)
    confidence: float
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)


class SemanticMemory:
    """
    الذاكرة الدلالية المتقدمة
    
    الميزات:
    - تخزين المفاهيم والعلاقات بينها
    - استعلامات دلالية
    - استدلال على العلاقات
    - تحديث ودمج المعرفة
    """
    
    def __init__(self):
        self._concepts: Dict[str, Concept] = {}
        self._category_index: Dict[str, List[str]] = defaultdict(list)
        
        logger.info("SemanticMemory initialized")
    
    async def add_concept(
        self,
        name: str,
        category: str,
        properties: Dict,
        relationships: List[Tuple[str, str, float]] = None,
        confidence: float = 0.8
    ):
        """
        إضافة مفهوم جديد
        
        Args:
            name: اسم المفهوم
            category: فئة المفهوم
            properties: خصائص المفهوم
            relationships: العلاقات مع مفاهيم أخرى
            confidence: مستوى الثقة
        """
        if name in self._concepts:
            await self.update_concept(name, properties, relationships, confidence)
            return
        
        concept = Concept(
            name=name,
            category=category,
            properties=properties,
            relationships=relationships or [],
            confidence=confidence
        )
        
        self._concepts[name] = concept
        self._category_index[category].append(name)
        
        logger.info(f"Concept added: {name} ({category})")
    
    async def update_concept(
        self,
        name: str,
        properties: Dict = None,
        relationships: List[Tuple[str, str, float]] = None,
        confidence: float = None
    ):
        """تحديث مفهوم موجود"""
        if name not in self._concepts:
            logger.warning(f"Concept {name} not found")
            return
        
        concept = self._concepts[name]
        
        if properties:
            concept.properties.update(properties)
        
        if relationships:
            concept.relationships.extend(relationships)
        
        if confidence:
            concept.confidence = confidence
        
        concept.updated_at = datetime.now()
        
        logger.debug(f"Concept updated: {name}")
    
    async def get_concept(self, name: str) -> Optional[Concept]:
        """الحصول على مفهوم بالاسم"""
        return self._concepts.get(name)
    
    async def get_related_concepts(
        self,
        name: str,
        relation_type: str = None,
        min_weight: float = 0.0
    ) -> List[Tuple[str, str, float]]:
        """
        الحصول على المفاهيم المرتبطة بمفهوم معين
        
        Args:
            name: اسم المفهوم
            relation_type: نوع العلاقة (اختياري)
            min_weight: الحد الأدنى لوزن العلاقة
        
        Returns:
            قائمة بالمفاهيم المرتبطة
        """
        concept = self._concepts.get(name)
        if not concept:
            return []
        
        relations = concept.relationships
        
        if relation_type:
            relations = [r for r in relations if r[1] == relation_type]
        
        if min_weight > 0:
            relations = [r for r in relations if r[2] >= min_weight]
        
        return relations
    
    async def find_similar_concepts(
        self,
        query: str,
        limit: int = 10
    ) -> List[Tuple[str, float]]:
        """
        البحث عن مفاهيم مشابهة
        
        Args:
            query: نص البحث
            limit: عدد النتائج
        
        Returns:
            قائمة (اسم المفهوم, درجة التشابه)
        """
        query_lower = query.lower()
        scores = []
        
        for name, concept in self._concepts.items():
            score = 0.0
            
            # تطابق الاسم
            if query_lower in name.lower():
                score += 0.5
            
            # تطابق الخصائص
            for prop_value in concept.properties.values():
                if query_lower in str(prop_value).lower():
                    score += 0.3
                    break
            
            scores.append((name, score))
        
        scores.sort(key=lambda x: x[1], reverse=True)
        return scores[:limit]
    
    async def infer_relation(
        self,
        source: str,
        target: str,
        relation_type: str = None
    ) -> float:
        """
        استدلال على وجود علاقة بين مفهومين
        
        Args:
            source: المفهوم المصدر
            target: المفهوم الهدف
            relation_type: نوع العلاقة (اختياري)
        
        Returns:
            قوة العلاقة (0-1)
        """
        source_concept = self._concepts.get(source)
        if not source_concept:
            return 0.0
        
        # بحث مباشر
        for rel_target, rel_type, weight in source_concept.relationships:
            if rel_target == target and (relation_type is None or rel_type == relation_type):
                return weight
        
        # بحث غير مباشر (من خلال مفاهيم وسيطة)
        max_weight = 0.0
        for rel_target, rel_type, weight in source_concept.relationships:
            target_concept = self._concepts.get(rel_target)
            if target_concept:
                for sub_target, sub_type, sub_weight in target_concept.relationships:
                    if sub_target == target and (relation_type is None or sub_type == relation_type):
                        path_weight = weight * sub_weight
                        max_weight = max(max_weight, path_weight)
        
        return max_weight
    
    async def get_concepts_by_category(self, category: str) -> List[Concept]:
        """الحصول على جميع المفاهيم في فئة معينة"""
        concept_names = self._category_index.get(category, [])
        return [self._concepts[name] for name in concept_names if name in self._concepts]
    
    async def delete_concept(self, name: str) -> bool:
        """حذف مفهوم"""
        if name not in self._concepts:
            return False
        
        concept = self._concepts[name]
        
        # إزالة من فهرس الفئة
        if concept.category in self._category_index:
            self._category_index[concept.category] = [
                n for n in self._category_index[concept.category]
                if n != name
            ]
        
        # إزالة العلاقات التي تشير إلى هذا المفهوم
        for other_concept in self._concepts.values():
            other_concept.relationships = [
                r for r in other_concept.relationships
                if r[0] != name
            ]
        
        del self._concepts[name]
        
        logger.info(f"Concept deleted: {name}")
        return True
    
    async def get_statistics(self) -> Dict:
        """إحصائيات الذاكرة"""
        total_concepts = len(self._concepts)
        total_relationships = sum(len(c.relationships) for c in self._concepts.values())
        
        # توزيع الفئات
        category_distribution = {
            category: len(names)
            for category, names in self._category_index.items()
        }
        
        # متوسط مستوى الثقة
        avg_confidence = sum(c.confidence for c in self._concepts.values()) / total_concepts if total_concepts > 0 else 0
        
        return {
            "total_concepts": total_concepts,
            "total_relationships": total_relationships,
            "category_distribution": category_distribution,
            "unique_categories": len(self._category_index),
            "average_confidence": avg_confidence
        }

