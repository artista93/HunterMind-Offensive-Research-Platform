
import math
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from collections import defaultdict
import random

from .payload_generator import Payload, PayloadType, get_payload_generator
from .payload_mutator import PayloadMutator, get_payload_mutator

import logging

logger = logging.getLogger(__name__)


@dataclass
class PayloadScore:
    """درجة الحمولة"""
    payload_id: str
    payload_name: str
    payload_type: PayloadType
    base_score: float  # الدرجة الأساسية (0-10)
    bypass_score: float  # درجة التجاوز (0-10)
    performance_score: float  # درجة الأداء (0-10)
    novelty_score: float  # درجة الجدة (0-10)
    total_score: float = 0.0
    rank: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)


class PayloadRanker:
    """
    ترتيب الحمولات المتقدم
    
    الميزات:
    - تقييم الحمولات حسب معايير متعددة
    - ترتيب ديناميكي حسب نوع الثغرة
    - تعلم من النجاحات السابقة
    - تفضيل الحمولات الناجحة تاريخياً
    - تحديث الأوزان بناءً على النتائج
    - تصفية الحمولات الضعيفة
    """
    
    # الأوزان الافتراضية للمعايير
    DEFAULT_WEIGHTS = {
        "base": 0.25,        # قوة الحمولة الأساسية
        "bypass": 0.35,      # قدرة تجاوز الحماية
        "performance": 0.15,  # الأداء (سرعة، حجم)
        "novelty": 0.10,     # الجدة وعدم التوقع
        "historical": 0.15,   # النجاح التاريخي
    }
    
    # درجات أساسية لأنواع الحمولات
    BASE_SCORES = {
        PayloadType.XSS: 7.5,
        PayloadType.SQLI: 8.5,
        PayloadType.RCE: 9.5,
        PayloadType.SSTI: 8.0,
        PayloadType.XXE: 7.0,
        PayloadType.SSRF: 7.5,
        PayloadType.LFI: 7.0,
        PayloadType.CMD_INJECT: 9.0,
    }
    
    def __init__(self):
        self._payload_scores: Dict[str, PayloadScore] = {}
        self._historical_success: Dict[str, float] = defaultdict(float)  # نسبة نجاح تاريخية
        self._success_history: Dict[str, List[bool]] = defaultdict(list)
        self._weights = self.DEFAULT_WEIGHTS.copy()
        
        logger.info("PayloadRanker initialized")
    
    def rank_payloads(
        self,
        payloads: List[Payload],
        context: Dict[str, Any] = None
    ) -> List[PayloadScore]:
        """
        ترتيب الحمولات حسب الفعالية المتوقعة
        
        Args:
            payloads: قائمة الحمولات
            context: سياق الاختبار (نوع الهدف، وجود WAF، إلخ)
        
        Returns:
            قائمة بالحمولات مرتبة حسب الدرجة
        """
        scores = []
        
        for payload in payloads:
            # حساب الدرجات المختلفة
            base_score = self._calculate_base_score(payload)
            bypass_score = self._calculate_bypass_score(payload, context)
            performance_score = self._calculate_performance_score(payload)
            novelty_score = self._calculate_novelty_score(payload)
            historical_score = self._get_historical_score(payload.id)
            
            # حساب الدرجة الإجمالية
            total_score = (
                base_score * self._weights["base"] +
                bypass_score * self._weights["bypass"] +
                performance_score * self._weights["performance"] +
                novelty_score * self._weights["novelty"] +
                historical_score * self._weights["historical"]
            )
            
            payload_score = PayloadScore(
                payload_id=payload.id,
                payload_name=payload.name,
                payload_type=payload.type,
                base_score=base_score,
                bypass_score=bypass_score,
                performance_score=performance_score,
                novelty_score=novelty_score,
                total_score=total_score,
                metadata={
                    "length": len(payload.payload),
                    "encoding": str(payload.encoding) if payload.encoding else "none",
                    "tags": payload.tags
                }
            )
            
            self._payload_scores[payload.id] = payload_score
            scores.append(payload_score)
        
        # ترتيب حسب الدرجة الإجمالية
        scores.sort(key=lambda x: x.total_score, reverse=True)
        
        # تحديث الترتيب
        for i, score in enumerate(scores):
            score.rank = i + 1
        
        return scores
    
    def _calculate_base_score(self, payload: Payload) -> float:
        """حساب الدرجة الأساسية للحمولة"""
        # الدرجة الأساسية حسب النوع
        base_score = self.BASE_SCORES.get(payload.type, 5.0)
        
        # تعديل حسب طول الحمولة (الحمولات الأقصر أفضل)
        length_factor = max(0, 1 - (len(payload.payload) / 500))
        base_score += length_factor * 1.0
        
        # حمولات البداية أفضل (XSS basic, SQLi basic)
        if payload.name.startswith("Basic") or "Classic" in payload.name:
            base_score += 1.0
        
        # حمولات ذات تقنيات متقدمة أفضل
        if "advanced" in str(payload.tags).lower():
            base_score += 1.5
        
        return min(base_score, 10.0)
    
    def _calculate_bypass_score(
        self,
        payload: Payload,
        context: Dict[str, Any] = None
    ) -> float:
        """حساب درجة قدرة الحمولة على تجاوز الحماية"""
        bypass_score = 5.0  # قيمة افتراضية
        
        # زيادة النقاط للحمولات المشفرة
        if payload.encoding and payload.encoding.value != "none":
            bypass_score += 2.0
        
        # زيادة النقاط للحمولات التي تحتوي على تعليقات
        if "comment" in str(payload.tags) or "comments" in str(payload.tags):
            bypass_score += 1.5
        
        # زيادة النقاط للحمولات متعددة الأشكال
        if "polymorphic" in str(payload.tags):
            bypass_score += 2.5
        
        # زيادة النقاط للحمولات المزدوجة الترميز
        if "double_encoded" in str(payload.tags):
            bypass_score += 2.0
        
        # إذا كان السياق يحتوي على WAF، نفضل الحمولات ذات الترميز
        if context and context.get("has_waf", False):
            if payload.encoding and payload.encoding.value != "none":
                bypass_score += 2.0
            if "double_encoded" in str(payload.tags):
                bypass_score += 1.5
        
        return min(bypass_score, 10.0)
    
    def _calculate_performance_score(self, payload: Payload) -> float:
        """حساب درجة أداء الحمولة"""
        performance_score = 8.0
        
        # الحمولات القصيرة أفضل
        length = len(payload.payload)
        if length < 50:
            performance_score += 2.0
        elif length < 200:
            performance_score += 1.0
        elif length > 500:
            performance_score -= 1.0
        
        # الحمولات البسيطة أفضل من المعقدة
        if "basic" in str(payload.tags).lower():
            performance_score += 1.0
        
        # حمولات RCE قد تكون بطيئة
        if payload.type == PayloadType.RCE and "sleep" in payload.payload.lower():
            performance_score -= 2.0
        
        return min(performance_score, 10.0)
    
    def _calculate_novelty_score(self, payload: Payload) -> float:
        """حساب درجة جدة الحمولة"""
        novelty_score = 5.0
        
        # الحمولات المتحورة تعتبر جديدة
        if "mutated" in str(payload.tags):
            novelty_score += 2.0
        
        if "polymorphic" in str(payload.tags):
            novelty_score += 3.0
        
        # الحمولات المشفرة
        if payload.encoding and payload.encoding.value != "none":
            novelty_score += 1.5
        
        # الحمولات المدمجة
        if "combined" in str(payload.tags):
            novelty_score += 2.0
        
        # الحمولات العشوائية
        if "random" in str(payload.tags):
            novelty_score += 3.0
        
        return min(novelty_score, 10.0)
    
    def _get_historical_score(self, payload_id: str) -> float:
        """الحصول على الدرجة التاريخية للحمولة"""
        success_rate = self._historical_success.get(payload_id, 0.5)  # افتراضي 50%
        return success_rate * 10.0  # تحويل إلى مقياس 0-10
    
    def record_success(self, payload_id: str, success: bool):
        """
        تسجيل نجاح أو فشل حمولة لتحسين الترتيب المستقبلي
        
        Args:
            payload_id: معرف الحمولة
            success: هل نجحت الحمولة؟
        """
        self._success_history[payload_id].append(success)
        
        # حساب نسبة النجاح
        total = len(self._success_history[payload_id])
        successes = sum(self._success_history[payload_id])
        success_rate = successes / total if total > 0 else 0
        
        # تخزين النسبة (مع عدم السماح بالصفر المطلق)
        self._historical_success[payload_id] = max(success_rate, 0.05)
        
        # تحديث الدرجة في الذاكرة المؤقتة
        if payload_id in self._payload_scores:
            # حساب الدرجة التاريخية
            historical_score = self._historical_success[payload_id] * 10.0
            
            # إعادة حساب الدرجة الإجمالية
            score = self._payload_scores[payload_id]
            total_score = (
                score.base_score * self._weights["base"] +
                score.bypass_score * self._weights["bypass"] +
                score.performance_score * self._weights["performance"] +
                score.novelty_score * self._weights["novelty"] +
                historical_score * self._weights["historical"]
            )
            score.total_score = total_score
        
        logger.debug(f"Recorded {'success' if success else 'failure'} for payload {payload_id}")
    
    def update_weights(self, feedback: Dict[str, float]):
        """
        تحديث أوزان المعايير بناءً على الملاحظات
        
        Args:
            feedback: قاموس بالأوزان الجديدة (اختياري)
        """
        for key, value in feedback.items():
            if key in self._weights:
                self._weights[key] = value
        
        # تطبيع الأوزان
        total = sum(self._weights.values())
        for key in self._weights:
            self._weights[key] /= total
        
        # إعادة حساب جميع الدرجات
        for payload_id in list(self._payload_scores.keys()):
            if payload_id in self._payload_scores:
                # سيتم إعادة الحساب عند الطلب التالي
                pass
        
        logger.info(f"Weights updated: {self._weights}")
    
    def get_top_payloads(
        self,
        payload_type: Optional[PayloadType] = None,
        limit: int = 10,
        min_score: float = 0.0
    ) -> List[PayloadScore]:
        """
        الحصول على أفضل الحمولات
        
        Args:
            payload_type: نوع الحمولة (اختياري)
            limit: عدد النتائج
            min_score: الحد الأدنى للدرجة
        """
        scores = list(self._payload_scores.values())
        
        if payload_type:
            scores = [s for s in scores if s.payload_type == payload_type]
        
        scores = [s for s in scores if s.total_score >= min_score]
        scores.sort(key=lambda x: x.total_score, reverse=True)
        
        return scores[:limit]
    
    def get_payload_recommendations(
        self,
        target_context: Dict[str, Any],
        limit: int = 5
    ) -> List[PayloadScore]:
        """
        الحصول على توصيات بحمولات بناءً على سياق الهدف
        
        Args:
            target_context: سياق الهدف (نوع الهدف، وجود WAF، إلخ)
            limit: عدد التوصيات
        """
        recommendations = []
        
        # إعطاء أولوية للحمولات المناسبة للسياق
        for payload_id, score in self._payload_scores.items():
            context_score = 0.0
            
            # الحمولات المشفرة أفضل إذا كان هناك WAF
            if target_context.get("has_waf", False):
                if "encoded" in str(score.metadata.get("tags", [])):
                    context_score += 2.0
            
            # الحمولات الأساسية أفضل للاختبار السريع
            if target_context.get("quick_test", False):
                if score.base_score > 8.0:
                    context_score += 1.0
            
            # الحمولات المتقدمة أفضل للاختبار العميق
            if target_context.get("deep_test", False):
                if score.bypass_score > 8.0:
                    context_score += 1.0
            
            # حساب الدرجة النهائية للتوصية
            recommendation_score = score.total_score + context_score
            
            recommendations.append((recommendation_score, score))
        
        # ترتيب حسب درجة التوصية
        recommendations.sort(key=lambda x: x[0], reverse=True)
        
        return [score for _, score in recommendations[:limit]]
    
    def get_statistics(self) -> Dict:
        """إحصائيات نظام الترتيب"""
        stats = {
            "total_payloads_scored": len(self._payload_scores),
            "historical_data_points": sum(len(v) for v in self._success_history.values()),
            "weights": self._weights,
            "avg_score_by_type": {},
            "top_payloads": []
        }
        
        # متوسط الدرجات حسب النوع
        for payload_type in PayloadType:
            scores = [s for s in self._payload_scores.values() if s.payload_type == payload_type]
            if scores:
                avg_score = sum(s.total_score for s in scores) / len(scores)
                stats["avg_score_by_type"][payload_type.value] = avg_score
        
        # أفضل 5 حمولات
        top_scores = self.get_top_payloads(limit=5)
        stats["top_payloads"] = [
            {
                "name": s.payload_name,
                "type": s.payload_type.value,
                "score": s.total_score,
                "success_rate": self._historical_success.get(s.payload_id, 0)
            }
            for s in top_scores
        ]
        
        return stats


# نسخة عالمية
_default_ranker = None


def get_payload_ranker() -> PayloadRanker:
    """الحصول على نسخة عالمية من ترتيب الحمولات"""
    global _default_ranker
    if _default_ranker is None:
        _default_ranker = PayloadRanker()
    return _default_ranker

