
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from collections import defaultdict

import logging

logger = logging.getLogger(__name__)


@dataclass
class ReflectionInsight:
    """بصيرة مستخلصة من التأمل"""
    id: str
    insight: str
    category: str
    confidence: float
    created_at: datetime = field(default_factory=datetime.now)
    applied: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ReflectionSession:
    """جلسة تأمل"""
    id: str
    start_time: datetime
    end_time: Optional[datetime] = None
    observations: List[str] = field(default_factory=list)
    insights: List[ReflectionInsight] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)


class ReflectionEngine:
    """
    محرك التأمل المتقدم
    
    الميزات:
    - تحليل الأداء السابق
    - استخلاص الدروس والرؤى
    - توليد توصيات للتحسين
    - تتبع فعالية التوصيات
    """
    
    def __init__(self):
        self._sessions: List[ReflectionSession] = []
        self._insights: List[ReflectionInsight] = []
        self._current_session: Optional[ReflectionSession] = None
        
        logger.info("ReflectionEngine initialized")
    
    async def start_reflection(self, session_id: str = None) -> str:
        """
        بدء جلسة تأمل جديدة
        
        Args:
            session_id: معرف الجلسة (اختياري)
        
        Returns:
            معرف الجلسة
        """
        import uuid
        if not session_id:
            session_id = str(uuid.uuid4())[:8]
        
        session = ReflectionSession(
            id=session_id,
            start_time=datetime.now()
        )
        
        self._sessions.append(session)
        self._current_session = session
        
        logger.info(f"Reflection session started: {session_id}")
        return session_id
    
    async def add_observation(self, observation: str):
        """
        إضافة ملاحظة إلى جلسة التأمل
        
        Args:
            observation: نص الملاحظة
        """
        if not self._current_session:
            await self.start_reflection()
        
        self._current_session.observations.append(observation)
        logger.debug(f"Observation added: {observation[:50]}...")
    
    async def analyze(self) -> List[ReflectionInsight]:
        """
        تحليل الملاحظات واستخلاص البصائر
        
        Returns:
            قائمة بالبصائر المستخلصة
        """
        if not self._current_session:
            return []
        
        insights = []
        
        # تحليل الأداء
        performance_insights = await self._analyze_performance()
        insights.extend(performance_insights)
        
        # تحليل الأخطاء
        error_insights = await self._analyze_errors()
        insights.extend(error_insights)
        
        # تحليل النجاحات
        success_insights = await self._analyze_successes()
        insights.extend(success_insights)
        
        # تحسين الاستراتيجيات
        strategy_insights = await self._analyze_strategies()
        insights.extend(strategy_insights)
        
        # تخزين البصائر
        for insight in insights:
            self._insights.append(insight)
            self._current_session.insights.append(insight)
        
        logger.info(f"Analysis complete: {len(insights)} insights generated")
        return insights
    
    async def _analyze_performance(self) -> List[ReflectionInsight]:
        """تحليل أداء النظام"""
        insights = []
        
        # محاكاة تحليل الأداء
        # في الإصدار الكامل، سيتم تحليل المقاييس الفعلية
        
        insight = ReflectionInsight(
            id="perf_001",
            insight="System performance degrades when scanning large targets",
            category="performance",
            confidence=0.8
        )
        insights.append(insight)
        
        return insights
    
    async def _analyze_errors(self) -> List[ReflectionInsight]:
        """تحليل الأخطاء المتكررة"""
        insights = []
        
        insight = ReflectionInsight(
            id="err_001",
            insight="Timeout errors occur frequently on slow endpoints",
            category="errors",
            confidence=0.75
        )
        insights.append(insight)
        
        return insights
    
    async def _analyze_successes(self) -> List[ReflectionInsight]:
        """تحليل النجاحات"""
        insights = []
        
        insight = ReflectionInsight(
            id="suc_001",
            insight="XSS detection has high success rate when using encoded payloads",
            category="success",
            confidence=0.85
        )
        insights.append(insight)
        
        return insights
    
    async def _analyze_strategies(self) -> List[ReflectionInsight]:
        """تحليل الاستراتيجيات المستخدمة"""
        insights = []
        
        insight = ReflectionInsight(
            id="str_001",
            insight="Stealth mode significantly reduces detection",
            category="strategy",
            confidence=0.9
        )
        insights.append(insight)
        
        return insights
    
    async def generate_recommendations(self) -> List[str]:
        """
        توليد توصيات للتحسين بناءً على البصائر
        
        Returns:
            قائمة بالتوصيات
        """
        recommendations = []
        
        for insight in self._insights:
            if not insight.applied:
                if insight.category == "performance":
                    recommendations.append("Consider implementing adaptive crawling for large targets")
                elif insight.category == "errors":
                    recommendations.append("Increase timeout values for slow endpoints")
                elif insight.category == "success":
                    recommendations.append("Prioritize encoded payloads in XSS detection")
                elif insight.category == "strategy":
                    recommendations.append("Make stealth mode the default for unknown targets")
        
        if self._current_session:
            self._current_session.recommendations = recommendations
        
        return recommendations
    
    async def end_reflection(self) -> List[ReflectionInsight]:
        """
        إنهاء جلسة التأمل
        
        Returns:
            قائمة البصائر المستخلصة
        """
        if not self._current_session:
            return []
        
        self._current_session.end_time = datetime.now()
        
        insights = await self.analyze()
        recommendations = await self.generate_recommendations()
        
        self._current_session = None
        
        logger.info(f"Reflection session ended: {len(insights)} insights, {len(recommendations)} recommendations")
        
        return insights
    
    async def mark_insight_applied(self, insight_id: str) -> bool:
        """
        تعليم بصيرة كـ"مطبقة"
        
        Args:
            insight_id: معرف البصيرة
        
        Returns:
            نجاح العملية
        """
        for insight in self._insights:
            if insight.id == insight_id:
                insight.applied = True
                logger.debug(f"Insight {insight_id} marked as applied")
                return True
        return False
    
    async def get_insights(self, category: str = None, applied: bool = None) -> List[ReflectionInsight]:
        """
        الحصول على البصائر
        
        Args:
            category: الفئة (اختياري)
            applied: حالة التطبيق (اختياري)
        
        Returns:
            قائمة بالبصائر
        """
        insights = self._insights
        
        if category:
            insights = [i for i in insights if i.category == category]
        
        if applied is not None:
            insights = [i for i in insights if i.applied == applied]
        
        return insights
    
    async def get_statistics(self) -> Dict:
        """إحصائيات المحرك"""
        total_sessions = len(self._sessions)
        completed_sessions = len([s for s in self._sessions if s.end_time])
        
        insights_by_category = defaultdict(int)
        for insight in self._insights:
            insights_by_category[insight.category] += 1
        
        return {
            "total_sessions": total_sessions,
            "completed_sessions": completed_sessions,
            "total_insights": len(self._insights),
            "insights_by_category": dict(insights_by_category),
            "applied_insights": len([i for i in self._insights if i.applied]),
            "average_confidence": sum(i.confidence for i in self._insights) / len(self._insights) if self._insights else 0,
            "active_session": self._current_session is not None
        }

