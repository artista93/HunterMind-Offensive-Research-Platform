
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from collections import defaultdict

import logging

logger = logging.getLogger(__name__)


@dataclass
class StrategyEvaluation:
    """تقييم استراتيجية"""
    strategy_name: str
    effectiveness_score: float  # 0-100
    strengths: List[str]
    weaknesses: List[str]
    suggestions: List[str]
    last_evaluated: datetime = field(default_factory=datetime.now)
    metrics: Dict[str, float] = field(default_factory=dict)


class StrategyReflection:
    """
    تأمل الاستراتيجيات المتقدم
    
    الميزات:
    - تحليل فعالية الاستراتيجيات
    - تحديد نقاط القوة والضعف
    - اقتراح تحسينات للاستراتيجيات
    - تتبع تطور الاستراتيجيات
    """
    
    def __init__(self):
        self._evaluations: Dict[str, StrategyEvaluation] = {}
        self._evaluation_history: List[StrategyEvaluation] = []
        
        # تهيئة التقييمات الافتراضية
        self._init_default_evaluations()
        
        logger.info("StrategyReflection initialized")
    
    def _init_default_evaluations(self):
        """تهيئة التقييمات الافتراضية"""
        
        default_evaluations = [
            StrategyEvaluation(
                strategy_name="aggressive",
                effectiveness_score=75.0,
                strengths=[
                    "High detection rate",
                    "Fast execution",
                    "Good coverage"
                ],
                weaknesses=[
                    "High false positive rate",
                    "May trigger WAF",
                    "Resource intensive"
                ],
                suggestions=[
                    "Add validation step",
                    "Implement rate limiting",
                    "Use stealth mode for sensitive targets"
                ],
                metrics={
                    "detection_rate": 0.85,
                    "false_positive_rate": 0.25,
                    "avg_response_time": 2.5
                }
            ),
            StrategyEvaluation(
                strategy_name="stealth",
                effectiveness_score=85.0,
                strengths=[
                    "Low detection risk",
                    "Good for sensitive targets",
                    "Respects rate limits"
                ],
                weaknesses=[
                    "Slower execution",
                    "Lower coverage",
                    "May miss some vulnerabilities"
                ],
                suggestions=[
                    "Balance speed and stealth",
                    "Use random delays",
                    "Rotate user agents"
                ],
                metrics={
                    "detection_rate": 0.70,
                    "false_positive_rate": 0.05,
                    "avg_response_time": 5.0
                }
            ),
            StrategyEvaluation(
                strategy_name="balanced",
                effectiveness_score=80.0,
                strengths=[
                    "Good balance of speed and stealth",
                    "Moderate resource usage",
                    "Adaptable to targets"
                ],
                weaknesses=[
                    "Not optimized for specific scenarios",
                    "May need tuning"
                ],
                suggestions=[
                    "Auto-adjust based on target response",
                    "Implement learning mechanism",
                    "Optimize for common targets"
                ],
                metrics={
                    "detection_rate": 0.78,
                    "false_positive_rate": 0.12,
                    "avg_response_time": 3.5
                }
            )
        ]
        
        for eval in default_evaluations:
            self._evaluations[eval.strategy_name] = eval
            self._evaluation_history.append(eval)
    
    async def evaluate_strategy(
        self,
        strategy_name: str,
        metrics: Dict[str, float],
        observations: List[str]
    ) -> StrategyEvaluation:
        """
        تقييم استراتيجية بناءً على المقاييس والملاحظات
        
        Args:
            strategy_name: اسم الاستراتيجية
            metrics: مقاييس الأداء
            observations: ملاحظات إضافية
        
        Returns:
            تقييم الاستراتيجية
        """
        # حساب درجة الفعالية
        effectiveness_score = 0.0
        
        if "detection_rate" in metrics:
            effectiveness_score += metrics["detection_rate"] * 40
        if "false_positive_rate" in metrics:
            effectiveness_score += (1 - metrics["false_positive_rate"]) * 30
        if "avg_response_time" in metrics:
            # وقت استجابة أقل أفضل
            time_score = max(0, 1 - metrics["avg_response_time"] / 10) * 20
            effectiveness_score += time_score
        
        effectiveness_score = min(effectiveness_score, 100)
        
        # تحليل نقاط القوة والضعف
        strengths, weaknesses = await self._analyze_strengths_weaknesses(
            strategy_name, metrics, observations
        )
        
        # اقتراح تحسينات
        suggestions = await self._generate_suggestions(
            strategy_name, weaknesses, metrics
        )
        
        evaluation = StrategyEvaluation(
            strategy_name=strategy_name,
            effectiveness_score=effectiveness_score,
            strengths=strengths,
            weaknesses=weaknesses,
            suggestions=suggestions,
            metrics=metrics
        )
        
        self._evaluations[strategy_name] = evaluation
        self._evaluation_history.append(evaluation)
        
        logger.info(f"Strategy evaluated: {strategy_name} (score={effectiveness_score:.1f})")
        return evaluation
    
    async def _analyze_strengths_weaknesses(
        self,
        strategy_name: str,
        metrics: Dict[str, float],
        observations: List[str]
    ) -> Tuple[List[str], List[str]]:
        """تحليل نقاط القوة والضعف"""
        strengths = []
        weaknesses = []
        
        # تحليل المقاييس
        if metrics.get("detection_rate", 0) > 0.8:
            strengths.append("High detection rate")
        elif metrics.get("detection_rate", 0) < 0.5:
            weaknesses.append("Low detection rate")
        
        if metrics.get("false_positive_rate", 1) < 0.1:
            strengths.append("Low false positive rate")
        elif metrics.get("false_positive_rate", 0) > 0.3:
            weaknesses.append("High false positive rate")
        
        if metrics.get("avg_response_time", 10) < 2:
            strengths.append("Fast response time")
        elif metrics.get("avg_response_time", 0) > 8:
            weaknesses.append("Slow response time")
        
        # تحليل الملاحظات
        for obs in observations:
            if "good" in obs.lower() or "excellent" in obs.lower():
                strengths.append(obs)
            elif "bad" in obs.lower() or "poor" in obs.lower():
                weaknesses.append(obs)
        
        return strengths[:5], weaknesses[:5]
    
    async def _generate_suggestions(
        self,
        strategy_name: str,
        weaknesses: List[str],
        metrics: Dict[str, float]
    ) -> List[str]:
        """توليد اقتراحات للتحسين"""
        suggestions = []
        
        if "Low detection rate" in weaknesses:
            suggestions.append("Increase scan sensitivity")
            suggestions.append("Add more payloads")
        
        if "High false positive rate" in weaknesses:
            suggestions.append("Implement validation step")
            suggestions.append("Improve context analysis")
        
        if "Slow response time" in weaknesses:
            suggestions.append("Optimize queries")
            suggestions.append("Implement caching")
        
        if not suggestions:
            suggestions.append("Continue monitoring performance")
            suggestions.append("Consider A/B testing with alternatives")
        
        return suggestions
    
    async def get_strategy_evaluation(
        self,
        strategy_name: str
    ) -> Optional[StrategyEvaluation]:
        """الحصول على تقييم استراتيجية"""
        return self._evaluations.get(strategy_name)
    
    async def get_all_evaluations(self) -> List[StrategyEvaluation]:
        """الحصول على جميع التقييمات"""
        return list(self._evaluations.values())
    
    async def get_best_strategy(self) -> Optional[str]:
        """الحصول على أفضل استراتيجية حسب الفعالية"""
        if not self._evaluations:
            return None
        
        best = max(
            self._evaluations.values(),
            key=lambda x: x.effectiveness_score
        )
        return best.strategy_name
    
    async def get_improvement_suggestions(
        self,
        strategy_name: str = None
    ) -> List[str]:
        """
        الحصول على اقتراحات التحسين
        
        Args:
            strategy_name: اسم الاستراتيجية (الكل إذا None)
        
        Returns:
            قائمة بالاقتراحات
        """
        if strategy_name:
            eval = self._evaluations.get(strategy_name)
            return eval.suggestions if eval else []
        
        all_suggestions = set()
        for eval in self._evaluations.values():
            all_suggestions.update(eval.suggestions)
        
        return list(all_suggestions)
    
    async def get_statistics(self) -> Dict:
        """إحصائيات تأمل الاستراتيجيات"""
        if not self._evaluations:
            return {"total_evaluations": 0}
        
        return {
            "total_evaluations": len(self._evaluations),
            "evaluation_history": len(self._evaluation_history),
            "best_strategy": await self.get_best_strategy(),
            "average_effectiveness": sum(e.effectiveness_score for e in self._evaluations.values()) / len(self._evaluations),
            "strategy_scores": {
                name: eval.effectiveness_score
                for name, eval in self._evaluations.items()
            },
            "total_suggestions": len(await self.get_improvement_suggestions())
        }

