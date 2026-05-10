
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from collections import defaultdict
from enum import Enum

import logging

logger = logging.getLogger(__name__)


class BehaviorStatus(Enum):
    """حالة السلوك"""
    EXCELLENT = "excellent"
    GOOD = "good"
    FAIR = "fair"
    POOR = "poor"
    CRITICAL = "critical"


@dataclass
class BehaviorMetric:
    """مقياس سلوكي"""
    name: str
    value: float
    threshold: float
    status: BehaviorStatus
    trend: str  # improving, stable, declining
    last_updated: datetime = field(default_factory=datetime.now)


@dataclass
class AgentBehavior:
    """سلوك وكيل"""
    agent_id: str
    agent_name: str
    metrics: Dict[str, BehaviorMetric]
    overall_score: float
    status: BehaviorStatus
    recommendations: List[str]
    last_evaluated: datetime = field(default_factory=datetime.now)


class BehaviorEvaluator:
    """
    مقيم السلوك المتقدم
    
    الميزات:
    - تقييم سلوك الوكلاء
    - قياس الامتثال للسياسات
    - تحديد الانحرافات السلوكية
    - اقتراح تحسينات سلوكية
    """
    
    def __init__(self):
        self._agent_behavior: Dict[str, AgentBehavior] = {}
        self._evaluation_history: List[Dict] = []
        
        logger.info("BehaviorEvaluator initialized")
    
    async def evaluate_agent(
        self,
        agent_id: str,
        agent_name: str,
        metrics: Dict[str, float],
        thresholds: Dict[str, float] = None
    ) -> AgentBehavior:
        """
        تقييم سلوك وكيل
        
        Args:
            agent_id: معرف الوكيل
            agent_name: اسم الوكيل
            metrics: مقاييس السلوك
            thresholds: عتبات التقييم
        
        Returns:
            تقييم سلوك الوكيل
        """
        if thresholds is None:
            thresholds = {
                "success_rate": 0.7,
                "response_time": 5.0,
                "error_rate": 0.1,
                "resource_usage": 0.8,
                "compliance": 0.9
            }
        
        behavior_metrics = {}
        total_score = 0.0
        metric_count = 0
        
        for name, value in metrics.items():
            threshold = thresholds.get(name, 0.5)
            
            # تحديد الحالة
            if name == "response_time" or name == "error_rate" or name == "resource_usage":
                # القيم الأصغر أفضل
                if value <= threshold * 0.5:
                    status = BehaviorStatus.EXCELLENT
                    score = 100
                elif value <= threshold:
                    status = BehaviorStatus.GOOD
                    score = 80
                elif value <= threshold * 1.5:
                    status = BehaviorStatus.FAIR
                    score = 60
                elif value <= threshold * 2:
                    status = BehaviorStatus.POOR
                    score = 40
                else:
                    status = BehaviorStatus.CRITICAL
                    score = 20
            else:
                # القيم الأكبر أفضل
                if value >= threshold * 1.5:
                    status = BehaviorStatus.EXCELLENT
                    score = 100
                elif value >= threshold:
                    status = BehaviorStatus.GOOD
                    score = 80
                elif value >= threshold * 0.7:
                    status = BehaviorStatus.FAIR
                    score = 60
                elif value >= threshold * 0.5:
                    status = BehaviorStatus.POOR
                    score = 40
                else:
                    status = BehaviorStatus.CRITICAL
                    score = 20
            
            # تحديد الاتجاه (محاكاة)
            trend = "stable"
            if name in metrics:
                previous = await self._get_previous_metric(agent_id, name)
                if previous is not None:
                    if value > previous * 1.1:
                        trend = "improving" if name in ["success_rate", "compliance"] else "declining"
                    elif value < previous * 0.9:
                        trend = "declining" if name in ["success_rate", "compliance"] else "improving"
            
            behavior_metrics[name] = BehaviorMetric(
                name=name,
                value=value,
                threshold=threshold,
                status=status,
                trend=trend
            )
            
            total_score += score
            metric_count += 1
        
        overall_score = total_score / metric_count if metric_count > 0 else 0
        
        # تحديد الحالة الإجمالية
        if overall_score >= 90:
            status = BehaviorStatus.EXCELLENT
        elif overall_score >= 70:
            status = BehaviorStatus.GOOD
        elif overall_score >= 50:
            status = BehaviorStatus.FAIR
        elif overall_score >= 30:
            status = BehaviorStatus.POOR
        else:
            status = BehaviorStatus.CRITICAL
        
        # توليد توصيات
        recommendations = await self._generate_recommendations(behavior_metrics)
        
        behavior = AgentBehavior(
            agent_id=agent_id,
            agent_name=agent_name,
            metrics=behavior_metrics,
            overall_score=overall_score,
            status=status,
            recommendations=recommendations
        )
        
        self._agent_behavior[agent_id] = behavior
        
        # تسجيل التاريخ
        self._evaluation_history.append({
            "agent_id": agent_id,
            "agent_name": agent_name,
            "score": overall_score,
            "status": status.value,
            "timestamp": datetime.now().isoformat()
        })
        
        # الحفاظ على آخر 1000 تقييم
        if len(self._evaluation_history) > 1000:
            self._evaluation_history.pop(0)
        
        logger.info(f"Agent evaluated: {agent_name} (score={overall_score:.1f}, status={status.value})")
        return behavior
    
    async def _get_previous_metric(
        self,
        agent_id: str,
        metric_name: str
    ) -> Optional[float]:
        """الحصول على قيمة سابقة لمقياس"""
        if agent_id in self._agent_behavior:
            previous = self._agent_behavior[agent_id].metrics.get(metric_name)
            if previous:
                return previous.value
        return None
    
    async def _generate_recommendations(
        self,
        metrics: Dict[str, BehaviorMetric]
    ) -> List[str]:
        """توليد توصيات للتحسين"""
        recommendations = []
        
        for name, metric in metrics.items():
            if metric.status in [BehaviorStatus.POOR, BehaviorStatus.CRITICAL]:
                if name == "success_rate":
                    recommendations.append("Review and improve success rate - consider better payload selection")
                elif name == "response_time":
                    recommendations.append(f"Response time is high ({metric.value:.2f}s) - optimize performance")
                elif name == "error_rate":
                    recommendations.append(f"Error rate is high ({metric.value:.2%}) - investigate failures")
                elif name == "resource_usage":
                    recommendations.append(f"Resource usage is high ({metric.value:.2%}) - optimize resource consumption")
                elif name == "compliance":
                    recommendations.append("Compliance score is low - review policy adherence")
        
        if not recommendations:
            recommendations.append("Continue current behavior - performance is satisfactory")
        
        return recommendations[:5]
    
    async def get_agent_behavior(
        self,
        agent_id: str
    ) -> Optional[AgentBehavior]:
        """الحصول على سلوك وكيل"""
        return self._agent_behavior.get(agent_id)
    
    async def get_all_agent_behaviors(self) -> List[AgentBehavior]:
        """الحصول على سلوك جميع الوكلاء"""
        return list(self._agent_behavior.values())
    
    async def get_agents_by_status(self, status: BehaviorStatus) -> List[AgentBehavior]:
        """الحصول على الوكلاء حسب الحالة"""
        return [b for b in self._agent_behavior.values() if b.status == status]
    
    async def get_summary(self) -> Dict:
        """ملخص تقييم السلوك"""
        if not self._agent_behavior:
            return {"total_agents": 0}
        
        status_counts = defaultdict(int)
        total_score = 0.0
        
        for behavior in self._agent_behavior.values():
            status_counts[behavior.status.value] += 1
            total_score += behavior.overall_score
        
        return {
            "total_agents": len(self._agent_behavior),
            "status_distribution": dict(status_counts),
            "average_score": total_score / len(self._agent_behavior),
            "best_agent": max(self._agent_behavior.values(), key=lambda x: x.overall_score).agent_name,
            "worst_agent": min(self._agent_behavior.values(), key=lambda x: x.overall_score).agent_name,
            "critical_agents": len([b for b in self._agent_behavior.values() if b.status == BehaviorStatus.CRITICAL])
        }
    
    async def get_evaluation_history(
        self,
        agent_id: str = None,
        limit: int = 50
    ) -> List[Dict]:
        """الحصول على تاريخ التقييمات"""
        history = self._evaluation_history
        
        if agent_id:
            history = [h for h in history if h["agent_id"] == agent_id]
        
        return history[-limit:]
    
    async def get_statistics(self) -> Dict:
        """إحصائيات مقيم السلوك"""
        return {
            "total_evaluations": len(self._evaluation_history),
            "total_agents_evaluated": len(self._agent_behavior),
            "agents_by_status": {
                status.value: len([b for b in self._agent_behavior.values() if b.status == status])
                for status in BehaviorStatus
            },
            "overall_average_score": sum(b.overall_score for b in self._agent_behavior.values()) / len(self._agent_behavior) if self._agent_behavior else 0,
            "improving_agents": len([b for b in self._agent_behavior.values() if any(m.trend == "improving" for m in b.metrics.values())])
        }

