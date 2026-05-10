
import asyncio
import numpy as np
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from collections import defaultdict

import logging

logger = logging.getLogger(__name__)


@dataclass
class StrategyPerformance:
    """أداء استراتيجية"""
    strategy_name: str
    total_uses: int
    successful_uses: int
    average_success_rate: float
    average_response_time: float
    last_used: datetime
    trend: str  # improving, stable, declining


class StrategyAnalytics:
    """
    تحليلات الاستراتيجيات المتقدمة
    
    الميزات:
    - تحليل فعالية الاستراتيجيات
    - مقارنة أداء الاستراتيجيات
    - توصيات لتحسين الاستراتيجيات
    - تتبع اتجاهات الأداء
    """
    
    def __init__(self):
        self.strategy_performance: Dict[str, List[Tuple[datetime, bool, float]]] = defaultdict(list)
        self.strategy_comparisons: List[Dict] = []
        self._lock = asyncio.Lock()
        
        logger.info("StrategyAnalytics initialized")
    
    async def record_strategy_use(
        self,
        strategy_name: str,
        success: bool,
        response_time: float,
        metadata: Dict = None
    ):
        """
        تسجيل استخدام استراتيجية
        
        Args:
            strategy_name: اسم الاستراتيجية
            success: نجاح الاستراتيجية
            response_time: وقت الاستجابة
            metadata: بيانات إضافية
        """
        async with self._lock:
            self.strategy_performance[strategy_name].append((
                datetime.now(),
                success,
                response_time
            ))
            
            # الاحتفاظ بآخر 1000 سجل فقط
            if len(self.strategy_performance[strategy_name]) > 1000:
                self.strategy_performance[strategy_name] = self.strategy_performance[strategy_name][-1000:]
        
        logger.debug(f"Strategy recorded: {strategy_name} - {'SUCCESS' if success else 'FAIL'}")
    
    async def get_strategy_performance(
        self,
        strategy_name: str,
        hours: int = 24
    ) -> StrategyPerformance:
        """
        الحصول على أداء استراتيجية
        
        Args:
            strategy_name: اسم الاستراتيجية
            hours: عدد الساعات للتحليل
        
        Returns:
            أداء الاستراتيجية
        """
        cutoff = datetime.now() - timedelta(hours=hours)
        
        async with self._lock:
            records = [
                (ts, success, rt) for ts, success, rt in self.strategy_performance.get(strategy_name, [])
                if ts >= cutoff
            ]
        
        if not records:
            return StrategyPerformance(
                strategy_name=strategy_name,
                total_uses=0,
                successful_uses=0,
                average_success_rate=0.0,
                average_response_time=0.0,
                last_used=datetime.now(),
                trend="stable"
            )
        
        total = len(records)
        successful = sum(1 for _, s, _ in records if s)
        avg_success = successful / total if total > 0 else 0
        avg_response = sum(rt for _, _, rt in records) / total if total > 0 else 0
        
        # حساب الاتجاه
        if len(records) >= 10:
            recent = records[-5:]
            older = records[-10:-5]
            
            recent_success = sum(1 for _, s, _ in recent) / len(recent) if recent else 0
            older_success = sum(1 for _, s, _ in older) / len(older) if older else 0
            
            if recent_success > older_success + 0.1:
                trend = "improving"
            elif recent_success < older_success - 0.1:
                trend = "declining"
            else:
                trend = "stable"
        else:
            trend = "stable"
        
        return StrategyPerformance(
            strategy_name=strategy_name,
            total_uses=total,
            successful_uses=successful,
            average_success_rate=avg_success,
            average_response_time=avg_response,
            last_used=max(ts for ts, _, _ in records),
            trend=trend
        )
    
    async def get_all_strategies_performance(self) -> Dict[str, StrategyPerformance]:
        """الحصول على أداء جميع الاستراتيجيات"""
        async with self._lock:
            strategy_names = list(self.strategy_performance.keys())
        
        performances = {}
        for name in strategy_names:
            performances[name] = await self.get_strategy_performance(name)
        
        return performances
    
    async def compare_strategies(self) -> List[Dict]:
        """
        مقارنة أداء الاستراتيجيات
        
        Returns:
            قائمة بمقارنات الاستراتيجيات
        """
        performances = await self.get_all_strategies_performance()
        
        comparisons = []
        strategy_list = list(performances.values())
        
        for i, perf1 in enumerate(strategy_list):
            for perf2 in strategy_list[i+1:]:
                comparison = {
                    "strategy1": perf1.strategy_name,
                    "strategy2": perf2.strategy_name,
                    "success_rate_diff": perf1.average_success_rate - perf2.average_success_rate,
                    "response_time_diff": perf1.average_response_time - perf2.average_response_time,
                    "better_strategy": perf1.strategy_name if perf1.average_success_rate > perf2.average_success_rate else perf2.strategy_name
                }
                comparisons.append(comparison)
        
        return comparisons
    
    async def get_best_strategy(self) -> Optional[str]:
        """الحصول على أفضل استراتيجية حالياً"""
        performances = await self.get_all_strategies_performance()
        
        if not performances:
            return None
        
        best = max(performances.values(), key=lambda x: x.average_success_rate)
        return best.strategy_name
    
    async def get_worst_strategy(self) -> Optional[str]:
        """الحصول على أسوأ استراتيجية حالياً"""
        performances = await self.get_all_strategies_performance()
        
        if not performances:
            return None
        
        worst = min(performances.values(), key=lambda x: x.average_success_rate)
        return worst.strategy_name
    
    async def get_recommendations(self) -> List[str]:
        """
        الحصول على توصيات لتحسين الاستراتيجيات
        
        Returns:
            قائمة بالتوصيات
        """
        recommendations = []
        performances = await self.get_all_strategies_performance()
        
        for perf in performances.values():
            if perf.trend == "declining":
                recommendations.append(f"Strategy '{perf.strategy_name}' is declining. Consider reviewing its parameters.")
            
            if perf.average_success_rate < 0.5 and perf.total_uses > 10:
                recommendations.append(f"Strategy '{perf.strategy_name}' has low success rate ({perf.average_success_rate:.1%}). Consider replacing it.")
            
            if perf.average_response_time > 10 and perf.average_success_rate > 0.7:
                recommendations.append(f"Strategy '{perf.strategy_name}' is successful but slow. Consider optimization.")
        
        if not recommendations:
            recommendations.append("All strategies performing well. Continue monitoring.")
        
        return recommendations
    
    async def get_strategy_analytics_report(self) -> str:
        """توليد تقرير تحليلات الاستراتيجيات"""
        performances = await self.get_all_strategies_performance()
        best = await self.get_best_strategy()
        worst = await self.get_worst_strategy()
        recommendations = await self.get_recommendations()
        
        report = f"""# Strategy Analytics Report

**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## Summary

- **Total Strategies:** {len(performances)}
- **Best Strategy:** {best or 'None'}
- **Worst Strategy:** {worst or 'None'}

## Strategy Performance

| Strategy | Uses | Success Rate | Avg Response (s) | Trend |
|----------|------|--------------|------------------|-------|
"""
        for perf in performances.values():
            status_icon = "📈" if perf.trend == "improving" else ("📉" if perf.trend == "declining" else "📊")
            report += f"| {perf.strategy_name} | {perf.total_uses} | {perf.average_success_rate:.1%} | {perf.average_response_time:.2f} | {status_icon} {perf.trend} |\n"
        
        report += "\n## Recommendations\n"
        for rec in recommendations:
            report += f"- {rec}\n"
        
        return report
    
    async def get_statistics(self) -> Dict:
        """إحصائيات تحليلات الاستراتيجيات"""
        async with self._lock:
            total_records = sum(len(v) for v in self.strategy_performance.values())
            
            return {
                "total_strategies": len(self.strategy_performance),
                "total_records": total_records,
                "average_records_per_strategy": total_records / len(self.strategy_performance) if self.strategy_performance else 0,
                "best_strategy": await self.get_best_strategy(),
                "worst_strategy": await self.get_worst_strategy()
            }


# نسخة عالمية
_default_analytics = None


async def get_strategy_analytics() -> StrategyAnalytics:
    """الحصول على نسخة عالمية من تحليلات الاستراتيجيات"""
    global _default_analytics
    if _default_analytics is None:
        _default_analytics = StrategyAnalytics()
    return _default_analytics

