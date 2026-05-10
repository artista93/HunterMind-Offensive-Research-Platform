
import asyncio
import numpy as np
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from collections import defaultdict

import logging

logger = logging.getLogger(__name__)


@dataclass
class PerformanceReport:
    """تقرير الأداء"""
    timestamp: datetime
    component: str
    metric: str
    value: float
    percentile: float
    threshold: float
    status: str  # good, warning, critical


class PerformanceAnalytics:
    """
    تحليلات الأداء المتقدمة
    
    الميزات:
    - تحليل أداء النظام والمكونات
    - كشف الاختناقات
    - تقارير دورية
    - تنبيهات الأداء
    """
    
    def __init__(self):
        self.performance_data: Dict[str, List[Tuple[datetime, float]]] = defaultdict(list)
        self.reports: List[PerformanceReport] = []
        self._lock = asyncio.Lock()
        
        # عتبات الأداء
        self.thresholds = {
            "response_time": {"warning": 5.0, "critical": 10.0},
            "cpu_usage": {"warning": 70.0, "critical": 85.0},
            "memory_usage": {"warning": 80.0, "critical": 90.0},
            "error_rate": {"warning": 0.05, "critical": 0.1},
            "throughput": {"warning": 100, "critical": 50}
        }
        
        logger.info("PerformanceAnalytics initialized")
    
    async def record_performance(
        self,
        component: str,
        metric: str,
        value: float,
        timestamp: datetime = None
    ):
        """
        تسجيل بيانات أداء
        
        Args:
            component: اسم المكون
            metric: اسم المقياس
            value: القيمة
            timestamp: وقت التسجيل
        """
        if timestamp is None:
            timestamp = datetime.now()
        
        key = f"{component}:{metric}"
        
        async with self._lock:
            self.performance_data[key].append((timestamp, value))
            
            # الاحتفاظ بآخر 10000 نقطة فقط
            if len(self.performance_data[key]) > 10000:
                self.performance_data[key] = self.performance_data[key][-10000:]
        
        # التحقق من العتبات
        await self._check_thresholds(component, metric, value, timestamp)
    
    async def _check_thresholds(self, component: str, metric: str, value: float, timestamp: datetime):
        """التحقق من تجاوز العتبات"""
        if metric not in self.thresholds:
            return
        
        thresholds = self.thresholds[metric]
        status = "good"
        
        if metric in ["response_time", "cpu_usage", "memory_usage", "error_rate"]:
            if value >= thresholds["critical"]:
                status = "critical"
            elif value >= thresholds["warning"]:
                status = "warning"
        elif metric == "throughput":
            if value <= thresholds["critical"]:
                status = "critical"
            elif value <= thresholds["warning"]:
                status = "warning"
        
        if status != "good":
            report = PerformanceReport(
                timestamp=timestamp,
                component=component,
                metric=metric,
                value=value,
                percentile=0,
                threshold=thresholds[status],
                status=status
            )
            
            async with self._lock:
                self.reports.append(report)
            
            logger.warning(f"Performance alert: {component} - {metric} = {value} ({status})")
    
    async def get_trend(
        self,
        component: str,
        metric: str,
        hours: int = 24
    ) -> Dict:
        """
        تحليل اتجاه الأداء
        
        Args:
            component: اسم المكون
            metric: اسم المقياس
            hours: عدد الساعات
        
        Returns:
            تحليل الاتجاه
        """
        key = f"{component}:{metric}"
        cutoff = datetime.now() - timedelta(hours=hours)
        
        async with self._lock:
            data = [(ts, val) for ts, val in self.performance_data.get(key, []) if ts >= cutoff]
        
        if len(data) < 10:
            return {"has_data": False}
        
        values = [val for _, val in data]
        
        # حساب الإحصائيات
        mean = np.mean(values)
        std = np.std(values)
        
        # حساب الاتجاه (الانحدار الخطي)
        x = np.arange(len(values))
        slope = np.polyfit(x, values, 1)[0]
        
        # تصنيف الاتجاه
        if slope > 0.01 * mean:
            trend = "increasing"
        elif slope < -0.01 * mean:
            trend = "decreasing"
        else:
            trend = "stable"
        
        return {
            "has_data": True,
            "component": component,
            "metric": metric,
            "period_hours": hours,
            "data_points": len(data),
            "current": values[-1],
            "min": min(values),
            "max": max(values),
            "mean": mean,
            "std": std,
            "trend": trend,
            "slope": slope
        }
    
    async def get_bottlenecks(self, minutes: int = 60) -> List[Dict]:
        """
        كشف الاختناقات في النظام
        
        Args:
            minutes: عدد الدقائق للتحليل
        
        Returns:
            قائمة بالاختناقات
        """
        bottlenecks = []
        cutoff = datetime.now() - timedelta(minutes=minutes)
        
        async with self._lock:
            for key, data in self.performance_data.items():
                recent_data = [(ts, val) for ts, val in data if ts >= cutoff]
                if len(recent_data) < 5:
                    continue
                
                values = [val for _, val in recent_data]
                avg = np.mean(values)
                
                # التحقق من تجاوز العتبات
                parts = key.split(":")
                component = parts[0]
                metric = parts[1] if len(parts) > 1 else ""
                
                if metric in self.thresholds:
                    thresholds = self.thresholds[metric]
                    if avg >= thresholds["critical"]:
                        bottlenecks.append({
                            "component": component,
                            "metric": metric,
                            "average": avg,
                            "severity": "critical",
                            "threshold": thresholds["critical"]
                        })
                    elif avg >= thresholds["warning"]:
                        bottlenecks.append({
                            "component": component,
                            "metric": metric,
                            "average": avg,
                            "severity": "warning",
                            "threshold": thresholds["warning"]
                        })
        
        return bottlenecks
    
    async def get_performance_summary(self, minutes: int = 60) -> Dict:
        """
        ملخص أداء النظام
        
        Args:
            minutes: عدد الدقائق للتحليل
        
        Returns:
            ملخص الأداء
        """
        cutoff = datetime.now() - timedelta(minutes=minutes)
        
        async with self._lock:
            components = set()
            for key in self.performance_data.keys():
                component = key.split(":")[0]
                components.add(component)
        
        summary = {
            "period_minutes": minutes,
            "components": {},
            "bottlenecks": await self.get_bottlenecks(minutes),
            "total_reports": len([r for r in self.reports if r.timestamp >= cutoff])
        }
        
        for component in components:
            component_summary = {}
            
            for metric in ["response_time", "cpu_usage", "memory_usage", "error_rate", "throughput"]:
                trend = await self.get_trend(component, metric, minutes // 60)
                if trend.get("has_data"):
                    component_summary[metric] = {
                        "current": trend["current"],
                        "trend": trend["trend"],
                        "status": "good"
                    }
                    
                    # تحديد الحالة
                    if metric in self.thresholds:
                        if trend["current"] >= self.thresholds[metric]["critical"]:
                            component_summary[metric]["status"] = "critical"
                        elif trend["current"] >= self.thresholds[metric]["warning"]:
                            component_summary[metric]["status"] = "warning"
            
            summary["components"][component] = component_summary
        
        return summary
    
    async def generate_performance_report(self) -> str:
        """توليد تقرير أداء بصيغة Markdown"""
        summary = await self.get_performance_summary(60)
        bottlenecks = await self.get_bottlenecks(60)
        
        report = f"""# Performance Report

**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**Period:** Last 60 minutes

## Summary

- **Components Monitored:** {len(summary['components'])}
- **Bottlenecks Found:** {len(bottlenecks)}
- **Performance Alerts:** {summary['total_reports']}

## Bottlenecks

"""
        if bottlenecks:
            for b in bottlenecks:
                report += f"- **{b['component']}** - {b['metric']}: {b['average']:.2f} ({b['severity']})\n"
        else:
            report += "- No bottlenecks detected\n"
        
        report += "\n## Component Details\n"
        
        for component, metrics in summary['components'].items():
            report += f"\n### {component}\n"
            for metric, data in metrics.items():
                status_icon = "🟢" if data['status'] == "good" else ("🟡" if data['status'] == "warning" else "🔴")
                report += f"- {status_icon} **{metric}**: {data['current']:.2f} (trend: {data['trend']})\n"
        
        return report
    
    async def get_statistics(self) -> Dict:
        """إحصائيات تحليلات الأداء"""
        async with self._lock:
            return {
                "total_performance_points": sum(len(v) for v in self.performance_data.values()),
                "unique_metrics": len(self.performance_data),
                "total_reports": len(self.reports),
                "critical_reports": len([r for r in self.reports if r.status == "critical"]),
                "warning_reports": len([r for r in self.reports if r.status == "warning"])
            }


# نسخة عالمية
_default_analytics = None


async def get_performance_analytics() -> PerformanceAnalytics:
    """الحصول على نسخة عالمية من تحليلات الأداء"""
    global _default_analytics
    if _default_analytics is None:
        _default_analytics = PerformanceAnalytics()
    return _default_analytics

