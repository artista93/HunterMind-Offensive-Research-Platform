
import asyncio
import numpy as np
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from collections import defaultdict

import logging

logger = logging.getLogger(__name__)


@dataclass
class TrendResult:
    """نتيجة تحليل الاتجاه"""
    metric: str
    period_days: int
    slope: float
    direction: str  # increasing, decreasing, stable
    magnitude: float  # 0-1
    confidence: float
    forecast: List[Tuple[datetime, float]]


class TrendAnalysis:
    """
    تحليل الاتجاهات المتقدم
    
    الميزات:
    - تحليل الاتجاهات الزمنية
    - التنبؤ بالقيم المستقبلية
    - كشف الأنماط الموسمية
    - تحديد نقاط التغيير
    """
    
    def __init__(self):
        self.time_series_data: Dict[str, List[Tuple[datetime, float]]] = defaultdict(list)
        self._lock = asyncio.Lock()
        
        logger.info("TrendAnalysis initialized")
    
    async def add_data_point(self, metric: str, value: float, timestamp: datetime = None):
        """
        إضافة نقطة بيانات جديدة
        
        Args:
            metric: اسم المقياس
            value: القيمة
            timestamp: وقت القياس
        """
        if timestamp is None:
            timestamp = datetime.now()
        
        async with self._lock:
            self.time_series_data[metric].append((timestamp, value))
            
            # الاحتفاظ بآخر 10000 نقطة فقط
            if len(self.time_series_data[metric]) > 10000:
                self.time_series_data[metric] = self.time_series_data[metric][-10000:]
        
        logger.debug(f"Data point added: {metric} = {value}")
    
    async def analyze_trend(
        self,
        metric: str,
        days: int = 30,
        forecast_days: int = 7
    ) -> Optional[TrendResult]:
        """
        تحليل الاتجاه لمقياس معين
        
        Args:
            metric: اسم المقياس
            days: عدد الأيام للتحليل
            forecast_days: عدد الأيام للتنبؤ
        
        Returns:
            نتيجة تحليل الاتجاه
        """
        cutoff = datetime.now() - timedelta(days=days)
        
        async with self._lock:
            data = [(ts, val) for ts, val in self.time_series_data.get(metric, []) if ts >= cutoff]
        
        if len(data) < 7:
            logger.warning(f"Insufficient data for trend analysis: {metric}")
            return None
        
        # استخراج القيم والطوابع الزمنية
        timestamps, values = zip(*data)
        x = np.arange(len(values))
        
        # الانحدار الخطي
        slope, intercept = np.polyfit(x, values, 1)
        
        # حساب معامل التحديد (R²)
        predicted = slope * x + intercept
        ss_res = sum((v - p) ** 2 for v, p in zip(values, predicted))
        ss_tot = sum((v - np.mean(values)) ** 2 for v in values)
        r2 = 1 - (ss_res / ss_tot) if ss_tot > 0 else 0
        
        # تحديد الاتجاه
        if slope > 0.01 * np.mean(values):
            direction = "increasing"
        elif slope < -0.01 * np.mean(values):
            direction = "decreasing"
        else:
            direction = "stable"
        
        # حساب حجم الاتجاه (0-1)
        magnitude = min(1.0, abs(slope) / (np.std(values) + 1e-6))
        
        # التنبؤ
        forecast = []
        last_x = len(values) - 1
        for i in range(1, forecast_days + 1):
            future_x = last_x + i
            future_value = slope * future_x + intercept
            future_date = timestamps[-1] + timedelta(days=i)
            forecast.append((future_date, future_value))
        
        return TrendResult(
            metric=metric,
            period_days=days,
            slope=slope,
            direction=direction,
            magnitude=magnitude,
            confidence=r2,
            forecast=forecast
        )
    
    async def get_all_trends(self) -> Dict[str, TrendResult]:
        """الحصول على تحليلات الاتجاه لجميع المقاييس"""
        async with self._lock:
            metrics = list(self.time_series_data.keys())
        
        trends = {}
        for metric in metrics:
            trend = await self.analyze_trend(metric)
            if trend:
                trends[metric] = trend
        
        return trends
    
    async def detect_seasonality(self, metric: str, days: int = 90) -> Dict:
        """
        كشف الأنماط الموسمية
        
        Args:
            metric: اسم المقياس
            days: عدد الأيام للتحليل
        
        Returns:
            معلومات عن الموسمية
        """
        cutoff = datetime.now() - timedelta(days=days)
        
        async with self._lock:
            data = [(ts, val) for ts, val in self.time_series_data.get(metric, []) if ts >= cutoff]
        
        if len(data) < 14:
            return {"has_seasonality": False}
        
        # تجميع حسب اليوم من الأسبوع
        dow_values = defaultdict(list)
        for ts, val in data:
            dow = ts.weekday()  # 0-6
            dow_values[dow].append(val)
        
        # حساب المتوسط لكل يوم
        dow_avg = {}
        for dow, vals in dow_values.items():
            dow_avg[dow] = sum(vals) / len(vals)
        
        # حساب الانحراف المعياري
        overall_avg = sum(dow_avg.values()) / len(dow_avg)
        std_dev = np.std(list(dow_avg.values()))
        
        # تحديد ما إذا كانت هناك موسمية
        has_seasonality = std_dev > 0.1 * overall_avg
        
        return {
            "has_seasonality": has_seasonality,
            "daily_averages": dow_avg,
            "overall_average": overall_avg,
            "std_dev": std_dev,
            "peak_day": max(dow_avg, key=dow_avg.get),
            "lowest_day": min(dow_avg, key=dow_avg.get)
        }
    
    async def detect_change_points(self, metric: str, days: int = 30) -> List[datetime]:
        """
        كشف نقاط التغيير في السلسلة الزمنية
        
        Args:
            metric: اسم المقياس
            days: عدد الأيام للتحليل
        
        Returns:
            قائمة بنقاط التغيير
        """
        cutoff = datetime.now() - timedelta(days=days)
        
        async with self._lock:
            data = [(ts, val) for ts, val in self.time_series_data.get(metric, []) if ts >= cutoff]
        
        if len(data) < 14:
            return []
        
        values = [val for _, val in data]
        change_points = []
        
        # طريقة بسيطة: البحث عن تغييرات كبيرة في المتوسط المتحرك
        window = max(3, len(values) // 7)
        if window < 2:
            return []
        
        moving_avg = []
        for i in range(len(values) - window + 1):
            avg = sum(values[i:i+window]) / window
            moving_avg.append(avg)
        
        # البحث عن تغييرات كبيرة
        for i in range(1, len(moving_avg)):
            if abs(moving_avg[i] - moving_avg[i-1]) > 0.2 * moving_avg[i-1]:
                change_points.append(data[i + window // 2][0])
        
        return change_points
    
    async def get_trend_report(self) -> str:
        """توليد تقرير تحليل الاتجاهات"""
        trends = await self.get_all_trends()
        
        report = f"""# Trend Analysis Report

**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## Summary

- **Metrics Analyzed:** {len(trends)}

## Trend Analysis

| Metric | Direction | Magnitude | Confidence | Forecast |
|--------|-----------|-----------|------------|----------|
"""
        for metric, trend in trends.items():
            direction_icon = "📈" if trend.direction == "increasing" else ("📉" if trend.direction == "decreasing" else "📊")
            forecast_val = trend.forecast[-1][1] if trend.forecast else 0
            report += f"| {metric} | {direction_icon} {trend.direction} | {trend.magnitude:.2f} | {trend.confidence:.2f} | {forecast_val:.2f} |\n"
        
        report += "\n## Seasonal Patterns\n"
        
        for metric in list(trends.keys())[:5]:
            seasonality = await self.detect_seasonality(metric)
            if seasonality.get("has_seasonality"):
                report += f"\n### {metric}\n"
                report += f"- **Peak Day:** {['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'][seasonality['peak_day']]}\n"
                report += f"- **Lowest Day:** {['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'][seasonality['lowest_day']]}\n"
        
        return report
    
    async def get_statistics(self) -> Dict:
        """إحصائيات تحليل الاتجاهات"""
        async with self._lock:
            return {
                "total_metrics": len(self.time_series_data),
                "total_data_points": sum(len(v) for v in self.time_series_data.values()),
                "metrics_with_trend": len(await self.get_all_trends())
            }


# نسخة عالمية
_default_analysis = None


async def get_trend_analysis() -> TrendAnalysis:
    """الحصول على نسخة عالمية من تحليل الاتجاهات"""
    global _default_analysis
    if _default_analysis is None:
        _default_analysis = TrendAnalysis()
    return _default_analysis

