

import asyncio
import time
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from collections import defaultdict, deque
from enum import Enum


class TrafficPattern(Enum):
    """أنماط حركة المرور"""
    NORMAL = "normal"
    SPIKY = "spiky"           # قمم مفاجئة
    BURSTY = "bursty"         # انفجارات
    STEADY = "steady"         # ثابت
    DECREASING = "decreasing"
    INCREASING = "increasing"
    CYCLIC = "cyclic"         # دوري


class AnomalyType(Enum):
    """أنواع الحالات الشاذة"""
    RATE_SPIKE = "rate_spike"           # ارتفاع مفاجئ في المعدل
    RATE_DROP = "rate_drop"             # انخفاض مفاجئ في المعدل
    HIGH_LATENCY = "high_latency"       # زمن استجابة عالي
    HIGH_ERROR_RATE = "high_error_rate" # معدل أخطاء مرتفع
    BURST = "burst"                      # انفجار طلبات
    PATTERN_CHANGE = "pattern_change"    # تغير في النمط


@dataclass
class TrafficSample:
    """عينة حركة مرور"""
    timestamp: float
    requests_count: int
    avg_response_time: float
    error_count: int
    blocked_count: int
    bytes_transferred: int


@dataclass
class Anomaly:
    """حالة شاذة مكتشفة"""
    type: AnomalyType
    severity: float  # 0-1
    description: str
    timestamp: float
    value: float
    threshold: float
    suggested_action: str


class TrafficAnalyzer:
    """محلل حركة المرور المتقدم"""
    
    def __init__(self, window_size: int = 60, sample_interval: int = 5):
        self.window_size = window_size  # حجم النافذة بالثواني
        self.sample_interval = sample_interval  # فاصل العينات بالثواني
        
        self._samples: deque = deque(maxlen=window_size // sample_interval + 10)
        self._anomalies: List[Anomaly] = []
        self._last_sample_time = 0
        self._current_sample = None
        self._lock = asyncio.Lock()
        
        # إحصائيات
        self._stats = {
            "total_samples": 0,
            "anomalies_detected": 0,
            "false_positives": 0
        }
        
        # متغيرات للتحليل
        self._request_counts: deque = deque(maxlen=100)
        self._response_times: deque = deque(maxlen=100)
        self._error_rates: deque = deque(maxlen=100)
    
    def record_request(self, url: str, response_time: float, success: bool, blocked: bool = False, bytes_size: int = 0):
        """تسجيل طلب للتحليل"""
        now = time.time()
        
        # بدء عينة جديدة إذا لزم الأمر
        if self._current_sample is None or now - self._last_sample_time >= self.sample_interval:
            self._finalize_current_sample()
            self._current_sample = TrafficSample(
                timestamp=now,
                requests_count=0,
                avg_response_time=0,
                error_count=0,
                blocked_count=0,
                bytes_transferred=0
            )
            self._last_sample_time = now
        
        # تحديث العينة الحالية
        if self._current_sample:
            self._current_sample.requests_count += 1
            
            # تحديث متوسط وقت الاستجابة
            total_time = self._current_sample.avg_response_time * (self._current_sample.requests_count - 1) + response_time
            self._current_sample.avg_response_time = total_time / self._current_sample.requests_count
            
            if not success:
                self._current_sample.error_count += 1
            if blocked:
                self._current_sample.blocked_count += 1
            
            self._current_sample.bytes_transferred += bytes_size
        
        # تحديث قوائم التحليل
        self._request_counts.append(1)
        self._response_times.append(response_time)
        self._error_rates.append(0 if success else 1)
    
    def _finalize_current_sample(self):
        """إنهاء العينة الحالية وإضافتها للتحليل"""
        if self._current_sample and self._current_sample.requests_count > 0:
            self._samples.append(self._current_sample)
            self._stats["total_samples"] += 1
            self._current_sample = None
    
    async def analyze(self) -> Dict:
        """تحليل حركة المرور"""
        async with self._lock:
            self._finalize_current_sample()
            
            if len(self._samples) < 3:
                return {"status": "insufficient_data", "samples": len(self._samples)}
            
            # استخراج البيانات
            rates = [s.requests_count / self.sample_interval for s in self._samples]
            latencies = [s.avg_response_time for s in self._samples if s.avg_response_time > 0]
            error_rates = [s.error_count / max(1, s.requests_count) for s in self._samples]
            
            # كشف الأنماط
            pattern = self._detect_pattern(rates)
            
            # كشف الحالات الشاذة
            anomalies = []
            
            # 1. ارتفاع مفاجئ في المعدل
            rate_anomaly = self._detect_rate_anomaly(rates)
            if rate_anomaly:
                anomalies.append(rate_anomaly)
            
            # 2. ارتفاع في زمن الاستجابة
            latency_anomaly = self._detect_latency_anomaly(latencies)
            if latency_anomaly:
                anomalies.append(latency_anomaly)
            
            # 3. ارتفاع في معدل الأخطاء
            error_anomaly = self._detect_error_anomaly(error_rates)
            if error_anomaly:
                anomalies.append(error_anomaly)
            
            # 4. كشف الانفجارات (bursts)
            burst_anomaly = self._detect_burst(rates)
            if burst_anomaly:
                anomalies.append(burst_anomaly)
            
            # 5. كشف تغير النمط
            pattern_change = self._detect_pattern_change(rates)
            if pattern_change:
                anomalies.append(pattern_change)
            
            # تخزين الحالات الشاذة
            for anomaly in anomalies:
                self._anomalies.append(anomaly)
                self._stats["anomalies_detected"] += 1
            
            # الاحتفاظ بآخر 100 حالة شاذة
            if len(self._anomalies) > 100:
                self._anomalies = self._anomalies[-100:]
            
            return {
                "pattern": pattern.value,
                "current_rate": rates[-1] if rates else 0,
                "avg_rate": sum(rates) / len(rates) if rates else 0,
                "avg_latency_ms": sum(latencies) / len(latencies) if latencies else 0,
                "error_rate": error_rates[-1] if error_rates else 0,
                "anomalies_detected": len(anomalies),
                "anomalies": [{
                    "type": a.type.value,
                    "severity": a.severity,
                    "description": a.description,
                    "suggested_action": a.suggested_action
                } for a in anomalies],
                "trend": self._calculate_trend(rates)
            }
    
    def _detect_pattern(self, rates: List[float]) -> TrafficPattern:
        """كشف نمط حركة المرور"""
        if len(rates) < 5:
            return TrafficPattern.NORMAL
        
        # حساب التغير
        changes = [abs(rates[i+1] - rates[i]) for i in range(len(rates)-1)]
        avg_change = sum(changes) / len(changes)
        avg_rate = sum(rates) / len(rates)
        
        # نسبة التغير
        change_ratio = avg_change / max(1, avg_rate)
        
        if change_ratio > 0.5:
            return TrafficPattern.SPIKY
        elif change_ratio > 0.2:
            return TrafficPattern.BURSTY
        elif change_ratio < 0.05:
            return TrafficPattern.STEADY
        else:
            # فحص الاتجاه
            if rates[-1] > rates[0] * 1.2:
                return TrafficPattern.INCREASING
            elif rates[-1] < rates[0] * 0.8:
                return TrafficPattern.DECREASING
        
        return TrafficPattern.NORMAL
    
    def _detect_rate_anomaly(self, rates: List[float]) -> Optional[Anomaly]:
        """كشف ارتفاع أو انخفاض غير طبيعي في المعدل"""
        if len(rates) < 5:
            return None
        
        recent = rates[-3:] if len(rates) >= 3 else rates
        historical = rates[:-3] if len(rates) > 3 else rates
        
        avg_recent = sum(recent) / len(recent)
        avg_historical = sum(historical) / len(historical) if historical else avg_recent
        
        if avg_historical == 0:
            return None
        
        ratio = avg_recent / avg_historical
        
        if ratio > 2.5:
            return Anomaly(
                type=AnomalyType.RATE_SPIKE,
                severity=min(1.0, (ratio - 2) / 5),
                description=f"Rate spike detected: {ratio:.1f}x normal rate",
                timestamp=time.time(),
                value=avg_recent,
                threshold=avg_historical * 2,
                suggested_action="Check for DDoS or unexpected traffic surge"
            )
        elif ratio < 0.3:
            return Anomaly(
                type=AnomalyType.RATE_DROP,
                severity=min(1.0, (1 - ratio) / 0.7),
                description=f"Rate drop detected: {ratio:.1f}x normal rate",
                timestamp=time.time(),
                value=avg_recent,
                threshold=avg_historical * 0.5,
                suggested_action="Check if target is blocking requests"
            )
        
        return None
    
    def _detect_latency_anomaly(self, latencies: List[float]) -> Optional[Anomaly]:
        """كشف ارتفاع غير طبيعي في زمن الاستجابة"""
        if len(latencies) < 5:
            return None
        
        recent = latencies[-3:] if len(latencies) >= 3 else latencies
        historical = latencies[:-3] if len(latencies) > 3 else latencies
        
        avg_recent = sum(recent) / len(recent)
        avg_historical = sum(historical) / len(historical) if historical else avg_recent
        
        if avg_historical == 0:
            return None
        
        ratio = avg_recent / avg_historical
        
        if ratio > 3:
            return Anomaly(
                type=AnomalyType.HIGH_LATENCY,
                severity=min(1.0, (ratio - 3) / 10),
                description=f"High latency detected: {avg_recent:.0f}ms (normal: {avg_historical:.0f}ms)",
                timestamp=time.time(),
                value=avg_recent,
                threshold=avg_historical * 2,
                suggested_action="Reduce request rate or use stealth mode"
            )
        
        return None
    
    def _detect_error_anomaly(self, error_rates: List[float]) -> Optional[Anomaly]:
        """كشف ارتفاع غير طبيعي في معدل الأخطاء"""
        if len(error_rates) < 5:
            return None
        
        recent = error_rates[-3:] if len(error_rates) >= 3 else error_rates
        historical = error_rates[:-3] if len(error_rates) > 3 else error_rates
        
        avg_recent = sum(recent) / len(recent)
        avg_historical = sum(historical) / len(historical) if historical else avg_recent
        
        if avg_historical == 0:
            return None
        
        ratio = avg_recent / avg_historical if avg_historical > 0 else avg_recent * 10
        
        if ratio > 5 or (avg_recent > 0.1 and avg_historical < 0.02):
            return Anomaly(
                type=AnomalyType.HIGH_ERROR_RATE,
                severity=min(1.0, ratio / 10),
                description=f"High error rate detected: {avg_recent:.1%} (normal: {avg_historical:.1%})",
                timestamp=time.time(),
                value=avg_recent,
                threshold=avg_historical * 3,
                suggested_action="Check if target is blocking or WAF is active"
            )
        
        return None
    
    def _detect_burst(self, rates: List[float]) -> Optional[Anomaly]:
        """كشف الانفجارات (Bursts)"""
        if len(rates) < 10:
            return None
        
        # حساب الانحراف المعياري
        avg = sum(rates) / len(rates)
        variance = sum((r - avg) ** 2 for r in rates) / len(rates)
        std = variance ** 0.5
        
        # فحص أحدث نقطة
        last_rate = rates[-1]
        
        if last_rate > avg + 3 * std:
            return Anomaly(
                type=AnomalyType.BURST,
                severity=min(1.0, (last_rate - avg) / (avg + 3 * std)),
                description=f"Burst detected: {last_rate:.0f} req/s (avg: {avg:.0f} req/s)",
                timestamp=time.time(),
                value=last_rate,
                threshold=avg + 2 * std,
                suggested_action="Implement rate limiting or increase delay"
            )
        
        return None
    
    def _detect_pattern_change(self, rates: List[float]) -> Optional[Anomaly]:
        """كشف تغير في نمط حركة المرور"""
        if len(rates) < 10:
            return None
        
        # تقسيم البيانات إلى نصفين
        mid = len(rates) // 2
        first_half = rates[:mid]
        second_half = rates[mid:]
        
        avg_first = sum(first_half) / len(first_half)
        avg_second = sum(second_half) / len(second_half)
        
        if avg_first == 0:
            return None
        
        ratio = avg_second / avg_first
        
        if ratio > 2 or ratio < 0.5:
            return Anomaly(
                type=AnomalyType.PATTERN_CHANGE,
                severity=min(1.0, abs(1 - ratio) / 2),
                description=f"Traffic pattern changed: {ratio:.1f}x previous rate",
                timestamp=time.time(),
                value=avg_second,
                threshold=avg_first * 1.5,
                suggested_action="Re-evaluate scan strategy"
            )
        
        return None
    
    def _calculate_trend(self, rates: List[float]) -> str:
        """حساب اتجاه حركة المرور"""
        if len(rates) < 5:
            return "stable"
        
        # حساب الانحدار الخطي البسيط
        n = len(rates)
        x = list(range(n))
        
        sum_x = sum(x)
        sum_y = sum(rates)
        sum_xy = sum(x[i] * rates[i] for i in range(n))
        sum_xx = sum(i * i for i in x)
        
        slope = (n * sum_xy - sum_x * sum_y) / (n * sum_xx - sum_x * sum_x) if (n * sum_xx - sum_x * sum_x) != 0 else 0
        
        if slope > 0.5:
            return "increasing"
        elif slope < -0.5:
            return "decreasing"
        return "stable"
    
    def get_recent_anomalies(self, limit: int = 10) -> List[Dict]:
        """الحصول على آخر الحالات الشاذة"""
        return [{
            "type": a.type.value,
            "severity": a.severity,
            "description": a.description,
            "timestamp": a.timestamp,
            "suggested_action": a.suggested_action
        } for a in self._anomalies[-limit:]]
    
    def get_stats(self) -> Dict:
        """إحصائيات المحلل"""
        return {
            "total_samples": self._stats["total_samples"],
            "anomalies_detected": self._stats["anomalies_detected"],
            "false_positives": self._stats["false_positives"],
            "window_size": self.window_size,
            "sample_interval": self.sample_interval,
            "active_samples": len(self._samples)
        }
    
    def clear(self):
        """مسح جميع البيانات"""
        self._samples.clear()
        self._anomalies.clear()
        self._current_sample = None
        self._request_counts.clear()
        self._response_times.clear()
        self._error_rates.clear()
        self._stats = {
            "total_samples": 0,
            "anomalies_detected": 0,
            "false_positives": 0
        }


# نسخة عالمية
_default_analyzer = None


def get_traffic_analyzer(window_size: int = 60, sample_interval: int = 5) -> TrafficAnalyzer:
    """الحصول على نسخة عالمية من محلل حركة المرور"""
    global _default_analyzer
    if _default_analyzer is None:
        _default_analyzer = TrafficAnalyzer(window_size=window_size, sample_interval=sample_interval)
    return _default_analyzer

