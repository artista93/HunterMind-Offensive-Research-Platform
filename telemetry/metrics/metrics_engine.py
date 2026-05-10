
import asyncio
import time
import psutil
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
from datetime import datetime
from collections import deque
from enum import Enum

import logging

logger = logging.getLogger(__name__)


class MetricType(Enum):
    """نوع المقياس"""
    COUNTER = "counter"
    GAUGE = "gauge"
    HISTOGRAM = "histogram"
    TIMER = "timer"


@dataclass
class Metric:
    """مقياس"""
    name: str
    type: MetricType
    value: Any
    labels: Dict[str, str] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.now)


class MetricsEngine:
    """
    محرك المقاييس المتقدم
    
    الميزات:
    - جمع المقاييس من النظام والمكونات
    - تجميع وتحليل المقاييس
    - تصدير بصيغ متعددة (Prometheus, JSON)
    - تنبيهات عند تجاوز العتبات
    """
    
    def __init__(self, retention_minutes: int = 60):
        self.retention_minutes = retention_minutes
        self.metrics: Dict[str, deque] = {}
        self.counters: Dict[str, int] = {}
        self.gauges: Dict[str, float] = {}
        self.histograms: Dict[str, List[float]] = {}
        self.timers: Dict[str, List[float]] = {}
        
        self._collector_task: Optional[asyncio.Task] = None
        self._running = False
        
        logger.info(f"MetricsEngine initialized (retention={retention_minutes}m)")
    
    async def start(self):
        """بدء جمع المقاييس"""
        if self._running:
            return
        
        self._running = True
        self._collector_task = asyncio.create_task(self._collect_loop())
        logger.info("MetricsEngine started")
    
    async def stop(self):
        """إيقاف جمع المقاييس"""
        self._running = False
        
        if self._collector_task:
            self._collector_task.cancel()
        
        logger.info("MetricsEngine stopped")
    
    async def _collect_loop(self):
        """حلقة جمع المقاييس الدورية"""
        while self._running:
            try:
                await self._collect_system_metrics()
                await asyncio.sleep(10)  # كل 10 ثواني
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Metrics collection error: {e}")
    
    async def _collect_system_metrics(self):
        """جمع مقاييس النظام"""
        # CPU
        cpu_percent = psutil.cpu_percent(interval=1)
        await self.record_gauge("system.cpu.percent", cpu_percent)
        
        # Memory
        memory = psutil.virtual_memory()
        await self.record_gauge("system.memory.percent", memory.percent)
        await self.record_gauge("system.memory.used_mb", memory.used / (1024 * 1024))
        await self.record_gauge("system.memory.available_mb", memory.available / (1024 * 1024))
        
        # Disk
        disk = psutil.disk_usage('/')
        await self.record_gauge("system.disk.percent", disk.percent)
        await self.record_gauge("system.disk.used_gb", disk.used / (1024 ** 3))
        await self.record_gauge("system.disk.free_gb", disk.free / (1024 ** 3))
        
        # Network
        net_io = psutil.net_io_counters()
        await self.record_counter("system.network.bytes_sent", net_io.bytes_sent)
        await self.record_counter("system.network.bytes_recv", net_io.bytes_recv)
    
    async def increment_counter(self, name: str, value: int = 1, labels: Dict = None):
        """زيادة عداد"""
        if name not in self.counters:
            self.counters[name] = 0
        self.counters[name] += value
        
        metric = Metric(
            name=name,
            type=MetricType.COUNTER,
            value=self.counters[name],
            labels=labels or {}
        )
        self._store_metric(metric)
    
    async def record_counter(self, name: str, value: int, labels: Dict = None):
        """تسجيل قيمة عداد"""
        self.counters[name] = value
        metric = Metric(
            name=name,
            type=MetricType.COUNTER,
            value=value,
            labels=labels or {}
        )
        self._store_metric(metric)
    
    async def record_gauge(self, name: str, value: float, labels: Dict = None):
        """تسجيل قيمة مقياس"""
        self.gauges[name] = value
        metric = Metric(
            name=name,
            type=MetricType.GAUGE,
            value=value,
            labels=labels or {}
        )
        self._store_metric(metric)
    
    async def record_histogram(self, name: str, value: float, labels: Dict = None):
        """تسجيل قيمة في الرسم البياني التكراري"""
        if name not in self.histograms:
            self.histograms[name] = []
        self.histograms[name].append(value)
        
        # الاحتفاظ بآخر 1000 قيمة
        if len(self.histograms[name]) > 1000:
            self.histograms[name] = self.histograms[name][-1000:]
        
        metric = Metric(
            name=name,
            type=MetricType.HISTOGRAM,
            value=value,
            labels=labels or {}
        )
        self._store_metric(metric)
    
    async def record_timer(self, name: str, duration: float, labels: Dict = None):
        """تسجيل وقت تنفيذ"""
        if name not in self.timers:
            self.timers[name] = []
        self.timers[name].append(duration)
        
        if len(self.timers[name]) > 1000:
            self.timers[name] = self.timers[name][-1000:]
        
        metric = Metric(
            name=name,
            type=MetricType.TIMER,
            value=duration,
            labels=labels or {}
        )
        self._store_metric(metric)
    
    def _store_metric(self, metric: Metric):
        """تخزين مقياس في الذاكرة"""
        if metric.name not in self.metrics:
            self.metrics[metric.name] = deque(maxlen=self.retention_minutes * 6)  # 6 عينات في الدقيقة
        
        self.metrics[metric.name].append(metric)
    
    async def get_metric(self, name: str, duration_minutes: int = 10) -> List[Metric]:
        """الحصول على مقاييس محددة"""
        if name not in self.metrics:
            return []
        
        cutoff = datetime.now().timestamp() - (duration_minutes * 60)
        return [
            m for m in self.metrics[name]
            if m.timestamp.timestamp() > cutoff
        ]
    
    async def get_counter(self, name: str) -> int:
        """الحصول على قيمة عداد"""
        return self.counters.get(name, 0)
    
    async def get_gauge(self, name: str) -> float:
        """الحصول على قيمة مقياس"""
        return self.gauges.get(name, 0.0)
    
    async def get_histogram_stats(self, name: str) -> Dict:
        """الحصول على إحصائيات الرسم البياني التكراري"""
        values = self.histograms.get(name, [])
        if not values:
            return {"count": 0}
        
        return {
            "count": len(values),
            "min": min(values),
            "max": max(values),
            "avg": sum(values) / len(values),
            "p50": self._percentile(values, 50),
            "p95": self._percentile(values, 95),
            "p99": self._percentile(values, 99)
        }
    
    async def get_timer_stats(self, name: str) -> Dict:
        """الحصول على إحصائيات المؤقت"""
        return await self.get_histogram_stats(name)
    
    def _percentile(self, values: List[float], p: int) -> float:
        """حساب النسبة المئوية"""
        if not values:
            return 0.0
        
        sorted_values = sorted(values)
        index = int(len(sorted_values) * p / 100)
        return sorted_values[min(index, len(sorted_values) - 1)]
    
    async def get_summary(self) -> Dict:
        """الحصول على ملخص المقاييس"""
        return {
            "counters": self.counters,
            "gauges": self.gauges,
            "histograms": {
                name: await self.get_histogram_stats(name)
                for name in self.histograms
            },
            "timers": {
                name: await self.get_timer_stats(name)
                for name in self.timers
            },
            "active_metrics": len(self.metrics)
        }
    
    async def export_prometheus(self) -> str:
        """تصدير المقاييس بصيغة Prometheus"""
        lines = []
        
        # Counters
        for name, value in self.counters.items():
            lines.append(f"{name} {value}")
        
        # Gauges
        for name, value in self.gauges.items():
            lines.append(f"{name} {value}")
        
        # Histograms (مبسط)
        for name, stats in self.histograms.items():
            lines.append(f"{name}_count {stats.get('count', 0)}")
            lines.append(f"{name}_sum {stats.get('avg', 0) * stats.get('count', 0)}")
        
        return "\n".join(lines)


# نسخة عالمية
_default_engine = None


async def get_metrics_engine() -> MetricsEngine:
    """الحصول على نسخة عالمية من محرك المقاييس"""
    global _default_engine
    if _default_engine is None:
        _default_engine = MetricsEngine()
        await _default_engine.start()
    return _default_engine

