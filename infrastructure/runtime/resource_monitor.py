
import asyncio
import psutil
import time
import json
from typing import Dict, List, Optional, Any, Callable, Awaitable, Tuple, Set
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from collections import deque
import logging
import numpy as np

logger = logging.getLogger(__name__)


class MetricType(Enum):
    """نوع المقياس"""
    CPU_PERCENT = "cpu_percent"
    MEMORY_PERCENT = "memory_percent"
    MEMORY_BYTES = "memory_bytes"
    DISK_USAGE = "disk_usage"
    DISK_IO_READ = "disk_io_read"
    DISK_IO_WRITE = "disk_io_write"
    NETWORK_SENT = "network_sent"
    NETWORK_RECV = "network_recv"
    OPEN_FDS = "open_fds"
    THREAD_COUNT = "thread_count"
    PROCESS_COUNT = "process_count"


class AggregationWindow(Enum):
    """نافذة التجميع"""
    MINUTE = 60  # ثواني
    FIVE_MINUTES = 300
    FIFTEEN_MINUTES = 900
    HOUR = 3600
    DAY = 86400


@dataclass
class MetricDataPoint:
    """نقطة بيانات مقياس"""
    timestamp: datetime
    value: float
    metric_type: MetricType
    source: str  # system, process, service


@dataclass
class AggregatedMetric:
    """مقياس مجمع"""
    metric_type: MetricType
    window: AggregationWindow
    min: float
    max: float
    avg: float
    p50: float
    p95: float
    p99: float
    stddev: float
    sample_count: int
    start_time: datetime
    end_time: datetime


@dataclass
class ResourceThreshold:
    """عتبة موارد للتنبيه"""
    metric_type: MetricType
    warning_threshold: float
    critical_threshold: float
    direction: str = "above"  # above, below
    cooldown_seconds: float = 300  # 5 دقائق


class ResourceMonitor:
    """
    مراقب الموارد المتقدم
    
    الميزات:
    - جمع المقاييس في الوقت الفعلي
    - تجميع إحصائي مع نوافذ زمنية متعددة
    - كشف الشذوذ (Anomaly Detection)
    - تنبيهات ذكية مع إلغاء التكرار
    - تحليل الاتجاهات (Trend Analysis)
    - تصدير البيانات بصيغ متعددة (JSON, Prometheus)
    - تكامل مع نظام التنبيهات
    """
    
    def __init__(
        self,
        collection_interval: float = 5.0,
        retention_days: int = 7,
        enable_anomaly_detection: bool = True
    ):
        self._collection_interval = collection_interval
        self._retention_seconds = retention_days * 86400
        self._enable_anomaly_detection = enable_anomaly_detection
        
        # تخزين المقاييس الزمني
        self._metrics_store: Dict[str, deque] = {}  # source:metric_type -> deque
        self._aggregated_metrics: Dict[str, List[AggregatedMetric]] = {}
        
        # العتبات والتنبيهات
        self._thresholds: List[ResourceThreshold] = []
        self._alert_history: Dict[str, datetime] = {}  # للحد من التكرار
        self._alerts: List[Dict] = []
        
        # مكونات التشغيل
        self._collection_task: Optional[asyncio.Task] = None
        self._aggregation_task: Optional[asyncio.Task] = None
        self._running = False
        self._lock = asyncio.Lock()
        
        # سجل العمليات المراقبة
        self._watched_pids: Set[int] = set()
        self._watched_services: Set[str] = set()
        
        # إحصائيات
        self._stats = {
            "total_metrics_collected": 0,
            "total_alerts_triggered": 0,
            "anomalies_detected": 0,
            "last_collection": None
        }
        
        # معالجات الأحداث
        self._event_handlers: Dict[str, List[Callable]] = {
            "alert": [],
            "anomaly": [],
            "trend": []
        }
        
        # تخزين للتحليل
        self._metric_history: Dict[str, List[float]] = {}
        self._anomaly_scores: Dict[str, float] = {}
        
        logger.info(f"ResourceMonitor initialized (interval={collection_interval}s, retention={retention_days}d)")
    
    def add_threshold(self, threshold: ResourceThreshold):
        """إضافة عتبة للتنبيه"""
        self._thresholds.append(threshold)
        logger.info(f"Added threshold: {threshold.metric_type.value} ({threshold.warning_threshold}/{threshold.critical_threshold})")
    
    def watch_process(self, pid: int):
        """مراقبة عملية معينة"""
        self._watched_pids.add(pid)
        logger.debug(f"Watching process PID: {pid}")
    
    def unwatch_process(self, pid: int):
        """إزالة عملية من المراقبة"""
        self._watched_pids.discard(pid)
    
    def watch_service(self, service_name: str):
        """مراقبة خدمة معينة"""
        self._watched_services.add(service_name)
        logger.debug(f"Watching service: {service_name}")
    
    def unwatch_service(self, service_name: str):
        """إزالة خدمة من المراقبة"""
        self._watched_services.discard(service_name)
    
    async def start(self):
        """بدء المراقبة"""
        if self._running:
            return
        
        self._running = True
        
        # بدء مهمة جمع المقاييس
        self._collection_task = asyncio.create_task(self._collection_loop())
        
        # بدء مهمة التجميع
        self._aggregation_task = asyncio.create_task(self._aggregation_loop())
        
        logger.info("ResourceMonitor started")
    
    async def stop(self):
        """إيقاف المراقبة"""
        if not self._running:
            return
        
        self._running = False
        
        if self._collection_task:
            self._collection_task.cancel()
        if self._aggregation_task:
            self._aggregation_task.cancel()
        
        logger.info("ResourceMonitor stopped")
    
    async def _collection_loop(self):
        """حلقة جمع المقاييس"""
        while self._running:
            try:
                start_time = time.time()
                
                # جمع مقاييس النظام
                await self._collect_system_metrics()
                
                # جمع مقاييس العمليات المراقبة
                await self._collect_process_metrics()
                
                # جمع مقاييس الخدمات المراقبة
                await self._collect_service_metrics()
                
                self._stats["last_collection"] = datetime.now().isoformat()
                
                # حساب وقت التنفيذ وتعديل الفاصل الزمني
                elapsed = time.time() - start_time
                sleep_time = max(0, self._collection_interval - elapsed)
                await asyncio.sleep(sleep_time)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Collection loop error: {e}")
                await asyncio.sleep(self._collection_interval)
    
    async def _collect_system_metrics(self):
        """جمع مقاييس النظام"""
        timestamp = datetime.now()
        
        try:
            # CPU
            cpu_percent = psutil.cpu_percent(interval=0.5)
            await self._store_metric("system", MetricType.CPU_PERCENT, timestamp, cpu_percent)
            
            # Memory
            memory = psutil.virtual_memory()
            await self._store_metric("system", MetricType.MEMORY_PERCENT, timestamp, memory.percent)
            await self._store_metric("system", MetricType.MEMORY_BYTES, timestamp, memory.used)
            
            # Disk
            disk = psutil.disk_usage('/')
            await self._store_metric("system", MetricType.DISK_USAGE, timestamp, disk.percent)
            
            # Disk IO
            disk_io = psutil.disk_io_counters()
            if disk_io:
                await self._store_metric("system", MetricType.DISK_IO_READ, timestamp, disk_io.read_bytes)
                await self._store_metric("system", MetricType.DISK_IO_WRITE, timestamp, disk_io.write_bytes)
            
            # Network
            net_io = psutil.net_io_counters()
            if net_io:
                await self._store_metric("system", MetricType.NETWORK_SENT, timestamp, net_io.bytes_sent)
                await self._store_metric("system", MetricType.NETWORK_RECV, timestamp, net_io.bytes_recv)
            
            # Process
            await self._store_metric("system", MetricType.PROCESS_COUNT, timestamp, len(psutil.pids()))
            
            self._stats["total_metrics_collected"] += 8
            
        except Exception as e:
            logger.error(f"Failed to collect system metrics: {e}")
    
    async def _collect_process_metrics(self):
        """جمع مقاييس العمليات المراقبة"""
        for pid in self._watched_pids:
            try:
                process = psutil.Process(pid)
                timestamp = datetime.now()
                
                cpu = process.cpu_percent(interval=0)
                memory = process.memory_info().rss
                
                await self._store_metric(f"process_{pid}", MetricType.CPU_PERCENT, timestamp, cpu)
                await self._store_metric(f"process_{pid}", MetricType.MEMORY_BYTES, timestamp, memory)
                
                self._stats["total_metrics_collected"] += 2
                
            except psutil.NoSuchProcess:
                self._watched_pids.discard(pid)
            except Exception as e:
                logger.debug(f"Failed to collect metrics for PID {pid}: {e}")
    
    async def _collect_service_metrics(self):
        """جمع مقاييس الخدمات المراقبة"""
        # سيتم جمعها من ServiceRegistry
        pass
    
    async def _store_metric(self, source: str, metric_type: MetricType, timestamp: datetime, value: float):
        """تخزين مقياس"""
        key = f"{source}:{metric_type.value}"
        
        async with self._lock:
            if key not in self._metrics_store:
                self._metrics_store[key] = deque(maxlen=int(self._retention_seconds / self._collection_interval))
            
            data_point = MetricDataPoint(
                timestamp=timestamp,
                value=value,
                metric_type=metric_type,
                source=source
            )
            
            self._metrics_store[key].append(data_point)
        
        # فحص العتبات
        await self._check_thresholds(source, metric_type, value, timestamp)
        
        # كشف الشذوذ
        if self._enable_anomaly_detection:
            await self._detect_anomaly(source, metric_type, value, timestamp)
    
    async def _check_thresholds(self, source: str, metric_type: MetricType, value: float, timestamp: datetime):
        """فحص العتبات وإطلاق التنبيهات"""
        for threshold in self._thresholds:
            if threshold.metric_type != metric_type:
                continue
            
            # تحديد ما إذا تم تجاوز العتبة
            if threshold.direction == "above":
                is_warning = value >= threshold.warning_threshold
                is_critical = value >= threshold.critical_threshold
            else:
                is_warning = value <= threshold.warning_threshold
                is_critical = value <= threshold.critical_threshold
            
            if not is_warning:
                continue
            
            # تحديد المستوى
            severity = "critical" if is_critical else "warning"
            threshold_value = threshold.critical_threshold if is_critical else threshold.warning_threshold
            
            # منع التكرار - التحقق من آخر تنبيه
            alert_key = f"{source}:{metric_type.value}:{severity}"
            last_alert = self._alert_history.get(alert_key)
            
            if last_alert and (timestamp - last_alert).total_seconds() < threshold.cooldown_seconds:
                continue
            
            # تسجيل التنبيه
            alert = {
                "timestamp": timestamp.isoformat(),
                "source": source,
                "metric": metric_type.value,
                "value": value,
                "threshold": threshold_value,
                "severity": severity,
                "message": f"{source} - {metric_type.value} = {value:.2f} (threshold: {threshold_value})"
            }
            
            self._alerts.append(alert)
            self._stats["total_alerts_triggered"] += 1
            self._alert_history[alert_key] = timestamp
            
            logger.warning(f"[{severity.upper()}] {alert['message']}")
            
            # إطلاق حدث
            await self._emit_event("alert", alert)
    
    async def _detect_anomaly(self, source: str, metric_type: MetricType, value: float, timestamp: datetime):
        """كشف الشذوذ باستخدام الانحراف المعياري"""
        key = f"{source}:{metric_type.value}"
        
        async with self._lock:
            history = self._metrics_store.get(key, [])
            if len(history) < 30:  # نحتاج 30 عينة على الأقل
                return
            
            # حساب المتوسط والانحراف المعياري
            values = [dp.value for dp in list(history)[-30:]]
            mean = np.mean(values)
            std = np.std(values)
            
            if std == 0:
                return
            
            # Z-score
            z_score = abs((value - mean) / std)
            
            # علامة شذوذ إذا كان Z-score > 3
            if z_score > 3:
                # تجميع نقاط البيانات لمعرفة ما إذا كان هذا شذوذ مستمر
                recent_anomalies = sum(1 for v in values[-5:] if abs((v - mean) / std) > 2)
                
                if recent_anomalies >= 3:
                    anomaly = {
                        "timestamp": timestamp.isoformat(),
                        "source": source,
                        "metric": metric_type.value,
                        "value": value,
                        "expected_range": f"{mean - 2*std:.2f} - {mean + 2*std:.2f}",
                        "z_score": z_score,
                        "confidence": min(1.0, z_score / 5)
                    }
                    
                    self._stats["anomalies_detected"] += 1
                    logger.warning(f"Anomaly detected: {source} - {metric_type.value} = {value:.2f} (expected ~{mean:.2f}±{2*std:.2f})")
                    
                    await self._emit_event("anomaly", anomaly)
    
    async def _aggregation_loop(self):
        """حلقة تجميع المقاييس"""
        while self._running:
            await asyncio.sleep(60)  # تجميع كل دقيقة
            
            try:
                await self._aggregate_metrics()
            except Exception as e:
                logger.error(f"Aggregation error: {e}")
    
    async def _aggregate_metrics(self):
        """تجميع المقاييس في نوافذ زمنية"""
        async with self._lock:
            for key, data_points in self._metrics_store.items():
                if not data_points:
                    continue
                
                # تجميع لكل نافذة زمنية
                for window in AggregationWindow:
                    window_seconds = window.value
                    cutoff = datetime.now().timestamp() - window_seconds
                    
                    # تصفية البيانات في النافذة
                    window_data = [
                        dp for dp in data_points
                        if dp.timestamp.timestamp() > cutoff
                    ]
                    
                    if len(window_data) < 5:
                        continue
                    
                    values = [dp.value for dp in window_data]
                    
                    aggregated = AggregatedMetric(
                        metric_type=window_data[0].metric_type,
                        window=window,
                        min=min(values),
                        max=max(values),
                        avg=np.mean(values),
                        p50=np.percentile(values, 50),
                        p95=np.percentile(values, 95),
                        p99=np.percentile(values, 99),
                        stddev=np.std(values),
                        sample_count=len(values),
                        start_time=window_data[0].timestamp,
                        end_time=window_data[-1].timestamp
                    )
                    
                    # تخزين النتيجة المجمعة
                    agg_key = f"{key}:{window.value}"
                    if agg_key not in self._aggregated_metrics:
                        self._aggregated_metrics[agg_key] = []
                    
                    self._aggregated_metrics[agg_key].append(aggregated)
                    
                    # الحفاظ على حجم معقول
                    if len(self._aggregated_metrics[agg_key]) > 100:
                        self._aggregated_metrics[agg_key].pop(0)
    
    async def get_current_metrics(self) -> Dict:
        """الحصول على المقاييس الحالية"""
        result = {"timestamp": datetime.now().isoformat()}
        
        try:
            # مقاييس النظام الحالية
            result["system"] = {
                "cpu_percent": psutil.cpu_percent(interval=0.5),
                "memory_percent": psutil.virtual_memory().percent,
                "memory_gb": psutil.virtual_memory().used / (1024**3),
                "disk_percent": psutil.disk_usage('/').percent,
                "process_count": len(psutil.pids())
            }
            
            # مقاييس العمليات المراقبة
            result["processes"] = {}
            for pid in self._watched_pids:
                try:
                    proc = psutil.Process(pid)
                    result["processes"][str(pid)] = {
                        "name": proc.name(),
                        "cpu_percent": proc.cpu_percent(interval=0),
                        "memory_mb": proc.memory_info().rss / (1024**2)
                    }
                except:
                    pass
            
        except Exception as e:
            logger.error(f"Failed to get current metrics: {e}")
        
        return result
    
    async def get_aggregated_metrics(
        self,
        metric_type: Optional[MetricType] = None,
        source: Optional[str] = None,
        window: Optional[AggregationWindow] = None
    ) -> List[AggregatedMetric]:
        """الحصول على المقاييس المجمعة"""
        result = []
        
        async with self._lock:
            for key, metrics in self._aggregated_metrics.items():
                # فحص التصفية
                if metric_type and key.find(metric_type.value) == -1:
                    continue
                if source and key.find(source) == -1:
                    continue
                if window and key.find(str(window.value)) == -1:
                    continue
                
                result.extend(metrics)
        
        return result
    
    async def get_alerts(
        self,
        since: Optional[datetime] = None,
        severity: Optional[str] = None
    ) -> List[Dict]:
        """الحصول على التنبيهات"""
        alerts = self._alerts.copy()
        
        if since:
            alerts = [a for a in alerts if datetime.fromisoformat(a["timestamp"]) > since]
        
        if severity:
            alerts = [a for a in alerts if a["severity"] == severity]
        
        return alerts
    
    async def get_statistics(self) -> Dict:
        """الحصول على إحصائيات المراقبة"""
        async with self._lock:
            return {
                **self._stats,
                "running": self._running,
                "metrics_stored": sum(len(q) for q in self._metrics_store.values()),
                "aggregated_metrics": sum(len(m) for m in self._aggregated_metrics.values()),
                "watched_pids": len(self._watched_pids),
                "watched_services": len(self._watched_services),
                "active_thresholds": len(self._thresholds),
                "collection_interval": self._collection_interval,
                "retention_days": self._retention_seconds / 86400
            }
    
    async def export_to_json(self, output_path: str):
        """تصدير البيانات إلى JSON"""
        data = {
            "timestamp": datetime.now().isoformat(),
            "statistics": await self.get_statistics(),
            "alerts": self._alerts[-100:],  # آخر 100 تنبيه
            "metrics_summary": {
                "system_cpu": {
                    "current": await self._get_latest_metric("system", MetricType.CPU_PERCENT),
                    "aggregated": await self.get_aggregated_metrics(MetricType.CPU_PERCENT, "system")
                },
                "system_memory": {
                    "current": await self._get_latest_metric("system", MetricType.MEMORY_PERCENT),
                    "aggregated": await self.get_aggregated_metrics(MetricType.MEMORY_PERCENT, "system")
                }
            }
        }
        
        with open(output_path, 'w') as f:
            json.dump(data, f, indent=2, default=str)
        
        logger.info(f"Exported metrics to {output_path}")
    
    async def export_to_prometheus(self) -> str:
        """تصدير المقاييس بتنسيق Prometheus"""
        lines = []
        
        # مقاييس النظام الحالية
        current = await self.get_current_metrics()
        
        lines.append("# HELP system_cpu_percent System CPU usage percentage")
        lines.append("# TYPE system_cpu_percent gauge")
        lines.append(f"system_cpu_percent {current['system']['cpu_percent']}")
        
        lines.append("# HELP system_memory_percent System memory usage percentage")
        lines.append("# TYPE system_memory_percent gauge")
        lines.append(f"system_memory_percent {current['system']['memory_percent']}")
        
        lines.append("# HELP system_memory_gb System memory usage in GB")
        lines.append("# TYPE system_memory_gb gauge")
        lines.append(f"system_memory_gb {current['system']['memory_gb']}")
        
        # مقاييس العمليات
        for pid, proc_info in current.get("processes", {}).items():
            lines.append(f'process_cpu_percent{{pid="{pid}",name="{proc_info["name"]}"}} {proc_info["cpu_percent"]}')
            lines.append(f'process_memory_mb{{pid="{pid}",name="{proc_info["name"]}"}} {proc_info["memory_mb"]}')
        
        # تنبيهات
        lines.append("# HELP resource_alerts_total Total number of resource alerts")
        lines.append("# TYPE resource_alerts_total counter")
        lines.append(f"resource_alerts_total {self._stats['total_alerts_triggered']}")
        
        return "\n".join(lines)
    
    async def _get_latest_metric(self, source: str, metric_type: MetricType) -> Optional[float]:
        """الحصول على أحدث قيمة لمقياس"""
        key = f"{source}:{metric_type.value}"
        
        async with self._lock:
            queue = self._metrics_store.get(key)
            if queue and len(queue) > 0:
                return queue[-1].value
        return None
    
    async def _emit_event(self, event_type: str, data: Dict):
        """إطلاق حدث"""
        if event_type not in self._event_handlers:
            return
        
        for handler in self._event_handlers[event_type]:
            try:
                if asyncio.iscoroutinefunction(handler):
                    await handler(data)
                else:
                    handler(data)
            except Exception as e:
                logger.error(f"Event handler error: {e}")
    
    def on(self, event: str, handler: Callable):
        """تسجيل معالج حدث"""
        if event in self._event_handlers:
            self._event_handlers[event].append(handler)
    
    async def clear_history(self):
        """مسح سجل المقاييس"""
        async with self._lock:
            self._metrics_store.clear()
            self._aggregated_metrics.clear()
            self._alerts.clear()
            self._alert_history.clear()
            self._stats["total_metrics_collected"] = 0
            self._stats["total_alerts_triggered"] = 0
        
        logger.info("Metrics history cleared")


# نسخة عالمية
_default_monitor = None


async def get_resource_monitor() -> ResourceMonitor:
    """الحصول على نسخة عالمية من مراقب الموارد"""
    global _default_monitor
    if _default_monitor is None:
        _default_monitor = ResourceMonitor()
        await _default_monitor.start()
    return _default_monitor

