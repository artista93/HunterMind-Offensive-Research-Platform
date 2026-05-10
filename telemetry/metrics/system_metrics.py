
import asyncio
import psutil
import platform
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime
from collections import defaultdict

from .metrics_engine import get_metrics_engine

import logging

logger = logging.getLogger(__name__)


@dataclass
class SystemRecord:
    """سجل حالة النظام"""
    timestamp: datetime
    cpu_percent: float
    memory_percent: float
    memory_used_mb: float
    disk_percent: float
    disk_used_gb: float
    network_sent_mb: float
    network_recv_mb: float
    process_count: int
    thread_count: int


class SystemMetrics:
    """
    مقاييس النظام المتقدمة
    
    الميزات:
    - جمع مقاييس النظام في الوقت الفعلي
    - تحليل استخدام الموارد
    - كشف الاختناقات
    - تنبيهات عند تجاوز العتبات
    """
    
    def __init__(self, collection_interval: int = 10):
        self.collection_interval = collection_interval
        self.records: List[SystemRecord] = []
        self.metrics_engine = None
        self._collector_task: Optional[asyncio.Task] = None
        self._running = False
        self._lock = asyncio.Lock()
        
        # عتبات التنبيه
        self.thresholds = {
            "cpu_percent": 80.0,
            "memory_percent": 85.0,
            "disk_percent": 90.0
        }
        
        logger.info(f"SystemMetrics initialized (interval={collection_interval}s)")
    
    async def initialize(self):
        """تهيئة مقاييس النظام"""
        self.metrics_engine = await get_metrics_engine()
        logger.info("SystemMetrics connected to metrics engine")
    
    async def start(self):
        """بدء جمع مقاييس النظام"""
        if self._running:
            return
        
        self._running = True
        self._collector_task = asyncio.create_task(self._collect_loop())
        logger.info("SystemMetrics started")
    
    async def stop(self):
        """إيقاف جمع مقاييس النظام"""
        self._running = False
        
        if self._collector_task:
            self._collector_task.cancel()
        
        logger.info("SystemMetrics stopped")
    
    async def _collect_loop(self):
        """حلقة جمع مقاييس النظام"""
        while self._running:
            try:
                await self._collect_system_metrics()
                await asyncio.sleep(self.collection_interval)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"System metrics collection error: {e}")
    
    async def _collect_system_metrics(self):
        """جمع مقاييس النظام الحالية"""
        # CPU
        cpu_percent = psutil.cpu_percent(interval=1)
        
        # Memory
        memory = psutil.virtual_memory()
        memory_percent = memory.percent
        memory_used_mb = memory.used / (1024 * 1024)
        
        # Disk
        disk = psutil.disk_usage('/')
        disk_percent = disk.percent
        disk_used_gb = disk.used / (1024 ** 3)
        
        # Network
        net_io = psutil.net_io_counters()
        network_sent_mb = net_io.bytes_sent / (1024 * 1024) if net_io else 0
        network_recv_mb = net_io.bytes_recv / (1024 * 1024) if net_io else 0
        
        # Processes
        process_count = len(psutil.pids())
        thread_count = sum(p.num_threads() for p in psutil.process_iter(['pid']) if p.is_running())
        
        record = SystemRecord(
            timestamp=datetime.now(),
            cpu_percent=cpu_percent,
            memory_percent=memory_percent,
            memory_used_mb=memory_used_mb,
            disk_percent=disk_percent,
            disk_used_gb=disk_used_gb,
            network_sent_mb=network_sent_mb,
            network_recv_mb=network_recv_mb,
            process_count=process_count,
            thread_count=thread_count
        )
        
        async with self._lock:
            self.records.append(record)
            
            # الاحتفاظ بآخر 10000 سجل فقط
            if len(self.records) > 10000:
                self.records = self.records[-10000:]
        
        # تسجيل المقاييس
        if self.metrics_engine:
            await self.metrics_engine.record_gauge("system.cpu.percent", cpu_percent)
            await self.metrics_engine.record_gauge("system.memory.percent", memory_percent)
            await self.metrics_engine.record_gauge("system.memory.used_mb", memory_used_mb)
            await self.metrics_engine.record_gauge("system.disk.percent", disk_percent)
            await self.metrics_engine.record_gauge("system.process.count", process_count)
        
        # التحقق من العتبات
        await self._check_thresholds(record)
    
    async def _check_thresholds(self, record: SystemRecord):
        """التحقق من تجاوز العتبات"""
        alerts = []
        
        if record.cpu_percent > self.thresholds["cpu_percent"]:
            alerts.append(f"High CPU usage: {record.cpu_percent:.1f}%")
        
        if record.memory_percent > self.thresholds["memory_percent"]:
            alerts.append(f"High memory usage: {record.memory_percent:.1f}%")
        
        if record.disk_percent > self.thresholds["disk_percent"]:
            alerts.append(f"High disk usage: {record.disk_percent:.1f}%")
        
        for alert in alerts:
            logger.warning(f"System alert: {alert}")
    
    async def get_current_metrics(self) -> Dict:
        """الحصول على المقاييس الحالية"""
        if not self.records:
            return await self._collect_system_metrics()
        
        latest = self.records[-1]
        return {
            "timestamp": latest.timestamp.isoformat(),
            "cpu_percent": latest.cpu_percent,
            "memory_percent": latest.memory_percent,
            "memory_used_mb": latest.memory_used_mb,
            "disk_percent": latest.disk_percent,
            "disk_used_gb": latest.disk_used_gb,
            "network_sent_mb": latest.network_sent_mb,
            "network_recv_mb": latest.network_recv_mb,
            "process_count": latest.process_count,
            "thread_count": latest.thread_count
        }
    
    async def get_system_info(self) -> Dict:
        """الحصول على معلومات النظام"""
        return {
            "platform": platform.system(),
            "platform_release": platform.release(),
            "platform_version": platform.version(),
            "architecture": platform.machine(),
            "processor": platform.processor(),
            "python_version": platform.python_version(),
            "hostname": platform.node()
        }
    
    async def get_resource_usage(self, minutes: int = 5) -> Dict:
        """
        الحصول على استخدام الموارد في فترة زمنية
        
        Args:
            minutes: عدد الدقائق
        
        Returns:
            استخدام الموارد
        """
        cutoff = datetime.now().timestamp() - (minutes * 60)
        records = [r for r in self.records if r.timestamp.timestamp() > cutoff]
        
        if not records:
            return {"has_data": False}
        
        return {
            "has_data": True,
            "cpu": {
                "current": records[-1].cpu_percent,
                "avg": sum(r.cpu_percent for r in records) / len(records),
                "max": max(r.cpu_percent for r in records),
                "min": min(r.cpu_percent for r in records)
            },
            "memory": {
                "current": records[-1].memory_percent,
                "avg": sum(r.memory_percent for r in records) / len(records),
                "max": max(r.memory_percent for r in records),
                "min": min(r.memory_percent for r in records)
            },
            "disk": {
                "current": records[-1].disk_percent,
                "avg": sum(r.disk_percent for r in records) / len(records),
                "max": max(r.disk_percent for r in records),
                "min": min(r.disk_percent for r in records)
            },
            "samples": len(records)
        }
    
    async def get_statistics(self) -> Dict:
        """إحصائيات النظام"""
        if not self.records:
            return {"total_records": 0}
        
        return {
            "total_records": len(self.records),
            "collection_interval": self.collection_interval,
            "uptime_seconds": (datetime.now() - self.records[0].timestamp).total_seconds(),
            "current_metrics": await self.get_current_metrics(),
            "resource_usage": await self.get_resource_usage(5),
            "system_info": await self.get_system_info(),
            "thresholds": self.thresholds,
            "running": self._running
        }


# نسخة عالمية
_default_metrics = None


async def get_system_metrics() -> SystemMetrics:
    """الحصول على نسخة عالمية من مقاييس النظام"""
    global _default_metrics
    if _default_metrics is None:
        _default_metrics = SystemMetrics()
        await _default_metrics.initialize()
        await _default_metrics.start()
    return _default_metrics

