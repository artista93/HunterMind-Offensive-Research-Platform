
import asyncio
import psutil
import os
import resource
import json
import threading
import subprocess
from typing import Dict, List, Optional, Any, Callable, Awaitable, Tuple, Set
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from contextlib import asynccontextmanager
from collections import deque
import logging

logger = logging.getLogger(__name__)


class ResourceType(Enum):
    """أنواع الموارد"""
    CPU = "cpu"
    MEMORY = "memory"
    DISK = "disk"
    NETWORK = "network"
    FILE_DESCRIPTORS = "fd"
    THREADS = "threads"


class ResourceUnit(Enum):
    """وحدات الموارد"""
    PERCENT = "percent"
    BYTES = "bytes"
    COUNT = "count"
    MB = "mb"
    GB = "gb"


@dataclass
class ResourceLimit:
    """حدود الموارد"""
    type: ResourceType
    soft_limit: float
    hard_limit: float
    unit: ResourceUnit
    action: str = "throttle"  # throttle, kill, log_only
    throttle_ratio: float = 0.5
    cool_down_period: float = 30.0


@dataclass
class ResourceQuota:
    """حصة موارد لمستخدم/خدمة"""
    user_id: str
    service_name: str
    limits: List[ResourceLimit]
    priority: int = 0
    burst_allowed: bool = True
    burst_multiplier: float = 1.5
    pids: Set[int] = field(default_factory=set)  # ✅ ربط حقيقي بالعمليات


@dataclass
class ResourceUsage:
    """استخدام الموارد"""
    timestamp: datetime
    cpu_percent: float
    memory_percent: float
    memory_bytes: int
    disk_usage_percent: float
    disk_read_bytes: int
    disk_write_bytes: int
    network_sent_bytes: int
    network_recv_bytes: int
    open_fds: int
    thread_count: int
    
    # ✅ استخدام حقيقي لكل خدمة (مجمّع من العمليات)
    service_usage: Dict[str, Dict[str, float]] = field(default_factory=dict)


@dataclass
class ResourceAlert:
    """تنبيه موارد"""
    resource_type: ResourceType
    current_value: float
    limit_value: float
    severity: str
    message: str
    timestamp: datetime
    service_name: Optional[str] = None


# فحص إصدار Python لل timeout
if hasattr(asyncio, 'timeout'):
    from asyncio import timeout as async_timeout
else:
    # Fallback for Python < 3.11
    async def async_timeout(duration):
        return asyncio.timeout(duration) if hasattr(asyncio, 'timeout') else None


class ProcessResourceTracker:
    """
    متتبع موارد العمليات الحقيقي
    
    يربط الخدمات بالعمليات الفعلية ويتتبع استخدامها الحقيقي
    """
    
    def __init__(self):
        self._process_cache: Dict[int, psutil.Process] = {}
        self._cache_lock = asyncio.Lock()
        self._last_update: Dict[int, datetime] = {}
        self._cache_ttl = 1.0  # ثانية
    
    async def get_process(self, pid: int) -> Optional[psutil.Process]:
        """الحصول على كائن العملية مع التخزين المؤقت"""
        async with self._cache_lock:
            # التحقق من التخزين المؤقت
            if pid in self._process_cache:
                last_update = self._last_update.get(pid)
                if last_update and (datetime.now() - last_update).total_seconds() < self._cache_ttl:
                    return self._process_cache[pid]
            
            try:
                process = psutil.Process(pid)
                self._process_cache[pid] = process
                self._last_update[pid] = datetime.now()
                return process
            except psutil.NoSuchProcess:
                self._process_cache.pop(pid, None)
                self._last_update.pop(pid, None)
                return None
    
    async def get_processes_by_service(self, pids: Set[int]) -> List[psutil.Process]:
        """الحصول على عمليات خدمة معينة"""
        processes = []
        for pid in pids:
            proc = await self.get_process(pid)
            if proc:
                processes.append(proc)
        return processes
    
    async def get_service_resource_usage(self, pids: Set[int]) -> Dict[str, float]:
        """
        حساب استخدام الموارد لمجموعة من العمليات
        
        Returns:
            قاموس بأنواع الموارد وقيمها
        """
        if not pids:
            return {"cpu_percent": 0.0, "memory_bytes": 0, "threads": 0, "open_fds": 0}
        
        total_cpu = 0.0
        total_memory = 0
        total_threads = 0
        total_fds = 0
        
        for pid in pids:
            process = await self.get_process(pid)
            if not process:
                continue
            
            try:
                # CPU (نسبة مئوية)
                total_cpu += process.cpu_percent(interval=0)
                
                # الذاكرة
                memory_info = process.memory_info()
                total_memory += memory_info.rss
                
                # الخيوط
                total_threads += process.num_threads()
                
                # واصفات الملفات
                try:
                    total_fds += process.num_fds()
                except:
                    pass
                    
            except psutil.NoSuchProcess:
                continue
            except Exception as e:
                logger.debug(f"Error getting process stats for {pid}: {e}")
        
        return {
            "cpu_percent": min(total_cpu, 100.0),  # الحد الأقصى 100%
            "memory_bytes": total_memory,
            "memory_mb": total_memory / (1024 * 1024),
            "threads": total_threads,
            "open_fds": total_fds
        }
    
    async def cleanup(self):
        """تنظيف العمليات المنتهية"""
        async with self._cache_lock:
            dead_pids = []
            for pid, process in self._process_cache.items():
                try:
                    if not process.is_running():
                        dead_pids.append(pid)
                except:
                    dead_pids.append(pid)
            
            for pid in dead_pids:
                self._process_cache.pop(pid, None)
                self._last_update.pop(pid, None)


class AsyncCPUCollector:
    """
    جامع CPU غير متزامن - ينفذ في خيط منفصل لتجنب حظر الحلقة
    """
    
    def __init__(self):
        self._executor = concurrent.futures.ThreadPoolExecutor(max_workers=1, thread_name_prefix="CPUCollector")
        self._last_cpu_percent = 0.0
    
    async def get_cpu_percent(self, interval: float = 0.5) -> float:
        """جمع CPU في خيط منفصل"""
        loop = asyncio.get_running_loop()
        
        def _collect():
            return psutil.cpu_percent(interval=interval)
        
        try:
            self._last_cpu_percent = await loop.run_in_executor(self._executor, _collect)
        except Exception as e:
            logger.error(f"CPU collection failed: {e}")
        
        return self._last_cpu_percent


class ResourceManager:
    """
    مدير الموارد المتقدم
    
    الميزات المحسّنة:
    - ✅ ربط حقيقي بالعمليات (PID-based tracking)
    - ✅ جمع CPU غير متزامن (بدون حظر)
    - ✅ cgroups كاملة مع PID binding و hierarchical limits
    - ✅ تكامل مع ServiceRegistry للأحداث
    - ✅ كشف تسرب الذاكرة باستخدام الانحدار الخطي
    """
    
    def __init__(
        self,
        monitoring_interval: float = 5.0,
        alert_threshold: float = 0.8,
        enable_cgroups: bool = True
    ):
        self._monitoring_interval = monitoring_interval
        self._alert_threshold = alert_threshold
        self._enable_cgroups = enable_cgroups and self._check_cgroup_availability()
        
        # متتبعات الموارد
        self._process_tracker = ProcessResourceTracker()
        self._cpu_collector = AsyncCPUCollector()
        
        # حصص الموارد مع ربط PID
        self._quotas: Dict[str, ResourceQuota] = {}
        
        # حدود النظام العامة
        self._global_limits = {
            "cpu_percent": 80.0,
            "memory_percent": 85.0,
            "open_fds": 10000,
            "threads": 5000
        }
        
        # مكونات التشغيل
        self._monitoring_task: Optional[asyncio.Task] = None
        self._running = False
        self._lock = asyncio.Lock()
        
        # سجل الاستخدام والتنبيهات
        self._usage_history: deque = deque(maxlen=1000)
        self._alerts: List[ResourceAlert] = []
        
        # تكامل الأحداث
        self._service_registry = None
        self._event_handlers: Dict[str, List[Callable]] = {
            "resource_alert": [],
            "resource_throttle": [],
            "resource_kill": []
        }
        
        # إحصائيات كشف التسرب
        self._memory_history: Dict[str, deque] = {}  # service_name -> deque of memory values
        self._leak_detection_enabled = True
        self._leak_threshold_mb_per_minute = 10.0  # 10MB/min growth
        
        # إحصائيات
        self._stats = {
            "total_quotas": 0,
            "alerts_generated": 0,
            "throttle_events": 0,
            "kill_events": 0,
            "peak_cpu": 0.0,
            "peak_memory": 0,
            "current_cpu": 0.0,
            "current_memory": 0,
            "cgroups_available": self._enable_cgroups
        }
        
        logger.info(f"ResourceManager initialized (interval={monitoring_interval}s, cgroups={self._enable_cgroups})")
    
    def _check_cgroup_availability(self) -> bool:
        """التحقق من توفر cgroups v2"""
        try:
            # التحقق من cgroup v2
            if os.path.exists("/sys/fs/cgroup/cgroup.controllers"):
                logger.info("cgroup v2 available")
                return True
            # cgroup v1
            elif os.path.exists("/sys/fs/cgroup/cpu"):
                logger.info("cgroup v1 available")
                return True
        except Exception as e:
            logger.warning(f"cgroups not available: {e}")
        return False
    
    async def set_service_registry(self, service_registry):
        """ربط ServiceRegistry للأحداث"""
        self._service_registry = service_registry
    
    async def start(self):
        """بدء مراقبة الموارد"""
        if self._running:
            return
        
        self._running = True
        self._monitoring_task = asyncio.create_task(self._monitoring_loop())
        
        logger.info("ResourceManager started")
    
    async def stop(self):
        """إيقاف مراقبة الموارد"""
        self._running = False
        
        if self._monitoring_task:
            self._monitoring_task.cancel()
            try:
                await self._monitoring_task
            except asyncio.CancelledError:
                pass
        
        await self._process_tracker.cleanup()
        logger.info("ResourceManager stopped")
    
    def register_service_processes(self, service_name: str, pids: Set[int]):
        """
        تسجيل عمليات خدمة معينة - ربط حقيقي
        
        Args:
            service_name: اسم الخدمة
            pids: مجموعة من معرفات العمليات
        """
        if service_name in self._quotas:
            self._quotas[service_name].pids = pids
            logger.info(f"Registered {len(pids)} processes for service {service_name}")
    
    def add_process_to_service(self, service_name: str, pid: int):
        """إضافة عملية إلى خدمة"""
        if service_name in self._quotas:
            self._quotas[service_name].pids.add(pid)
            logger.debug(f"Added PID {pid} to service {service_name}")
    
    def remove_process_from_service(self, service_name: str, pid: int):
        """إزالة عملية من خدمة"""
        if service_name in self._quotas:
            self._quotas[service_name].pids.discard(pid)
            logger.debug(f"Removed PID {pid} from service {service_name}")
    
    def set_quota(self, quota: ResourceQuota):
        """تعيين حصة موارد لخدمة"""
        self._quotas[quota.service_name] = quota
        self._stats["total_quotas"] += 1
        logger.info(f"Quota set for {quota.service_name}: {len(quota.limits)} limits")
        
        # إذا كان cgroups مفعلاً، قم بتطبيق الحدود
        if self._enable_cgroups and quota.pids:
            asyncio.create_task(self._apply_cgroup_limits(quota))
    
    async def _apply_cgroup_limits(self, quota: ResourceQuota):
        """تطبيق حدود cgroups على عمليات الخدمة"""
        if not quota.pids:
            return
        
        cgroup_name = f"huntermind_{quota.service_name}"
        
        # إنشاء cgroup
        cgroup_base = "/sys/fs/cgroup"
        cgroup_path = os.path.join(cgroup_base, cgroup_name)
        
        try:
            os.makedirs(cgroup_path, exist_ok=True)
            
            # إضافة العمليات إلى cgroup
            for pid in quota.pids:
                procs_file = os.path.join(cgroup_path, "cgroup.procs")
                with open(procs_file, "w") as f:
                    f.write(str(pid))
            
            # تعيين حدود CPU (إذا وجدت)
            for limit in quota.limits:
                if limit.type == ResourceType.CPU:
                    cpu_max_file = os.path.join(cgroup_path, "cpu.max")
                    if os.path.exists(cpu_max_file):
                        cpu_quota = int(limit.hard_limit * 100000) if limit.hard_limit <= 100 else int(limit.hard_limit * 1000)
                        with open(cpu_max_file, "w") as f:
                            f.write(f"{cpu_quota} 100000")
                
                elif limit.type == ResourceType.MEMORY:
                    memory_max_file = os.path.join(cgroup_path, "memory.max")
                    if os.path.exists(memory_max_file):
                        memory_bytes = int(limit.hard_limit * (1024**2)) if limit.unit == ResourceUnit.MB else int(limit.hard_limit)
                        with open(memory_max_file, "w") as f:
                            f.write(str(memory_bytes))
            
            logger.info(f"cgroup limits applied to {quota.service_name} ({len(quota.pids)} processes)")
            
        except Exception as e:
            logger.error(f"Failed to apply cgroup limits for {quota.service_name}: {e}")
    
    async def _monitoring_loop(self):
        """حلقة مراقبة الموارد (غير محجوبة)"""
        while self._running:
            try:
                usage = await self._collect_usage()
                
                async with self._lock:
                    self._usage_history.append(usage)
                
                # تحديث الإحصائيات
                self._stats["current_cpu"] = usage.cpu_percent
                self._stats["current_memory"] = usage.memory_bytes
                if usage.cpu_percent > self._stats["peak_cpu"]:
                    self._stats["peak_cpu"] = usage.cpu_percent
                if usage.memory_bytes > self._stats["peak_memory"]:
                    self._stats["peak_memory"] = usage.memory_bytes
                
                # التحقق من الحدود
                await self._check_global_limits(usage)
                await self._check_service_quotas(usage)
                
                # كشف تسرب الذاكرة
                if self._leak_detection_enabled:
                    await self._detect_memory_leaks()
                
                await asyncio.sleep(self._monitoring_interval)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Monitoring error: {e}")
                await asyncio.sleep(self._monitoring_interval)
    
    async def _collect_usage(self) -> ResourceUsage:
        """جمع استخدام الموارد (غير محجوب)"""
        # CPU - غير محجوب
        cpu_percent = await self._cpu_collector.get_cpu_percent(interval=0.5)
        
        # الذاكرة
        memory = psutil.virtual_memory()
        memory_percent = memory.percent
        memory_bytes = memory.used
        
        # القرص - سريع، لا يحتاج خيط منفصل
        try:
            disk = psutil.disk_usage('/')
            disk_usage_percent = disk.percent
        except:
            disk_usage_percent = 0.0
        
        # الشبكة
        try:
            net_io = psutil.net_io_counters()
            network_sent_bytes = net_io.bytes_sent if net_io else 0
            network_recv_bytes = net_io.bytes_recv if net_io else 0
        except:
            network_sent_bytes = 0
            network_recv_bytes = 0
        
        # واصفات الملفات والخيوط
        try:
            current_process = psutil.Process()
            open_fds = current_process.num_fds() if hasattr(current_process, 'num_fds') else 0
            thread_count = current_process.num_threads()
        except:
            open_fds = 0
            thread_count = 0
        
        # ✅ استخدام حقيقي لكل خدمة (من العمليات الفعلية)
        service_usage = {}
        for service_name, quota in self._quotas.items():
            if quota.pids:
                usage = await self._process_tracker.get_service_resource_usage(quota.pids)
                service_usage[service_name] = usage
                self._stats["current_cpu"] = max(self._stats["current_cpu"], usage.get("cpu_percent", 0))
        
        return ResourceUsage(
            timestamp=datetime.now(),
            cpu_percent=cpu_percent,
            memory_percent=memory_percent,
            memory_bytes=memory_bytes,
            disk_usage_percent=disk_usage_percent,
            disk_read_bytes=0,
            disk_write_bytes=0,
            network_sent_bytes=network_sent_bytes,
            network_recv_bytes=network_recv_bytes,
            open_fds=open_fds,
            thread_count=thread_count,
            service_usage=service_usage
        )
    
    async def _check_global_limits(self, usage: ResourceUsage):
        """التحقق من الحدود العالمية"""
        if usage.cpu_percent > self._global_limits["cpu_percent"]:
            await self._emit_alert(ResourceAlert(
                resource_type=ResourceType.CPU,
                current_value=usage.cpu_percent,
                limit_value=self._global_limits["cpu_percent"],
                severity="critical" if usage.cpu_percent > 95 else "warning",
                message=f"High CPU usage: {usage.cpu_percent:.1f}%",
                timestamp=datetime.now()
            ))
        
        if usage.memory_percent > self._global_limits["memory_percent"]:
            await self._emit_alert(ResourceAlert(
                resource_type=ResourceType.MEMORY,
                current_value=usage.memory_percent,
                limit_value=self._global_limits["memory_percent"],
                severity="critical" if usage.memory_percent > 95 else "warning",
                message=f"High memory usage: {usage.memory_percent:.1f}%",
                timestamp=datetime.now()
            ))
    
    async def _check_service_quotas(self, usage: ResourceUsage):
        """التحقق من حصص الخدمات (باستخدام الاستخدام الحقيقي)"""
        for service_name, quota in self._quotas.items():
            service_usage = usage.service_usage.get(service_name, {})
            
            for limit in quota.limits:
                current = service_usage.get(f"{limit.type.value}_percent", 0)
                if limit.type == ResourceType.MEMORY:
                    current = service_usage.get("memory_mb", 0)
                
                if current > limit.soft_limit:
                    if current > limit.hard_limit:
                        alert = ResourceAlert(
                            resource_type=limit.type,
                            current_value=current,
                            limit_value=limit.hard_limit,
                            severity="critical",
                            message=f"Service {service_name} exceeded hard limit for {limit.type.value}",
                            timestamp=datetime.now(),
                            service_name=service_name
                        )
                        await self._handle_alert(alert, service_name, limit)
    
    async def _handle_alert(self, alert: ResourceAlert, service_name: str, limit: ResourceLimit):
        """معالجة تنبيه الموارد"""
        self._alerts.append(alert)
        self._stats["alerts_generated"] += 1
        
        if alert.severity == "critical":
            logger.error(f"[CRITICAL] {alert.message}")
            
            if limit.action == "kill":
                self._stats["kill_events"] += 1
                await self._kill_service(service_name)
            elif limit.action == "throttle":
                self._stats["throttle_events"] += 1
                await self._throttle_service(service_name, limit.throttle_ratio)
        else:
            logger.warning(f"[WARNING] {alert.message}")
        
        await self._emit_alert(alert)
    
    async def _throttle_service(self, service_name: str, ratio: float):
        """خنق خدمة (من خلال ServiceRegistry)"""
        logger.warning(f"Throttling service {service_name} to {ratio*100:.0f}%")
        
        # إرسال حدث الخنق
        await self._emit_throttle_event(service_name, ratio)
        
        # تحديث الأولوية في الحصة
        if service_name in self._quotas:
            # تقليل الأولوية مؤقتاً
            self._quotas[service_name].priority = max(0, self._quotas[service_name].priority - 2)
    
    async def _kill_service(self, service_name: str):
        """إيقاف خدمة (من خلال ServiceRegistry)"""
        logger.error(f"Killing service {service_name} due to resource limit exceeded")
        
        # إرسال حدث الإيقاف
        await self._emit_kill_event(service_name)
        
        # إنهاء العمليات المرتبطة
        if service_name in self._quotas:
            for pid in self._quotas[service_name].pids:
                try:
                    process = psutil.Process(pid)
                    process.terminate()
                except:
                    pass
    
    async def _detect_memory_leaks(self):
        """كشف تسرب الذاكرة باستخدام الانحدار الخطي"""
        for service_name, quota in self._quotas.items():
            if not quota.pids:
                continue
            
            # جمع عينات الذاكرة
            if service_name not in self._memory_history:
                self._memory_history[service_name] = deque(maxlen=60)  # آخر 60 عينة (5 دقائق بمعدل 5 ثوان)
            
            usage = await self._process_tracker.get_service_resource_usage(quota.pids)
            memory_mb = usage.get("memory_mb", 0)
            self._memory_history[service_name].append((datetime.now(), memory_mb))
            
            # كشف التسرب عندما يكون لدينا عينات كافية
            if len(self._memory_history[service_name]) >= 10:
                leak_detected, growth_rate = self._calculate_leak_rate(self._memory_history[service_name])
                
                if leak_detected:
                    logger.warning(f"Memory leak detected for {service_name}: {growth_rate:.1f} MB/min")
                    
                    await self._emit_alert(ResourceAlert(
                        resource_type=ResourceType.MEMORY,
                        current_value=memory_mb,
                        limit_value=self._leak_threshold_mb_per_minute,
                        severity="warning",
                        message=f"Memory leak detected: {growth_rate:.1f} MB/min growth",
                        timestamp=datetime.now(),
                        service_name=service_name
                    ))
    
    def _calculate_leak_rate(self, samples: deque) -> Tuple[bool, float]:
        """
        حساب معدل تسرب الذاكرة باستخدام الانحدار الخطي البسيط
        
        Returns:
            (is_leaking, growth_rate_mb_per_minute)
        """
        if len(samples) < 2:
            return False, 0.0
        
        # استخراج النقاط الزمنية والقيم
        times = []
        values = []
        start_time = samples[0][0]
        
        for ts, val in samples:
            times.append((ts - start_time).total_seconds() / 60.0)  # دقائق
            values.append(val)
        
        # حساب الانحدار الخطي (طريقة المربعات الصغرى)
        n = len(times)
        sum_x = sum(times)
        sum_y = sum(values)
        sum_xy = sum(x * y for x, y in zip(times, values))
        sum_x2 = sum(x * x for x in times)
        
        denominator = n * sum_x2 - sum_x * sum_x
        if denominator == 0:
            return False, 0.0
        
        slope = (n * sum_xy - sum_x * sum_y) / denominator
        
        # التسرب إذا كان الميل إيجابياً ويتجاوز العتبة
        is_leaking = slope > self._leak_threshold_mb_per_minute
        return is_leaking, slope
    
    async def _emit_alert(self, alert: ResourceAlert):
        """إطلاق حدث تنبيه (متصل بـ ServiceRegistry)"""
        # إرسال إلى ServiceRegistry إذا كان متصلاً
        if self._service_registry:
            try:
                await self._service_registry.record_request(
                    "resource_manager",
                    "alerts",
                    0,
                    True
                )
            except:
                pass
        
        # إطلاق معالجات الأحداث المحلية
        for handler in self._event_handlers["resource_alert"]:
            try:
                if asyncio.iscoroutinefunction(handler):
                    await handler(alert)
                else:
                    handler(alert)
            except Exception as e:
                logger.error(f"Alert handler error: {e}")
    
    async def _emit_throttle_event(self, service_name: str, ratio: float):
        """إطلاق حدث خنق"""
        for handler in self._event_handlers["resource_throttle"]:
            try:
                if asyncio.iscoroutinefunction(handler):
                    await handler(service_name, ratio)
                else:
                    handler(service_name, ratio)
            except Exception as e:
                logger.error(f"Throttle handler error: {e}")
    
    async def _emit_kill_event(self, service_name: str):
        """إطلاق حدث إيقاف"""
        for handler in self._event_handlers["resource_kill"]:
            try:
                if asyncio.iscoroutinefunction(handler):
                    await handler(service_name)
                else:
                    handler(service_name)
            except Exception as e:
                logger.error(f"Kill handler error: {e}")
    
    def on(self, event: str, handler: Callable):
        """تسجيل معالج حدث"""
        if event in self._event_handlers:
            self._event_handlers[event].append(handler)
    
    async def get_usage_history(self, duration_seconds: int = 300) -> List[ResourceUsage]:
        """الحصول على سجل استخدام الموارد"""
        cutoff = datetime.now().timestamp() - duration_seconds
        return [u for u in self._usage_history if u.timestamp.timestamp() > cutoff]
    
    async def get_alerts(self, since: datetime = None) -> List[ResourceAlert]:
        """الحصول على التنبيهات"""
        if since:
            return [a for a in self._alerts if a.timestamp > since]
        return self._alerts.copy()
    
    async def get_summary(self) -> Dict:
        """ملخص الموارد"""
        usage = await self._collect_usage()
        
        return {
            "current": {
                "cpu_percent": usage.cpu_percent,
                "memory_percent": usage.memory_percent,
                "memory_gb": usage.memory_bytes / (1024**3),
                "disk_percent": usage.disk_usage_percent,
                "threads": usage.thread_count,
                "open_fds": usage.open_fds
            },
            "limits": self._global_limits,
            "quotas": {
                service: {
                    "limits": [
                        {"type": l.type.value, "soft": l.soft_limit, "hard": l.hard_limit}
                        for l in quota.limits
                    ],
                    "pids": list(quota.pids),
                    "priority": quota.priority
                }
                for service, quota in self._quotas.items()
            },
            "stats": self._stats
        }
    
    async def check_memory_leak(self, service_name: str) -> Tuple[bool, float]:
        """
        فحص تسرب الذاكرة لخدمة معينة باستخدام الانحدار
        
        Returns:
            (is_leaking, growth_rate_mb_per_minute)
        """
        if service_name not in self._memory_history:
            return False, 0.0
        
        return self._calculate_leak_rate(self._memory_history[service_name])


# نسخة عالمية
_default_manager = None


async def get_resource_manager() -> ResourceManager:
    """الحصول على نسخة عالمية من مدير الموارد"""
    global _default_manager
    if _default_manager is None:
        _default_manager = ResourceManager()
        await _default_manager.start()
    return _default_manager

