
import asyncio
import signal
import subprocess
import os
import psutil
import uuid
import concurrent.futures
from typing import Dict, List, Optional, Any, Callable, Awaitable, Tuple, Set
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from contextlib import asynccontextmanager
import logging

logger = logging.getLogger(__name__)


class ProcessStatus(Enum):
    """حالة العملية"""
    CREATED = "created"
    STARTING = "starting"
    RUNNING = "running"
    STOPPING = "stopping"
    STOPPED = "stopped"
    FAILED = "failed"
    RESTARTING = "restarting"
    CRASHED = "crashed"


class ProcessHealth(Enum):
    """صحة العملية"""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


@dataclass
class ProcessConfig:
    """إعدادات العملية"""
    name: str
    command: List[str]
    working_dir: Optional[str] = None
    environment: Dict[str, str] = field(default_factory=dict)
    
    # إعادة التشغيل
    auto_restart: bool = True
    max_restarts: int = 5
    restart_delay: float = 1.0
    restart_backoff_factor: float = 2.0
    
    # مهلات
    startup_timeout: float = 30.0
    shutdown_timeout: float = 10.0
    health_check_interval: float = 5.0
    
    # حدود الموارد
    cpu_limit_percent: Optional[float] = None
    memory_limit_mb: Optional[float] = None
    
    # إعادة التوجيه
    redirect_stdout: bool = True
    redirect_stderr: bool = True
    log_file: Optional[str] = None


@dataclass
class ProcessInstance:
    """مثيل عملية قيد التشغيل"""
    id: str
    config: ProcessConfig
    pid: Optional[int] = None
    process: Optional[asyncio.subprocess.Process] = None
    status: ProcessStatus = ProcessStatus.CREATED
    health: ProcessHealth = ProcessHealth.UNKNOWN
    created_at: datetime = field(default_factory=datetime.now)
    started_at: Optional[datetime] = None
    stopped_at: Optional[datetime] = None
    restart_count: int = 0
    last_restart: Optional[datetime] = None
    last_heartbeat: Optional[datetime] = None
    error: Optional[str] = None
    
    # منع إعادة التشغيل المتزامن
    is_restarting: bool = False
    
    # إحصائيات
    stdout_lines: List[str] = field(default_factory=list)
    stderr_lines: List[str] = field(default_factory=list)
    max_log_lines: int = 1000
    
    # تجميع استخدام الموارد (من psutil)
    cpu_percent: float = 0.0
    memory_mb: float = 0.0


class ProcessManager:
    """
    مدير العمليات المتقدم
    
    الميزات:
    - تشغيل وإدارة عمليات فرعية
    - مراقبة الصحة وإعادة التشغيل التلقائي
    - إعادة تشغيل بتأخير متزايد (exponential backoff)
    - مراقبة استهلاك الموارد الحقيقية عبر psutil
    - التقاط stdout/stderr
    - إيقاف آمن مع مهلة
    - تكامل مع ServiceRegistry و ResourceManager
    - منع إعادة التشغيل المتزامن
    """
    
    def __init__(self):
        self._processes: Dict[str, ProcessInstance] = {}
        self._monitoring_tasks: Dict[str, asyncio.Task] = {}
        self._health_check_tasks: Dict[str, asyncio.Task] = {}
        self._resource_collection_tasks: Dict[str, asyncio.Task] = {}
        self._lock = asyncio.Lock()
        self._running = False
        self._shutdown_event = asyncio.Event()
        
        # منفذ للعمليات المتزامنة (لـ psutil)
        self._cpu_executor = concurrent.futures.ThreadPoolExecutor(max_workers=2, thread_name_prefix="CPUCollector")
        
        # مكونات خارجية
        self._service_registry = None
        self._resource_manager = None
        
        # معالج إشارات العمليات
        self._signal_handlers: Dict[int, Callable] = {}
        
        # إحصائيات
        self._stats = {
            "total_processes": 0,
            "running_processes": 0,
            "failed_processes": 0,
            "restarts_total": 0,
            "crashes_total": 0
        }
        
        logger.info("ProcessManager initialized")
    
    async def set_service_registry(self, service_registry):
        """ربط ServiceRegistry للاكتشاف"""
        self._service_registry = service_registry
    
    async def set_resource_manager(self, resource_manager):
        """ربط ResourceManager لمراقبة الموارد"""
        self._resource_manager = resource_manager
    
    async def start(self):
        """بدء تشغيل المدير"""
        if self._running:
            return
        
        self._running = True
        logger.info("ProcessManager started")
    
    async def stop(self, timeout: float = 30.0):
        """إيقاف تشغيل المدير وجميع العمليات"""
        if not self._running:
            return
        
        logger.info(f"Stopping ProcessManager, stopping {len(self._processes)} processes...")
        self._running = False
        
        # إيقاف جميع العمليات بشكل آمن
        stop_tasks = []
        for proc_id in list(self._processes.keys()):
            stop_tasks.append(self.stop_process(proc_id))
        
        try:
            await asyncio.wait_for(asyncio.gather(*stop_tasks), timeout=timeout)
        except asyncio.TimeoutError:
            logger.warning("Timeout stopping processes, forcing termination")
            for proc_id in list(self._processes.keys()):
                await self.force_terminate(proc_id)
        
        # إلغاء مهام المراقبة
        for task in self._monitoring_tasks.values():
            task.cancel()
        for task in self._health_check_tasks.values():
            task.cancel()
        for task in self._resource_collection_tasks.values():
            task.cancel()
        
        # إغلاق منفذ العمليات
        self._cpu_executor.shutdown(wait=False)
        
        self._shutdown_event.set()
        logger.info("ProcessManager stopped")
    
    async def spawn_process(
        self,
        config: ProcessConfig,
        register_with_resource_manager: bool = True
    ) -> str:
        """إنشاء وتشغيل عملية جديدة"""
        process_id = str(uuid.uuid4())[:8]
        
        instance = ProcessInstance(
            id=process_id,
            config=config,
            is_restarting=False
        )
        
        async with self._lock:
            self._processes[process_id] = instance
            self._stats["total_processes"] += 1
        
        # بدء العملية
        success = await self._start_process_instance(process_id, register_with_resource_manager)
        
        if not success:
            async with self._lock:
                self._processes.pop(process_id, None)
                self._stats["total_processes"] -= 1
            raise RuntimeError(f"Failed to start process {config.name}")
        
        logger.info(f"Process spawned: {config.name} (id={process_id}, pid={instance.pid})")
        return process_id
    
    async def _start_process_instance(
        self,
        process_id: str,
        register_with_resource_manager: bool = True
    ) -> bool:
        """بدء تشغيل مثيل عملية"""
        async with self._lock:
            if process_id not in self._processes:
                return False
            
            instance = self._processes[process_id]
            
            # منع إعادة التشغيل المتزامن
            if instance.is_restarting:
                logger.debug(f"Process {instance.config.name} is already restarting, skipping")
                return False
            
            instance.status = ProcessStatus.STARTING
            instance.is_restarting = False
        
        config = instance.config
        
        try:
            # إعداد بيئة التشغيل
            env = os.environ.copy()
            env.update(config.environment)
            
            # إعداد إعادة التوجيه - التعامل مع None بأمان
            stdout_dest = None
            stderr_dest = None
            
            if config.redirect_stdout:
                stdout_dest = asyncio.subprocess.PIPE
            if config.redirect_stderr:
                stderr_dest = asyncio.subprocess.PIPE
            
            # تشغيل العملية
            process = await asyncio.create_subprocess_exec(
                *config.command,
                cwd=config.working_dir,
                env=env,
                stdout=stdout_dest,
                stderr=stderr_dest
            )
            
            async with self._lock:
                instance.process = process
                instance.pid = process.pid
                instance.started_at = datetime.now()
                instance.status = ProcessStatus.RUNNING
                instance.health = ProcessHealth.HEALTHY
                instance.error = None
                instance.restart_count = instance.restart_count if instance.restart_count > 0 else 0
            
            self._stats["running_processes"] += 1
            
            # تسجيل العملية في ResourceManager
            if register_with_resource_manager and self._resource_manager:
                await self._resource_manager.add_process_to_service(config.name, process.pid)
            
            # بدء مهمة مراقبة العملية
            monitor_task = asyncio.create_task(self._monitor_process(process_id))
            self._monitoring_tasks[process_id] = monitor_task
            
            # بدء مهمة فحص الصحة
            if config.health_check_interval > 0:
                health_task = asyncio.create_task(self._health_check_loop(process_id))
                self._health_check_tasks[process_id] = health_task
            
            # بدء مهمة جمع الموارد
            resource_task = asyncio.create_task(self._collect_resources_loop(process_id))
            self._resource_collection_tasks[process_id] = resource_task
            
            # انتظار بدء التشغيل
            await self._wait_for_startup(process_id, config.startup_timeout)
            
            return True
            
        except asyncio.TimeoutError:
            async with self._lock:
                instance.status = ProcessStatus.FAILED
                instance.error = f"Startup timeout after {config.startup_timeout}s"
                instance.is_restarting = False
            logger.error(f"Process startup timeout: {config.name}")
            return False
            
        except Exception as e:
            async with self._lock:
                instance.status = ProcessStatus.FAILED
                instance.error = str(e)
                instance.is_restarting = False
            logger.error(f"Failed to start process {config.name}: {e}")
            return False
    
    async def _wait_for_startup(self, process_id: str, timeout: float):
        """انتظار بدء تشغيل العملية"""
        start_time = datetime.now()
        
        while (datetime.now() - start_time).total_seconds() < timeout:
            async with self._lock:
                if process_id not in self._processes:
                    return
                instance = self._processes[process_id]
                if instance.status == ProcessStatus.RUNNING:
                    return
            
            await asyncio.sleep(0.1)
        
        raise asyncio.TimeoutError()
    
    async def _monitor_process(self, process_id: str):
        """مراقبة عملية وجمع stdout/stderr"""
        async with self._lock:
            if process_id not in self._processes:
                return
            instance = self._processes[process_id]
            process = instance.process
        
        if not process:
            return
        
        try:
            # مراقبة stdout و stderr بشكل متوازي
            tasks = []
            
            # التعامل مع None بأمان - التحقق من وجود stream قبل القراءة
            if process.stdout:
                tasks.append(self._read_stream(process_id, process.stdout, "stdout"))
            if process.stderr:
                tasks.append(self._read_stream(process_id, process.stderr, "stderr"))
            
            # انتظار انتهاء العملية
            return_code = await process.wait()
            
            # العملية انتهت
            async with self._lock:
                if process_id not in self._processes:
                    return
                instance = self._processes[process_id]
            
            if return_code == 0:
                logger.info(f"Process {instance.config.name} exited normally")
                instance.status = ProcessStatus.STOPPED
                self._stats["running_processes"] -= 1
            else:
                logger.warning(f"Process {instance.config.name} crashed with code {return_code}")
                instance.status = ProcessStatus.CRASHED
                instance.error = f"Exit code: {return_code}"
                self._stats["running_processes"] -= 1
                self._stats["crashes_total"] += 1
                
                # إعادة التشغيل التلقائي - مع منع التزامن
                if instance.config.auto_restart and not instance.is_restarting:
                    await self._restart_process(process_id)
            
            instance.stopped_at = datetime.now()
            
            # إلغاء مهام القراءة
            for task in tasks:
                task.cancel()
            
        except asyncio.CancelledError:
            logger.debug(f"Process monitor cancelled for {instance.config.name}")
        except Exception as e:
            logger.error(f"Process monitor error for {instance.config.name}: {e}")
            if not instance.is_restarting:
                await self._restart_process(process_id)
    
    async def _read_stream(self, process_id: str, stream, stream_type: str):
        """قراءة من stdout/stderr بشكل غير محجوب"""
        async with self._lock:
            if process_id not in self._processes:
                return
            instance = self._processes[process_id]
        
        while True:
            try:
                line = await stream.readline()
                if not line:
                    break
                
                line_str = line.decode('utf-8').rstrip()
                
                async with self._lock:
                    if process_id not in self._processes:
                        break
                    instance = self._processes[process_id]
                    
                    if stream_type == "stdout":
                        instance.stdout_lines.append(line_str)
                        if len(instance.stdout_lines) > instance.max_log_lines:
                            instance.stdout_lines.pop(0)
                    else:
                        instance.stderr_lines.append(line_str)
                        if len(instance.stderr_lines) > instance.max_log_lines:
                            instance.stderr_lines.pop(0)
                    
                    if stream_type == "stderr":
                        logger.debug(f"[{instance.config.name}] {line_str}")
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error reading {stream_type} for {process_id}: {e}")
                break
    
    async def _collect_resources_loop(self, process_id: str):
        """جمع استخدام الموارد الحقيقي للعملية"""
        interval = 5.0  # كل 5 ثواني
        
        while self._running:
            await asyncio.sleep(interval)
            
            async with self._lock:
                if process_id not in self._processes:
                    break
                instance = self._processes[process_id]
                
                if instance.status != ProcessStatus.RUNNING or not instance.pid:
                    continue
            
            try:
                # استخدام psutil في خيط منفصل لتجنب حظر الحلقة
                loop = asyncio.get_running_loop()
                
                def get_process_stats():
                    try:
                        proc = psutil.Process(instance.pid)
                        # استخدام interval=0 لجمع عينة فورية
                        cpu = proc.cpu_percent(interval=0)
                        memory = proc.memory_info().rss / (1024 * 1024)  # MB
                        return cpu, memory
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        return 0.0, 0.0
                
                cpu, memory = await loop.run_in_executor(self._cpu_executor, get_process_stats)
                
                async with self._lock:
                    if process_id in self._processes:
                        instance = self._processes[process_id]
                        instance.cpu_percent = cpu
                        instance.memory_mb = memory
                        
                        # تحديث ResourceManager إذا كان متصلاً
                        if self._resource_manager:
                            await self._resource_manager.report_usage(
                                instance.config.name,
                                {
                                    "cpu_percent": cpu,
                                    "memory_mb": memory
                                }
                            )
                
            except Exception as e:
                logger.debug(f"Error collecting resources for {instance.config.name}: {e}")
    
    async def _health_check_loop(self, process_id: str):
        """حلقة فحص صحة العملية"""
        while self._running:
            async with self._lock:
                if process_id not in self._processes:
                    break
                instance = self._processes[process_id]
                interval = instance.config.health_check_interval
            
            await asyncio.sleep(interval)
            
            async with self._lock:
                if process_id not in self._processes:
                    break
                instance = self._processes[process_id]
                
                if instance.status != ProcessStatus.RUNNING:
                    continue
                
                old_health = instance.health
                
                # فحص الصحة الأساسي
                if instance.process and instance.process.returncode is not None:
                    instance.health = ProcessHealth.UNHEALTHY
                else:
                    instance.health = ProcessHealth.HEALTHY
                
                instance.last_heartbeat = datetime.now()
                
                if old_health != instance.health:
                    logger.warning(f"Process {instance.config.name} health changed: {old_health.value} -> {instance.health.value}")
    
    async def _restart_process(self, process_id: str) -> bool:
        """إعادة تشغيل عملية - مع منع التزامن"""
        async with self._lock:
            if process_id not in self._processes:
                return False
            
            instance = self._processes[process_id]
            
            # منع إعادة التشغيل المتزامن
            if instance.is_restarting:
                logger.debug(f"Process {instance.config.name} is already restarting, skipping")
                return False
            
            # التحقق من عدد إعادة التشغيل
            if instance.restart_count >= instance.config.max_restarts:
                logger.error(f"Process {instance.config.name} exceeded max restarts ({instance.config.max_restarts})")
                instance.status = ProcessStatus.FAILED
                return False
            
            instance.status = ProcessStatus.RESTARTING
            instance.is_restarting = True
            instance.restart_count += 1
            instance.last_restart = datetime.now()
            self._stats["restarts_total"] += 1
        
        # حساب تأخير إعادة التشغيل (exponential backoff)
        delay = instance.config.restart_delay * (instance.config.restart_backoff_factor ** (instance.restart_count - 1))
        delay = min(delay, 60.0)
        
        logger.info(f"Restarting process {instance.config.name} in {delay:.1f}s (attempt {instance.restart_count}/{instance.config.max_restarts})")
        
        await asyncio.sleep(delay)
        
        # تنظيف العملية القديمة
        await self._cleanup_process(process_id)
        
        # بدء عملية جديدة - reset is_restarting بعد البدء
        success = await self._start_process_instance(process_id)
        
        if success:
            async with self._lock:
                if process_id in self._processes:
                    self._processes[process_id].is_restarting = False
        
        return success
    
    async def stop_process(self, process_id: str) -> bool:
        """إيقاف عملية بشكل آمن (SIGTERM ثم SIGKILL)"""
        async with self._lock:
            if process_id not in self._processes:
                return False
            
            instance = self._processes[process_id]
            
            if instance.status not in [ProcessStatus.RUNNING, ProcessStatus.STARTING]:
                return True
            
            instance.status = ProcessStatus.STOPPING
        
        timeout = instance.config.shutdown_timeout
        
        if instance.process and instance.pid:
            try:
                logger.info(f"Stopping process {instance.config.name} (PID: {instance.pid})")
                
                instance.process.terminate()
                
                try:
                    await asyncio.wait_for(instance.process.wait(), timeout=timeout)
                    logger.info(f"Process {instance.config.name} stopped gracefully")
                except asyncio.TimeoutError:
                    logger.warning(f"Process {instance.config.name} didn't stop, force killing")
                    instance.process.kill()
                    await instance.process.wait()
                    
            except Exception as e:
                logger.error(f"Error stopping process {instance.config.name}: {e}")
        
        async with self._lock:
            if process_id in self._processes:
                instance = self._processes[process_id]
                instance.status = ProcessStatus.STOPPED
                instance.stopped_at = datetime.now()
                instance.process = None
                self._stats["running_processes"] -= 1
        
        return True
    
    async def force_terminate(self, process_id: str) -> bool:
        """إنهاء عملية بالقوة (SIGKILL)"""
        async with self._lock:
            if process_id not in self._processes:
                return False
            
            instance = self._processes[process_id]
            
            if not instance.process or not instance.pid:
                return False
            
            try:
                logger.warning(f"Force terminating process {instance.config.name} (PID: {instance.pid})")
                instance.process.kill()
                await instance.process.wait()
                
                instance.status = ProcessStatus.STOPPED
                instance.process = None
                self._stats["running_processes"] -= 1
                
                return True
                
            except Exception as e:
                logger.error(f"Error force terminating process: {e}")
                return False
    
    async def _cleanup_process(self, process_id: str):
        """تنظيف موارد العملية"""
        # إلغاء مهام المراقبة
        if process_id in self._monitoring_tasks:
            self._monitoring_tasks[process_id].cancel()
            del self._monitoring_tasks[process_id]
        
        if process_id in self._health_check_tasks:
            self._health_check_tasks[process_id].cancel()
            del self._health_check_tasks[process_id]
        
        if process_id in self._resource_collection_tasks:
            self._resource_collection_tasks[process_id].cancel()
            del self._resource_collection_tasks[process_id]
        
        # إزالة من ResourceManager
        async with self._lock:
            if process_id in self._processes:
                instance = self._processes[process_id]
                if self._resource_manager and instance.pid:
                    await self._resource_manager.remove_process_from_service(
                        instance.config.name,
                        instance.pid
                    )
    
    async def send_signal(self, process_id: str, signal: int) -> bool:
        """إرسال إشارة إلى عملية"""
        async with self._lock:
            if process_id not in self._processes:
                return False
            
            instance = self._processes[process_id]
            
            if not instance.process or instance.pid is None:
                return False
            
            try:
                instance.process.send_signal(signal)
                return True
            except Exception as e:
                logger.error(f"Error sending signal to process {process_id}: {e}")
                return False
    
    async def get_process_info(self, process_id: str) -> Optional[Dict]:
        """الحصول على معلومات مفصلة عن عملية"""
        async with self._lock:
            if process_id not in self._processes:
                return None
            
            instance = self._processes[process_id]
            
            return {
                "id": instance.id,
                "name": instance.config.name,
                "pid": instance.pid,
                "status": instance.status.value,
                "health": instance.health.value,
                "restart_count": instance.restart_count,
                "is_restarting": instance.is_restarting,
                "uptime_seconds": (datetime.now() - instance.started_at).total_seconds() if instance.started_at else 0,
                "cpu_percent": instance.cpu_percent,
                "memory_mb": instance.memory_mb,
                "command": " ".join(instance.config.command),
                "working_dir": instance.config.working_dir,
                "log_lines": {
                    "stdout": instance.stdout_lines[-10:],
                    "stderr": instance.stderr_lines[-10:]
                },
                "error": instance.error,
                "created_at": instance.created_at.isoformat(),
                "started_at": instance.started_at.isoformat() if instance.started_at else None,
                "last_restart": instance.last_restart.isoformat() if instance.last_restart else None
            }
    
    async def list_processes(self) -> List[Dict]:
        """قائمة جميع العمليات"""
        async with self._lock:
            return [
                {
                    "id": proc.id,
                    "name": proc.config.name,
                    "pid": proc.pid,
                    "status": proc.status.value,
                    "health": proc.health.value,
                    "restart_count": proc.restart_count,
                    "cpu_percent": proc.cpu_percent,
                    "memory_mb": proc.memory_mb
                }
                for proc in self._processes.values()
            ]
    
    async def get_stats(self) -> Dict:
        """إحصائيات المدير"""
        async with self._lock:
            return {
                **self._stats,
                "running": self._running,
                "processes_by_status": {
                    status.value: sum(1 for p in self._processes.values() if p.status == status)
                    for status in ProcessStatus
                }
            }


# نسخة عالمية
_default_manager = None


async def get_process_manager() -> ProcessManager:
    """الحصول على نسخة عالمية من مدير العمليات"""
    global _default_manager
    if _default_manager is None:
        _default_manager = ProcessManager()
        await _default_manager.start()
    return _default_manager

