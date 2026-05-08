
import asyncio
import json
import pickle
import os
import hashlib
from typing import Dict, List, Optional, Any, Callable, Awaitable, Tuple, Set
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from collections import deque
import logging

logger = logging.getLogger(__name__)


class RecoveryStatus(Enum):
    """حالة التعافي"""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    RECOVERING = "recovering"
    FAILED = "failed"
    UNKNOWN = "unknown"


class ComponentType(Enum):
    """نوع المكون"""
    SERVICE = "service"
    AGENT = "agent"
    PROCESS = "process"
    CONNECTION = "connection"
    DATA = "data"


@dataclass
class ComponentState:
    """حالة مكون"""
    component_id: str
    component_type: ComponentType
    name: str
    state_data: Dict[str, Any]
    last_heartbeat: datetime
    status: RecoveryStatus
    version: str
    dependencies: List[str]


@dataclass
class RecoveryPoint:
    """نقطة استعادة"""
    id: str
    timestamp: datetime
    components: Dict[str, ComponentState]
    metadata: Dict[str, Any]
    checksum: str


@dataclass
class CrashReport:
    """تقرير عطل"""
    crash_id: str
    timestamp: datetime
    component_id: str
    component_name: str
    error_type: str
    error_message: str
    stack_trace: Optional[str]
    recovery_attempted: bool
    recovery_success: bool
    recovery_strategy: str


class CrashRecovery:
    """
    نظام التعافي من الأعطال
    
    الميزات:
    - كشف الأعطال في المكونات
    - حفظ واستعادة نقاط التفتيش
    - استراتيجيات تعافي متعددة (إعادة تشغيل، استعادة، تبديل)
    - سجل الأعطال وتحليل الأنماط
    - تعافي تلقائي مع backoff
    - تكامل مع ServiceRegistry و ProcessManager
    - دوال ping/healthCheck للمكونات المسجلة
    """
    
    def __init__(
        self,
        checkpoint_interval: int = 300,  # 5 دقائق
        heartbeat_timeout: float = 60.0,  # ثانية
        max_recovery_attempts: int = 3,
        recovery_backoff: float = 5.0,
        checkpoint_dir: str = "./checkpoints"
    ):
        self._checkpoint_interval = checkpoint_interval
        self._heartbeat_timeout = heartbeat_timeout
        self._max_recovery_attempts = max_recovery_attempts
        self._recovery_backoff = recovery_backoff
        self._checkpoint_dir = checkpoint_dir
        
        # تخزين حالة المكونات
        self._components: Dict[str, ComponentState] = {}
        self._component_health_checks: Dict[str, Callable[[], Awaitable[bool]]] = {}
        self._component_recovery_fns: Dict[str, Callable[[], Awaitable[bool]]] = {}
        
        # نقاط الاستعادة
        self._recovery_points: List[RecoveryPoint] = []
        self._last_checkpoint: Optional[datetime] = None
        
        # سجل الأعطال
        self._crash_reports: List[CrashReport] = []
        self._crash_patterns: Dict[str, int] = {}
        
        # إحصائيات التعافي
        self._recovery_attempts: Dict[str, int] = {}
        self._last_recovery_attempt: Dict[str, datetime] = {}
        
        # المكونات الخارجية
        self._service_registry = None
        self._process_manager = None
        
        # مكونات التشغيل
        self._monitoring_task: Optional[asyncio.Task] = None
        self._checkpoint_task: Optional[asyncio.Task] = None
        self._running = False
        self._lock = asyncio.Lock()
        
        # إحصائيات
        self._stats = {
            "total_crashes": 0,
            "successful_recoveries": 0,
            "failed_recoveries": 0,
            "active_components": 0,
            "checkpoints_created": 0,
            "checkpoints_restored": 0
        }
        
        # إنشاء دليل نقاط التفتيش
        os.makedirs(checkpoint_dir, exist_ok=True)
        
        logger.info(f"CrashRecovery initialized (checkpoint_interval={checkpoint_interval}s)")
    
    async def set_service_registry(self, service_registry):
        """ربط ServiceRegistry للاكتشاف"""
        self._service_registry = service_registry
    
    async def set_process_manager(self, process_manager):
        """ربط ProcessManager لإدارة العمليات"""
        self._process_manager = process_manager
    
    def register_component(
        self,
        component_id: str,
        component_type: ComponentType,
        name: str,
        health_check_fn: Optional[Callable[[], Awaitable[bool]]] = None,
        recovery_fn: Optional[Callable[[], Awaitable[bool]]] = None,
        dependencies: List[str] = None,
        version: str = "1.0.0"
    ):
        """
        تسجيل مكون للنظام مع دوال الصحة والتعافي
        
        Args:
            component_id: معرف فريد للمكون
            component_type: نوع المكون
            name: اسم المكون
            health_check_fn: دالة غير متزامنة ترجع bool لفحص الصحة
            recovery_fn: دالة غير متزامنة ترجع bool للتعافي
            dependencies: قائمة المكونات التي يعتمد عليها
            version: إصدار المكون
        """
        state = ComponentState(
            component_id=component_id,
            component_type=component_type,
            name=name,
            state_data={},
            last_heartbeat=datetime.now(),
            status=RecoveryStatus.UNKNOWN,
            version=version,
            dependencies=dependencies or []
        )
        
        self._components[component_id] = state
        if health_check_fn:
            self._component_health_checks[component_id] = health_check_fn
        if recovery_fn:
            self._component_recovery_fns[component_id] = recovery_fn
        
        self._stats["active_components"] += 1
        logger.info(f"Registered component: {name} ({component_type.value}) id={component_id[:8]}")
    
    def unregister_component(self, component_id: str):
        """إلغاء تسجيل مكون"""
        if component_id in self._components:
            del self._components[component_id]
            self._component_health_checks.pop(component_id, None)
            self._component_recovery_fns.pop(component_id, None)
            self._stats["active_components"] -= 1
            logger.info(f"Unregistered component: {component_id[:8]}")
    
    async def heartbeat(self, component_id: str, state_data: Dict[str, Any] = None):
        """
        تسجيل نبض قلب لمكون
        
        Args:
            component_id: معرف المكون
            state_data: بيانات حالة اختيارية
        """
        async with self._lock:
            if component_id not in self._components:
                logger.warning(f"Heartbeat from unknown component: {component_id[:8]}")
                return False
            
            component = self._components[component_id]
            component.last_heartbeat = datetime.now()
            component.status = RecoveryStatus.HEALTHY
            
            if state_data:
                component.state_data.update(state_data)
            
            return True
    
    async def start(self):
        """بدء مراقبة الأعطال"""
        if self._running:
            return
        
        self._running = True
        
        # استعادة آخر نقطة تفتيش صالحة
        await self._restore_last_checkpoint()
        
        # بدء مراقبة نبضات القلب
        self._monitoring_task = asyncio.create_task(self._monitoring_loop())
        
        # بدء حفظ نقاط التفتيش الدورية
        self._checkpoint_task = asyncio.create_task(self._checkpoint_loop())
        
        logger.info("CrashRecovery started")
    
    async def stop(self):
        """إيقاف المراقبة وحفظ نقطة تفتيش أخيرة"""
        if not self._running:
            return
        
        self._running = False
        
        if self._monitoring_task:
            self._monitoring_task.cancel()
        if self._checkpoint_task:
            self._checkpoint_task.cancel()
        
        # حفظ نقطة تفتيش أخيرة
        await self._create_checkpoint("shutdown")
        
        logger.info("CrashRecovery stopped")
    
    async def _monitoring_loop(self):
        """حلقة مراقبة نبضات القلب والأعطال"""
        while self._running:
            await asyncio.sleep(10)  # فحص كل 10 ثواني
            
            try:
                await self._check_components_health()
            except Exception as e:
                logger.error(f"Health check error: {e}")
    
    async def _check_components_health(self):
        """فحص صحة جميع المكونات المسجلة"""
        now = datetime.now()
        
        async with self._lock:
            for component_id, component in list(self._components.items()):
                # التحقق من آخر نبضة قلب
                time_since_heartbeat = (now - component.last_heartbeat).total_seconds()
                
                if time_since_heartbeat <= self._heartbeat_timeout:
                    continue
                
                # المكون لا يستجيب - محاولة فحص الصحة
                logger.warning(f"Component {component.name} missed heartbeat ({time_since_heartbeat:.0f}s)")
                
                is_healthy = await self._perform_health_check(component_id)
                
                if not is_healthy:
                    # مكون معطل
                    component.status = RecoveryStatus.FAILED
                    await self._handle_crash(component_id)
    
    async def _perform_health_check(self, component_id: str) -> bool:
        """تنفيذ فحص صحة المكون"""
        if component_id in self._component_health_checks:
            try:
                return await asyncio.wait_for(
                    self._component_health_checks[component_id](),
                    timeout=10.0
                )
            except asyncio.TimeoutError:
                logger.warning(f"Health check timeout for {component_id[:8]}")
                return False
            except Exception as e:
                logger.error(f"Health check failed for {component_id[:8]}: {e}")
                return False
        
        # فحص افتراضي - استخدام ServiceRegistry أو ProcessManager
        if self._service_registry:
            status = await self._service_registry.get_status()
            # فحص بسيط
            return True
        
        return True
    
    async def _handle_crash(self, component_id: str):
        """معالجة عطل مكون"""
        async with self._lock:
            if component_id not in self._components:
                return
            
            component = self._components[component_id]
            
            # زيادة عدد المحاولات
            attempt_count = self._recovery_attempts.get(component_id, 0)
            
            if attempt_count >= self._max_recovery_attempts:
                logger.error(f"Component {component.name} exceeded max recovery attempts")
                component.status = RecoveryStatus.FAILED
                
                # تسجيل تقرير عطل نهائي
                report = CrashReport(
                    crash_id=f"crash_{datetime.now().timestamp()}",
                    timestamp=datetime.now(),
                    component_id=component_id,
                    component_name=component.name,
                    error_type="max_attempts_exceeded",
                    error_message=f"Failed after {attempt_count} recovery attempts",
                    stack_trace=None,
                    recovery_attempted=True,
                    recovery_success=False,
                    recovery_strategy="exponential_backoff"
                )
                self._crash_reports.append(report)
                self._stats["total_crashes"] += 1
                self._stats["failed_recoveries"] += 1
                return
            
            # تحديث عدد المحاولات
            self._recovery_attempts[component_id] = attempt_count + 1
            self._last_recovery_attempt[component_id] = datetime.now()
            
            # حساب تأخير التعافي (exponential backoff)
            delay = self._recovery_backoff * (2 ** attempt_count)
            delay = min(delay, 60.0)
            
            component.status = RecoveryStatus.RECOVERING
        
        logger.info(f"Attempting recovery for {component.name} (attempt {attempt_count + 1}/{self._max_recovery_attempts}, delay={delay:.1f}s)")
        
        await asyncio.sleep(delay)
        
        # محاولة التعافي
        success = await self._attempt_recovery(component_id)
        
        async with self._lock:
            if component_id not in self._components:
                return
            
            component = self._components[component_id]
            
            if success:
                component.status = RecoveryStatus.HEALTHY
                component.last_heartbeat = datetime.now()
                self._stats["successful_recoveries"] += 1
                self._stats["total_crashes"] += 1
                
                # إعادة ضبط عدد المحاولات
                self._recovery_attempts[component_id] = 0
                
                logger.info(f"Successfully recovered {component.name}")
            else:
                # ستتم المحاولة مرة أخرى في الدورة التالية
                logger.warning(f"Failed to recover {component.name}, will retry")
    
    async def _attempt_recovery(self, component_id: str) -> bool:
        """
        محاولة تعافي مكون
        
        استراتيجيات التعافي:
        1. استدعاء دالة التعافي المسجلة
        2. إعادة تشغيل العملية (إذا كانت عملية)
        3. استعادة حالة من نقطة تفتيش
        """
        # الاستراتيجية 1: دالة تعافي مخصصة
        if component_id in self._component_recovery_fns:
            try:
                return await asyncio.wait_for(
                    self._component_recovery_fns[component_id](),
                    timeout=30.0
                )
            except Exception as e:
                logger.error(f"Custom recovery failed for {component_id[:8]}: {e}")
        
        # الاستراتيجية 2: إعادة تشغيل عبر ProcessManager
        if self._process_manager:
            # البحث عن عملية مرتبطة بهذا المكون
            processes = await self._process_manager.list_processes()
            for proc in processes:
                if proc.get("name") == component_id:
                    await self._process_manager.restart_process(proc["id"])
                    return True
        
        # الاستراتيجية 3: استعادة من نقطة تفتيش
        restored = await self._restore_component_state(component_id)
        if restored:
            return True
        
        return False
    
    async def _checkpoint_loop(self):
        """حلقة حفظ نقاط التفتيش الدورية"""
        while self._running:
            await asyncio.sleep(self._checkpoint_interval)
            
            try:
                await self._create_checkpoint("periodic")
            except Exception as e:
                logger.error(f"Checkpoint creation error: {e}")
    
    async def _create_checkpoint(self, reason: str) -> Optional[RecoveryPoint]:
        """إنشاء نقطة استعادة"""
        async with self._lock:
            checkpoint_id = f"ckpt_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            
            # نسخة من الحالة الحالية
            components_copy = {}
            for comp_id, component in self._components.items():
                components_copy[comp_id] = ComponentState(
                    component_id=component.component_id,
                    component_type=component.component_type,
                    name=component.name,
                    state_data=component.state_data.copy(),
                    last_heartbeat=component.last_heartbeat,
                    status=component.status,
                    version=component.version,
                    dependencies=component.dependencies.copy()
                )
            
            checkpoint = RecoveryPoint(
                id=checkpoint_id,
                timestamp=datetime.now(),
                components=components_copy,
                metadata={
                    "reason": reason,
                    "stats": self._stats.copy(),
                    "version": "1.0"
                },
                checksum=""
            )
            
            # حساب checksum
            checkpoint_data = {
                "components": {k: v.__dict__ for k, v in components_copy.items()},
                "metadata": checkpoint.metadata
            }
            checkpoint.checksum = hashlib.md5(
                json.dumps(checkpoint_data, default=str).encode()
            ).hexdigest()
            
            self._recovery_points.append(checkpoint)
            
            # الحفاظ على آخر 10 نقاط فقط
            if len(self._recovery_points) > 10:
                old_checkpoint = self._recovery_points.pop(0)
                await self._delete_checkpoint_file(old_checkpoint.id)
            
            # حفظ إلى ملف
            await self._save_checkpoint_to_file(checkpoint)
            
            self._last_checkpoint = datetime.now()
            self._stats["checkpoints_created"] += 1
            
            logger.info(f"Checkpoint created: {checkpoint_id} (reason={reason})")
            
            return checkpoint
    
    async def _save_checkpoint_to_file(self, checkpoint: RecoveryPoint):
        """حفظ نقطة استعادة إلى ملف"""
        filepath = os.path.join(self._checkpoint_dir, f"{checkpoint.id}.pkl")
        
        def _save():
            with open(filepath, 'wb') as f:
                pickle.dump(checkpoint, f)
        
        await asyncio.get_event_loop().run_in_executor(None, _save)
    
    async def _restore_last_checkpoint(self) -> bool:
        """استعادة آخر نقطة استعادة صالحة"""
        checkpoints = sorted(self._recovery_points, key=lambda x: x.timestamp, reverse=True)
        
        for checkpoint in checkpoints:
            if await self._validate_checkpoint(checkpoint):
                return await self._restore_checkpoint(checkpoint.id)
        
        # محاولة استعادة من الملفات
        return await self._restore_from_files()
    
    async def _restore_checkpoint(self, checkpoint_id: str) -> bool:
        """استعادة حالة من نقطة استعادة"""
        checkpoint = None
        
        # البحث في الذاكرة
        for cp in self._recovery_points:
            if cp.id == checkpoint_id:
                checkpoint = cp
                break
        
        if not checkpoint:
            # محاولة تحميل من ملف
            checkpoint = await self._load_checkpoint_from_file(checkpoint_id)
        
        if not checkpoint:
            return False
        
        # التحقق من الصحة
        if not await self._validate_checkpoint(checkpoint):
            logger.warning(f"Checkpoint {checkpoint_id} validation failed")
            return False
        
        async with self._lock:
            # استعادة حالة المكونات
            for comp_id, component_state in checkpoint.components.items():
                if comp_id in self._components:
                    self._components[comp_id] = component_state
            
            self._stats["checkpoints_restored"] += 1
        
        logger.info(f"Restored checkpoint: {checkpoint_id}")
        return True
    
    async def _restore_component_state(self, component_id: str) -> bool:
        """استعادة حالة مكون واحد من أحدث نقطة استعادة"""
        # البحث عن أحدث نقطة استعادة تحتوي على هذا المكون
        for checkpoint in reversed(self._recovery_points):
            if component_id in checkpoint.components:
                component_state = checkpoint.components[component_id]
                
                async with self._lock:
                    if component_id in self._components:
                        self._components[component_id] = component_state
                
                logger.info(f"Restored state for component {component_id[:8]} from checkpoint {checkpoint.id}")
                return True
        
        return False
    
    async def _validate_checkpoint(self, checkpoint: RecoveryPoint) -> bool:
        """التحقق من صحة نقطة استعادة"""
        # التحقق من checksum
        checkpoint_data = {
            "components": {k: v.__dict__ for k, v in checkpoint.components.items()},
            "metadata": checkpoint.metadata
        }
        expected_checksum = hashlib.md5(
            json.dumps(checkpoint_data, default=str).encode()
        ).hexdigest()
        
        return checkpoint.checksum == expected_checksum
    
    async def _save_checkpoint_to_file(self, checkpoint: RecoveryPoint):
        """حفظ نقطة استعادة إلى ملف"""
        filepath = os.path.join(self._checkpoint_dir, f"{checkpoint.id}.pkl")
        
        def _save():
            with open(filepath, 'wb') as f:
                pickle.dump(checkpoint, f)
        
        await asyncio.get_event_loop().run_in_executor(None, _save)
    
    async def _load_checkpoint_from_file(self, checkpoint_id: str) -> Optional[RecoveryPoint]:
        """تحميل نقطة استعادة من ملف"""
        filepath = os.path.join(self._checkpoint_dir, f"{checkpoint_id}.pkl")
        
        if not os.path.exists(filepath):
            return None
        
        def _load():
            with open(filepath, 'rb') as f:
                return pickle.load(f)
        
        try:
            checkpoint = await asyncio.get_event_loop().run_in_executor(None, _load)
            return checkpoint
        except Exception as e:
            logger.error(f"Failed to load checkpoint {checkpoint_id}: {e}")
            return None
    
    async def _restore_from_files(self) -> bool:
        """استعادة من ملفات نقاط التفتيش"""
        try:
            files = os.listdir(self._checkpoint_dir)
            checkpoint_files = [f for f in files if f.endswith('.pkl')]
            
            if not checkpoint_files:
                return False
            
            # ترتيب حسب التاريخ
            checkpoint_files.sort(reverse=True)
            
            for filename in checkpoint_files[:3]:  # جرب آخر 3 ملفات
                checkpoint_id = filename.replace('.pkl', '')
                checkpoint = await self._load_checkpoint_from_file(checkpoint_id)
                
                if checkpoint and await self._validate_checkpoint(checkpoint):
                    await self._restore_checkpoint(checkpoint.id)
                    return True
            
            return False
            
        except Exception as e:
            logger.error(f"Failed to restore from files: {e}")
            return False
    
    async def _delete_checkpoint_file(self, checkpoint_id: str):
        """حذف ملف نقطة استعادة قديمة"""
        filepath = os.path.join(self._checkpoint_dir, f"{checkpoint_id}.pkl")
        if os.path.exists(filepath):
            os.unlink(filepath)
    
    async def create_manual_checkpoint(self) -> str:
        """إنشاء نقطة استعادة يدوية"""
        checkpoint = await self._create_checkpoint("manual")
        return checkpoint.id if checkpoint else ""
    
    async def get_crash_patterns(self) -> Dict[str, int]:
        """تحليل أنماط الأعطال"""
        patterns = {}
        
        for report in self._crash_reports:
            key = f"{report.component_name}:{report.error_type}"
            patterns[key] = patterns.get(key, 0) + 1
        
        return patterns
    
    async def get_crash_reports(self, limit: int = 100) -> List[Dict]:
        """الحصول على تقارير الأعطال"""
        reports = self._crash_reports[-limit:]
        
        return [
            {
                "crash_id": r.crash_id,
                "timestamp": r.timestamp.isoformat(),
                "component_name": r.component_name,
                "error_type": r.error_type,
                "error_message": r.error_message,
                "recovery_success": r.recovery_success,
                "recovery_strategy": r.recovery_strategy
            }
            for r in reports
        ]
    
    async def get_stats(self) -> Dict:
        """الحصول على إحصائيات النظام"""
        async with self._lock:
            return {
                **self._stats,
                "running": self._running,
                "components_by_status": {
                    status.value: sum(1 for c in self._components.values() if c.status == status)
                    for status in RecoveryStatus
                },
                "total_components": len(self._components),
                "recovery_points": len(self._recovery_points),
                "crash_reports": len(self._crash_reports),
                "heartbeat_timeout": self._heartbeat_timeout,
                "max_recovery_attempts": self._max_recovery_attempts
            }
    
    async def get_component_status(self, component_id: str) -> Optional[Dict]:
        """الحصول على حالة مكون محدد"""
        async with self._lock:
            if component_id not in self._components:
                return None
            
            component = self._components[component_id]
            
            return {
                "component_id": component.component_id,
                "name": component.name,
                "type": component.component_type.value,
                "status": component.status.value,
                "last_heartbeat": component.last_heartbeat.isoformat(),
                "time_since_heartbeat": (datetime.now() - component.last_heartbeat).total_seconds(),
                "version": component.version,
                "dependencies": component.dependencies,
                "recovery_attempts": self._recovery_attempts.get(component_id, 0)
            }


# نسخة عالمية
_default_recovery = None


async def get_crash_recovery() -> CrashRecovery:
    """الحصول على نسخة عالمية من نظام التعافي"""
    global _default_recovery
    if _default_recovery is None:
        _default_recovery = CrashRecovery()
        await _default_recovery.start()
    return _default_recovery

