
import asyncio
import time
import logging
from typing import Dict, List, Optional, Any, Callable, Awaitable, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from contextlib import asynccontextmanager

from .lifecycle_manager import LifecycleManager, ComponentPriority, ComponentState, get_lifecycle_manager
from .dependency_container import get_dependency_container, Scope
from .service_registry import get_service_registry

logger = logging.getLogger(__name__)


class StartupPhase(Enum):
    """مراحل بدء التشغيل"""
    INITIALIZING = "initializing"
    VALIDATING = "validating"
    LOADING_CONFIG = "loading_config"
    INITIALIZING_COMPONENTS = "initializing_components"
    STARTING_SERVICES = "starting_services"
    HEALTH_CHECK = "health_check"
    READY = "ready"
    FAILED = "failed"


class ShutdownPriority(Enum):
    """أولوية الإيقاف"""
    FIRST = 1      # أول من يتوقف (الخدمات الخارجية)
    NORMAL = 2     # عادي
    LAST = 3       # آخر من يتوقف (المكونات الأساسية)


@dataclass
class StartupComponent:
    """مكون يتم تشغيله عند البدء"""
    name: str
    startup_fn: Optional[Callable[[], Awaitable[None]]] = None
    shutdown_fn: Optional[Callable[[], Awaitable[None]]] = None
    dependencies: List[str] = field(default_factory=list)
    shutdown_priority: ShutdownPriority = ShutdownPriority.NORMAL
    timeout: float = 30.0
    required: bool = True
    health_check_fn: Optional[Callable[[], Awaitable[bool]]] = None


@dataclass
class StartupStep:
    """خطوة في عملية البدء"""
    name: str
    phase: StartupPhase
    duration: float = 0.0
    status: str = "pending"
    error: Optional[str] = None
    timestamp: datetime = field(default_factory=datetime.now)


class StartupManager:
    """
    مدير بدء التشغيل
    
    المسؤوليات:
    - ترتيب بدء المكونات حسب التبعيات
    - تأخير زمني ذكي (staggering) لتجنب spike
    - فحص الصحة بعد البدء
    - إيقاف آمن عند الفشل (rollback)
    - إدارة مراحل بدء التشغيل المتعددة
    - دعم بدء التشغيل التزايدي (incremental startup)
    """
    
    def __init__(self):
        self._components: Dict[str, StartupComponent] = {}
        self._startup_steps: List[StartupStep] = []
        self._current_phase = StartupPhase.INITIALIZING
        self._start_time: Optional[datetime] = None
        self._end_time: Optional[datetime] = None
        
        # إعدادات
        self._default_timeout = 30.0
        self._health_check_wait = 5.0  # ثواني بعد بدء كل مكون
        self._stagger_delay = 0.5  # تأخير بين المكونات
        self._enable_rollback = True
        
        # مكونات النظام
        self._lifecycle_manager: Optional[LifecycleManager] = None
        self._dependency_container = None
        self._service_registry = None
        
        # إحصائيات
        self._stats = {
            "total_components": 0,
            "started_components": 0,
            "failed_components": 0,
            "rollback_triggered": False
        }
        
        logger.info("StartupManager initialized")
    
    async def initialize(self):
        """تهيئة المدير"""
        self._lifecycle_manager = get_lifecycle_manager()
        self._dependency_container = get_dependency_container()
        self._service_registry = await get_service_registry()
        
        logger.info("StartupManager ready")
    
    def register_component(
        self,
        name: str,
        startup_fn: Optional[Callable[[], Awaitable[None]]] = None,
        shutdown_fn: Optional[Callable[[], Awaitable[None]]] = None,
        dependencies: List[str] = None,
        shutdown_priority: ShutdownPriority = ShutdownPriority.NORMAL,
        timeout: float = None,
        required: bool = True,
        health_check_fn: Optional[Callable[[], Awaitable[bool]]] = None
    ):
        """
        تسجيل مكون لبدء التشغيل
        
        Args:
            name: اسم المكون
            startup_fn: دالة البدء غير المتزامنة
            shutdown_fn: دالة الإيقاف غير المتزامنة
            dependencies: قائمة المكونات التي يعتمد عليها
            shutdown_priority: أولوية الإيقاف
            timeout: مهلة البدء بالثواني
            required: هل المكون إلزامي؟
            health_check_fn: دالة فحص الصحة بعد البدء
        """
        component = StartupComponent(
            name=name,
            startup_fn=startup_fn,
            shutdown_fn=shutdown_fn,
            dependencies=dependencies or [],
            shutdown_priority=shutdown_priority,
            timeout=timeout or self._default_timeout,
            required=required,
            health_check_fn=health_check_fn
        )
        
        self._components[name] = component
        self._stats["total_components"] += 1
        
        logger.debug(f"Registered startup component: {name}")
    
    async def start(self) -> bool:
        """
        بدء تشغيل جميع المكونات
        
        Returns:
            نجاح بدء التشغيل
        """
        self._start_time = datetime.now()
        self._current_phase = StartupPhase.INITIALIZING
        
        logger.info("=" * 60)
        logger.info("🚀 HunterMind Platform - Starting up...")
        logger.info("=" * 60)
        
        try:
            # المرحلة 1: التحقق من الصحة
            await self._record_step("Validation", StartupPhase.VALIDATING)
            if not await self._validate():
                raise RuntimeError("Startup validation failed")
            
            # المرحلة 2: تحميل الإعدادات
            await self._record_step("Config Loading", StartupPhase.LOADING_CONFIG)
            await self._load_configurations()
            
            # المرحلة 3: تهيئة المكونات (حسب التبعيات)
            await self._record_step("Component Initialization", StartupPhase.INITIALIZING_COMPONENTS)
            if not await self._initialize_components():
                raise RuntimeError("Component initialization failed")
            
            # المرحلة 4: بدء الخدمات (بترتيب ذكي)
            await self._record_step("Service Startup", StartupPhase.STARTING_SERVICES)
            if not await self._start_services():
                raise RuntimeError("Service startup failed")
            
            # المرحلة 5: فحص الصحة النهائي
            await self._record_step("Health Check", StartupPhase.HEALTH_CHECK)
            if not await self._final_health_check():
                logger.warning("Final health check reported issues but continuing")
            
            # المرحلة 6: جاهز
            self._current_phase = StartupPhase.READY
            self._end_time = datetime.now()
            duration = (self._end_time - self._start_time).total_seconds()
            
            logger.info("=" * 60)
            logger.info(f"✅ Platform started successfully in {duration:.2f}s")
            logger.info(f"   Components: {self._stats['started_components']}/{self._stats['total_components']}")
            logger.info("=" * 60)
            
            return True
            
        except Exception as e:
            self._current_phase = StartupPhase.FAILED
            logger.error(f"❌ Startup failed: {e}", exc_info=True)
            
            # التراجع عن التغييرات
            if self._enable_rollback:
                await self.rollback()
            
            return False
    
    async def _validate(self) -> bool:
        """التحقق من صحة الإعدادات والتبعيات"""
        # التحقق من وجود تبعيات دائرية
        visited = set()
        recursion_stack = set()
        
        def has_cycle(node: str, path: List[str]) -> Tuple[bool, List[str]]:
            if node in recursion_stack:
                cycle_start = path.index(node)
                return True, path[cycle_start:] + [node]
            if node in visited:
                return False, []
            
            visited.add(node)
            recursion_stack.add(node)
            path.append(node)
            
            if node in self._components:
                for dep in self._components[node].dependencies:
                    cycle_found, cycle_path = has_cycle(dep, path.copy())
                    if cycle_found:
                        return True, cycle_path
            
            recursion_stack.remove(node)
            return False, []
        
        for name in self._components:
            cycle_found, cycle_path = has_cycle(name, [])
            if cycle_found:
                logger.error(f"Dependency cycle detected: {' -> '.join(cycle_path)}")
                return False
        
        logger.info(f"✅ Validation passed - {len(self._components)} components registered")
        return True
    
    async def _load_configurations(self):
        """تحميل إعدادات النظام"""
        # هنا سيتم تحميل الإعدادات من config.yaml
        logger.info("📋 Loading configurations...")
        await asyncio.sleep(0.1)  # محاكاة
        logger.info("✅ Configurations loaded")
    
    async def _initialize_components(self) -> bool:
        """تهيئة المكونات حسب الترتيب الطوبولوجي"""
        sorted_components = await self._topological_sort()
        
        logger.info(f"🔧 Initializing {len(sorted_components)} components...")
        
        for name in sorted_components:
            component = self._components[name]
            
            try:
                logger.info(f"   Initializing {name}...")
                
                # تسجيل في LifecycleManager
                self._lifecycle_manager.register_component(
                    name=name,
                    instance=component,
                    priority=self._get_priority_from_deps(component.dependencies),
                    dependencies=component.dependencies,
                    on_init=component.startup_fn,
                    on_start=component.startup_fn,
                    on_stop=component.shutdown_fn,
                    health_check=component.health_check_fn
                )
                
                # تأخير بسيط بين المكونات (stagger)
                await asyncio.sleep(self._stagger_delay)
                
                self._stats["started_components"] += 1
                logger.info(f"   ✅ {name} initialized")
                
            except Exception as e:
                logger.error(f"   ❌ Failed to initialize {name}: {e}")
                self._stats["failed_components"] += 1
                
                if component.required:
                    raise
        
        # تهيئة جميع المكونات عبر LifecycleManager
        return await self._lifecycle_manager.initialize_all()
    
    async def _topological_sort(self) -> List[str]:
        """ترتيب المكونات طوبولوجياً حسب التبعيات"""
        from collections import deque
        
        in_degree = {name: 0 for name in self._components}
        graph = {name: [] for name in self._components}
        
        for name, component in self._components.items():
            for dep in component.dependencies:
                if dep in graph:
                    graph[dep].append(name)
                    in_degree[name] += 1
        
        queue = deque([name for name, degree in in_degree.items() if degree == 0])
        sorted_order = []
        
        while queue:
            node = queue.popleft()
            sorted_order.append(node)
            
            for neighbor in graph[node]:
                in_degree[neighbor] -= 1
                if in_degree[neighbor] == 0:
                    queue.append(neighbor)
        
        return sorted_order
    
    def _get_priority_from_deps(self, dependencies: List[str]) -> ComponentPriority:
        """تحديد الأولوية بناءً على عدد التبعيات"""
        if len(dependencies) > 5:
            return ComponentPriority.CRITICAL
        elif len(dependencies) > 2:
            return ComponentPriority.HIGH
        elif dependencies:
            return ComponentPriority.NORMAL
        else:
            return ComponentPriority.LOW
    
    async def _start_services(self) -> bool:
        """بدء الخدمات مع تأخير ذكي"""
        # الحصول على ترتيب الإيقاف العكسي
        sorted_components = await self._topological_sort()
        
        logger.info(f"▶️ Starting {len(sorted_components)} services...")
        
        for i, name in enumerate(sorted_components):
            component = self._components[name]
            
            if not component.startup_fn:
                logger.debug(f"   Skipping {name} (no startup function)")
                continue
            
            try:
                logger.info(f"   Starting {name}...")
                
                # تنفيذ دالة البدء مع timeout
                await asyncio.wait_for(
                    component.startup_fn(),
                    timeout=component.timeout
                )
                
                # فحص الصحة بعد البدء
                if component.health_check_fn:
                    healthy = await asyncio.wait_for(
                        component.health_check_fn(),
                        timeout=10.0
                    )
                    if not healthy:
                        logger.warning(f"   ⚠️ {name} started but health check failed")
                
                # تأخير متزايد بين الخدمات لتجنب spike
                delay = min(self._stagger_delay * (i + 1) * 0.5, 5.0)
                await asyncio.sleep(delay)
                
                logger.info(f"   ✅ {name} started")
                
            except asyncio.TimeoutError:
                logger.error(f"   ❌ {name} startup timeout after {component.timeout}s")
                if component.required:
                    raise
                    
            except Exception as e:
                logger.error(f"   ❌ {name} startup failed: {e}")
                if component.required:
                    raise
        
        return True
    
    async def _final_health_check(self) -> bool:
        """فحص الصحة النهائي لجميع المكونات"""
        logger.info("🏥 Running final health check...")
        
        # انتظار استقرار النظام
        await asyncio.sleep(self._health_check_wait)
        
        failed_components = []
        
        for name, component in self._components.items():
            if component.health_check_fn:
                try:
                    healthy = await asyncio.wait_for(
                        component.health_check_fn(),
                        timeout=10.0
                    )
                    if not healthy:
                        failed_components.append(name)
                        logger.warning(f"   ⚠️ {name} is unhealthy")
                    else:
                        logger.debug(f"   ✅ {name} is healthy")
                        
                except asyncio.TimeoutError:
                    failed_components.append(name)
                    logger.warning(f"   ⏰ {name} health check timeout")
                except Exception as e:
                    failed_components.append(name)
                    logger.warning(f"   ❌ {name} health check error: {e}")
        
        if failed_components:
            logger.warning(f"⚠️ {len(failed_components)} components are unhealthy: {failed_components}")
            return False
        
        logger.info("✅ All components healthy")
        return True
    
    async def rollback(self):
        """التراجع عن بدء التشغيل - إيقاف المكونات التي بدأت"""
        self._stats["rollback_triggered"] = True
        
        logger.warning("🔄 Rolling back startup...")
        
        # إيقاف المكونات بترتيب عكسي
        sorted_components = await self._topological_sort()
        
        for name in reversed(sorted_components):
            component = self._components[name]
            
            if component.shutdown_fn and component.startup_fn:  # فقط المكونات التي بدأت
                try:
                    logger.info(f"   Stopping {name}...")
                    await asyncio.wait_for(
                        component.shutdown_fn(),
                        timeout=component.timeout
                    )
                    logger.info(f"   ✅ {name} stopped")
                except Exception as e:
                    logger.error(f"   ⚠️ Error stopping {name}: {e}")
        
        logger.warning("Rollback complete")
    
    async def graceful_shutdown(self, timeout: float = 30.0):
        """
        إيقاف تشغيل آمن
        
        Args:
            timeout: المهلة الإجمالية للإيقاف
        """
        logger.info("🛑 Graceful shutdown initiated...")
        
        start_time = time.time()
        
        # إيقاف حسب الأولوية
        for priority in [ShutdownPriority.FIRST, ShutdownPriority.NORMAL, ShutdownPriority.LAST]:
            for name, component in self._components.items():
                if component.shutdown_priority != priority:
                    continue
                
                if not component.shutdown_fn:
                    continue
                
                remaining_time = timeout - (time.time() - start_time)
                if remaining_time <= 0:
                    logger.warning("Shutdown timeout reached, forcing stop")
                    break
                
                try:
                    logger.info(f"   Stopping {name}...")
                    await asyncio.wait_for(
                        component.shutdown_fn(),
                        timeout=min(component.timeout, remaining_time)
                    )
                    logger.info(f"   ✅ {name} stopped")
                except asyncio.TimeoutError:
                    logger.warning(f"   ⏰ {name} shutdown timeout")
                except Exception as e:
                    logger.error(f"   ⚠️ Error stopping {name}: {e}")
        
        # إيقاف LifecycleManager
        if self._lifecycle_manager:
            await self._lifecycle_manager.stop_all()
        
        elapsed = time.time() - start_time
        logger.info(f"✅ Shutdown complete in {elapsed:.2f}s")
    
    async def _record_step(self, name: str, phase: StartupPhase):
        """تسجيل خطوة في عملية البدء"""
        step = StartupStep(name=name, phase=phase)
        self._startup_steps.append(step)
        logger.info(f"📌 Phase: {phase.value} - {name}")
    
    async def get_status(self) -> Dict:
        """الحصول على حالة بدء التشغيل"""
        return {
            "phase": self._current_phase.value,
            "start_time": self._start_time.isoformat() if self._start_time else None,
            "end_time": self._end_time.isoformat() if self._end_time else None,
            "duration": (self._end_time - self._start_time).total_seconds() if self._end_time else 0,
            "stats": self._stats,
            "steps": [
                {
                    "name": step.name,
                    "phase": step.phase.value,
                    "duration": step.duration,
                    "status": step.status,
                    "error": step.error
                }
                for step in self._startup_steps
            ]
        }
    
    async def is_ready(self) -> bool:
        """هل النظام جاهز؟"""
        return self._current_phase == StartupPhase.READY
    
    async def wait_for_ready(self, timeout: float = 60.0):
        """انتظار وصول النظام إلى حالة الجاهزية"""
        start_time = time.time()
        
        while not await self.is_ready():
            if time.time() - start_time > timeout:
                raise TimeoutError(f"Platform not ready within {timeout}s")
            await asyncio.sleep(0.5)
        
        logger.info("Platform is ready")


# نسخة عالمية
_default_manager = None


async def get_startup_manager() -> StartupManager:
    """الحصول على نسخة عالمية من مدير بدء التشغيل"""
    global _default_manager
    if _default_manager is None:
        _default_manager = StartupManager()
        await _default_manager.initialize()
    return _default_manager


# دالة مساعدة لبدء النظام بسهولة
async def run_platform(
    components: Dict[str, Dict],
    enable_rollback: bool = True,
    stagger_delay: float = 0.5
) -> bool:
    """
    تشغيل المنصة بالكامل
    
    Args:
        components: قاموس المكونات
        enable_rollback: تمكين التراجع عند الفشل
        stagger_delay: التأخير بين بدء المكونات
    
    Example:
        components = {
            "browser_pool": {
                "startup_fn": browser_pool.start,
                "shutdown_fn": browser_pool.stop,
                "dependencies": [],
                "required": True
            },
            "orchestrator": {
                "startup_fn": orchestrator.start,
                "shutdown_fn": orchestrator.stop,
                "dependencies": ["browser_pool"],
                "required": True
            }
        }
        
        success = await run_platform(components)
    """
    manager = await get_startup_manager()
    manager._enable_rollback = enable_rollback
    manager._stagger_delay = stagger_delay
    
    # تسجيل المكونات
    for name, config in components.items():
        manager.register_component(
            name=name,
            startup_fn=config.get("startup_fn"),
            shutdown_fn=config.get("shutdown_fn"),
            dependencies=config.get("dependencies", []),
            shutdown_priority=config.get("shutdown_priority", ShutdownPriority.NORMAL),
            timeout=config.get("timeout", 30.0),
            required=config.get("required", True),
            health_check_fn=config.get("health_check_fn")
        )
    
    # بدء التشغيل
    success = await manager.start()
    
    if success:
        await manager.wait_for_ready()
    
    return success

