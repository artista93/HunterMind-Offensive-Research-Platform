
import asyncio
import signal
import sys
import traceback
from typing import Dict, List, Optional, Any, Callable, Awaitable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from contextlib import asynccontextmanager


class ComponentState(Enum):
    """حالات المكون"""
    CREATED = "created"
    INITIALIZING = "initializing"
    INITIALIZED = "initialized"
    STARTING = "starting"
    RUNNING = "running"
    STOPPING = "stopping"
    STOPPED = "stopped"
    ERROR = "error"
    DESTROYED = "destroyed"


class ComponentPriority(Enum):
    """أولوية المكون (للإيقاف والبدء)"""
    CRITICAL = 1      # لا يمكن تشغيل النظام بدونه
    HIGH = 2          # مهم جداً
    NORMAL = 3        # عادي
    LOW = 4           # منخفض
    BACKGROUND = 5    # خدمة خلفية


@dataclass
class Component:
    """تعريف مكون في النظام"""
    name: str
    instance: Any
    state: ComponentState = ComponentState.CREATED
    priority: ComponentPriority = ComponentPriority.NORMAL
    dependencies: List[str] = field(default_factory=list)
    start_time: Optional[datetime] = None
    stop_time: Optional[datetime] = None
    error: Optional[str] = None
    
    # إعادة التشغيل
    restart_count: int = 0
    last_restart_attempt: Optional[datetime] = None
    circuit_breaker_open: bool = False
    circuit_breaker_open_until: Optional[datetime] = None
    
    # دوال دورة الحياة
    on_init: Optional[Callable[[], Awaitable[None]]] = None
    on_start: Optional[Callable[[], Awaitable[None]]] = None
    on_stop: Optional[Callable[[], Awaitable[None]]] = None
    on_destroy: Optional[Callable[[], Awaitable[None]]] = None
    health_check: Optional[Callable[[], Awaitable[bool]]] = None


class LifecycleManager:
    """
    مدير دورة حياة المكونات
    
    المسؤوليات:
    - تسجيل وإدارة جميع المكونات
    - بدء المكونات حسب الأولوية والتبعيات (مع كشف الدورات)
    - إيقاف المكونات بأمان
    - مراقبة صحة المكونات (بشكل متوازي)
    - التعافي من الأعطال (مع backoff وقاطع دائرة)
    """
    
    def __init__(self):
        self._components: Dict[str, Component] = {}
        self._lock = asyncio.Lock()
        self._running = False
        self._health_check_task: Optional[asyncio.Task] = None
        self._shutdown_event = asyncio.Event()
        self._shutdown_complete = asyncio.Event()
        
        # إحصائيات
        self._stats = {
            "total_components": 0,
            "start_count": 0,
            "stop_count": 0,
            "error_count": 0,
            "last_startup": None,
            "last_shutdown": None
        }
        
        # إعدادات إعادة التشغيل
        self._max_restart_attempts = 5
        self._restart_backoff_ms = [1000, 2000, 4000, 8000, 16000]  # 1s, 2s, 4s, 8s, 16s
        self._circuit_breaker_timeout = 60  # 60 seconds
        
        # تسجيل إشارات النظام
        self._setup_signal_handlers()
    
    def _setup_signal_handlers(self):
        """إعداد معالجات الإشارات للإيقاف الآمن"""
        try:
            loop = asyncio.get_running_loop()
            for sig in [signal.SIGTERM, signal.SIGINT]:
                loop.add_signal_handler(sig, lambda: asyncio.create_task(self.shutdown()))
        except (RuntimeError, NotImplementedError):
            # لا يوجد حلقة تشغيل أو Windows
            pass
    
    def register_component(
        self,
        name: str,
        instance: Any,
        priority: ComponentPriority = ComponentPriority.NORMAL,
        dependencies: List[str] = None,
        on_init: Optional[Callable[[], Awaitable[None]]] = None,
        on_start: Optional[Callable[[], Awaitable[None]]] = None,
        on_stop: Optional[Callable[[], Awaitable[None]]] = None,
        on_destroy: Optional[Callable[[], Awaitable[None]]] = None,
        health_check: Optional[Callable[[], Awaitable[bool]]] = None
    ) -> None:
        """تسجيل مكون في النظام"""
        if name in self._components:
            raise ValueError(f"Component {name} already registered")
        
        component = Component(
            name=name,
            instance=instance,
            priority=priority,
            dependencies=dependencies or [],
            on_init=on_init,
            on_start=on_start,
            on_stop=on_stop,
            on_destroy=on_destroy,
            health_check=health_check
        )
        
        self._components[name] = component
        self._stats["total_components"] += 1
        print(f"   📦 Registered component: {name} (priority={priority.name})")
    
    async def _validate_dependencies_advanced(self) -> tuple[bool, List[str]]:
        """
        التحقق المتقدم من التبعيات
        
        Returns:
            (is_valid, errors)
        """
        component_names = set(self._components.keys())
        errors = []
        
        # 1. التحقق من وجود التبعيات
        for name, component in self._components.items():
            for dep in component.dependencies:
                if dep not in component_names:
                    errors.append(f"Component '{name}' depends on unknown component: '{dep}'")
        
        if errors:
            return False, errors
        
        # 2. كشف الدورات (cycles) في التبعيات
        visited = set()
        recursion_stack = set()
        
        def has_cycle(node: str, path: List[str]) -> tuple[bool, List[str]]:
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
        
        for name in component_names:
            cycle_found, cycle_path = has_cycle(name, [])
            if cycle_found:
                errors.append(f"Dependency cycle detected: {' -> '.join(cycle_path)}")
        
        return len(errors) == 0, errors
    
    async def _topological_sort(self) -> List[str]:
        """
        ترتيب المكونات طوبولوجياً حسب التبعيات
        
        Returns:
            قائمة بأسماء المكونات مرتبة (الأقل اعتماداً أولاً)
        """
        from collections import deque
        
        # حساب عدد التبعيات لكل مكون
        in_degree = {name: 0 for name in self._components}
        graph = {name: [] for name in self._components}
        
        for name, component in self._components.items():
            for dep in component.dependencies:
                if dep in graph:
                    graph[dep].append(name)
                    in_degree[name] += 1
        
        # قائمة انتظار للمكونات بدون تبعيات
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
    
    async def initialize_all(self) -> bool:
        """تهيئة جميع المكونات"""
        print(f"\n🔄 Initializing {len(self._components)} components...")
        
        # التحقق من التبعيات والدورات
        valid, errors = await self._validate_dependencies_advanced()
        if not valid:
            for error in errors:
                print(f"   ❌ {error}")
            return False
        
        # الحصول على الترتيب الصحيح
        sorted_components = await self._topological_sort()
        
        success = True
        for name in sorted_components:
            component = self._components[name]
            if component.state != ComponentState.CREATED:
                continue
            
            try:
                component.state = ComponentState.INITIALIZING
                print(f"   🔧 Initializing {name}...")
                
                if component.on_init:
                    await component.on_init()
                
                component.state = ComponentState.INITIALIZED
                print(f"   ✅ {name} initialized")
                
            except Exception as e:
                component.state = ComponentState.ERROR
                component.error = str(e)
                print(f"   ❌ Failed to initialize {name}: {e}")
                traceback.print_exc()
                success = False
        
        return success
    
    async def start_all(self) -> bool:
        """بدء جميع المكونات"""
        print(f"\n🚀 Starting {len(self._components)} components...")
        
        # الحصول على الترتيب الصحيح
        sorted_components = await self._topological_sort()
        
        success = True
        for name in sorted_components:
            component = self._components[name]
            if component.state not in [ComponentState.INITIALIZED, ComponentState.STOPPED]:
                continue
            
            try:
                component.state = ComponentState.STARTING
                print(f"   ▶️ Starting {name}...")
                
                if component.on_start:
                    await component.on_start()
                
                component.state = ComponentState.RUNNING
                component.start_time = datetime.now()
                component.error = None
                component.restart_count = 0
                component.circuit_breaker_open = False
                print(f"   ✅ {name} started")
                
            except Exception as e:
                component.state = ComponentState.ERROR
                component.error = str(e)
                print(f"   ❌ Failed to start {name}: {e}")
                traceback.print_exc()
                success = False
        
        if success:
            self._running = True
            self._stats["last_startup"] = datetime.now()
            self._stats["start_count"] += 1
            
            # بدء مراقبة الصحة
            await self._start_health_monitoring()
        
        return success
    
    async def stop_all(self, graceful: bool = True) -> bool:
        """
        إيقاف جميع المكونات
        
        Args:
            graceful: إيقاف آمن مع انتظار المهام
        """
        print(f"\n🛑 Stopping all components (graceful={graceful})...")
        
        # إيقاف مراقبة الصحة
        if self._health_check_task:
            self._health_check_task.cancel()
            try:
                await self._health_check_task
            except asyncio.CancelledError:
                pass
        
        # إيقاف بالترتيب العكسي
        sorted_components = await self._topological_sort()
        
        success = True
        for name in reversed(sorted_components):
            component = self._components[name]
            if component.state != ComponentState.RUNNING:
                continue
            
            try:
                component.state = ComponentState.STOPPING
                print(f"   ⏹️ Stopping {name}...")
                
                if component.on_stop:
                    await asyncio.wait_for(
                        component.on_stop(),
                        timeout=30.0
                    )
                
                component.state = ComponentState.STOPPED
                component.stop_time = datetime.now()
                print(f"   ✅ {name} stopped")
                
            except asyncio.TimeoutError:
                component.state = ComponentState.ERROR
                component.error = "Stop timeout (30s)"
                print(f"   ⏰ Timeout stopping {name}")
                success = False
            except Exception as e:
                component.state = ComponentState.ERROR
                component.error = str(e)
                print(f"   ⚠️ Error stopping {name}: {e}")
                success = False
        
        self._running = False
        self._stats["last_shutdown"] = datetime.now()
        self._stats["stop_count"] += 1
        
        return success
    
    async def destroy_all(self) -> bool:
        """تدمير جميع المكونات (تنظيف كامل)"""
        print(f"\n💀 Destroying all components...")
        
        # إيقاف أولاً
        await self.stop_all()
        
        sorted_components = await self._topological_sort()
        
        success = True
        for name in reversed(sorted_components):
            component = self._components[name]
            try:
                print(f"   🗑️ Destroying {name}...")
                
                if component.on_destroy:
                    await asyncio.wait_for(
                        component.on_destroy(),
                        timeout=10.0
                    )
                
                component.state = ComponentState.DESTROYED
                
            except Exception as e:
                print(f"   ⚠️ Error destroying {name}: {e}")
                success = False
        
        self._components.clear()
        return success
    
    async def _start_health_monitoring(self, interval: float = 30.0):
        """بدء مراقبة صحة المكونات (بشكل متوازي)"""
        async def health_check_loop():
            while self._running:
                await asyncio.sleep(interval)
                await self._check_component_health_parallel()
        
        self._health_check_task = asyncio.create_task(health_check_loop())
        print(f"   💚 Health monitoring started (interval={interval}s, parallel=true)")
    
    async def _check_component_health_parallel(self):
        """فحص صحة المكونات بشكل متوازي"""
        health_checks = []
        components_to_check = []
        
        for name, component in self._components.items():
            if component.state != ComponentState.RUNNING:
                continue
            if component.health_check:
                health_checks.append(component.health_check())
                components_to_check.append(name)
        
        if not health_checks:
            return
        
        # تنفيذ جميع فحوصات الصحة بشكل متوازي
        results = await asyncio.gather(*health_checks, return_exceptions=True)
        
        for name, result in zip(components_to_check, results):
            if isinstance(result, Exception):
                print(f"   ❌ Health check failed for {name}: {result}")
                self._stats["error_count"] += 1
                await self._restart_component_with_backoff(name)
            elif not result:
                print(f"   ⚠️ Component {name} is unhealthy!")
                self._stats["error_count"] += 1
                await self._restart_component_with_backoff(name)
    
    async def _restart_component_with_backoff(self, name: str) -> bool:
        """إعادة تشغيل مكون مع backoff وقاطع دائرة"""
        if name not in self._components:
            return False
        
        component = self._components[name]
        
        # التحقق من قاطع الدائرة
        if component.circuit_breaker_open:
            if datetime.now() < component.circuit_breaker_open_until:
                print(f"   🔌 Circuit breaker open for {name}, skipping restart")
                return False
            else:
                component.circuit_breaker_open = False
        
        # التحقق من عدد محاولات إعادة التشغيل
        if component.restart_count >= self._max_restart_attempts:
            print(f"   ❌ Component {name} exceeded max restart attempts ({self._max_restart_attempts})")
            return False
        
        # حساب وقت الانتظار (exponential backoff)
        backoff_ms = self._restart_backoff_ms[min(component.restart_count, len(self._restart_backoff_ms) - 1)]
        backoff_seconds = backoff_ms / 1000.0
        
        component.last_restart_attempt = datetime.now()
        component.restart_count += 1
        
        print(f"   🔄 Restarting {name} (attempt {component.restart_count}, backoff={backoff_seconds}s)...")
        
        # انتظار backoff
        await asyncio.sleep(backoff_seconds)
        
        # محاولة إعادة التشغيل
        try:
            # إيقاف
            if component.on_stop:
                await asyncio.wait_for(component.on_stop(), timeout=10.0)
            
            # إعادة تهيئة
            if component.on_init:
                await asyncio.wait_for(component.on_init(), timeout=30.0)
            
            # بدء
            if component.on_start:
                await asyncio.wait_for(component.on_start(), timeout=30.0)
            
            component.state = ComponentState.RUNNING
            component.error = None
            print(f"   ✅ {name} restarted successfully")
            return True
            
        except asyncio.TimeoutError:
            component.state = ComponentState.ERROR
            component.error = "Restart timeout"
            print(f"   ⏰ Timeout restarting {name}")
            
            # فتح قاطع الدائرة
            component.circuit_breaker_open = True
            component.circuit_breaker_open_until = datetime.now() + timedelta(seconds=self._circuit_breaker_timeout)
            
        except Exception as e:
            component.state = ComponentState.ERROR
            component.error = str(e)
            print(f"   ❌ Failed to restart {name}: {e}")
        
        return False
    
    async def get_component(self, name: str) -> Optional[Any]:
        """الحصول على كائن المكون (تم إصلاح اسم الدالة)"""
        if name in self._components:
            return self._components[name].instance
        return None
    
    async def get_component_state(self, name: str) -> Optional[ComponentState]:
        """الحصول على حالة مكون"""
        if name in self._components:
            return self._components[name].state
        return None
    
    async def get_all_components(self) -> Dict[str, Dict]:
        """الحصول على جميع المكونات مع معلوماتها"""
        return {
            name: {
                "state": comp.state.value,
                "priority": comp.priority.name,
                "dependencies": comp.dependencies,
                "start_time": comp.start_time.isoformat() if comp.start_time else None,
                "stop_time": comp.stop_time.isoformat() if comp.stop_time else None,
                "error": comp.error,
                "has_health_check": comp.health_check is not None,
                "restart_count": comp.restart_count,
                "circuit_breaker_open": comp.circuit_breaker_open
            }
            for name, comp in self._components.items()
        }
    
    async def shutdown(self):
        """إيقاف تشغيل النظام بالكامل (بدون sys.exit)"""
        if not self._running:
            return
        
        print("\n🛑 Shutting down HunterMind Platform...")
        self._shutdown_event.set()
        
        # إيقاف المكونات
        await self.stop_all()
        
        # تنظيف الموارد
        await self.destroy_all()
        
        # إشعار باكتمال الإيقاف
        self._shutdown_complete.set()
        print("👋 Shutdown complete")
    
    async def wait_for_shutdown(self):
        """انتظار اكتمال الإيقاف"""
        await self._shutdown_complete.wait()
    
    @asynccontextmanager
    async def lifecycle_context(self):
        """سياق لإدارة دورة الحياة تلقائياً"""
        try:
            await self.initialize_all()
            await self.start_all()
            yield self
        finally:
            await self.shutdown()
    
    def is_running(self) -> bool:
        """هل النظام قيد التشغيل؟"""
        return self._running
    
    def get_stats(self) -> Dict:
        """إحصائيات مدير دورة الحياة"""
        running_components = sum(
            1 for c in self._components.values()
            if c.state == ComponentState.RUNNING
        )
        
        return {
            **self._stats,
            "running": self._running,
            "running_components": running_components,
            "total_components": len(self._components),
            "components_by_state": {
                state.value: sum(1 for c in self._components.values() if c.state == state)
                for state in ComponentState
            }
        }


# نسخة عالمية
_default_lifecycle_manager = None


def get_lifecycle_manager() -> LifecycleManager:
    """الحصول على نسخة عالمية من مدير دورة الحياة"""
    global _default_lifecycle_manager
    if _default_lifecycle_manager is None:
        _default_lifecycle_manager = LifecycleManager()
    return _default_lifecycle_manager


# دالة مساعدة لبدء النظام
async def run_platform(components: Dict[str, Any]):
    """تشغيل المنصة مع مجموعة من المكونات"""
    manager = get_lifecycle_manager()
    
    # تسجيل المكونات
    for name, component_info in components.items():
        manager.register_component(
            name=name,
            instance=component_info.get("instance"),
            priority=component_info.get("priority", ComponentPriority.NORMAL),
            dependencies=component_info.get("dependencies", []),
            on_init=component_info.get("on_init"),
            on_start=component_info.get("on_start"),
            on_stop=component_info.get("on_stop"),
            health_check=component_info.get("health_check")
        )
    
    # تشغيل النظام
    async with manager.lifecycle_context():
        print("\n✅ HunterMind Platform is running!")
        print("   Press Ctrl+C to stop\n")
        
        # انتظار إشارة الإيقاف
        try:
            await asyncio.Event().wait()
        except KeyboardInterrupt:
            pass

