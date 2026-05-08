
import asyncio
import inspect
import uuid
from contextlib import asynccontextmanager
from typing import Dict, List, Optional, Any, Type, TypeVar, Callable, Awaitable, Union
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime


class Scope(Enum):
    """نطاق عمر التبعية"""
    SINGLETON = "singleton"    # نسخة واحدة طوال عمر النظام
    SCOPED = "scoped"          # نسخة لكل نطاق (مثل طلب)
    TRANSIENT = "transient"    # نسخة جديدة في كل مرة


class RegistrationType(Enum):
    """نوع التسجيل"""
    INSTANCE = "instance"      # كائن جاهز
    FACTORY = "factory"        # دالة مصنع
    CLASS = "class"            # كلاس يتم إنشاؤه


@dataclass
class DependencyRegistration:
    """تسجيل تبعية"""
    name: str
    type: RegistrationType
    scope: Scope
    implementation: Any  # instance, factory function, or class
    dependencies: List[str] = field(default_factory=list)
    lazy: bool = False
    initialized: bool = False
    instance: Any = None
    created_at: Optional[datetime] = None
    
    # دورة الحياة
    on_create: Optional[Callable[[Any], Awaitable[None]]] = None
    on_destroy: Optional[Callable[[Any], Awaitable[None]]] = None


class DependencyContainer:
    """
    حاوية التبعيات - Inversion of Control Container
    
    الميزات:
    - حقن التبعيات التلقائي
    - دورات حياة (Singleton, Scoped, Transient)
    - تحميل كسول (Lazy Loading)
    - Factory functions
    - دوال إنشاء وتدمير غير متزامنة
    - كشف الدورات (Cycle Detection)
    - تجمعات النطاقات (Scopes)
    """
    
    def __init__(self):
        self._registrations: Dict[str, DependencyRegistration] = {}
        self._singletons: Dict[str, Any] = {}
        self._scoped_instances: Dict[str, Dict[str, Any]] = {}  # scope_id -> {name -> instance}
        self._current_scope: Optional[str] = None
        self._lock = asyncio.Lock()  # فقط لتعديل البيانات المشتركة
        self._initialized = False
        
        # إحصائيات
        self._stats = {
            "total_registrations": 0,
            "singleton_instances": 0,
            "transient_instances": 0,
            "resolutions": 0,
            "resolution_errors": 0
        }
        
        # تسجيل self كخدمة
        self.register_instance("container", self, scope=Scope.SINGLETON)
    
    def register_instance(
        self,
        name: str,
        instance: Any,
        scope: Scope = Scope.SINGLETON,
        dependencies: List[str] = None,
        lazy: bool = False
    ) -> None:
        """
        تسجيل كائن جاهز
        
        Args:
            name: اسم الخدمة
            instance: الكائن
            scope: النطاق
            dependencies: قائمة التبعيات
            lazy: تحميل كسول
        """
        registration = DependencyRegistration(
            name=name,
            type=RegistrationType.INSTANCE,
            scope=scope,
            implementation=instance,
            dependencies=dependencies or [],
            lazy=lazy,
            initialized=True,
            instance=instance,
            created_at=datetime.now()
        )
        
        self._registrations[name] = registration
        self._stats["total_registrations"] += 1
        
        if scope == Scope.SINGLETON:
            self._singletons[name] = instance
            self._stats["singleton_instances"] += 1
        
        print(f"   📦 Registered instance: {name} (scope={scope.value})")
    
    def register_factory(
        self,
        name: str,
        factory: Callable[..., Awaitable[Any]],
        scope: Scope = Scope.SINGLETON,
        dependencies: List[str] = None,
        lazy: bool = True
    ) -> None:
        """
        تسجيل دالة مصنع (async)
        
        Args:
            name: اسم الخدمة
            factory: دالة مصنع غير متزامنة
            scope: النطاق
            dependencies: قائمة التبعيات
            lazy: تحميل كسول
        """
        registration = DependencyRegistration(
            name=name,
            type=RegistrationType.FACTORY,
            scope=scope,
           implementation=factory,
            dependencies=dependencies or [],
            lazy=lazy
        )
        
        self._registrations[name] = registration
        self._stats["total_registrations"] += 1
        
        print(f"   🏭 Registered factory: {name} (scope={scope.value})")
    
    def register_class(
        self,
        name: str,
        cls: Type,
        scope: Scope = Scope.TRANSIENT,
        dependencies: List[str] = None,
        lazy: bool = True
    ) -> None:
        """
        تسجيل كلاس (يتم إنشاؤه عند الطلب)
        
        Args:
            name: اسم الخدمة
            cls: الكلاس
            scope: النطاق
            dependencies: قائمة التبعيات
            lazy: تحميل كسول
        """
        registration = DependencyRegistration(
            name=name,
            type=RegistrationType.CLASS,
            scope=scope,
            implementation=cls,
            dependencies=dependencies or [],
            lazy=lazy
        )
        
        self._registrations[name] = registration
        self._stats["total_registrations"] += 1
        
        print(f"   📋 Registered class: {name} (scope={scope.value})")
    
    def register_lazy(
        self,
        name: str,
        provider: Callable[[], Awaitable[Any]],
        dependencies: List[str] = None
    ) -> None:
        """
        تسجيل مزود كسول (يتم استدعاؤه مرة واحدة عند أول طلب)
        
        Args:
            name: اسم الخدمة
            provider: دالة مزود غير متزامنة
            dependencies: قائمة التبعيات
        """
        self.register_factory(name, provider, scope=Scope.SINGLETON, dependencies=dependencies, lazy=True)
    
    async def _get_cached(
        self,
        name: str,
        scope_id: Optional[str] = None
    ) -> Optional[Any]:
        """الحصول على مثيل مخزن (بدون lock للاستخدام الداخلي)"""
        registration = self._registrations[name]
        
        # Singleton
        if registration.scope == Scope.SINGLETON:
            return self._singletons.get(name)
        
        # Scoped
        if registration.scope == Scope.SCOPED and scope_id:
            if scope_id in self._scoped_instances:
                return self._scoped_instances[scope_id].get(name)
        
        # Transient لا يخزن
        return None
    
    async def _cache_instance(
        self,
        name: str,
        instance: Any,
        scope_id: Optional[str] = None
    ) -> None:
        """تخزين مثيل (مع lock)"""
        async with self._lock:
            registration = self._registrations[name]
            
            if registration.scope == Scope.SINGLETON:
                self._singletons[name] = instance
                self._stats["singleton_instances"] += 1
            elif registration.scope == Scope.SCOPED and scope_id:
                if scope_id not in self._scoped_instances:
                    self._scoped_instances[scope_id] = {}
                self._scoped_instances[scope_id][name] = instance
    
    async def resolve(
        self,
        name: str,
        scope_id: Optional[str] = None,
        force_new: bool = False,
        _resolution_path: Optional[List[str]] = None
    ) -> Optional[Any]:
        """
        حل تبعية والحصول على المثيل
        
        Args:
            name: اسم الخدمة
            scope_id: معرف النطاق (لـ SCOPED)
            force_new: إجبار إنشاء مثيل جديد
            _resolution_path: مسار الحل الحالي (للكشف عن الدورات)
        
        Returns:
            المثيل المطلوب
        """
        # تهيئة مسار التبعيات للكشف عن الدورات
        if _resolution_path is None:
            _resolution_path = []
        
        # كشف الدورات (Cycle Detection)
        if name in _resolution_path:
            cycle = " -> ".join(_resolution_path + [name])
            self._stats["resolution_errors"] += 1
            raise RuntimeError(f"Circular dependency detected: {cycle}")
        
        self._stats["resolutions"] += 1
        
        if name not in self._registrations:
            self._stats["resolution_errors"] += 1
            raise KeyError(f"Service '{name}' not registered")
        
        registration = self._registrations[name]
        
        # التحقق من الكائنات الجاهزة
        if registration.type == RegistrationType.INSTANCE:
            return registration.instance
        
        # التحقق من الكائنات المخزنة (بدون lock للقراءة فقط)
        if not force_new:
            cached = await self._get_cached(name, scope_id)
            if cached is not None:
                return cached
        
        # إنشاء مثيل جديد (خارج الـ lock لتجنب deadlock)
        instance = await self._build_instance(
            registration,
            scope_id,
            _resolution_path + [name]
        )
        
        # تخزين المثيل (مع lock)
        if not force_new:
            await self._cache_instance(name, instance, scope_id)
        
        registration.instance = instance
        registration.initialized = True
        
        return instance
    
    async def _build_instance(
        self,
        registration: DependencyRegistration,
        scope_id: Optional[str] = None,
        resolution_path: Optional[List[str]] = None
    ) -> Any:
        """إنشاء مثيل جديد من التسجيل (بدون lock)"""
        
        # حل التبعيات أولاً (هنا قد تحدث استدعاءات resolve متداخلة)
        dependencies = {}
        for dep_name in registration.dependencies:
            dep = await self.resolve(
                dep_name,
                scope_id,
                _resolution_path=resolution_path
            )
            dependencies[dep_name] = dep
        
        try:
            if registration.type == RegistrationType.FACTORY:
                # دالة مصنع
                factory = registration.implementation
                
                # تحقق من توقيع الدالة لحقن التبعيات تلقائياً
                sig = inspect.signature(factory)
                kwargs = {}
                
                for param_name, param in sig.parameters.items():
                    if param_name in dependencies:
                        kwargs[param_name] = dependencies[param_name]
                    elif param.default == inspect.Parameter.empty:
                        # معلمة مطلوبة بدون تبعية - نمرر None
                        kwargs[param_name] = None
                
                instance = await factory(**kwargs)
                
            elif registration.type == RegistrationType.CLASS:
                # كلاس - إنشاء مثيل جديد
                cls = registration.implementation
                
                # حقن التبعيات في الـ __init__
                init_sig = inspect.signature(cls.__init__)
                kwargs = {}
                
                for param_name, param in init_sig.parameters.items():
                    if param_name == 'self':
                        continue
                    if param_name in dependencies:
                        kwargs[param_name] = dependencies[param_name]
                
                instance = cls(**kwargs)
                
            else:
                raise ValueError(f"Unknown registration type: {registration.type}")
            
            # استدعاء دالة onCreate إذا وجدت
            if registration.on_create:
                await registration.on_create(instance)
            
            return instance
            
        except Exception as e:
            self._stats["resolution_errors"] += 1
            raise RuntimeError(f"Failed to create instance of '{registration.name}': {e}") from e
    
    async def resolve_all(
        self,
        names: List[str],
        scope_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """حل مجموعة من التبعيات بشكل متوازي"""
        tasks = [self.resolve(name, scope_id) for name in names]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        resolved = {}
        for name, result in zip(names, results):
            if isinstance(result, Exception):
                raise result
            resolved[name] = result
        
        return resolved
    
    async def resolve_with_params(
        self,
        name: str,
        extra_params: Dict[str, Any] = None,
        scope_id: Optional[str] = None
    ) -> Optional[Any]:
        """
        حل تبعية مع معاملات إضافية
        
        Args:
            name: اسم الخدمة
            extra_params: معاملات إضافية لتجاوز التبعيات
            scope_id: معرف النطاق
        """
        if name not in self._registrations:
            raise KeyError(f"Service '{name}' not registered")
        
        registration = self._registrations[name]
        
        # لا تخزين للمعاملات الإضافية (تنشأ جديد كل مرة)
        if registration.scope == Scope.SINGLETON and not extra_params:
            cached = await self._get_cached(name, scope_id)
            if cached is not None:
                return cached
        
        # حل التبعيات مع تجاوز المعاملات الإضافية
        dependencies = {}
        for dep_name in registration.dependencies:
            if extra_params and dep_name in extra_params:
                dependencies[dep_name] = extra_params[dep_name]
            else:
                dep = await self.resolve(dep_name, scope_id)
                dependencies[dep_name] = dep
        
        # إنشاء المثيل
        instance = await self._build_instance(registration, dependencies)
        
        # تخزين فقط إذا كان Singleton ولا توجد معاملات إضافية
        if registration.scope == Scope.SINGLETON and not extra_params:
            await self._cache_instance(name, instance, scope_id)
        
        return instance
    
    async def _build_instance_with_params(
        self,
        registration: DependencyRegistration,
        dependencies: Dict[str, Any]
    ) -> Any:
        """إنشاء مثيل مع تبعيات محددة مسبقاً"""
        
        if registration.type == RegistrationType.FACTORY:
            factory = registration.implementation
            sig = inspect.signature(factory)
            kwargs = {}
            
            for param_name, param in sig.parameters.items():
                if param_name in dependencies:
                    kwargs[param_name] = dependencies[param_name]
            
            return await factory(**kwargs)
            
        elif registration.type == RegistrationType.CLASS:
            cls = registration.implementation
            init_sig = inspect.signature(cls.__init__)
            kwargs = {}
            
            for param_name, param in init_sig.parameters.items():
                if param_name == 'self':
                    continue
                if param_name in dependencies:
                    kwargs[param_name] = dependencies[param_name]
            
            return cls(**kwargs)
        
        return registration.implementation
    
    def create_scope(self) -> str:
        """إنشاء نطاق جديد (للـ Scoped services)"""
        scope_id = str(uuid.uuid4())
        self._scoped_instances[scope_id] = {}
        print(f"   🔬 Created scope: {scope_id[:8]}...")
        return scope_id
    
    async def dispose_scope(self, scope_id: str) -> None:
        """
        تدمير نطاق وتنظيف جميع خدماته
        
        Calls on_destroy for all services in the scope
        """
        if scope_id not in self._scoped_instances:
            return
        
        scope_instances = self._scoped_instances[scope_id]
        
        # استدعاء on_destroy لكل خدمة
        for name, instance in scope_instances.items():
            registration = self._registrations.get(name)
            if registration and registration.on_destroy:
                try:
                    await registration.on_destroy(instance)
                except Exception as e:
                    print(f"   ⚠️ Error destroying {name} in scope: {e}")
        
        # حذف النطاق
        del self._scoped_instances[scope_id]
        print(f"   🗑️ Disposed scope: {scope_id[:8]}...")
    
    @asynccontextmanager
    async def scope_context(self):
        """سياق للنطاق - يتم التدمير تلقائياً عند الخروج"""
        scope_id = self.create_scope()
        old_scope = self._current_scope
        self._current_scope = scope_id
        
        try:
            yield scope_id
        finally:
            await self.dispose_scope(scope_id)
            self._current_scope = old_scope
    
    def register_on_create(
        self,
        name: str,
        callback: Callable[[Any], Awaitable[None]]
    ) -> None:
        """تسجيل دالة يتم استدعاؤها بعد إنشاء الخدمة"""
        if name not in self._registrations:
            raise KeyError(f"Service '{name}' not registered")
        
        self._registrations[name].on_create = callback
    
    def register_on_destroy(
        self,
        name: str,
        callback: Callable[[Any], Awaitable[None]]
    ) -> None:
        """تسجيل دالة يتم استدعاؤها قبل تدمير الخدمة"""
        if name not in self._registrations:
            raise KeyError(f"Service '{name}' not registered")
        
        self._registrations[name].on_destroy = callback
    
    async def has_service(self, name: str) -> bool:
        """التحقق من وجود خدمة"""
        return name in self._registrations
    
    async def get_service_info(self, name: str) -> Optional[Dict]:
        """الحصول على معلومات عن خدمة"""
        if name not in self._registrations:
            return None
        
        reg = self._registrations[name]
        return {
            "name": reg.name,
            "type": reg.type.value,
            "scope": reg.scope.value,
            "dependencies": reg.dependencies,
            "lazy": reg.lazy,
            "initialized": reg.initialized,
            "created_at": reg.created_at.isoformat() if reg.created_at else None
        }
    
    async def list_services(self) -> List[str]:
        """قائمة جميع الخدمات المسجلة"""
        return list(self._registrations.keys())
    
    async def get_stats(self) -> Dict:
        """إحصائيات الحاوية"""
        return {
            **self._stats,
            "registered_services": len(self._registrations),
            "active_scopes": len(self._scoped_instances),
            "current_scope": self._current_scope,
            "singletons_cached": len(self._singletons)
        }
    
    async def reset(self) -> None:
        """إعادة تعيين الحاوية (للاستخدام في الاختبارات)"""
        # استدعاء on_destroy لكل service (بدون lock)
        for name, registration in self._registrations.items():
            if registration.on_destroy and registration.instance:
                try:
                    await registration.on_destroy(registration.instance)
                except Exception:
                    pass
        
        # تنظيف البيانات (مع lock)
        async with self._lock:
            self._registrations.clear()
            self._singletons.clear()
            self._scoped_instances.clear()
            self._current_scope = None
            self._stats = {
                "total_registrations": 0,
                "singleton_instances": 0,
                "transient_instances": 0,
                "resolutions": 0,
                "resolution_errors": 0
            }
        
        # إعادة تسجيل self
        self.register_instance("container", self, scope=Scope.SINGLETON)
        
        print("   🔄 Dependency container reset")


# نسخة عالمية
_default_container = None


def get_dependency_container() -> DependencyContainer:
    """الحصول على نسخة عالمية من حاوية التبعيات"""
    global _default_container
    if _default_container is None:
        _default_container = DependencyContainer()
    return _default_container


# ديكوراتور لحقن التبعيات التلقائي
def inject(*service_names: str):
    """
    ديكوراتور لحقن التبعيات في دوال غير متزامنة
    
    Example:
        @inject("browser_pool", "auth_manager")
        async def my_function(browser_pool, auth_manager):
            # تم حقن التبعيات تلقائياً
            pass
    """
    def decorator(func: Callable[..., Awaitable[Any]]) -> Callable[..., Awaitable[Any]]:
        async def wrapper(*args, **kwargs):
            container = get_dependency_container()
            
            # حل التبعيات
            services = {}
            for service_name in service_names:
                services[service_name] = await container.resolve(service_name)
            
            # دمج مع المعاملات الموجودة
            all_kwargs = {**services, **kwargs}
            
            return await func(*args, **all_kwargs)
        
        return wrapper
    
    return decorator

