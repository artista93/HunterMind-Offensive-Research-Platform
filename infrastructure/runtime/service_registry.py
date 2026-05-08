
import asyncio
import uuid
import json
import os
from typing import Dict, List, Optional, Any, Callable, Awaitable, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from contextlib import asynccontextmanager
import logging

from .dependency_container import get_dependency_container, Scope

logger = logging.getLogger(__name__)


class ServiceStatus(Enum):
    """حالة الخدمة"""
    DOWN = "down"
    STARTING = "starting"
    RUNNING = "running"
    STOPPING = "stopping"
    DEGRADED = "degraded"
    UNKNOWN = "unknown"


class ServiceHealth(Enum):
    """صحة الخدمة"""
    HEALTHY = "healthy"
    UNHEALTHY = "unhealthy"
    DEGRADED = "degraded"
    UNKNOWN = "unknown"


@dataclass
class ServiceEndpoint:
    """نقطة نهاية الخدمة"""
    host: str
    port: int
    protocol: str = "http"
    path: str = ""
    
    @property
    def url(self) -> str:
        """بناء URL كامل"""
        base = f"{self.protocol}://{self.host}:{self.port}"
        if self.path:
            return f"{base}/{self.path.lstrip('/')}"
        return base


@dataclass
class ServiceInstance:
    """مثيل خدمة"""
    service_id: str
    service_name: str
    instance_id: str
    endpoint: ServiceEndpoint
    status: ServiceStatus = ServiceStatus.UNKNOWN
    health: ServiceHealth = ServiceHealth.UNKNOWN
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    # إحصائيات
    registered_at: datetime = field(default_factory=datetime.now)
    last_heartbeat: datetime = field(default_factory=datetime.now)
    last_health_check: Optional[datetime] = None
    
    # مقاييس
    uptime: float = 0.0
    request_count: int = 0
    error_count: int = 0
    avg_response_time: float = 0.0
    active_connections: int = 0
    
    # Generation counter لمنع stale instances
    generation: int = 0
    
    # دالة فحص الصحة
    health_check_fn: Optional[Callable[[], Awaitable[bool]]] = None


@dataclass
class ServiceRegistration:
    """تسجيل خدمة"""
    name: str
    version: str
    description: str = ""
    tags: List[str] = field(default_factory=list)
    dependencies: List[str] = field(default_factory=list)
    
    # إعدادات
    health_check_interval: int = 30
    heartbeat_interval: int = 10
    timeout: int = 5
    max_instances: int = 0
    
    # تخزين
    endpoints: Dict[str, ServiceEndpoint] = field(default_factory=dict)
    instances: Dict[str, ServiceInstance] = field(default_factory=dict)
    
    # قفل خاص بالخدمة (per-service lock)
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    
    # إحصائيات
    total_requests: int = 0
    total_errors: int = 0


class ServiceRegistry:
    """
    سجل الخدمات المركزي - نسخة نهائية آمنة
    
    التصميم:
    - Per-service locks لتجنب الـ contention
    - Heartbeat حقيقي مع generation counter
    - فحص صحة خارج القفل
    - Connection scope للتسريب الآمن
    - Event bus مع semaphore
    """
    
    def __init__(self, max_concurrent_events: int = 100):
        self._registrations: Dict[str, ServiceRegistration] = {}
        self._service_by_name: Dict[str, str] = {}
        self._health_check_tasks: Dict[str, asyncio.Task] = {}
        self._global_lock = asyncio.Lock()  # فقط لتعديل _registrations
        
        self._running = False
        
        # استراتيجيات موازنة الحمل
        self._load_balancer_strategy = "round_robin"
        self._round_robin_counters: Dict[str, int] = {}
        
        # أحداث
        self._event_handlers: Dict[str, List[Callable]] = {
            "service_registered": [],
            "service_deregistered": [],
            "instance_added": [],
            "instance_removed": [],
            "health_changed": [],
            "status_changed": []
        }
        self._event_semaphore = asyncio.Semaphore(max_concurrent_events)
        self._pending_event_tasks: Set[asyncio.Task] = set()
        
        # إحصائيات
        self._stats = {
            "total_services": 0,
            "total_instances": 0,
            "health_check_count": 0,
            "discovery_count": 0
        }
        
        # استراتيجيات موازنة الحمل
        self._strategies = {
            "round_robin": self._select_round_robin,
            "least_conn": self._select_least_connections,
            "random": self._select_random
        }
        
        logger.info("ServiceRegistry initialized")
    
    async def start(self):
        """بدء تشغيل السجل"""
        if self._running:
            return
        
        self._running = True
        
        # بدء مهمة التنظيف
        asyncio.create_task(self._cleanup_loop())
        
        logger.info("ServiceRegistry started")
    
    async def stop(self, timeout: float = 5.0):
        """إيقاف تشغيل السجل"""
        self._running = False
        
        # إلغاء مهام الفحص
        for task in self._health_check_tasks.values():
            task.cancel()
        
        if self._health_check_tasks:
            await asyncio.sleep(0.5)
        
        # انتظار مهام الأحداث مع timeout
        if self._pending_event_tasks:
            try:
                await asyncio.wait_for(
                    asyncio.gather(*self._pending_event_tasks, return_exceptions=True),
                    timeout=timeout
                )
            except asyncio.TimeoutError:
                logger.warning(f"Event tasks did not complete within {timeout}s")
                for task in self._pending_event_tasks:
                    task.cancel()
        
        logger.info("ServiceRegistry stopped")
    
    async def register_service(
        self,
        name: str,
        version: str,
        endpoint: ServiceEndpoint,
        metadata: Dict[str, Any] = None,
        tags: List[str] = None,
        dependencies: List[str] = None,
        health_check_fn: Optional[Callable[[], Awaitable[bool]]] = None,
        health_check_interval: int = 30
    ) -> str:
        """
        تسجيل خدمة جديدة
        """
        container = get_dependency_container()
        
        service_id = str(uuid.uuid4())
        instance_id = str(uuid.uuid4())[:8]
        
        instance = ServiceInstance(
            service_id=service_id,
            service_name=name,
            instance_id=instance_id,
            endpoint=endpoint,
            metadata=metadata or {},
            status=ServiceStatus.STARTING,
            health_check_fn=health_check_fn,
            generation=0
        )
        
        # استخدام القفل العام فقط للتسجيل الأولي
        async with self._global_lock:
            if name in self._service_by_name:
                registration_id = self._service_by_name[name]
                registration = self._registrations[registration_id]
                
                async with registration.lock:
                    if registration.max_instances > 0 and len(registration.instances) >= registration.max_instances:
                        raise RuntimeError(f"Max instances reached for service {name}")
                    
                    registration.instances[instance_id] = instance
                    registration.endpoints[instance_id] = endpoint
                    
                    if registration_id not in self._round_robin_counters:
                        self._round_robin_counters[registration_id] = 0
                
                self._stats["total_instances"] += 1
            else:
                registration = ServiceRegistration(
                    name=name,
                    version=version,
                    description=metadata.get("description", "") if metadata else "",
                    tags=tags or [],
                    dependencies=dependencies or [],
                    health_check_interval=health_check_interval,
                    endpoints={instance_id: endpoint},
                    instances={instance_id: instance}
                )
                
                self._registrations[service_id] = registration
                self._service_by_name[name] = service_id
                self._round_robin_counters[service_id] = 0
                self._stats["total_services"] += 1
                self._stats["total_instances"] += 1
        
        # تحديث الحالة
        instance.status = ServiceStatus.RUNNING
        instance.health = ServiceHealth.HEALTHY
        
        # بدء فحص الصحة
        if health_check_fn:
            task = asyncio.create_task(self._health_check_loop(service_id, instance_id, health_check_interval))
            self._health_check_tasks[f"{service_id}:{instance_id}"] = task
        
        # تسجيل في حاوية التبعيات
        await container.register_instance(f"service.{name}", instance, scope=Scope.SINGLETON)
        
        # إطلاق أحداث
        asyncio.create_task(self._emit_event("service_registered", {"service_id": service_id, "name": name}))
        asyncio.create_task(self._emit_event("instance_added", {"service_id": service_id, "instance_id": instance_id}))
        
        logger.info(f"Service registered: {name} v{version} (id={service_id[:8]}, instance={instance_id})")
        
        return service_id
    
    async def heartbeat(self, service_name: str, instance_id: str) -> bool:
        """
        تسجيل heartbeat من خدمة
        
        يتم استدعاؤها من الخدمة نفسها بشكل دوري
        """
        async with self._global_lock:
            if service_name not in self._service_by_name:
                logger.warning(f"Heartbeat from unknown service: {service_name}")
                return False
            
            service_id = self._service_by_name[service_name]
            registration = self._registrations[service_id]
        
        # استخدام per-service lock
        async with registration.lock:
            if instance_id not in registration.instances:
                logger.warning(f"Heartbeat from unknown instance: {service_name}:{instance_id}")
                return False
            
            instance = registration.instances[instance_id]
            instance.last_heartbeat = datetime.now()
            instance.uptime = (datetime.now() - instance.registered_at).total_seconds()
            
            if instance.health == ServiceHealth.HEALTHY:
                if instance.status != ServiceStatus.RUNNING:
                    instance.status = ServiceStatus.RUNNING
                    asyncio.create_task(self._emit_event("status_changed", {
                        "service_id": service_id,
                        "instance_id": instance_id,
                        "old_status": instance.status.value,
                        "new_status": ServiceStatus.RUNNING.value
                    }))
        
        return True
    
    async def deregister_service(self, service_id: str, instance_id: str = None):
        """إلغاء تسجيل خدمة أو مثيل - بدون deadlock"""
        # تحديد ما إذا كنا سنحذف الخدمة بالكامل
        should_remove_full = False
        
        async with self._global_lock:
            if service_id not in self._registrations:
                logger.warning(f"Service {service_id} not found")
                return
            
            registration = self._registrations[service_id]
            
            if instance_id:
                # إزالة مثيل محدد
                async with registration.lock:
                    if instance_id in registration.instances:
                        del registration.instances[instance_id]
                        registration.endpoints.pop(instance_id, None)
                        self._stats["total_instances"] -= 1
                        
                        # إلغاء مهمة الفحص
                        task_key = f"{service_id}:{instance_id}"
                        if task_key in self._health_check_tasks:
                            self._health_check_tasks[task_key].cancel()
                            del self._health_check_tasks[task_key]
                        
                        asyncio.create_task(self._emit_event("instance_removed", {
                            "service_id": service_id,
                            "instance_id": instance_id
                        }))
                        
                        logger.info(f"Instance {instance_id} removed from service {registration.name}")
                        
                        # التحقق من حذف الخدمة بالكامل (خارج القفل)
                        if not registration.instances:
                            should_remove_full = True
        
        # حذف الخدمة بالكامل خارج القفل
        if should_remove_full:
            await self._deregister_service_full(service_id)
    
    async def _deregister_service_full(self, service_id: str):
        """إلغاء تسجيل خدمة بالكامل - بدون deadlock"""
        async with self._global_lock:
            if service_id not in self._registrations:
                return
            
            registration = self._registrations[service_id]
            
            # إلغاء مهام الفحص
            for instance_id in list(registration.instances.keys()):
                task_key = f"{service_id}:{instance_id}"
                if task_key in self._health_check_tasks:
                    self._health_check_tasks[task_key].cancel()
                    del self._health_check_tasks[task_key]
            
            # حذف من القواميس
            del self._registrations[service_id]
            if registration.name in self._service_by_name:
                del self._service_by_name[registration.name]
            
            self._round_robin_counters.pop(service_id, None)
            self._stats["total_services"] -= 1
            self._stats["total_instances"] -= len(registration.instances)
        
        asyncio.create_task(self._emit_event("service_deregistered", {
            "service_id": service_id,
            "name": registration.name
        }))
        
        logger.info(f"Service fully deregistered: {registration.name}")
    
    async def discover_service(
        self,
        service_name: str,
        strategy: str = "round_robin"
    ) -> Optional[ServiceInstance]:
        """اكتشاف خدمة - مع validation للحصول على مثيل صالح"""
        self._stats["discovery_count"] += 1
        
        async with self._global_lock:
            if service_name not in self._service_by_name:
                return None
            
            service_id = self._service_by_name[service_name]
            registration = self._registrations[service_id]
        
        strategy_func = self._strategies.get(strategy, self._select_round_robin)
        instance = await strategy_func(service_id, registration)
        
        # Validation: تأكد أن المثيل لا يزال صالحاً
        if instance:
            async with registration.lock:
                if instance_id := instance.instance_id:
                    if instance_id in registration.instances:
                        stored_instance = registration.instances[instance_id]
                        # التحقق من generation counter
                        if (stored_instance.generation == instance.generation and
                            stored_instance.status == ServiceStatus.RUNNING):
                            return stored_instance
        
        return None
    
    async def _select_round_robin(self, service_id: str, registration: ServiceRegistration) -> Optional[ServiceInstance]:
        """Round Robin - مع إعادة ضبط العداد"""
        async with registration.lock:
            instances = list(registration.instances.values())
            if not instances:
                return None
            
            healthy_instances = [i for i in instances if i.health == ServiceHealth.HEALTHY]
            if not healthy_instances:
                healthy_instances = instances
            
            counter = self._round_robin_counters.get(service_id, 0)
            # إعادة ضبط العداد إذا exceeded
            if counter >= len(healthy_instances):
                counter = 0
                self._round_robin_counters[service_id] = counter
            
            instance = healthy_instances[counter]
            self._round_robin_counters[service_id] = counter + 1
            
            return instance
    
    async def _select_least_connections(self, service_id: str, registration: ServiceRegistration) -> Optional[ServiceInstance]:
        """Least Connections"""
        async with registration.lock:
            instances = list(registration.instances.values())
            if not instances:
                return None
            
            healthy_instances = [i for i in instances if i.health == ServiceHealth.HEALTHY]
            if not healthy_instances:
                healthy_instances = instances
            
            return min(healthy_instances, key=lambda i: i.active_connections)
    
    async def _select_random(self, service_id: str, registration: ServiceRegistration) -> Optional[ServiceInstance]:
        """Random"""
        import random
        async with registration.lock:
            instances = list(registration.instances.values())
            if not instances:
                return None
            
            healthy_instances = [i for i in instances if i.health == ServiceHealth.HEALTHY]
            if not healthy_instances:
                healthy_instances = instances
            
            return random.choice(healthy_instances)
    
    @asynccontextmanager
    async def connection_scope(self, service_name: str, instance_id: str):
        """
        سياق لإدارة الاتصالات النشطة
        
        يزيد العداد تلقائياً وينقصه عند الخروج
        """
        async with self._global_lock:
            if service_name not in self._service_by_name:
                raise KeyError(f"Service {service_name} not found")
            
            service_id = self._service_by_name[service_name]
            registration = self._registrations[service_id]
        
        async with registration.lock:
            if instance_id not in registration.instances:
                raise KeyError(f"Instance {instance_id} not found")
            
            registration.instances[instance_id].active_connections += 1
        
        try:
            yield
        finally:
            async with registration.lock:
                if instance_id in registration.instances:
                    registration.instances[instance_id].active_connections -= 1
    
    async def _health_check_loop(
        self,
        service_id: str,
        instance_id: str,
        interval: int
    ):
        """حلقة فحص صحة - مع تنفيذ خارج القفل"""
        while self._running:
            await asyncio.sleep(interval)
            
            # الحصول على reference خارج القفل
            async with self._global_lock:
                if service_id not in self._registrations:
                    break
                
                registration = self._registrations[service_id]
                
                async with registration.lock:
                    if instance_id not in registration.instances:
                        break
                    
                    instance = registration.instances[instance_id]
                    health_fn = instance.health_check_fn
                    old_health = instance.health
            
            if not health_fn:
                continue
            
            # تنفيذ فحص الصحة خارج القفل (حرج!)
            try:
                healthy = await asyncio.wait_for(health_fn(), timeout=interval // 2)
                new_health = ServiceHealth.HEALTHY if healthy else ServiceHealth.UNHEALTHY
            except asyncio.TimeoutError:
                new_health = ServiceHealth.UNHEALTHY
                logger.warning(f"Health check timeout: {service_id}:{instance_id}")
            except Exception as e:
                new_health = ServiceHealth.UNHEALTHY
                logger.error(f"Health check failed: {e}")
            
            # تحديث النتيجة تحت القفل
            async with self._global_lock:
                if service_id not in self._registrations:
                    continue
                
                registration = self._registrations[service_id]
                
                async with registration.lock:
                    if instance_id not in registration.instances:
                        continue
                    
                    instance = registration.instances[instance_id]
                    instance.health = new_health
                    instance.last_health_check = datetime.now()
                    
                    if old_health != new_health:
                        asyncio.create_task(self._emit_event("health_changed", {
                            "service_id": service_id,
                            "instance_id": instance_id,
                            "old_health": old_health.value,
                            "new_health": new_health.value
                        }))
            
            self._stats["health_check_count"] += 1
    
    async def _cleanup_loop(self):
        """حلقة تنظيف الخدمات الميتة"""
        while self._running:
            await asyncio.sleep(60)
            
            dead_instances = []
            
            async with self._global_lock:
                for service_id, registration in list(self._registrations.items()):
                    async with registration.lock:
                        for instance_id, instance in list(registration.instances.items()):
                            time_since_heartbeat = (datetime.now() - instance.last_heartbeat).total_seconds()
                            
                            if time_since_heartbeat > 120:  # دقيقتين
                                dead_instances.append((service_id, instance_id))
                                logger.warning(f"Dead instance detected: {registration.name}:{instance_id}")
            
            for service_id, instance_id in dead_instances:
                await self.deregister_service(service_id, instance_id)
    
    async def record_request(
        self,
        service_name: str,
        instance_id: str,
        response_time: float,
        success: bool
    ):
        """تسجيل طلب"""
        async with self._global_lock:
            if service_name not in self._service_by_name:
                return
            
            service_id = self._service_by_name[service_name]
            registration = self._registrations[service_id]
        
        async with registration.lock:
            if instance_id in registration.instances:
                instance = registration.instances[instance_id]
                instance.request_count += 1
                
                if success:
                    instance.avg_response_time = (
                        (instance.avg_response_time * (instance.request_count - 1) + response_time)
                        / instance.request_count
                    )
                else:
                    instance.error_count += 1
                
                registration.total_requests += 1
                if not success:
                    registration.total_errors += 1
    
    async def get_status(self, service_name: str = None) -> Dict:
        """الحصول على حالة الخدمة/الخدمات"""
        if service_name:
            if service_name not in self._service_by_name:
                return {"error": f"Service {service_name} not found"}
            
            async with self._global_lock:
                service_id = self._service_by_name[service_name]
                registration = self._registrations[service_id]
            
            async with registration.lock:
                return {
                    "name": registration.name,
                    "version": registration.version,
                    "instances": {
                        inst_id: {
                            "status": inst.status.value,
                            "health": inst.health.value,
                            "endpoint": inst.endpoint.url,
                            "uptime": inst.uptime,
                            "requests": inst.request_count,
                            "errors": inst.error_count,
                            "active_connections": inst.active_connections,
                            "last_heartbeat": inst.last_heartbeat.isoformat()
                        }
                        for inst_id, inst in registration.instances.items()
                    },
                    "total_requests": registration.total_requests,
                    "total_errors": registration.total_errors
                }
        
        # جميع الخدمات
        async with self._global_lock:
            services = {}
            for name, service_id in self._service_by_name.items():
                registration = self._registrations[service_id]
                async with registration.lock:
                    services[name] = {
                        "version": registration.version,
                        "instances": len(registration.instances),
                        "status": self._get_service_status(registration),
                        "healthy_instances": sum(1 for i in registration.instances.values() if i.health == ServiceHealth.HEALTHY)
                    }
            
            return {
                "services": services,
                "stats": self._stats,
                "running": self._running
            }
    
    def _get_service_status(self, registration: ServiceRegistration) -> str:
        """الحصول على الحالة الإجمالية للخدمة"""
        if not registration.instances:
            return "down"
        
        healthy_instances = sum(1 for i in registration.instances.values() if i.health == ServiceHealth.HEALTHY)
        
        if healthy_instances == len(registration.instances):
            return "healthy"
        elif healthy_instances > 0:
            return "degraded"
        else:
            return "unhealthy"
    
    async def on(self, event: str, handler: Callable):
        """تسجيل معالج حدث"""
        if event in self._event_handlers:
            self._event_handlers[event].append(handler)
    
    async def _emit_event(self, event: str, data: Dict):
        """إطلاق حدث - مع semaphore للتحكم في التدفق"""
        if event not in self._event_handlers:
            return
        
        async with self._event_semaphore:
            for handler in self._event_handlers[event]:
                try:
                    if asyncio.iscoroutinefunction(handler):
                        task = asyncio.create_task(handler(data))
                        self._pending_event_tasks.add(task)
                        task.add_done_callback(lambda t: self._pending_event_tasks.discard(t))
                    else:
                        handler(data)
                except Exception as e:
                    logger.error(f"Event handler error: {e}")
    
    async def health_check(self) -> Dict:
        """فحص صحة السجل نفسه"""
        return {
            "status": "healthy" if self._running else "down",
            "services": len(self._registrations),
            "instances": self._stats["total_instances"],
            "running": self._running
        }


# نسخة عالمية
_default_registry = None


async def get_service_registry() -> ServiceRegistry:
    """الحصول على نسخة عالمية من سجل الخدمات"""
    global _default_registry
    if _default_registry is None:
        _default_registry = ServiceRegistry()
        await _default_registry.start()
    return _default_registry

