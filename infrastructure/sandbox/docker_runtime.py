
import asyncio
import json
import io
import tarfile
import tempfile
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import docker
from docker.errors import NotFound, APIError, ImageNotFound


class ContainerStatus(Enum):
    """حالة الحاوية"""
    CREATED = "created"
    RUNNING = "running"
    PAUSED = "paused"
    STOPPED = "stopped"
    REMOVED = "removed"
    ERROR = "error"


class IsolationLevel(Enum):
    """مستوى العزل"""
    NONE = "none"
    DOCKER = "docker"
    KUBERNETES = "k8s"
    FULL = "full"


@dataclass
class ContainerConfig:
    """إعدادات الحاوية"""
    image: str = "alpine:latest"
    command: List[str] = field(default_factory=list)
    environment: Dict[str, str] = field(default_factory=dict)
    volumes: List[str] = field(default_factory=list)
    ports: Dict[str, str] = field(default_factory=dict)
    network: str = "bridge"
    memory_limit: str = "512m"
    cpu_limit: float = 0.5
    privileged: bool = False
    read_only: bool = True
    security_opt: List[str] = field(default_factory=lambda: ["no-new-privileges:true"])
    tmpfs: Dict[str, str] = field(default_factory=lambda: {"/tmp": ""})
    remove_on_exit: bool = True
    timeout: int = 300


@dataclass
class Container:
    """حاوية Docker"""
    id: str
    name: str
    image: str
    status: ContainerStatus
    docker_object: Any = None  # حفظ الكائن الأصلي
    created_at: datetime = field(default_factory=datetime.now)
    started_at: Optional[datetime] = None
    stopped_at: Optional[datetime] = None
    config: ContainerConfig = field(default_factory=ContainerConfig)
    logs: List[str] = field(default_factory=list)
    exit_code: Optional[int] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


class DockerRuntime:
    """بيئة تشغيل Docker للعزل"""
    
    def __init__(self):
        self._client: Optional[docker.DockerClient] = None
        self._containers: Dict[str, Container] = {}
        self._lock = asyncio.Lock()
        self._initialized = False
        self._available = False
        self._cleanup_task: Optional[asyncio.Task] = None
        self._running = False
        
        # إحصائيات
        self._stats = {
            "containers_created": 0,
            "containers_started": 0,
            "containers_stopped": 0,
            "containers_removed": 0,
            "errors": 0
        }
    
    async def initialize(self):
        """تهيئة اتصال Docker"""
        if self._initialized:
            return
        
        try:
            self._client = docker.from_env()
            self._client.ping()
            self._available = True
            self._running = True
            self._cleanup_task = asyncio.create_task(self._cleanup_loop())
            print("   🐳 Docker runtime initialized")
        except Exception as e:
            print(f"   ⚠️ Docker not available: {str(e)[:50]}")
            self._available = False
        
        self._initialized = True
    
    def is_available(self) -> bool:
        return self._available
    
    async def _cleanup_loop(self):
        """حلقة تنظيف دورية للحاويات الميتة"""
        while self._running:
            await asyncio.sleep(60)  # كل دقيقة
            await self._cleanup_stopped_containers()
    
    async def _cleanup_stopped_containers(self):
        """تنظيف الحاويات المتوقفة من الذاكرة"""
        async with self._lock:
            to_remove = []
            for cid, container in self._containers.items():
                if container.status in [ContainerStatus.STOPPED, ContainerStatus.REMOVED]:
                    if (datetime.now() - container.stopped_at).total_seconds() > 300 if container.stopped_at else True:
                        to_remove.append(cid)
            
            for cid in to_remove:
                del self._containers[cid]
    
    async def create_container(self, name: str, config: ContainerConfig) -> Optional[Container]:
        """إنشاء حاوية جديدة"""
        if not self._available:
            return None
        
        async with self._lock:
            try:
                # إعدادات الأمان
                security_opts = config.security_opt.copy()
                security_opts.append("no-new-privileges:true")
                
                # إنشاء الحاوية
                docker_container = self._client.containers.create(
                    image=config.image,
                    command=config.command,
                    environment=config.environment,
                    volumes=config.volumes,
                    ports=config.ports,
                    network=config.network,
                    mem_limit=config.memory_limit,
                    nano_cpus=int(config.cpu_limit * 1e9),
                    privileged=config.privileged,
                    read_only=config.read_only,
                    security_opt=security_opts,
                    tmpfs=config.tmpfs,
                    detach=True,
                    name=name
                )
                
                container_obj = Container(
                    id=docker_container.id[:12],
                    name=name,
                    image=config.image,
                    status=ContainerStatus.CREATED,
                    docker_object=docker_container,
                    config=config
                )
                
                self._containers[docker_container.id[:12]] = container_obj
                self._stats["containers_created"] += 1
                
                return container_obj
                
            except (APIError, ImageNotFound) as e:
                self._stats["errors"] += 1
                print(f"   ❌ Failed to create container: {e}")
                return None
    
    async def start_container(self, container_id: str) -> bool:
        """بدء تشغيل الحاوية"""
        if not self._available:
            return False
        
        async with self._lock:
            try:
                # الحصول على الحاوية من الكائن المخزن أو من Docker
                container_obj = self._containers.get(container_id)
                
                if container_obj and container_obj.docker_object:
                    docker_container = container_obj.docker_object
                else:
                    # ✅ استخدام get بدلاً من filters
                    docker_container = self._client.containers.get(container_id)
                    if container_obj:
                        container_obj.docker_object = docker_container
                
                docker_container.start()
                
                if container_id in self._containers:
                    self._containers[container_id].status = ContainerStatus.RUNNING
                    self._containers[container_id].started_at = datetime.now()
                
                self._stats["containers_started"] += 1
                return True
                
            except (NotFound, APIError) as e:
                self._stats["errors"] += 1
                return False
    
    async def stop_container(self, container_id: str, timeout: int = 10) -> bool:
        """إيقاف الحاوية"""
        if not self._available:
            return False
        
        async with self._lock:
            try:
                container_obj = self._containers.get(container_id)
                
                if container_obj and container_obj.docker_object:
                    docker_container = container_obj.docker_object
                else:
                    docker_container = self._client.containers.get(container_id)
                
                docker_container.stop(timeout=timeout)
                
                if container_id in self._containers:
                    self._containers[container_id].status = ContainerStatus.STOPPED
                    self._containers[container_id].stopped_at = datetime.now()
                
                self._stats["containers_stopped"] += 1
                return True
                
            except (NotFound, APIError) as e:
                self._stats["errors"] += 1
                return False
    
    async def remove_container(self, container_id: str, force: bool = False) -> bool:
        """حذف الحاوية"""
        if not self._available:
            return False
        
        async with self._lock:
            try:
                container_obj = self._containers.get(container_id)
                
                if container_obj and container_obj.docker_object:
                    docker_container = container_obj.docker_object
                else:
                    docker_container = self._client.containers.get(container_id)
                
                docker_container.remove(force=force)
                
                if container_id in self._containers:
                    self._containers[container_id].status = ContainerStatus.REMOVED
                    self._containers[container_id].stopped_at = datetime.now()
                
                self._stats["containers_removed"] += 1
                return True
                
            except (NotFound, APIError) as e:
                self._stats["errors"] += 1
                return False
    
    async def get_container_logs(self, container_id: str, tail: int = 100) -> List[str]:
        """الحصول على سجلات الحاوية"""
        if not self._available:
            return []
        
        try:
            container_obj = self._containers.get(container_id)
            
            if container_obj and container_obj.docker_object:
                docker_container = container_obj.docker_object
            else:
                docker_container = self._client.containers.get(container_id)
            
            logs = docker_container.logs(tail=tail).decode('utf-8', errors='ignore').split('\n')
            
            if container_id in self._containers:
                self._containers[container_id].logs.extend(logs[-50:])
            
            return logs
            
        except (NotFound, APIError):
            return []
    
    async def execute_command(self, container_id: str, command: List[str]) -> Tuple[int, str, str]:
        """تنفيذ أمر داخل الحاوية"""
        if not self._available:
            return -1, "", "Docker not available"
        
        try:
            container_obj = self._containers.get(container_id)
            
            if container_obj and container_obj.docker_object:
                docker_container = container_obj.docker_object
            else:
                docker_container = self._client.containers.get(container_id)
            
            exit_code, output = docker_container.exec_run(command, demux=True)
            
            stdout = output[0].decode('utf-8', errors='ignore') if output and output[0] else ""
            stderr = output[1].decode('utf-8', errors='ignore') if output and output[1] else ""
            
            return exit_code, stdout, stderr
            
        except (NotFound, APIError) as e:
            return -1, "", str(e)
    
    async def copy_to_container(self, container_id: str, source_path: str, dest_path: str) -> bool:
        """نسخ ملف إلى الحاوية"""
        if not self._available:
            return False
        
        try:
            container_obj = self._containers.get(container_id)
            
            if container_obj and container_obj.docker_object:
                docker_container = container_obj.docker_object
            else:
                docker_container = self._client.containers.get(container_id)
            
            with open(source_path, 'rb') as f:
                docker_container.put_archive(dest_path, f)
            
            return True
            
        except (NotFound, APIError):
            return False
    
    async def copy_from_container(self, container_id: str, source_path: str, dest_path: str) -> bool:
        """نسخ ملف من الحاوية (مع فك الضغط)"""
        if not self._available:
            return False
        
        try:
            container_obj = self._containers.get(container_id)
            
            if container_obj and container_obj.docker_object:
                docker_container = container_obj.docker_object
            else:
                docker_container = self._client.containers.get(container_id)
            
            # الحصول على الدفق
            stream, _ = docker_container.get_archive(source_path)
            
            # تجميع الدفق
            data = b"".join(stream)
            
            # فك ضغط tar
            file_like = io.BytesIO(data)
            with tarfile.open(fileobj=file_like) as tar:
                # استخراج الملف الأول فقط (للبساطة)
                for member in tar.getmembers():
                    if member.isfile():
                        f = tar.extractfile(member)
                        if f:
                            with open(dest_path, 'wb') as out:
                                out.write(f.read())
                            break
            
            return True
            
        except (NotFound, APIError, tarfile.TarError) as e:
            return False
    
    async def get_container_status(self, container_id: str) -> ContainerStatus:
        """الحصول على حالة الحاوية"""
        if not self._available:
            return ContainerStatus.ERROR
        
        try:
            container_obj = self._containers.get(container_id)
            
            if container_obj and container_obj.docker_object:
                docker_container = container_obj.docker_object
            else:
                docker_container = self._client.containers.get(container_id)
            
            status_map = {
                "created": ContainerStatus.CREATED,
                "running": ContainerStatus.RUNNING,
                "paused": ContainerStatus.PAUSED,
                "exited": ContainerStatus.STOPPED,
                "dead": ContainerStatus.ERROR
            }
            
            return status_map.get(docker_container.status, ContainerStatus.ERROR)
            
        except NotFound:
            return ContainerStatus.REMOVED
        except APIError:
            return ContainerStatus.ERROR
    
    async def list_containers(self) -> List[Dict]:
        """قائمة الحاويات"""
        if not self._available:
            return []
        
        try:
            containers = self._client.containers.list(all=True)
            return [
                {
                    "id": c.id[:12],
                    "name": c.name,
                    "image": c.image.tags[0] if c.image.tags else "unknown",
                    "status": c.status,
                    "created": c.attrs.get("Created", ""),
                    "state": c.attrs.get("State", {})
                }
                for c in containers
            ]
            
        except APIError:
            return []
    
    async def get_stats(self) -> Dict:
        """إحصائيات بيئة التشغيل"""
        return {
            "available": self._available,
            "initialized": self._initialized,
            "containers_created": self._stats["containers_created"],
            "containers_started": self._stats["containers_started"],
            "containers_stopped": self._stats["containers_stopped"],
            "containers_removed": self._stats["containers_removed"],
            "errors": self._stats["errors"],
            "active_containers": len(self._containers),
            "docker_version": self._client.version()["Version"] if self._available else None
        }
    
    async def cleanup(self):
        """تنظيف الموارد"""
        self._running = False
        
        if self._cleanup_task:
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass
        
        async with self._lock:
            for container_id in list(self._containers.keys()):
                if self._containers[container_id].status in [ContainerStatus.RUNNING, ContainerStatus.CREATED]:
                    await self.stop_container(container_id)
                    await self.remove_container(container_id)
            
            if self._client:
                self._client.close()
            
            self._initialized = False
            self._available = False
            print("   🧹 Docker runtime cleaned up")


# نسخة عالمية
_default_runtime = None


async def get_docker_runtime() -> DockerRuntime:
    global _default_runtime
    if _default_runtime is None:
        _default_runtime = DockerRuntime()
        await _default_runtime.initialize()
    return _default_runtime


async def close_docker_runtime():
    global _default_runtime
    if _default_runtime:
        await _default_runtime.cleanup()
        _default_runtime = None

