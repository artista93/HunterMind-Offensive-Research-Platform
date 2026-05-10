
import uuid
import asyncio
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

import logging

logger = logging.getLogger(__name__)


class ContextPriority(Enum):
    """أولوية السياق"""
    CRITICAL = 1
    HIGH = 2
    NORMAL = 3
    LOW = 4
    BACKGROUND = 5


@dataclass
class ExecutionContext:
    """سياق التنفيذ"""
    id: str
    parent_id: Optional[str] = None
    target_url: Optional[str] = None
    parameters: Dict[str, Any] = field(default_factory=dict)
    start_time: datetime = field(default_factory=datetime.now)
    end_time: Optional[datetime] = None
    status: str = "running"
    result: Any = None
    error: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ResourceContext:
    """سياق الموارد"""
    cpu_limit: Optional[float] = None
    memory_limit_mb: Optional[float] = None
    timeout_seconds: float = 30.0
    max_retries: int = 3
    rate_limit: float = 10.0
    allowed_hosts: List[str] = field(default_factory=list)
    blocked_hosts: List[str] = field(default_factory=list)


@dataclass
class SecurityContext:
    """سياق الأمان"""
    auth_token: Optional[str] = None
    api_key: Optional[str] = None
    cookies: Dict[str, str] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    proxy_url: Optional[str] = None
    stealth_mode: bool = False
    sandboxed: bool = True


class AgentContext:
    """
    سياق الوكيل المتقدم
    
    الميزات:
    - إدارة سياقات التنفيذ المتعددة
    - تتبع الوقت والموارد
    - دعم السياقات المتداخلة (parent-child)
    - حفظ واستعادة السياق
    - دمج السياقات
    """
    
    def __init__(self, agent_id: str, agent_name: str):
        self._agent_id = agent_id
        self._agent_name = agent_name
        
        # السياقات النشطة
        self._execution_contexts: Dict[str, ExecutionContext] = {}
        self._current_context_id: Optional[str] = None
        
        # سياق الموارد
        self._resource_context = ResourceContext()
        
        # سياق الأمان
        self._security_context = SecurityContext()
        
        # بيانات السياق العامة
        self._data: Dict[str, Any] = {}
        self._tags: Set[str] = set()
        self._lock = asyncio.Lock()
        
        # إحصائيات
        self._stats = {
            "contexts_created": 0,
            "contexts_completed": 0,
            "contexts_failed": 0,
            "total_execution_time": 0.0
        }
        
        logger.debug(f"AgentContext initialized for {agent_name}")
    
    async def create_context(
        self,
        target_url: str = None,
        parameters: Dict = None,
        parent_id: str = None,
        priority: ContextPriority = ContextPriority.NORMAL
    ) -> str:
        """
        إنشاء سياق تنفيذ جديد
        
        Args:
            target_url: الرابط المستهدف
            parameters: معاملات إضافية
            parent_id: معرف السياق الأب
            priority: أولوية السياق
        
        Returns:
            معرف السياق
        """
        context_id = str(uuid.uuid4())[:8]
        
        context = ExecutionContext(
            id=context_id,
            parent_id=parent_id,
            target_url=target_url,
            parameters=parameters or {},
            start_time=datetime.now(),
            status="running",
            metadata={"priority": priority.value}
        )
        
        async with self._lock:
            self._execution_contexts[context_id] = context
            self._current_context_id = context_id
            self._stats["contexts_created"] += 1
        
        logger.debug(f"Context created: {context_id} for {self._agent_name}")
        return context_id
    
    async def complete_context(
        self,
        context_id: str,
        result: Any = None,
        error: str = None
    ) -> bool:
        """
        إكمال سياق تنفيذ
        
        Args:
            context_id: معرف السياق
            result: نتيجة التنفيذ
            error: رسالة خطأ
        
        Returns:
            نجاح العملية
        """
        async with self._lock:
            if context_id not in self._execution_contexts:
                logger.warning(f"Context {context_id} not found")
                return False
            
            context = self._execution_contexts[context_id]
            context.end_time = datetime.now()
            context.result = result
            context.error = error
            context.status = "failed" if error else "completed"
            
            duration = (context.end_time - context.start_time).total_seconds()
            self._stats["total_execution_time"] += duration
            
            if error:
                self._stats["contexts_failed"] += 1
            else:
                self._stats["contexts_completed"] += 1
            
            if self._current_context_id == context_id:
                self._current_context_id = None
        
        logger.debug(f"Context completed: {context_id} (duration: {duration:.2f}s)")
        return True
    
    async def get_context(self, context_id: str = None) -> Optional[ExecutionContext]:
        """
        الحصول على سياق تنفيذ
        
        Args:
            context_id: معرف السياق (السياق الحالي إذا None)
        
        Returns:
            سياق التنفيذ أو None
        """
        context_id = context_id or self._current_context_id
        
        async with self._lock:
            return self._execution_contexts.get(context_id)
    
    async def get_current_context(self) -> Optional[ExecutionContext]:
        """الحصول على السياق الحالي"""
        return await self.get_context()
    
    async def update_context(
        self,
        context_id: str,
        parameters: Dict = None,
        metadata: Dict = None
    ) -> bool:
        """
        تحديث سياق تنفيذ
        
        Args:
            context_id: معرف السياق
            parameters: معاملات جديدة
            metadata: بيانات وصفية جديدة
        
        Returns:
            نجاح العملية
        """
        async with self._lock:
            if context_id not in self._execution_contexts:
                return False
            
            context = self._execution_contexts[context_id]
            if parameters:
                context.parameters.update(parameters)
            if metadata:
                context.metadata.update(metadata)
        
        return True
    
    async def set_resource_limits(
        self,
        cpu_limit: float = None,
        memory_limit_mb: float = None,
        timeout_seconds: float = None,
        rate_limit: float = None
    ):
        """
        تعيين حدود الموارد
        
        Args:
            cpu_limit: حد CPU
            memory_limit_mb: حد الذاكرة
            timeout_seconds: مهلة التنفيذ
            rate_limit: حد الطلبات في الثانية
        """
        async with self._lock:
            if cpu_limit is not None:
                self._resource_context.cpu_limit = cpu_limit
            if memory_limit_mb is not None:
                self._resource_context.memory_limit_mb = memory_limit_mb
            if timeout_seconds is not None:
                self._resource_context.timeout_seconds = timeout_seconds
            if rate_limit is not None:
                self._resource_context.rate_limit = rate_limit
        
        logger.debug(f"Resource limits updated for {self._agent_name}")
    
    async def get_resource_limits(self) -> ResourceContext:
        """الحصول على حدود الموارد"""
        async with self._lock:
            return self._resource_context
    
    async def set_auth(
        self,
        auth_token: str = None,
        api_key: str = None,
        cookies: Dict = None,
        headers: Dict = None,
        proxy_url: str = None,
        stealth_mode: bool = None
    ):
        """
        تعيين معلومات المصادقة
        
        Args:
            auth_token: توكن المصادقة
            api_key: مفتاح API
            cookies: كوكيز
            headers: هيدرات إضافية
            proxy_url: رابط البروكسي
            stealth_mode: وضع التخفي
        """
        async with self._lock:
            if auth_token is not None:
                self._security_context.auth_token = auth_token
            if api_key is not None:
                self._security_context.api_key = api_key
            if cookies is not None:
                self._security_context.cookies.update(cookies)
            if headers is not None:
                self._security_context.headers.update(headers)
            if proxy_url is not None:
                self._security_context.proxy_url = proxy_url
            if stealth_mode is not None:
                self._security_context.stealth_mode = stealth_mode
        
        logger.debug(f"Auth settings updated for {self._agent_name}")
    
    async def get_auth(self) -> SecurityContext:
        """الحصول على معلومات المصادقة"""
        async with self._lock:
            return self._security_context
    
    async def set_data(self, key: str, value: Any):
        """
        تخزين بيانات في السياق
        
        Args:
            key: المفتاح
            value: القيمة
        """
        async with self._lock:
            self._data[key] = value
    
    async def get_data(self, key: str, default: Any = None) -> Any:
        """
        استرجاع بيانات من السياق
        
        Args:
            key: المفتاح
            default: القيمة الافتراضية
        
        Returns:
            القيمة المخزنة أو القيمة الافتراضية
        """
        async with self._lock:
            return self._data.get(key, default)
    
    async def delete_data(self, key: str) -> bool:
        """حذف بيانات من السياق"""
        async with self._lock:
            if key in self._data:
                del self._data[key]
                return True
            return False
    
    async def add_tag(self, tag: str):
        """إضافة علامة للسياق"""
        async with self._lock:
            self._tags.add(tag)
    
    async def remove_tag(self, tag: str) -> bool:
        """إزالة علامة من السياق"""
        async with self._lock:
            if tag in self._tags:
                self._tags.remove(tag)
                return True
            return False
    
    async def has_tag(self, tag: str) -> bool:
        """التحقق من وجود علامة"""
        async with self._lock:
            return tag in self._tags
    
    async def get_tags(self) -> List[str]:
        """الحصول على جميع العلامات"""
        async with self._lock:
            return list(self._tags)
    
    async def get_contexts(
        self,
        status: str = None,
        limit: int = 50
    ) -> List[ExecutionContext]:
        """
        الحصول على قائمة السياقات
        
        Args:
            status: حالة السياق (running, completed, failed)
            limit: الحد الأقصى للنتائج
        
        Returns:
            قائمة السياقات
        """
        async with self._lock:
            contexts = list(self._execution_contexts.values())
            
            if status:
                contexts = [c for c in contexts if c.status == status]
            
            contexts.sort(key=lambda x: x.start_time, reverse=True)
            return contexts[:limit]
    
    async def clear_completed(self, older_than_seconds: int = 3600):
        """
        تنظيف السياقات المكتملة القديمة
        
        Args:
            older_than_seconds: العمر بالثواني
        """
        cutoff = datetime.now().timestamp() - older_than_seconds
        
        async with self._lock:
            to_remove = [
                cid for cid, ctx in self._execution_contexts.items()
                if ctx.status in ["completed", "failed"] and
                ctx.end_time and ctx.end_time.timestamp() < cutoff
            ]
            
            for cid in to_remove:
                del self._execution_contexts[cid]
        
        logger.debug(f"Cleared {len(to_remove)} old contexts")
        return len(to_remove)
    
    async def get_statistics(self) -> Dict:
        """إحصائيات السياق"""
        async with self._lock:
            active = len([c for c in self._execution_contexts.values() if c.status == "running"])
            completed = len([c for c in self._execution_contexts.values() if c.status == "completed"])
            failed = len([c for c in self._execution_contexts.values() if c.status == "failed"])
            
            return {
                **self._stats,
                "active_contexts": active,
                "completed_contexts": completed,
                "failed_contexts": failed,
                "total_contexts": len(self._execution_contexts),
                "current_context_id": self._current_context_id,
                "tags_count": len(self._tags),
                "data_keys": len(self._data),
                "resource_limits": {
                    "cpu_limit": self._resource_context.cpu_limit,
                    "memory_limit_mb": self._resource_context.memory_limit_mb,
                    "timeout_seconds": self._resource_context.timeout_seconds,
                    "rate_limit": self._resource_context.rate_limit
                }
            }
    
    async def save_state(self) -> Dict:
        """حفظ حالة السياق"""
        async with self._lock:
            return {
                "data": self._data.copy(),
                "tags": list(self._tags),
                "resource_context": {
                    "cpu_limit": self._resource_context.cpu_limit,
                    "memory_limit_mb": self._resource_context.memory_limit_mb,
                    "timeout_seconds": self._resource_context.timeout_seconds,
                    "max_retries": self._resource_context.max_retries,
                    "rate_limit": self._resource_context.rate_limit,
                    "allowed_hosts": self._resource_context.allowed_hosts,
                    "blocked_hosts": self._resource_context.blocked_hosts
                },
                "security_context": {
                    "has_auth": bool(self._security_context.auth_token),
                    "has_api_key": bool(self._security_context.api_key),
                    "cookies_count": len(self._security_context.cookies),
                    "headers_count": len(self._security_context.headers),
                    "proxy_url": self._security_context.proxy_url,
                    "stealth_mode": self._security_context.stealth_mode,
                    "sandboxed": self._security_context.sandboxed
                },
                "statistics": self._stats
            }
    
    async def restore_state(self, state: Dict):
        """استعادة حالة السياق"""
        async with self._lock:
            self._data = state.get("data", {})
            self._tags = set(state.get("tags", []))
            
            rc = state.get("resource_context", {})
            self._resource_context.cpu_limit = rc.get("cpu_limit")
            self._resource_context.memory_limit_mb = rc.get("memory_limit_mb")
            self._resource_context.timeout_seconds = rc.get("timeout_seconds", 30.0)
            self._resource_context.max_retries = rc.get("max_retries", 3)
            self._resource_context.rate_limit = rc.get("rate_limit", 10.0)
            self._resource_context.allowed_hosts = rc.get("allowed_hosts", [])
            self._resource_context.blocked_hosts = rc.get("blocked_hosts", [])
            
            self._stats = state.get("statistics", self._stats)
        
        logger.info(f"Context state restored for {self._agent_name}")

