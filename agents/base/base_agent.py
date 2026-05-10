
import asyncio
import uuid
from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Any, Callable, Awaitable
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

import logging

logger = logging.getLogger(__name__)


class AgentState(Enum):
    """حالة الوكيل"""
    CREATED = "created"
    INITIALIZING = "initializing"
    IDLE = "idle"
    BUSY = "busy"
    WAITING = "waiting"
    ERROR = "error"
    STOPPED = "stopped"


class AgentPriority(Enum):
    """أولوية الوكيل"""
    CRITICAL = 1
    HIGH = 2
    NORMAL = 3
    LOW = 4
    BACKGROUND = 5


@dataclass
class AgentMessage:
    """رسالة بين الوكلاء"""
    id: str
    sender: str
    receiver: str
    type: str  # request, response, event, command
    content: Any
    timestamp: datetime = field(default_factory=datetime.now)
    correlation_id: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AgentContext:
    """سياق الوكيل"""
    agent_id: str
    agent_name: str
    state: AgentState
    start_time: datetime
    last_activity: datetime
    tasks_completed: int = 0
    tasks_failed: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)


class BaseAgent(ABC):
    """
    الوكيل الأساسي لجميع الوكلاء في المنصة
    
    الميزات:
    - دورة حياة كاملة (init, start, stop, destroy)
    - معالجة الرسائل غير المتزامنة
    - تسجيل الأحداث
    - إدارة الحالة
    - تكامل مع الحاوية
    """
    
    def __init__(
        self,
        name: str,
        priority: AgentPriority = AgentPriority.NORMAL,
        auto_register: bool = True
    ):
        self.id = str(uuid.uuid4())[:8]
        self.name = name
        self.priority = priority
        
        self._state = AgentState.CREATED
        self._context = AgentContext(
            agent_id=self.id,
            agent_name=name,
            state=self._state,
            start_time=datetime.now(),
            last_activity=datetime.now()
        )
        
        self._message_queue: asyncio.Queue = asyncio.Queue()
        self._processing_task: Optional[asyncio.Task] = None
        self._running = False
        
        self._container = None
        self._service_registry = None
        
        if auto_register:
            asyncio.create_task(self._auto_register())
        
        logger.info(f"Agent initialized: {name} ({self.id})")
    
    async def _auto_register(self):
        """تسجيل تلقائي في الحاوية"""
        try:
            from ...infrastructure.runtime.dependency_container import get_dependency_container
            self._container = get_dependency_container()
            await self._container.register_instance(f"agent.{self.name}", self)
            logger.debug(f"Agent auto-registered: {self.name}")
        except Exception as e:
            logger.warning(f"Failed to auto-register agent {self.name}: {e}")
    
    async def initialize(self):
        """تهيئة الوكيل"""
        self._state = AgentState.INITIALIZING
        self._context.state = self._state
        
        logger.info(f"Initializing agent: {self.name}")
        
        try:
            await self._on_initialize()
            self._state = AgentState.IDLE
            self._context.state = self._state
            logger.info(f"Agent initialized: {self.name}")
        except Exception as e:
            self._state = AgentState.ERROR
            self._context.state = self._state
            logger.error(f"Failed to initialize agent {self.name}: {e}")
            raise
    
    async def start(self):
        """بدء تشغيل الوكيل"""
        if self._running:
            return
        
        self._running = True
        self._state = AgentState.IDLE
        self._context.state = self._state
        self._context.start_time = datetime.now()
        
        # بدء معالجة الرسائل
        self._processing_task = asyncio.create_task(self._process_messages())
        
        # استدعاء دالة البدء المخصصة
        await self._on_start()
        
        logger.info(f"Agent started: {self.name}")
    
    async def stop(self):
        """إيقاف تشغيل الوكيل"""
        if not self._running:
            return
        
        self._running = False
        self._state = AgentState.STOPPED
        self._context.state = self._state
        
        # إلغاء معالجة الرسائل
        if self._processing_task:
            self._processing_task.cancel()
            try:
                await self._processing_task
            except asyncio.CancelledError:
                pass
        
        # استدعاء دالة الإيقاف المخصصة
        await self._on_stop()
        
        logger.info(f"Agent stopped: {self.name}")
    
    async def send_message(self, message: AgentMessage) -> bool:
        """
        إرسال رسالة إلى وكيل آخر
        
        Args:
            message: الرسالة
        
        Returns:
            نجاح الإرسال
        """
        try:
            # الحصول على الوكيل المستهدف من الحاوية
            if not self._container:
                return False
            
            target_agent = await self._container.resolve(f"agent.{message.receiver}")
            if not target_agent:
                logger.warning(f"Target agent not found: {message.receiver}")
                return False
            
            # إضافة الرسالة إلى قائمة انتظار الوكيل المستهدف
            await target_agent._receive_message(message)
            return True
            
        except Exception as e:
            logger.error(f"Failed to send message: {e}")
            return False
    
    async def _receive_message(self, message: AgentMessage):
        """استقبال رسالة (داخلي)"""
        await self._message_queue.put(message)
    
    async def _process_messages(self):
        """معالجة الرسائل الواردة"""
        while self._running:
            try:
                message = await self._message_queue.get()
                self._context.last_activity = datetime.now()
                
                # معالجة الرسالة
                response = await self._handle_message(message)
                
                # إرسال رد إذا لزم الأمر
                if response and message.correlation_id:
                    response.correlation_id = message.id
                    await self.send_message(response)
                
                self._context.tasks_completed += 1
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error processing message: {e}")
                self._context.tasks_failed += 1
    
    async def _handle_message(self, message: AgentMessage) -> Optional[AgentMessage]:
        """
        معالجة رسالة مستلمة (يتم تجاوزها في الوكلاء المشتقة)
        
        Args:
            message: الرسالة المستلمة
        
        Returns:
            رسالة رد أو None
        """
        # تنفيذ افتراضي
        return AgentMessage(
            id=str(uuid.uuid4())[:8],
            sender=self.name,
            receiver=message.sender,
            type="response",
            content={"status": "received", "original": message.content}
        )
    
    async def broadcast(self, message_type: str, content: Any) -> int:
        """
        بث رسالة إلى جميع الوكلاء
        
        Args:
            message_type: نوع الرسالة
            content: محتوى الرسالة
        
        Returns:
            عدد الوكلاء الذين استلموا الرسالة
        """
        # الحصول على جميع الوكلاء المسجلين
        if not self._container:
            return 0
        
        # هنا يمكن الحصول على قائمة الوكلاء من service_registry
        # تنفيذ مبسط
        return 0
    
    @abstractmethod
    async def _on_initialize(self):
        """دالة التهيئة المخصصة (يتم تجاوزها)"""
        pass
    
    @abstractmethod
    async def _on_start(self):
        """دالة البدء المخصصة (يتم تجاوزها)"""
        pass
    
    @abstractmethod
    async def _on_stop(self):
        """دالة الإيقاف المخصصة (يتم تجاوزها)"""
        pass
    
    def get_state(self) -> AgentState:
        """الحصول على حالة الوكيل"""
        return self._state
    
    def get_context(self) -> AgentContext:
        """الحصول على سياق الوكيل"""
        self._context.state = self._state
        return self._context
    
    def is_running(self) -> bool:
        """هل الوكيل قيد التشغيل؟"""
        return self._running and self._state == AgentState.IDLE
    
    async def health_check(self) -> bool:
        """فحص صحة الوكيل"""
        return self._running and self._state not in [AgentState.ERROR, AgentState.STOPPED]
    
    async def get_statistics(self) -> Dict:
        """إحصائيات الوكيل"""
        return {
            "id": self.id,
            "name": self.name,
            "state": self._state.value,
            "priority": self.priority.name,
            "uptime": (datetime.now() - self._context.start_time).total_seconds(),
            "tasks_completed": self._context.tasks_completed,
            "tasks_failed": self._context.tasks_failed,
            "queue_size": self._message_queue.qsize()
        }

