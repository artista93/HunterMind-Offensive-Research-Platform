
import asyncio
import uuid
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

from .base_agent import BaseAgent, AgentPriority, AgentState
from .agent_state import AgentStateManager

import logging

logger = logging.getLogger(__name__)


class AgentType(Enum):
    """نوع الوكيل"""
    CRAWLER = "crawler"
    RECON = "recon"
    XSS = "xss"
    SQLI = "sqli"
    IDOR = "idor"
    WAF = "waf"
    AUTH = "auth"
    EXPLOITATION = "exploitation"
    LEARNING = "learning"
    REASONING = "reasoning"
    PLANNING = "planning"
    CUSTOM = "custom"


@dataclass
class AgentInfo:
    """معلومات الوكيل"""
    agent_id: str
    agent_name: str
    agent_type: AgentType
    priority: AgentPriority
    state: AgentState
    capabilities: List[str]
    registered_at: datetime
    last_heartbeat: datetime
    metadata: Dict[str, Any] = field(default_factory=dict)


class AgentRegistry:
    """
    سجل الوكلاء المتقدم
    
    الميزات:
    - تسجيل وإلغاء تسجيل الوكلاء
    - اكتشاف الوكلاء حسب النوع والإمكانيات
    - توزيع المهام بين الوكلاء
    - مراقبة نبضات القلب
    - تنشيط تلقائي للوكلاء
    - تنسيق الاتصال بين الوكلاء
    """
    
    def __init__(self):
        self._agents: Dict[str, BaseAgent] = {}
        self._agents_info: Dict[str, AgentInfo] = {}
        self._agents_by_type: Dict[AgentType, List[str]] = {}
        self._agents_by_capability: Dict[str, List[str]] = {}
        
        self._heartbeat_task: Optional[asyncio.Task] = None
        self._cleanup_task: Optional[asyncio.Task] = None
        self._running = False
        self._lock = asyncio.Lock()
        
        # إحصائيات
        self._stats = {
            "total_agents": 0,
            "active_agents": 0,
            "dead_agents": 0,
            "heartbeat_timeout": 60  # ثواني
        }
        
        logger.info("AgentRegistry initialized")
    
    async def start(self):
        """بدء تشغيل السجل"""
        if self._running:
            return
        
        self._running = True
        self._heartbeat_task = asyncio.create_task(self._heartbeat_loop())
        self._cleanup_task = asyncio.create_task(self._cleanup_loop())
        
        logger.info("AgentRegistry started")
    
    async def stop(self):
        """إيقاف تشغيل السجل"""
        if not self._running:
            return
        
        self._running = False
        
        if self._heartbeat_task:
            self._heartbeat_task.cancel()
        if self._cleanup_task:
            self._cleanup_task.cancel()
        
        # إيقاف جميع الوكلاء
        for agent in self._agents.values():
            try:
                await agent.stop()
            except Exception as e:
                logger.error(f"Error stopping agent {agent.name}: {e}")
        
        logger.info("AgentRegistry stopped")
    
    async def register_agent(
        self,
        agent: BaseAgent,
        agent_type: AgentType,
        capabilities: List[str] = None,
        metadata: Dict = None
    ) -> bool:
        """
        تسجيل وكيل جديد
        
        Args:
            agent: الوكيل
            agent_type: نوع الوكيل
            capabilities: قائمة الإمكانيات
            metadata: بيانات إضافية
        
        Returns:
            نجاح التسجيل
        """
        async with self._lock:
            if agent.id in self._agents:
                logger.warning(f"Agent {agent.name} already registered")
                return False
            
            # تخزين الوكيل
            self._agents[agent.id] = agent
            
            # تخزين المعلومات
            agent_info = AgentInfo(
                agent_id=agent.id,
                agent_name=agent.name,
                agent_type=agent_type,
                priority=agent.priority,
                state=agent.get_state(),
                capabilities=capabilities or [],
                registered_at=datetime.now(),
                last_heartbeat=datetime.now(),
                metadata=metadata or {}
            )
            self._agents_info[agent.id] = agent_info
            
            # فهرسة حسب النوع
            if agent_type not in self._agents_by_type:
                self._agents_by_type[agent_type] = []
            self._agents_by_type[agent_type].append(agent.id)
            
            # فهرسة حسب الإمكانيات
            for cap in capabilities or []:
                if cap not in self._agents_by_capability:
                    self._agents_by_capability[cap] = []
                self._agents_by_capability[cap].append(agent.id)
            
            self._stats["total_agents"] += 1
            self._stats["active_agents"] += 1
        
        logger.info(f"Agent registered: {agent.name} ({agent_type.value})")
        return True
    
    async def unregister_agent(self, agent_id: str) -> bool:
        """
        إلغاء تسجيل وكيل
        
        Args:
            agent_id: معرف الوكيل
        
        Returns:
            نجاح إلغاء التسجيل
        """
        async with self._lock:
            if agent_id not in self._agents:
                return False
            
            agent = self._agents[agent_id]
            agent_info = self._agents_info[agent_id]
            
            # إزالة من الفهارس
            self._agents_by_type[agent_info.agent_type].remove(agent_id)
            if not self._agents_by_type[agent_info.agent_type]:
                del self._agents_by_type[agent_info.agent_type]
            
            for cap in agent_info.capabilities:
                if cap in self._agents_by_capability:
                    self._agents_by_capability[cap].remove(agent_id)
                    if not self._agents_by_capability[cap]:
                        del self._agents_by_capability[cap]
            
            # حذف
            del self._agents[agent_id]
            del self._agents_info[agent_id]
            
            self._stats["total_agents"] -= 1
            self._stats["active_agents"] -= 1
        
        logger.info(f"Agent unregistered: {agent.name}")
        return True
    
    async def get_agent(self, agent_id: str) -> Optional[BaseAgent]:
        """الحصول على وكيل بالمعرف"""
        async with self._lock:
            return self._agents.get(agent_id)
    
    async def get_agent_info(self, agent_id: str) -> Optional[AgentInfo]:
        """الحصول على معلومات وكيل"""
        async with self._lock:
            return self._agents_info.get(agent_id)
    
    async def get_agents_by_type(self, agent_type: AgentType) -> List[BaseAgent]:
        """الحصول على وكلاء حسب النوع"""
        async with self._lock:
            agent_ids = self._agents_by_type.get(agent_type, [])
            return [self._agents[aid] for aid in agent_ids if aid in self._agents]
    
    async def get_agents_by_capability(self, capability: str) -> List[BaseAgent]:
        """الحصول على وكلاء حسب الإمكانية"""
        async with self._lock:
            agent_ids = self._agents_by_capability.get(capability, [])
            return [self._agents[aid] for aid in agent_ids if aid in self._agents]
    
    async def get_best_agent(
        self,
        task_type: str,
        required_capabilities: List[str] = None
    ) -> Optional[BaseAgent]:
        """
        الحصول على أفضل وكيل للمهمة
        
        Args:
            task_type: نوع المهمة
            required_capabilities: الإمكانيات المطلوبة
        
        Returns:
            أفضل وكيل مناسب
        """
        async with self._lock:
            candidates = []
            
            # تحديد نوع الوكيل المناسب
            agent_type_map = {
                "crawl": AgentType.CRAWLER,
                "recon": AgentType.RECON,
                "xss": AgentType.XSS,
                "sqli": AgentType.SQLI,
                "idor": AgentType.IDOR,
                "exploit": AgentType.EXPLOITATION,
                "auth": AgentType.AUTH,
                "learning": AgentType.LEARNING
            }
            
            agent_type = agent_type_map.get(task_type.lower())
            
            if agent_type:
                candidates = await self.get_agents_by_type(agent_type)
            
            # تصفية حسب الإمكانيات
            if required_capabilities:
                candidates = [
                    a for a in candidates
                    if all(cap in await self.get_agent_capabilities(a.id) for cap in required_capabilities)
                ]
            
            # اختيار أفضل وكيل (أعلى أولوية، أقل حمل)
            if candidates:
                # ترتيب حسب الأولوية
                candidates.sort(key=lambda a: a.priority.value)
                return candidates[0]
            
            return None
    
    async def get_agent_capabilities(self, agent_id: str) -> List[str]:
        """الحصول على إمكانيات الوكيل"""
        async with self._lock:
            if agent_id in self._agents_info:
                return self._agents_info[agent_id].capabilities
            return []
    
    async def update_heartbeat(self, agent_id: str) -> bool:
        """
        تحديث نبض قلب الوكيل
        
        Args:
            agent_id: معرف الوكيل
        
        Returns:
            نجاح التحديث
        """
        async with self._lock:
            if agent_id not in self._agents_info:
                return False
            
            self._agents_info[agent_id].last_heartbeat = datetime.now()
            return True
    
    async def _heartbeat_loop(self):
        """حلقة مراقبة نبضات القلب"""
        while self._running:
            await asyncio.sleep(30)  # كل 30 ثانية
            
            now = datetime.now()
            timeout_seconds = self._stats["heartbeat_timeout"]
            
            async with self._lock:
                for agent_id, info in self._agents_info.items():
                    time_since_heartbeat = (now - info.last_heartbeat).total_seconds()
                    
                    if time_since_heartbeat > timeout_seconds:
                        logger.warning(f"Agent {info.agent_name} missed heartbeat")
                        # محاولة إعادة التنشيط
                        agent = self._agents.get(agent_id)
                        if agent and not agent.is_running():
                            asyncio.create_task(self._reactivate_agent(agent_id))
    
    async def _cleanup_loop(self):
        """حلقة تنظيف الوكلاء الميتين"""
        while self._running:
            await asyncio.sleep(300)  # كل 5 دقائق
            
            dead_agents = []
            
            async with self._lock:
                for agent_id, info in self._agents_info.items():
                    time_since_heartbeat = (datetime.now() - info.last_heartbeat).total_seconds()
                    
                    if time_since_heartbeat > self._stats["heartbeat_timeout"] * 2:
                        dead_agents.append(agent_id)
            
            for agent_id in dead_agents:
                await self.unregister_agent(agent_id)
                self._stats["dead_agents"] += 1
            
            if dead_agents:
                logger.info(f"Cleaned up {len(dead_agents)} dead agents")
    
    async def _reactivate_agent(self, agent_id: str) -> bool:
        """
        إعادة تنشيط وكيل متوقف
        
        Args:
            agent_id: معرف الوكيل
        
        Returns:
            نجاح إعادة التنشيط
        """
        async with self._lock:
            if agent_id not in self._agents:
                return False
            
            agent = self._agents[agent_id]
            
            try:
                await agent.stop()
                await agent.initialize()
                await agent.start()
                
                self._agents_info[agent_id].last_heartbeat = datetime.now()
                self._agents_info[agent_id].state = AgentState.IDLE
                
                logger.info(f"Agent reactivated: {agent.name}")
                return True
                
            except Exception as e:
                logger.error(f"Failed to reactivate agent {agent.name}: {e}")
                return False
    
    async def broadcast(
        self,
        message_type: str,
        content: Any,
        agent_type: AgentType = None,
        min_priority: AgentPriority = None
    ) -> int:
        """
        بث رسالة إلى مجموعة من الوكلاء
        
        Args:
            message_type: نوع الرسالة
            content: محتوى الرسالة
            agent_type: نوع الوكيل (اختياري)
            min_priority: الحد الأدنى للأولوية (اختياري)
        
        Returns:
            عدد الوكلاء الذين استلموا الرسالة
        """
        recipients = []
        
        async with self._lock:
            if agent_type:
                agent_ids = self._agents_by_type.get(agent_type, [])
            else:
                agent_ids = list(self._agents.keys())
            
            for agent_id in agent_ids:
                if agent_id in self._agents:
                    info = self._agents_info[agent_id]
                    if not min_priority or info.priority.value <= min_priority.value:
                        recipients.append(self._agents[agent_id])
        
        # إرسال الرسائل بشكل متوازي
        tasks = []
        for agent in recipients:
            from .base_agent import AgentMessage
            message = AgentMessage(
                id=str(uuid.uuid4())[:8],
                sender="registry",
                receiver=agent.name,
                type=message_type,
                content=content
            )
            tasks.append(agent.send_message(message))
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return sum(1 for r in results if r is True)
    
    async def get_all_agents(self) -> List[BaseAgent]:
        """الحصول على جميع الوكلاء"""
        async with self._lock:
            return list(self._agents.values())
    
    async def get_statistics(self) -> Dict:
        """إحصائيات السجل"""
        async with self._lock:
            agents_by_state = {}
            for info in self._agents_info.values():
                state = info.state.value
                agents_by_state[state] = agents_by_state.get(state, 0) + 1
            
            return {
                **self._stats,
                "active_agents": len(self._agents),
                "agents_by_type": {k.value: len(v) for k, v in self._agents_by_type.items()},
                "agents_by_state": agents_by_state,
                "total_capabilities": len(self._agents_by_capability),
                "running": self._running
            }
    
    async def get_agents_summary(self) -> List[Dict]:
        """ملخص الوكلاء"""
        async with self._lock:
            return [
                {
                    "id": info.agent_id,
                    "name": info.agent_name,
                    "type": info.agent_type.value,
                    "priority": info.priority.name,
                    "state": info.state.value,
                    "capabilities": info.capabilities,
                    "registered_at": info.registered_at.isoformat(),
                    "last_heartbeat": info.last_heartbeat.isoformat()
                }
                for info in self._agents_info.values()
            ]


# نسخة عالمية
_default_registry = None


def get_agent_registry() -> AgentRegistry:
    """الحصول على نسخة عالمية من سجل الوكلاء"""
    global _default_registry
    if _default_registry is None:
        _default_registry = AgentRegistry()
    return _default_registry

