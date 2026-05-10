
import asyncio
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import heapq
import uuid

import logging

logger = logging.getLogger(__name__)


class NodeStatus(Enum):
    """حالة العقدة"""
    ACTIVE = "active"
    INACTIVE = "inactive"
    DEGRADED = "degraded"
    UNKNOWN = "unknown"


@dataclass
class Node:
    """عقدة في النظام الموزع"""
    id: str
    name: str
    address: str
    status: NodeStatus = NodeStatus.ACTIVE
    last_heartbeat: datetime = field(default_factory=datetime.now)
    capacity: int = 10  # عدد المهام المتزامنة
    current_load: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DistributedTask:
    """مهمة موزعة"""
    id: str
    name: str
    handler: Callable
    node_id: Optional[str] = None
    status: str = "pending"
    created_at: datetime = field(default_factory=datetime.now)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    result: Any = None
    error: Optional[str] = None
    priority: int = 3


class DistributedScheduler:
    """
    المجدول الموزع المتقدم
    
    الميزات:
    - توزيع المهام على العقد
    - موازنة الحمل
    - اكتشاف العقد غير النشطة
    - نقل المهام بين العقد
    """
    
    def __init__(self):
        self.nodes: Dict[str, Node] = {}
        self.tasks: Dict[str, DistributedTask] = {}
        self.task_queue: List[tuple] = []
        self._heartbeat_task: Optional[asyncio.Task] = None
        self._scheduler_task: Optional[asyncio.Task] = None
        self._running = False
        self._lock = asyncio.Lock()
        
        logger.info("DistributedScheduler initialized")
    
    async def start(self):
        """بدء تشغيل المجدول الموزع"""
        if self._running:
            return
        
        self._running = True
        self._heartbeat_task = asyncio.create_task(self._heartbeat_loop())
        self._scheduler_task = asyncio.create_task(self._scheduler_loop())
        
        logger.info("DistributedScheduler started")
    
    async def stop(self):
        """إيقاف تشغيل المجدول الموزع"""
        self._running = False
        
        if self._heartbeat_task:
            self._heartbeat_task.cancel()
        if self._scheduler_task:
            self._scheduler_task.cancel()
        
        logger.info("DistributedScheduler stopped")
    
    def register_node(
        self,
        node_id: str,
        name: str,
        address: str,
        capacity: int = 10,
        metadata: Dict = None
    ):
        """
        تسجيل عقدة جديدة
        
        Args:
            node_id: معرف العقدة
            name: اسم العقدة
            address: عنوان العقدة
            capacity: سعة العقدة
            metadata: بيانات إضافية
        """
        node = Node(
            id=node_id,
            name=name,
            address=address,
            capacity=capacity,
            metadata=metadata or {}
        )
        
        self.nodes[node_id] = node
        logger.info(f"Node registered: {name} ({node_id})")
    
    def unregister_node(self, node_id: str) -> bool:
        """
        إلغاء تسجيل عقدة
        
        Args:
            node_id: معرف العقدة
        
        Returns:
            نجاح الإلغاء
        """
        if node_id in self.nodes:
            del self.nodes[node_id]
            logger.info(f"Node unregistered: {node_id}")
            return True
        return False
    
    async def submit_task(
        self,
        name: str,
        handler: Callable,
        priority: int = 3,
        node_id: str = None,
        *args,
        **kwargs
    ) -> str:
        """
        إرسال مهمة جديدة
        
        Args:
            name: اسم المهمة
            handler: دالة المعالجة
            priority: الأولوية
            node_id: معرف العقدة المحددة (اختياري)
        
        Returns:
            معرف المهمة
        """
        task_id = str(uuid.uuid4())[:8]
        
        task = DistributedTask(
            id=task_id,
            name=name,
            handler=handler,
            node_id=node_id,
            priority=priority,
            args=args,
            kwargs=kwargs
        )
        
        async with self._lock:
            self.tasks[task_id] = task
            heapq.heappush(self.task_queue, (priority, task_id))
        
        logger.debug(f"Task submitted: {name} ({task_id})")
        return task_id
    
    async def _scheduler_loop(self):
        """حلقة الجدولة - توزيع المهام على العقد"""
        while self._running:
            try:
                # اختيار أفضل عقدة
                best_node = await self._select_best_node()
                
                if best_node is None:
                    await asyncio.sleep(1)
                    continue
                
                # اختيار مهمة من قائمة الانتظار
                async with self._lock:
                    if not self.task_queue:
                        await asyncio.sleep(0.5)
                        continue
                    
                    priority, task_id = heapq.heappop(self.task_queue)
                    task = self.tasks.get(task_id)
                    
                    if not task:
                        continue
                
                # تعيين المهمة للعقدة
                task.node_id = best_node.id
                task.status = "assigned"
                
                # محاكاة إرسال المهمة للعقدة
                asyncio.create_task(self._execute_on_node(task, best_node))
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Scheduler error: {e}")
                await asyncio.sleep(1)
    
    async def _select_best_node(self) -> Optional[Node]:
        """اختيار أفضل عقدة لتنفيذ المهمة"""
        available_nodes = [
            n for n in self.nodes.values()
            if n.status == NodeStatus.ACTIVE and n.current_load < n.capacity
        ]
        
        if not available_nodes:
            return None
        
        # اختيار العقدة الأقل حملاً
        return min(available_nodes, key=lambda x: x.current_load / x.capacity)
    
    async def _execute_on_node(self, task: DistributedTask, node: Node):
        """تنفيذ مهمة على عقدة محددة"""
        node.current_load += 1
        task.status = "running"
        task.started_at = datetime.now()
        
        try:
            if asyncio.iscoroutinefunction(task.handler):
                result = await task.handler(*task.args, **task.kwargs)
            else:
                result = task.handler(*task.args, **task.kwargs)
            
            task.result = result
            task.status = "completed"
            task.completed_at = datetime.now()
            
            logger.debug(f"Task completed on {node.name}: {task.name}")
            
        except Exception as e:
            task.status = "failed"
            task.error = str(e)
            task.completed_at = datetime.now()
            logger.error(f"Task failed on {node.name}: {task.name} - {e}")
        
        finally:
            node.current_load -= 1
    
    async def _heartbeat_loop(self):
        """حلقة مراقبة نبضات القلب للعقد"""
        while self._running:
            await asyncio.sleep(30)
            
            now = datetime.now()
            for node in self.nodes.values():
                time_since = (now - node.last_heartbeat).total_seconds()
                
                if time_since > 60:
                    node.status = NodeStatus.INACTIVE
                    logger.warning(f"Node {node.name} is inactive")
                elif time_since > 30:
                    node.status = NodeStatus.DEGRADED
    
    async def heartbeat(self, node_id: str) -> bool:
        """
        تحديث نبض قلب عقدة
        
        Args:
            node_id: معرف العقدة
        
        Returns:
            نجاح التحديث
        """
        if node_id in self.nodes:
            self.nodes[node_id].last_heartbeat = datetime.now()
            self.nodes[node_id].status = NodeStatus.ACTIVE
            return True
        return False
    
    async def get_statistics(self) -> Dict:
        """إحصائيات المجدول الموزع"""
        active_nodes = len([n for n in self.nodes.values() if n.status == NodeStatus.ACTIVE])
        pending_tasks = len([t for t in self.tasks.values() if t.status == "pending"])
        completed_tasks = len([t for t in self.tasks.values() if t.status == "completed"])
        failed_tasks = len([t for t in self.tasks.values() if t.status == "failed"])
        
        return {
            "total_nodes": len(self.nodes),
            "active_nodes": active_nodes,
            "total_tasks": len(self.tasks),
            "pending_tasks": pending_tasks,
            "completed_tasks": completed_tasks,
            "failed_tasks": failed_tasks,
            "running": self._running
        }

