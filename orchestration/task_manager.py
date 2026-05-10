
import asyncio
import uuid
from typing import Dict, List, Optional, Any, Set, Callable
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from collections import deque

import logging

logger = logging.getLogger(__name__)


class TaskPriority(Enum):
    """أولوية المهمة"""
    CRITICAL = 1
    HIGH = 2
    NORMAL = 3
    LOW = 4
    BACKGROUND = 5


class TaskStatus(Enum):
    """حالة المهمة"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class Task:
    """مهمة"""
    id: str
    name: str
    handler: Callable
    args: tuple
    kwargs: dict
    priority: TaskPriority
    status: TaskStatus = TaskStatus.PENDING
    created_at: datetime = field(default_factory=datetime.now)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    result: Any = None
    error: Optional[str] = None
    retry_count: int = 0
    max_retries: int = 3
    dependencies: List[str] = field(default_factory=list)


class TaskManager:
    """
    مدير المهام المتقدم
    
    الميزات:
    - جدولة المهام بأولويات مختلفة
    - تنفيذ متزامن ومتوازي
    - إعادة محاولة المهام الفاشلة
    - تتبع التبعيات بين المهام
    - مقاييس الأداء
    """
    
    def __init__(self, max_concurrent: int = 10):
        self.max_concurrent = max_concurrent
        self.tasks: Dict[str, Task] = {}
        self.task_queues: Dict[TaskPriority, asyncio.Queue] = {
            priority: asyncio.Queue()
            for priority in TaskPriority
        }
        self.running_tasks: Set[str] = set()
        self.completed_tasks: Set[str] = set()
        self.failed_tasks: Set[str] = set()
        self._lock = asyncio.Lock()
        self._scheduler_task: Optional[asyncio.Task] = None
        self._workers: List[asyncio.Task] = []
        self._running = False
        
        logger.info(f"TaskManager initialized (max_concurrent={max_concurrent})")
    
    async def start(self):
        """بدء تشغيل مدير المهام"""
        if self._running:
            return
        
        self._running = True
        self._scheduler_task = asyncio.create_task(self._scheduler_loop())
        
        for i in range(self.max_concurrent):
            worker = asyncio.create_task(self._worker_loop(i))
            self._workers.append(worker)
        
        logger.info("TaskManager started")
    
    async def stop(self):
        """إيقاف تشغيل مدير المهام"""
        self._running = False
        
        if self._scheduler_task:
            self._scheduler_task.cancel()
        
        for worker in self._workers:
            worker.cancel()
        
        await asyncio.gather(*self._workers, return_exceptions=True)
        
        logger.info("TaskManager stopped")
    
    async def submit_task(
        self,
        name: str,
        handler: Callable,
        *args,
        priority: TaskPriority = TaskPriority.NORMAL,
        max_retries: int = 3,
        dependencies: List[str] = None,
        **kwargs
    ) -> str:
        """
        إرسال مهمة جديدة
        
        Args:
            name: اسم المهمة
            handler: دالة المعالجة
            priority: الأولوية
            max_retries: عدد مرات إعادة المحاولة
            dependencies: قائمة التبعيات
        
        Returns:
            معرف المهمة
        """
        task_id = str(uuid.uuid4())[:8]
        
        task = Task(
            id=task_id,
            name=name,
            handler=handler,
            args=args,
            kwargs=kwargs,
            priority=priority,
            max_retries=max_retries,
            dependencies=dependencies or []
        )
        
        async with self._lock:
            self.tasks[task_id] = task
        
        # إضافة إلى قائمة الانتظار المناسبة
        await self.task_queues[priority].put(task_id)
        
        logger.debug(f"Task submitted: {name} ({task_id})")
        return task_id
    
    async def _scheduler_loop(self):
        """حلقة الجدولة - توزيع المهام على العمال"""
        while self._running:
            try:
                # اختيار مهمة بأعلى أولوية
                task_id = None
                for priority in [TaskPriority.CRITICAL, TaskPriority.HIGH,
                                 TaskPriority.NORMAL, TaskPriority.LOW,
                                 TaskPriority.BACKGROUND]:
                    if not self.task_queues[priority].empty():
                        task_id = await self.task_queues[priority].get()
                        break
                
                if task_id is None:
                    await asyncio.sleep(0.1)
                    continue
                
                # التحقق من التبعيات
                task = self.tasks.get(task_id)
                if task and task.dependencies:
                    deps_met = all(
                        dep in self.completed_tasks
                        for dep in task.dependencies
                    )
                    if not deps_met:
                        # إعادة المهمة إلى قائمة الانتظار
                        await self.task_queues[task.priority].put(task_id)
                        continue
                
                # انتظار دور في الـ semaphore
                while len(self.running_tasks) >= self.max_concurrent:
                    await asyncio.sleep(0.1)
                
                # تشغيل المهمة
                asyncio.create_task(self._execute_task(task_id))
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Scheduler error: {e}")
    
    async def _worker_loop(self, worker_id: int):
        """حلقة العامل - تنفيذ المهام"""
        while self._running:
            await asyncio.sleep(0.1)
    
    async def _execute_task(self, task_id: str):
        """تنفيذ مهمة محددة"""
        task = self.tasks.get(task_id)
        if not task:
            return
        
        async with self._lock:
            task.status = TaskStatus.RUNNING
            task.started_at = datetime.now()
            self.running_tasks.add(task_id)
        
        try:
            # تنفيذ المعالج
            if asyncio.iscoroutinefunction(task.handler):
                result = await task.handler(*task.args, **task.kwargs)
            else:
                result = task.handler(*task.args, **task.kwargs)
            
            async with self._lock:
                task.status = TaskStatus.COMPLETED
                task.completed_at = datetime.now()
                task.result = result
                self.running_tasks.discard(task_id)
                self.completed_tasks.add(task_id)
            
            logger.debug(f"Task completed: {task.name} ({task_id})")
            
        except Exception as e:
            logger.error(f"Task failed: {task.name} - {e}")
            
            if task.retry_count < task.max_retries:
                task.retry_count += 1
                task.status = TaskStatus.PENDING
                await self.task_queues[task.priority].put(task_id)
                logger.debug(f"Task retry {task.retry_count}/{task.max_retries}: {task.name}")
            else:
                async with self._lock:
                    task.status = TaskStatus.FAILED
                    task.completed_at = datetime.now()
                    task.error = str(e)
                    self.running_tasks.discard(task_id)
                    self.failed_tasks.add(task_id)
    
    async def get_task_status(self, task_id: str) -> Optional[Dict]:
        """الحصول على حالة مهمة"""
        task = self.tasks.get(task_id)
        if not task:
            return None
        
        return {
            "id": task.id,
            "name": task.name,
            "status": task.status.value,
            "priority": task.priority.name,
            "created_at": task.created_at.isoformat(),
            "started_at": task.started_at.isoformat() if task.started_at else None,
            "completed_at": task.completed_at.isoformat() if task.completed_at else None,
            "error": task.error,
            "retry_count": task.retry_count
        }
    
    async def cancel_task(self, task_id: str) -> bool:
        """إلغاء مهمة"""
        task = self.tasks.get(task_id)
        if not task:
            return False
        
        if task.status == TaskStatus.PENDING:
            task.status = TaskStatus.CANCELLED
            logger.info(f"Task cancelled: {task.name} ({task_id})")
            return True
        
        return False
    
    async def get_statistics(self) -> Dict:
        """إحصائيات مدير المهام"""
        return {
            "total_tasks": len(self.tasks),
            "pending_tasks": len([t for t in self.tasks.values() if t.status == TaskStatus.PENDING]),
            "running_tasks": len(self.running_tasks),
            "completed_tasks": len(self.completed_tasks),
            "failed_tasks": len(self.failed_tasks),
            "cancelled_tasks": len([t for t in self.tasks.values() if t.status == TaskStatus.CANCELLED]),
            "max_concurrent": self.max_concurrent,
            "running": self._running
        }

