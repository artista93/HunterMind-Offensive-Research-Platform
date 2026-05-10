
import asyncio
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
import heapq

import logging

logger = logging.getLogger(__name__)


class ScheduleType(Enum):
    """نوع الجدولة"""
    ONCE = "once"
    INTERVAL = "interval"
    CRON = "cron"


@dataclass
class ScheduledTask:
    """مهمة مجدولة"""
    id: str
    name: str
    handler: Callable
    schedule_type: ScheduleType
    interval_seconds: float = 0
    cron_expression: str = ""
    next_run: datetime = field(default_factory=datetime.now)
    args: tuple = ()
    kwargs: dict = field(default_factory=dict)
    enabled: bool = True
    run_count: int = 0
    last_run: Optional[datetime] = None
    last_error: Optional[str] = None


class AsyncScheduler:
    """
    المجدول غير المتزامن المتقدم
    
    الميزات:
    - جدولة مهام لمرة واحدة أو دورية
    - تنفيذ غير متزامن
    - أولويات للمهام
    - تتبع تنفيذ المهام
    """
    
    def __init__(self):
        self.tasks: Dict[str, ScheduledTask] = {}
        self.task_heap: List[tuple] = []  # (next_run, task_id)
        self._scheduler_task: Optional[asyncio.Task] = None
        self._running = False
        self._lock = asyncio.Lock()
        
        logger.info("AsyncScheduler initialized")
    
    async def start(self):
        """بدء تشغيل المجدول"""
        if self._running:
            return
        
        self._running = True
        self._scheduler_task = asyncio.create_task(self._scheduler_loop())
        logger.info("AsyncScheduler started")
    
    async def stop(self):
        """إيقاف تشغيل المجدول"""
        self._running = False
        
        if self._scheduler_task:
            self._scheduler_task.cancel()
            try:
                await self._scheduler_task
            except asyncio.CancelledError:
                pass
        
        logger.info("AsyncScheduler stopped")
    
    async def schedule_once(
        self,
        name: str,
        handler: Callable,
        delay_seconds: float,
        *args,
        **kwargs
    ) -> str:
        """
        جدولة مهمة لمرة واحدة
        
        Args:
            name: اسم المهمة
            handler: دالة المعالجة
            delay_seconds: التأخير بالثواني
            *args, **kwargs: معاملات الدالة
        
        Returns:
            معرف المهمة
        """
        import uuid
        task_id = str(uuid.uuid4())[:8]
        
        task = ScheduledTask(
            id=task_id,
            name=name,
            handler=handler,
            schedule_type=ScheduleType.ONCE,
            next_run=datetime.now() + timedelta(seconds=delay_seconds),
            args=args,
            kwargs=kwargs
        )
        
        async with self._lock:
            self.tasks[task_id] = task
            heapq.heappush(self.task_heap, (task.next_run.timestamp(), task_id))
        
        logger.debug(f"Task scheduled (once): {name} in {delay_seconds}s")
        return task_id
    
    async def schedule_interval(
        self,
        name: str,
        handler: Callable,
        interval_seconds: float,
        *args,
        **kwargs
    ) -> str:
        """
        جدولة مهمة دورية
        
        Args:
            name: اسم المهمة
            handler: دالة المعالجة
            interval_seconds: الفاصل الزمني بالثواني
            *args, **kwargs: معاملات الدالة
        
        Returns:
            معرف المهمة
        """
        import uuid
        task_id = str(uuid.uuid4())[:8]
        
        task = ScheduledTask(
            id=task_id,
            name=name,
            handler=handler,
            schedule_type=ScheduleType.INTERVAL,
            interval_seconds=interval_seconds,
            next_run=datetime.now(),
            args=args,
            kwargs=kwargs
        )
        
        async with self._lock:
            self.tasks[task_id] = task
            heapq.heappush(self.task_heap, (task.next_run.timestamp(), task_id))
        
        logger.info(f"Task scheduled (interval): {name} every {interval_seconds}s")
        return task_id
    
    async def unschedule(self, task_id: str) -> bool:
        """
        إلغاء جدولة مهمة
        
        Args:
            task_id: معرف المهمة
        
        Returns:
            نجاح الإلغاء
        """
        async with self._lock:
            if task_id in self.tasks:
                self.tasks[task_id].enabled = False
                logger.debug(f"Task unscheduled: {task_id}")
                return True
        return False
    
    async def _scheduler_loop(self):
        """حلقة المجدول الرئيسية"""
        while self._running:
            try:
                next_task = await self._get_next_task()
                
                if next_task is None:
                    await asyncio.sleep(1)
                    continue
                
                now = datetime.now()
                wait_seconds = (next_task.next_run - now).total_seconds()
                
                if wait_seconds > 0:
                    await asyncio.sleep(min(wait_seconds, 60))
                    continue
                
                # تنفيذ المهمة
                asyncio.create_task(self._execute_task(next_task.id))
                
                # إعادة جدولة المهمة الدورية
                if next_task.schedule_type == ScheduleType.INTERVAL and next_task.enabled:
                    next_task.next_run = datetime.now() + timedelta(seconds=next_task.interval_seconds)
                    async with self._lock:
                        heapq.heappush(self.task_heap, (next_task.next_run.timestamp(), next_task.id))
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Scheduler loop error: {e}")
                await asyncio.sleep(1)
    
    async def _get_next_task(self) -> Optional[ScheduledTask]:
        """الحصول على المهمة التالية للتنفيذ"""
        async with self._lock:
            while self.task_heap:
                next_time, task_id = self.task_heap[0]
                task = self.tasks.get(task_id)
                
                if not task or not task.enabled:
                    heapq.heappop(self.task_heap)
                    continue
                
                return task
            
            return None
    
    async def _execute_task(self, task_id: str):
        """تنفيذ مهمة مجدولة"""
        task = self.tasks.get(task_id)
        if not task or not task.enabled:
            return
        
        try:
            if asyncio.iscoroutinefunction(task.handler):
                await task.handler(*task.args, **task.kwargs)
            else:
                task.handler(*task.args, **task.kwargs)
            
            task.run_count += 1
            task.last_run = datetime.now()
            task.last_error = None
            
            logger.debug(f"Task executed: {task.name} ({task_id})")
            
        except Exception as e:
            task.last_error = str(e)
            logger.error(f"Task failed: {task.name} - {e}")
    
    async def get_tasks(self) -> List[Dict]:
        """الحصول على قائمة المهام المجدولة"""
        tasks = []
        for task in self.tasks.values():
            tasks.append({
                "id": task.id,
                "name": task.name,
                "type": task.schedule_type.value,
                "enabled": task.enabled,
                "run_count": task.run_count,
                "next_run": task.next_run.isoformat(),
                "last_run": task.last_run.isoformat() if task.last_run else None,
                "last_error": task.last_error
            })
        return tasks
    
    async def get_statistics(self) -> Dict:
        """إحصائيات المجدول"""
        total = len(self.tasks)
        enabled = len([t for t in self.tasks.values() if t.enabled])
        total_runs = sum(t.run_count for t in self.tasks.values())
        
        return {
            "total_tasks": total,
            "enabled_tasks": enabled,
            "total_executions": total_runs,
            "tasks_by_type": {
                ScheduleType.ONCE.value: len([t for t in self.tasks.values() if t.schedule_type == ScheduleType.ONCE]),
                ScheduleType.INTERVAL.value: len([t for t in self.tasks.values() if t.schedule_type == ScheduleType.INTERVAL])
            },
            "running": self._running
        }

