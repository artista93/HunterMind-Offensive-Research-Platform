
import asyncio
import signal
import time
import traceback
import logging
import uuid
from typing import Dict, List, Optional, Any, Callable, Awaitable, Coroutine, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from contextlib import asynccontextmanager
import concurrent.futures

logger = logging.getLogger(__name__)


class TaskPriority(Enum):
    """أولوية المهمة"""
    CRITICAL = 0
    HIGH = 1
    NORMAL = 2
    LOW = 3
    BACKGROUND = 4


class TaskStatus(Enum):
    """حالة المهمة"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    TIMEOUT = "timeout"


@dataclass
class AsyncTask:
    """مهمة غير متزامنة"""
    id: str
    name: str
    coroutine: Coroutine
    priority: TaskPriority
    status: TaskStatus = TaskStatus.PENDING
    created_at: datetime = field(default_factory=datetime.now)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    error: Optional[str] = None
    result: Any = None
    timeout: Optional[float] = None
    retry_count: int = 0
    max_retries: int = 0
    parent_task_id: Optional[str] = None
    
    # المهمة asyncio الفعلية
    asyncio_task: Optional[asyncio.Task] = None
    
    # Future للانتظار بدون polling
    completion_future: Optional[asyncio.Future] = None
    
    # إحصائيات
    execution_time: float = 0.0
    memory_usage: float = 0.0


class AsyncRuntime:
    """
    بيئة التشغيل غير المتزامنة النهائية
    
    الميزات:
    - Scheduler واحد مع Semaphore
    - تتبع حقيقي للمهام
    - Future-based waiting (بدون polling)
    - إلغاء حقيقي
    - Weighted scheduling مع Aging
    - Backpressure حقيقي
    - تنظيف تلقائي للمهام القديمة
    """
    
    def __init__(
        self,
        max_concurrent_tasks: int = 50,
        task_timeout_default: float = 300.0,
        queue_max_size: int = 1000,
        max_completed_tasks: int = 10000,
        enable_metrics: bool = True,
        # معاملات الجدولة
        priority_weights: Optional[Dict[TaskPriority, float]] = None,
        aging_factor: float = 0.1
    ):
        self._max_concurrent_tasks = max_concurrent_tasks
        self._task_timeout_default = task_timeout_default
        self._queue_max_size = queue_max_size
        self._max_completed_tasks = max_completed_tasks
        self._enable_metrics = enable_metrics
        self._aging_factor = aging_factor
        
        # أوزان الأولويات (للـ Weighted Round Robin)
        self._priority_weights = priority_weights or {
            TaskPriority.CRITICAL: 1.0,
            TaskPriority.HIGH: 0.7,
            TaskPriority.NORMAL: 0.4,
            TaskPriority.LOW: 0.2,
            TaskPriority.BACKGROUND: 0.1
        }
        
        # قوائم المهام - استخدام put_nowait للـ backpressure الحقيقي
        self._task_queues: Dict[TaskPriority, asyncio.Queue] = {}
        for priority in TaskPriority:
            self._task_queues[priority] = asyncio.Queue(maxsize=queue_max_size)
        
        # تخزين المهام
        self._tasks: Dict[str, AsyncTask] = {}
        self._active_asyncio_tasks: Dict[str, asyncio.Task] = {}
        self._pending_task_ids: Set[str] = set()
        self._completed_task_ids: List[str] = []  # قائمة للتنظيف
        
        # التحكم في التوافقية
        self._semaphore = asyncio.Semaphore(max_concurrent_tasks)
        
        # تتبع المهام النشطة
        self._running_task_ids: Set[str] = set()
        self._tasks_lock = asyncio.Lock()
        
        # جدولة Weighted Round Robin
        self._priority_tokens: Dict[TaskPriority, float] = {
            priority: 0.0 for priority in TaskPriority
        }
        self._priority_last_run: Dict[TaskPriority, float] = {
            priority: 0.0 for priority in TaskPriority
        }
        
        # معاملات لتحسين الجدولة
        self._scheduler_tokens = 1.0  # عدد الرموز المتراكمة
        
        # مكونات التشغيل
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._scheduler_task: Optional[asyncio.Task] = None
        self._cleanup_task: Optional[asyncio.Task] = None
        self._running = False
        self._shutdown_event = asyncio.Event()
        self._draining = False
        
        # تجمع الخيوط للمهام المتزامنة
        self._thread_pool = concurrent.futures.ThreadPoolExecutor(
            max_workers=min(10, max_concurrent_tasks // 5),
            thread_name_prefix="AsyncRuntimeWorker"
        )
        
        # إحصائيات
        self._stats = {
            "total_tasks_submitted": 0,
            "total_tasks_completed": 0,
            "total_tasks_failed": 0,
            "total_tasks_cancelled": 0,
            "total_tasks_timeout": 0,
            "peak_concurrent_tasks": 0,
            "average_task_time": 0.0,
            "queue_overflows": 0,
            "cleaned_tasks": 0
        }
        
        # مقاييس الوقت
        self._task_times: List[float] = []
        
        logger.info(f"AsyncRuntime initialized (max_concurrent={max_concurrent_tasks})")
    
    async def start(self):
        """بدء تشغيل البيئة"""
        if self._running:
            return
        
        self._running = True
        self._draining = False
        self._loop = asyncio.get_running_loop()
        
        # بدء المجدول
        self._scheduler_task = asyncio.create_task(self._scheduler_loop())
        
        # بدء مهمة التنظيف التلقائي
        self._cleanup_task = asyncio.create_task(self._cleanup_loop())
        
        logger.info(f"AsyncRuntime started")
    
    async def shutdown(self, timeout: float = 30.0):
        """إيقاف تشغيل البيئة"""
        if not self._running:
            return
        
        logger.info("Shutting down AsyncRuntime...")
        
        # 1. إلغاء المجدول أولاً (لا مهام جديدة)
        self._running = False
        if self._scheduler_task and not self._scheduler_task.done():
            self._scheduler_task.cancel()
            try:
                await self._scheduler_task
            except asyncio.CancelledError:
                pass
        
        # 2. وضع التصريف - انتظار المهام الجارية
        self._draining = True
        if self._running_task_ids:
            logger.info(f"Waiting for {len(self._running_task_ids)} running tasks...")
            try:
                await asyncio.wait_for(self._wait_for_running_tasks(), timeout=timeout)
            except asyncio.TimeoutError:
                logger.warning("Timeout waiting for tasks, cancelling...")
                await self._cancel_all_running_tasks()
        
        # 3. إلغاء مهمة التنظيف
        if self._cleanup_task and not self._cleanup_task.done():
            self._cleanup_task.cancel()
        
        # 4. إغلاق تجمع الخيوط
        self._thread_pool.shutdown(wait=False)
        
        self._shutdown_event.set()
        logger.info("AsyncRuntime stopped")
    
    async def _wait_for_running_tasks(self):
        """انتظار المهام الجارية"""
        while self._running_task_ids:
            # استخدام asyncio.wait على المهام الحقيقية
            active_tasks = [
                self._active_asyncio_tasks[tid]
                for tid in self._running_task_ids
                if tid in self._active_asyncio_tasks
            ]
            if active_tasks:
                await asyncio.wait(active_tasks, timeout=0.5)
            else:
                await asyncio.sleep(0.05)
    
    async def _cancel_all_running_tasks(self):
        """إلغاء جميع المهام الجارية"""
        for task_id, asyncio_task in list(self._active_asyncio_tasks.items()):
            if not asyncio_task.done():
                asyncio_task.cancel()
    
    async def _cleanup_loop(self):
        """حلقة التنظيف التلقائي للمهام المكتملة"""
        while self._running:
            await asyncio.sleep(60)  # كل دقيقة
            
            async with self._tasks_lock:
                # جمع المهام المكتملة القديمة
                to_remove = []
                now = time.time()
                
                for task_id in self._completed_task_ids:
                    task = self._tasks.get(task_id)
                    if task and task.completed_at:
                        age = (datetime.now() - task.completed_at).total_seconds()
                        if age > 300:  # 5 دقائق
                            to_remove.append(task_id)
                
                # حذف المهام القديمة
                for task_id in to_remove:
                    if task_id in self._tasks:
                        del self._tasks[task_id]
                        self._completed_task_ids.remove(task_id)
                        self._stats["cleaned_tasks"] += 1
                
                # التحكم في الحجم الأقصى
                while len(self._completed_task_ids) > self._max_completed_tasks:
                    oldest = self._completed_task_ids.pop(0)
                    if oldest in self._tasks:
                        del self._tasks[oldest]
                        self._stats["cleaned_tasks"] += 1
    
    async def submit_task(
        self,
        name: str,
        coroutine: Coroutine,
        priority: TaskPriority = TaskPriority.NORMAL,
        timeout: Optional[float] = None,
        max_retries: int = 0,
        parent_task_id: Optional[str] = None
    ) -> str:
        """
        إرسال مهمة للتنفيذ مع backpressure حقيقي
        """
        if self._draining or not self._running:
            raise RuntimeError("Runtime is shutting down")
        
        # استخدام UUID كامل لمنع التصادم
        task_id = str(uuid.uuid4())
        
        task = AsyncTask(
            id=task_id,
            name=name,
            coroutine=coroutine,
            priority=priority,
            timeout=timeout or self._task_timeout_default,
            max_retries=max_retries,
            parent_task_id=parent_task_id
        )
        
        # إنشاء Future للانتظار بدون polling
        task.completion_future = asyncio.get_running_loop().create_future()
        
        async with self._tasks_lock:
            self._tasks[task_id] = task
            self._pending_task_ids.add(task_id)
        
        # إضافة إلى قائمة الانتظار مع backpressure حقيقي
        try:
            self._task_queues[priority].put_nowait(task_id)
        except asyncio.QueueFull:
            # تنظيف coroutine لمنع التسرب
            coroutine.close()
            async with self._tasks_lock:
                if task_id in self._tasks:
                    del self._tasks[task_id]
                self._pending_task_ids.discard(task_id)
            self._stats["queue_overflows"] += 1
            raise RuntimeError(f"Task queue full for priority {priority.name}")
        
        self._stats["total_tasks_submitted"] += 1
        logger.debug(f"Task submitted: {name} ({task_id[:8]})")
        
        return task_id
    
    async def _scheduler_loop(self):
        """
        حلقة الجدولة - Weighted Round Robin مع Aging
        """
        while self._running:
            try:
                task_id = await self._select_next_task_weighted()
                
                if task_id is None:
                    await asyncio.sleep(0.01)
                    continue
                
                # التحكم في التوافقية
                await self._semaphore.acquire()
                
                # تشغيل المهمة
                asyncio.create_task(self._execute_task_with_semaphore(task_id))
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Scheduler error: {e}", exc_info=True)
                await asyncio.sleep(0.1)
    
    async def _select_next_task_weighted(self) -> Optional[str]:
        """
        اختيار المهمة التالية باستخدام Weighted Round Robin مع Aging
        
        الخوارزمية:
        - تتراكم الرموز مع مرور الوقت (Aging)
        - يتم تشغيل المهمة ذات الأولوية الأعلى التي تجاوزت عتبة الرموز
        """
        now = time.time()
        
        # إضافة رموز بناءً على مرور الوقت
        time_delta = now - getattr(self, '_last_token_update', now)
        self._scheduler_tokens += time_delta * 10  # 10 tokens per second
        if self._scheduler_tokens > 100:
            self._scheduler_tokens = 100
        
        # تحديث الوقت
        self._last_token_update = now
        
        # حساب الرموز المطلوبة لكل أولوية (مع Aging)
        required_tokens = {
            TaskPriority.CRITICAL: 1,
            TaskPriority.HIGH: 2,
            TaskPriority.NORMAL: 3,
            TaskPriority.LOW: 5,
            TaskPriority.BACKGROUND: 10
        }
        
        # إضافة Aging لتقليل الرموز المطلوبة للمهام القديمة
        for priority in TaskPriority:
            time_since_last_run = now - self._priority_last_run.get(priority, 0)
            if time_since_last_run > 5:  # بعد 5 ثوان
                reduction = min(
                    required_tokens[priority] * 0.5,
                    (time_since_last_run - 5) * 0.1
                )
                current_required = max(1, required_tokens[priority] - reduction)
            else:
                current_required = required_tokens[priority]
            
            # إذا كانت الرموز كافية وهناك مهام في القائمة
            if self._scheduler_tokens >= current_required:
                if not self._task_queues[priority].empty():
                    task_id = self._task_queues[priority].get_nowait()
                    self._scheduler_tokens -= current_required
                    self._priority_last_run[priority] = now
                    return task_id
        
        return None
    
    async def _execute_task_with_semaphore(self, task_id: str):
        """تنفيذ مهمة مع إدارة الـ semaphore"""
        try:
            await self._execute_task(task_id)
        finally:
            self._semaphore.release()
    
    async def _execute_task(self, task_id: str):
        """تنفيذ مهمة محددة"""
        async with self._tasks_lock:
            if task_id not in self._tasks:
                return
            
            task = self._tasks[task_id]
            task.status = TaskStatus.RUNNING
            task.started_at = datetime.now()
            self._pending_task_ids.discard(task_id)
            self._running_task_ids.add(task_id)
        
        # تحديث الذروة
        current_concurrent = len(self._running_task_ids)
        if current_concurrent > self._stats["peak_concurrent_tasks"]:
            self._stats["peak_concurrent_tasks"] = current_concurrent
        
        try:
            # إنشاء asyncio.Task
            asyncio_task = asyncio.create_task(
                self._run_with_timeout(task, task.timeout)
            )
            
            async with self._tasks_lock:
                self._active_asyncio_tasks[task_id] = asyncio_task
            
            # انتظار النتيجة
            result = await asyncio_task
            
            async with self._tasks_lock:
                if task_id not in self._tasks:
                    return
                
                task.result = result
                task.status = TaskStatus.COMPLETED
                
                # إكمال Future الخاص بالمهمة
                if task.completion_future and not task.completion_future.done():
                    task.completion_future.set_result(result)
                
                self._stats["total_tasks_completed"] += 1
                self._completed_task_ids.append(task_id)
                
                # تسجيل وقت التنفيذ
                execution_time = (datetime.now() - task.started_at).total_seconds()
                task.execution_time = execution_time
                self._task_times.append(execution_time)
                
                if len(self._task_times) > 1000:
                    self._task_times.pop(0)
                self._stats["average_task_time"] = sum(self._task_times) / len(self._task_times)
            
        except asyncio.TimeoutError:
            async with self._tasks_lock:
                if task_id in self._tasks:
                    task.status = TaskStatus.TIMEOUT
                    task.error = f"Timeout after {task.timeout}s"
                    if task.completion_future and not task.completion_future.done():
                        task.completion_future.set_exception(TimeoutError(task.error))
                    self._stats["total_tasks_timeout"] += 1
                    self._stats["total_tasks_failed"] += 1
                    self._completed_task_ids.append(task_id)
            
        except asyncio.CancelledError:
            async with self._tasks_lock:
                if task_id in self._tasks:
                    task.status = TaskStatus.CANCELLED
                    if task.completion_future and not task.completion_future.done():
                        task.completion_future.set_exception(asyncio.CancelledError())
                    self._stats["total_tasks_cancelled"] += 1
                    self._completed_task_ids.append(task_id)
            
        except Exception as e:
            async with self._tasks_lock:
                if task_id in self._tasks:
                    task.status = TaskStatus.FAILED
                    task.error = str(e)
                    if task.completion_future and not task.completion_future.done():
                        task.completion_future.set_exception(e)
                    self._stats["total_tasks_failed"] += 1
                    self._completed_task_ids.append(task_id)
            logger.error(f"Task failed: {task.name} - {e}", exc_info=True)
        
        finally:
            async with self._tasks_lock:
                if task_id in self._tasks:
                    task.completed_at = datetime.now()
                self._running_task_ids.discard(task_id)
                self._active_asyncio_tasks.pop(task_id, None)
    
    async def _run_with_timeout(self, task: AsyncTask, timeout: float) -> Any:
        """تشغيل coroutine مع timeout"""
        return await asyncio.wait_for(task.coroutine, timeout=timeout)
    
    async def wait_for_task(self, task_id: str, timeout: Optional[float] = None) -> Any:
        """
        انتظار اكتمال مهمة باستخدام Future (بدون polling)
        """
        if task_id not in self._tasks:
            raise KeyError(f"Task {task_id} not found")
        
        task = self._tasks[task_id]
        
        # إذا كانت المهمة مكتملة، أرجع النتيجة مباشرة
        if task.status == TaskStatus.COMPLETED:
            return task.result
        elif task.status in [TaskStatus.FAILED, TaskStatus.TIMEOUT]:
            raise RuntimeError(task.error)
        elif task.status == TaskStatus.CANCELLED:
            raise asyncio.CancelledError()
        
        # انتظار Future مع timeout
        try:
            return await asyncio.wait_for(task.completion_future, timeout=timeout)
        except asyncio.TimeoutError:
            raise TimeoutError(f"Task {task_id} not completed within {timeout}s")
    
    async def cancel_task(self, task_id: str) -> bool:
        """إلغاء مهمة - دعم حقيقي"""
        async with self._tasks_lock:
            if task_id not in self._tasks:
                return False
            
            task = self._tasks[task_id]
            
            if task.status == TaskStatus.PENDING:
                task.status = TaskStatus.CANCELLED
                if task.completion_future and not task.completion_future.done():
                    task.completion_future.set_exception(asyncio.CancelledError())
                self._pending_task_ids.discard(task_id)
                self._completed_task_ids.append(task_id)
                self._stats["total_tasks_cancelled"] += 1
                return True
                
            elif task.status == TaskStatus.RUNNING:
                if task_id in self._active_asyncio_tasks:
                    asyncio_task = self._active_asyncio_tasks[task_id]
                    if not asyncio_task.done():
                        cancelled = asyncio_task.cancel()
                        task.status = TaskStatus.CANCELLED
                        if task.completion_future and not task.completion_future.done():
                            task.completion_future.set_exception(asyncio.CancelledError())
                        self._stats["total_tasks_cancelled"] += 1
                        return True
            
            return False
    
    async def submit_sync(
        self,
        name: str,
        func: Callable[..., Any],
        *args,
        priority: TaskPriority = TaskPriority.NORMAL,
        timeout: Optional[float] = None,
        **kwargs
    ) -> str:
        """إرسال دالة متزامنة"""
        async def sync_wrapper():
            loop = asyncio.get_running_loop()
            return await loop.run_in_executor(
                self._thread_pool,
                lambda: func(*args, **kwargs)
            )
        
        return await self.submit_task(name, sync_wrapper(), priority, timeout)
    
    async def retry_async(
        self,
        coroutine_factory: Callable[[], Awaitable[Any]],
        max_attempts: int = 3,
        backoff_factor: float = 1.0,
        exceptions: tuple = (Exception,)
    ) -> Any:
        """تنفيذ مع إعادة محاولة - مع حماية CancelledError"""
        last_exception = None
        
        for attempt in range(max_attempts):
            try:
                return await coroutine_factory()
            except asyncio.CancelledError:
                # إعادة رفع CancelledError دون محاولة
                raise
            except exceptions as e:
                last_exception = e
                if attempt < max_attempts - 1:
                    delay = backoff_factor * (2 ** attempt)
                    await asyncio.sleep(delay)
        
        raise last_exception
    
    async def get_stats(self) -> Dict:
        """إحصائيات البيئة"""
        async with self._tasks_lock:
            return {
                **self._stats,
                "running": self._running,
                "draining": self._draining,
                "pending_tasks": len(self._pending_task_ids),
                "running_tasks": len(self._running_task_ids),
                "total_tasks": len(self._tasks),
                "completed_tasks": len(self._completed_task_ids),
                "max_concurrent": self._max_concurrent_tasks,
                "semaphore_available": self._semaphore._value,
                "queue_sizes": {
                    p.name: self._task_queues[p].qsize()
                    for p in TaskPriority
                },
                "scheduler_tokens": self._scheduler_tokens
            }
    
    def is_running(self) -> bool:
        return self._running and not self._draining


# نسخة عالمية
_default_runtime = None


async def get_async_runtime() -> AsyncRuntime:
    global _default_runtime
    if _default_runtime is None:
        _default_runtime = AsyncRuntime()
        await _default_runtime.start()
    return _default_runtime

