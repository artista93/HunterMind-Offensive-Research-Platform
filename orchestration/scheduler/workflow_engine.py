
import asyncio
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import uuid

import logging

logger = logging.getLogger(__name__)


class WorkflowStatus(Enum):
    """حالة سير العمل"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    PAUSED = "paused"
    CANCELLED = "cancelled"


class StepStatus(Enum):
    """حالة الخطوة"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class WorkflowStep:
    """خطوة في سير العمل"""
    id: str
    name: str
    handler: Callable
    depends_on: List[str]
    condition: Optional[str] = None
    timeout: float = 60.0
    retry_count: int = 0
    max_retries: int = 3
    status: StepStatus = StepStatus.PENDING
    result: Any = None
    error: Optional[str] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None


@dataclass
class Workflow:
    """سير العمل"""
    id: str
    name: str
    steps: List[WorkflowStep]
    status: WorkflowStatus = WorkflowStatus.PENDING
    created_at: datetime = field(default_factory=datetime.now)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


class WorkflowEngine:
    """
    محرك سير العمل المتقدم
    
    الميزات:
    - تنفيذ سلاسل عمل معقدة مع تبعيات
    - إعادة محاولة الخطوات الفاشلة
    - شروط التنفيذ
    - مهلات زمنية
    - تتبع التقدم
    """
    
    def __init__(self, max_concurrent: int = 10):
        self.max_concurrent = max_concurrent
        self.workflows: Dict[str, Workflow] = {}
        self._running = False
        self._lock = asyncio.Lock()
        
        logger.info("WorkflowEngine initialized (max_concurrent={})", max_concurrent)
    
    async def create_workflow(
        self,
        name: str,
        steps: List[Dict],
        metadata: Dict = None
    ) -> str:
        """
        إنشاء سير عمل جديد
        
        Args:
            name: اسم سير العمل
            steps: قائمة خطوات سير العمل
            metadata: بيانات إضافية
        
        Returns:
            معرف سير العمل
        """
        workflow_id = str(uuid.uuid4())[:8]
        
        workflow_steps = []
        for i, step_data in enumerate(steps):
            step = WorkflowStep(
                id=f"step_{i}",
                name=step_data.get("name", f"Step {i}"),
                handler=step_data["handler"],
                depends_on=step_data.get("depends_on", []),
                condition=step_data.get("condition"),
                timeout=step_data.get("timeout", 60.0),
                max_retries=step_data.get("max_retries", 3)
            )
            workflow_steps.append(step)
        
        workflow = Workflow(
            id=workflow_id,
            name=name,
            steps=workflow_steps,
            metadata=metadata or {}
        )
        
        async with self._lock:
            self.workflows[workflow_id] = workflow
        
        logger.info(f"Workflow created: {name} ({workflow_id})")
        return workflow_id
    
    async def execute_workflow(self, workflow_id: str) -> Workflow:
        """
        تنفيذ سير عمل
        
        Args:
            workflow_id: معرف سير العمل
        
        Returns:
            سير العمل بعد التنفيذ
        """
        if workflow_id not in self.workflows:
            raise ValueError(f"Workflow {workflow_id} not found")
        
        workflow = self.workflows[workflow_id]
        workflow.status = WorkflowStatus.RUNNING
        workflow.started_at = datetime.now()
        
        # تنفيذ الخطوات حسب التبعيات
        completed_steps = set()
        
        while len(completed_steps) < len(workflow.steps):
            # الحصول على الخطوات الجاهزة للتنفيذ
            ready_steps = []
            for step in workflow.steps:
                if step.status != StepStatus.PENDING:
                    continue
                
                # التحقق من التبعيات
                deps_met = all(
                    dep in completed_steps
                    for dep in step.depends_on
                )
                
                if not deps_met:
                    continue
                
                # التحقق من الشرط
                if step.condition:
                    condition_met = await self._evaluate_condition(step.condition, workflow)
                    if not condition_met:
                        step.status = StepStatus.SKIPPED
                        continue
                
                ready_steps.append(step)
            
            if not ready_steps:
                # لا توجد خطوات جاهزة - تأكد من عدم وجود حلقات
                pending = [s for s in workflow.steps if s.status == StepStatus.PENDING]
                if pending:
                    logger.error(f"Deadlock detected in workflow {workflow.name}")
                    workflow.status = WorkflowStatus.FAILED
                    break
                break
            
            # تنفيذ الخطوات الجاهزة بشكل متوازي
            semaphore = asyncio.Semaphore(self.max_concurrent)
            
            async def execute_with_limit(step):
                async with semaphore:
                    return await self._execute_step(step, workflow)
            
            tasks = [execute_with_limit(step) for step in ready_steps]
            results = await asyncio.gather(*tasks)
            
            for step, success in zip(ready_steps, results):
                if success:
                    completed_steps.add(step.id)
        
        # تحديث حالة سير العمل
        workflow.completed_at = datetime.now()
        
        failed_steps = [s for s in workflow.steps if s.status == StepStatus.FAILED]
        if failed_steps:
            workflow.status = WorkflowStatus.FAILED
        else:
            workflow.status = WorkflowStatus.COMPLETED
        
        logger.info(f"Workflow {workflow.name} completed: {workflow.status.value}")
        return workflow
    
    async def _execute_step(self, step: WorkflowStep, workflow: Workflow) -> bool:
        """تنفيذ خطوة واحدة"""
        step.status = StepStatus.RUNNING
        step.started_at = datetime.now()
        
        for attempt in range(step.max_retries):
            try:
                if asyncio.iscoroutinefunction(step.handler):
                    result = await asyncio.wait_for(
                        step.handler(step, workflow),
                        timeout=step.timeout
                    )
                else:
                    result = step.handler(step, workflow)
                
                step.result = result
                step.status = StepStatus.COMPLETED
                step.completed_at = datetime.now()
                
                logger.debug(f"Step completed: {step.name}")
                return True
                
            except asyncio.TimeoutError:
                step.error = f"Timeout after {step.timeout}s"
                logger.warning(f"Step {step.name} timeout (attempt {attempt + 1})")
                
            except Exception as e:
                step.error = str(e)
                logger.warning(f"Step {step.name} failed: {e} (attempt {attempt + 1})")
            
            step.retry_count = attempt + 1
            
            if attempt < step.max_retries - 1:
                await asyncio.sleep(2 ** attempt)  # exponential backoff
        
        step.status = StepStatus.FAILED
        step.completed_at = datetime.now()
        logger.error(f"Step {step.name} failed after {step.max_retries} attempts")
        return False
    
    async def _evaluate_condition(self, condition: str, workflow: Workflow) -> bool:
        """تقييم شرط التنفيذ"""
        # محاكاة بسيطة لتقييم الشرط
        # في الإصدار الكامل، سيتم استخدام parser حقيقي
        try:
            return eval(condition, {"workflow": workflow})
        except Exception:
            return True
    
    async def get_workflow(self, workflow_id: str) -> Optional[Workflow]:
        """الحصول على سير عمل بالمعرف"""
        return self.workflows.get(workflow_id)
    
    async def get_statistics(self) -> Dict:
        """إحصائيات محرك سير العمل"""
        total = len(self.workflows)
        completed = len([w for w in self.workflows.values() if w.status == WorkflowStatus.COMPLETED])
        failed = len([w for w in self.workflows.values() if w.status == WorkflowStatus.FAILED])
        
        return {
            "total_workflows": total,
            "completed_workflows": completed,
            "failed_workflows": failed,
            "success_rate": completed / total if total > 0 else 0,
            "running": self._running,
            "max_concurrent": self.max_concurrent
        }

