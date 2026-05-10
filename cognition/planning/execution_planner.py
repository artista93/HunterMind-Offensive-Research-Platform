
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

from .tactical_planner import TacticalAction, TacticalPlan

import logging

logger = logging.getLogger(__name__)


class ExecutionStatus(Enum):
    """حالة التنفيذ"""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class ExecutionStep:
    """خطوة تنفيذية"""
    id: str
    action_id: str
    command: str
    parameters: Dict[str, Any]
    status: ExecutionStatus = ExecutionStatus.PENDING
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    result: Optional[Any] = None
    error: Optional[str] = None
    retry_count: int = 0
    max_retries: int = 3


@dataclass
class ExecutionPlan:
    """خطة تنفيذية"""
    id: str
    tactical_plan_id: str
    steps: List[ExecutionStep]
    created_at: datetime = field(default_factory=datetime.now)
    status: ExecutionStatus = ExecutionStatus.PENDING
    metadata: Dict[str, Any] = field(default_factory=dict)


class ExecutionPlanner:
    """
    مخطط التنفيذ المتقدم
    
    الميزات:
    - تحويل الإجراءات التكتيكية إلى خطوات تنفيذية
    - تحديد الأوامر والبارامترات اللازمة
    - إدارة إعادة المحاولة والأخطاء
    - تتبع حالة التنفيذ
    """
    
    def __init__(self):
        self._execution_plans: Dict[str, ExecutionPlan] = {}
        
        logger.info("ExecutionPlanner initialized")
    
    async def create_execution_plan(
        self,
        tactical_plan: TacticalPlan
    ) -> ExecutionPlan:
        """
        إنشاء خطة تنفيذية من خطة تكتيكية
        
        Args:
            tactical_plan: الخطة التكتيكية
        
        Returns:
            الخطة التنفيذية
        """
        import uuid
        plan_id = str(uuid.uuid4())[:8]
        
        steps = []
        
        for action in tactical_plan.actions:
            execution_steps = await self._convert_to_steps(action)
            steps.extend(execution_steps)
        
        plan = ExecutionPlan(
            id=plan_id,
            tactical_plan_id=tactical_plan.id,
            steps=steps
        )
        
        self._execution_plans[plan_id] = plan
        
        logger.info(f"Execution plan created: {plan_id} with {len(steps)} steps")
        return plan
    
    async def _convert_to_steps(
        self,
        action: TacticalAction
    ) -> List[ExecutionStep]:
        """تحويل إجراء تكتيكي إلى خطوات تنفيذية"""
        steps = []
        import uuid
        
        if action.id == "detect_001":
            step = ExecutionStep(
                id=str(uuid.uuid4())[:8],
                action_id=action.id,
                command="update_scanner_config",
                parameters={"threshold": 0.1, "sensitivity": "high"}
            )
            steps.append(step)
        
        elif action.id == "detect_002":
            step = ExecutionStep(
                id=str(uuid.uuid4())[:8],
                action_id=action.id,
                command="add_payloads",
                parameters={"source": "payload_library", "count": 50}
            )
            steps.append(step)
        
        elif action.id == "fp_001":
            step = ExecutionStep(
                id=str(uuid.uuid4())[:8],
                action_id=action.id,
                command="enable_validation",
                parameters={"validation_level": "strict"}
            )
            steps.append(step)
        
        elif action.id == "fp_002":
            step = ExecutionStep(
                id=str(uuid.uuid4())[:8],
                action_id=action.id,
                command="update_context_analyzer",
                parameters={"model": "advanced", "confidence": 0.8}
            )
            steps.append(step)
        
        elif action.id == "res_001":
            step = ExecutionStep(
                id=str(uuid.uuid4())[:8],
                action_id=action.id,
                command="adjust_concurrency",
                parameters={"max_concurrent": 5, "max_queued": 100}
            )
            steps.append(step)
        
        elif action.id == "res_002":
            step = ExecutionStep(
                id=str(uuid.uuid4())[:8],
                action_id=action.id,
                command="enable_caching",
                parameters={"ttl": 300, "max_size": 1000}
            )
            steps.append(step)
        
        elif action.id == "cov_001":
            step = ExecutionStep(
                id=str(uuid.uuid4())[:8],
                action_id=action.id,
                command="set_crawl_depth",
                parameters={"max_depth": 5, "max_pages": 500}
            )
            steps.append(step)
        
        elif action.id == "cov_002":
            step = ExecutionStep(
                id=str(uuid.uuid4())[:8],
                action_id=action.id,
                command="enable_js_analysis",
                parameters={"analyze_inline": True, "fetch_external": True}
            )
            steps.append(step)
        
        elif action.id == "resp_001":
            step = ExecutionStep(
                id=str(uuid.uuid4())[:8],
                action_id=action.id,
                command="enable_async",
                parameters={"max_workers": 10, "timeout": 30}
            )
            steps.append(step)
        
        elif action.id == "resp_002":
            step = ExecutionStep(
                id=str(uuid.uuid4())[:8],
                action_id=action.id,
                command="optimize_queries",
                parameters={"add_indexes": True, "analyze": True}
            )
            steps.append(step)
        
        elif action.id == "adapt_001":
            step = ExecutionStep(
                id=str(uuid.uuid4())[:8],
                action_id=action.id,
                command="enable_ml",
                parameters={"learning_rate": 0.01, "batch_size": 32}
            )
            steps.append(step)
        
        elif action.id == "adapt_002":
            step = ExecutionStep(
                id=str(uuid.uuid4())[:8],
                action_id=action.id,
                command="update_threat_model",
                parameters={"interval_hours": 24, "auto_update": True}
            )
            steps.append(step)
        
        return steps
    
    async def update_step_status(
        self,
        plan_id: str,
        step_id: str,
        status: ExecutionStatus,
        result: Any = None,
        error: str = None
    ) -> bool:
        """
        تحديث حالة خطوة تنفيذية
        
        Args:
            plan_id: معرف الخطة التنفيذية
            step_id: معرف الخطوة
            status: الحالة الجديدة
            result: نتيجة التنفيذ
            error: رسالة خطأ
        
        Returns:
            نجاح العملية
        """
        plan = self._execution_plans.get(plan_id)
        if not plan:
            return False
        
        for step in plan.steps:
            if step.id == step_id:
                step.status = status
                step.result = result
                step.error = error
                
                if status == ExecutionStatus.IN_PROGRESS:
                    step.start_time = datetime.now()
                elif status in [ExecutionStatus.COMPLETED, ExecutionStatus.FAILED]:
                    step.end_time = datetime.now()
                
                logger.debug(f"Step {step_id} status updated to {status.value}")
                return True
        
        return False
    
    async def get_execution_plan(self, plan_id: str) -> Optional[ExecutionPlan]:
        """الحصول على خطة تنفيذية"""
        return self._execution_plans.get(plan_id)
    
    async def get_progress(self, plan_id: str) -> float:
        """
        الحصول على نسبة التقدم في الخطة التنفيذية
        
        Args:
            plan_id: معرف الخطة
        
        Returns:
            نسبة التقدم (0-1)
        """
        plan = self._execution_plans.get(plan_id)
        if not plan or not plan.steps:
            return 0.0
        
        completed = sum(1 for s in plan.steps if s.status == ExecutionStatus.COMPLETED)
        return completed / len(plan.steps)
    
    async def get_statistics(self) -> Dict:
        """إحصائيات المخطط"""
        total_steps = sum(len(p.steps) for p in self._execution_plans.values())
        completed_steps = sum(
            1 for p in self._execution_plans.values()
            for s in p.steps if s.status == ExecutionStatus.COMPLETED
        )
        
        return {
            "total_execution_plans": len(self._execution_plans),
            "total_steps": total_steps,
            "completed_steps": completed_steps,
            "completion_rate": completed_steps / total_steps if total_steps > 0 else 0,
            "failed_steps": sum(
                1 for p in self._execution_plans.values()
                for s in p.steps if s.status == ExecutionStatus.FAILED
            )
        }

