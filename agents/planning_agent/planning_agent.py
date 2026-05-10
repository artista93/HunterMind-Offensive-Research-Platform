
import asyncio
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

from ..base.base_agent import BaseAgent, AgentPriority, AgentMessage
from ..base.agent_state import AgentStateEnum
from ..reasoning_agent.objective_solver import ObjectiveType, Solution

import logging

logger = logging.getLogger(__name__)


class PlanStatus(Enum):
    """حالة الخطة"""
    DRAFT = "draft"
    APPROVED = "approved"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class PlanStep:
    """خطوة في الخطة"""
    id: str
    action: str
    agent: str
    parameters: Dict[str, Any]
    status: PlanStatus = PlanStatus.DRAFT
    result: Optional[Any] = None
    error: Optional[str] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None


@dataclass
class AttackPlan:
    """خطة هجوم"""
    id: str
    name: str
    objective: ObjectiveType
    steps: List[PlanStep]
    status: PlanStatus = PlanStatus.DRAFT
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    completed_at: Optional[datetime] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


class PlanningAgent(BaseAgent):
    """
    وكيل التخطيط المتقدم
    
    الميزات:
    - وضع خطط هجوم متعددة الخطوات
    - تنفيذ الخطط بشكل متسلسل أو متوازي
    - تتبع تقدم الخطة
    - تعديل الخطط ديناميكياً
    - تقييم نجاح الخطة
    """
    
    def __init__(
        self,
        name: str = "PlanningAgent",
        priority: AgentPriority = AgentPriority.HIGH
    ):
        super().__init__(name, priority)
        
        self._active_plans: Dict[str, AttackPlan] = {}
        self._plan_history: List[AttackPlan] = []
        self._current_plan_id: Optional[str] = None
        
        logger.info(f"PlanningAgent initialized: {name}")
    
    async def _on_initialize(self):
        """تهيئة الوكيل"""
        logger.info("PlanningAgent components initialized")
    
    async def _on_start(self):
        """بدء تشغيل الوكيل"""
        logger.info("PlanningAgent started")
    
    async def _on_stop(self):
        """إيقاف تشغيل الوكيل"""
        # إيقاف الخطط النشطة
        for plan_id, plan in self._active_plans.items():
            if plan.status == PlanStatus.IN_PROGRESS:
                plan.status = PlanStatus.CANCELLED
        logger.info("PlanningAgent stopped")
    
    async def _handle_message(self, message: AgentMessage) -> Optional[AgentMessage]:
        """معالجة الرسائل الواردة"""
        if message.type == "create_plan":
            result = await self.create_plan(message.content)
            return AgentMessage(
                id="",
                sender=self.name,
                receiver=message.sender,
                type="plan_created",
                content={"plan_id": result.id}
            )
        
        elif message.type == "execute_plan":
            result = await self.execute_plan(message.content.get("plan_id"))
            return AgentMessage(
                id="",
                sender=self.name,
                receiver=message.sender,
                type="plan_executed",
                content={"success": result}
            )
        
        elif message.type == "get_plan_status":
            status = await self.get_plan_status(message.content.get("plan_id"))
            return AgentMessage(
                id="",
                sender=self.name,
                receiver=message.sender,
                type="plan_status",
                content=status
            )
        
        return await super()._handle_message(message)
    
    async def create_plan(
        self,
        data: Dict[str, Any]
    ) -> AttackPlan:
        """
        إنشاء خطة هجوم جديدة
        
        Args:
            data: بيانات الخطة (objective, findings, available_agents)
        
        Returns:
            خطة الهجوم
        """
        import uuid
        plan_id = str(uuid.uuid4())[:8]
        
        objective = data.get("objective", ObjectiveType.FULL_COMPROMISE)
        findings = data.get("findings", [])
        available_agents = data.get("available_agents", [])
        
        steps = await self._generate_steps(objective, findings, available_agents)
        
        plan = AttackPlan(
            id=plan_id,
            name=f"Plan_{objective.value}_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            objective=objective,
            steps=steps,
            status=PlanStatus.DRAFT,
            metadata={
                "findings_count": len(findings),
                "agents_available": len(available_agents)
            }
        )
        
        self._active_plans[plan_id] = plan
        
        logger.info(f"Plan created: {plan.name} with {len(steps)} steps")
        
        return plan
    
    async def _generate_steps(
        self,
        objective: ObjectiveType,
        findings: List[Any],
        available_agents: List[str]
    ) -> List[PlanStep]:
        """توليد خطوات الخطة"""
        steps = []
        
        if objective == ObjectiveType.DATA_EXTRACTION:
            steps = [
                PlanStep(
                    id="1",
                    action="scan_parameters",
                    agent="scanner_agent",
                    parameters={"target": "all", "vulnerability": "SQLi"}
                ),
                PlanStep(
                    id="2",
                    action="extract_schema",
                    agent="sqli_agent",
                    parameters={"action": "schema_extraction"}
                ),
                PlanStep(
                    id="3",
                    action="dump_data",
                    agent="sqli_agent",
                    parameters={"action": "data_dump", "tables": ["users", "passwords"]}
                )
            ]
        
        elif objective == ObjectiveType.PRIVILEGE_ESCALATION:
            steps = [
                PlanStep(
                    id="1",
                    action="enumerate_roles",
                    agent="recon_agent",
                    parameters={"action": "role_enumeration"}
                ),
                PlanStep(
                    id="2",
                    action="test_role_params",
                    agent="idor_agent",
                    parameters={"action": "role_parameter_test"}
                ),
                PlanStep(
                    id="3",
                    action="escalate_privileges",
                    agent="exploitation_agent",
                    parameters={"action": "privilege_escalation", "target_role": "admin"}
                )
            ]
        
        elif objective == ObjectiveType.FULL_COMPROMISE:
            steps = [
                PlanStep(
                    id="1",
                    action="initial_access",
                    agent="exploitation_agent",
                    parameters={"action": "rce_exploit"}
                ),
                PlanStep(
                    id="2",
                    action="privilege_escalation",
                    agent="exploitation_agent",
                    parameters={"action": "privilege_escalation"}
                ),
                PlanStep(
                    id="3",
                    action="persistence",
                    agent="exploitation_agent",
                    parameters={"action": "install_backdoor"}
                ),
                PlanStep(
                    id="4",
                    action="data_extraction",
                    agent="sqli_agent",
                    parameters={"action": "data_dump"}
                ),
                PlanStep(
                    id="5",
                    action="cleanup",
                    agent="exploitation_agent",
                    parameters={"action": "clear_logs"}
                )
            ]
        
        return steps
    
    async def execute_plan(self, plan_id: str) -> bool:
        """
        تنفيذ خطة الهجوم
        
        Args:
            plan_id: معرف الخطة
        
        Returns:
            نجاح التنفيذ
        """
        if plan_id not in self._active_plans:
            logger.warning(f"Plan {plan_id} not found")
            return False
        
        plan = self._active_plans[plan_id]
        plan.status = PlanStatus.IN_PROGRESS
        self._current_plan_id = plan_id
        
        logger.info(f"Executing plan: {plan.name}")
        
        for step in plan.steps:
            step.start_time = datetime.now()
            step.status = PlanStatus.IN_PROGRESS
            
            try:
                # محاكاة تنفيذ الخطوة
                result = await self._execute_step(step)
                step.result = result
                step.status = PlanStatus.COMPLETED
                logger.info(f"Step {step.id} completed: {step.action}")
                
            except Exception as e:
                step.error = str(e)
                step.status = PlanStatus.FAILED
                logger.error(f"Step {step.id} failed: {e}")
                
                # إذا فشلت خطوة، توقف التنفيذ
                plan.status = PlanStatus.FAILED
                return False
            
            finally:
                step.end_time = datetime.now()
        
        plan.status = PlanStatus.COMPLETED
        plan.completed_at = datetime.now()
        self._plan_history.append(plan)
        
        logger.info(f"Plan {plan.name} completed successfully")
        return True
    
    async def _execute_step(self, step: PlanStep) -> Any:
        """تنفيذ خطوة واحدة"""
        # محاكاة التنفيذ
        await asyncio.sleep(0.5)
        
        # يمكن هنا استدعاء الوكلاء المناسبين
        if step.action == "scan_parameters":
            return {"parameters_found": 10, "vulnerable": ["id", "user"]}
        elif step.action == "extract_schema":
            return {"tables": ["users", "products", "orders"]}
        elif step.action == "dump_data":
            return {"records": 100, "data": "sample_data"}
        elif step.action == "enumerate_roles":
            return {"current_role": "user", "available_roles": ["user", "moderator", "admin"]}
        elif step.action == "escalate_privileges":
            return {"new_role": "admin", "success": True}
        else:
            return {"status": "success"}
    
    async def get_plan_status(self, plan_id: str = None) -> Dict:
        """الحصول على حالة الخطة"""
        if plan_id:
            plan = self._active_plans.get(plan_id)
            if not plan:
                return {"error": "Plan not found"}
            
            return {
                "plan_id": plan.id,
                "name": plan.name,
                "objective": plan.objective.value,
                "status": plan.status.value,
                "steps": [
                    {
                        "id": s.id,
                        "action": s.action,
                        "status": s.status.value,
                        "duration": (s.end_time - s.start_time).total_seconds() if s.end_time and s.start_time else 0
                    }
                    for s in plan.steps
                ],
                "created_at": plan.created_at.isoformat(),
                "updated_at": plan.updated_at.isoformat()
            }
        
        # جميع الخطط
        return {
            "active_plans": len(self._active_plans),
            "completed_plans": len(self._plan_history),
            "current_plan": self._current_plan_id,
            "plans": [
                {
                    "id": p.id,
                    "name": p.name,
                    "status": p.status.value,
                    "objective": p.objective.value
                }
                for p in self._active_plans.values()
            ]
        }
    
    async def get_statistics(self) -> Dict:
        """إحصائيات الوكيل"""
        base_stats = await super().get_statistics()
        
        completed = [p for p in self._plan_history if p.status == PlanStatus.COMPLETED]
        failed = [p for p in self._plan_history if p.status == PlanStatus.FAILED]
        
        return {
            **base_stats,
            "planning_specific": {
                "total_plans": len(self._active_plans) + len(self._plan_history),
                "active_plans": len(self._active_plans),
                "completed_plans": len(completed),
                "failed_plans": len(failed),
                "success_rate": len(completed) / (len(completed) + len(failed)) if (completed or failed) else 0,
                "average_plan_duration": sum(
                    (p.completed_at - p.created_at).total_seconds() 
                    for p in completed if p.completed_at
                ) / len(completed) if completed else 0
            }
        }


_default_planning_agent = None

async def get_planning_agent() -> PlanningAgent:
    global _default_planning_agent
    if _default_planning_agent is None:
        _default_planning_agent = PlanningAgent()
        await _default_planning_agent.initialize()
        await _default_planning_agent.start()
    return _default_planning_agent

