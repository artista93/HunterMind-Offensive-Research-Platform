
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime

from .strategic_planner import StrategicGoal, StrategicPlan

import logging

logger = logging.getLogger(__name__)


@dataclass
class TacticalAction:
    """إجراء تكتيكي"""
    id: str
    name: str
    description: str
    priority: int
    estimated_duration: float
    dependencies: List[str]
    resources: List[str]
    success_criteria: List[str]
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class TacticalPlan:
    """خطة تكتيكية"""
    id: str
    name: str
    strategic_plan_id: str
    actions: List[TacticalAction]
    created_at: datetime = field(default_factory=datetime.now)
    status: str = "pending"


class TacticalPlanner:
    """
    المخطط التكتيكي المتقدم
    
    الميزات:
    - تحويل الأهداف الاستراتيجية إلى إجراءات تكتيكية
    - تحديد أولويات الإجراءات
    - إدارة التبعيات بين الإجراءات
    - تقدير الوقت والموارد المطلوبة
    """
    
    def __init__(self):
        self._tactical_plans: Dict[str, TacticalPlan] = {}
        
        logger.info("TacticalPlanner initialized")
    
    async def create_tactical_plan(
        self,
        strategic_plan: StrategicPlan,
        name: str = None
    ) -> TacticalPlan:
        """
        إنشاء خطة تكتيكية من خطة استراتيجية
        
        Args:
            strategic_plan: الخطة الاستراتيجية
            name: اسم الخطة التكتيكية
        
        Returns:
            الخطة التكتيكية
        """
        import uuid
        plan_id = str(uuid.uuid4())[:8]
        
        actions = []
        
        for objective in strategic_plan.objectives:
            tactical_actions = await self._convert_to_actions(objective)
            actions.extend(tactical_actions)
        
        # ترتيب الإجراءات حسب الأولوية والتبعيات
        actions = self._order_actions(actions)
        
        plan = TacticalPlan(
            id=plan_id,
            name=name or f"Tactical Plan for {strategic_plan.name}",
            strategic_plan_id=strategic_plan.id,
            actions=actions
        )
        
        self._tactical_plans[plan_id] = plan
        
        logger.info(f"Tactical plan created: {plan.name} with {len(actions)} actions")
        return plan
    
    async def _convert_to_actions(
        self,
        objective
    ) -> List[TacticalAction]:
        """تحويل هدف استراتيجي إلى إجراءات تكتيكية"""
        actions = []
        
        if objective.goal == StrategicGoal.MAXIMIZE_DETECTION:
            actions.append(TacticalAction(
                id="detect_001",
                name="Increase Scan Sensitivity",
                description="Lower detection threshold to catch more vulnerabilities",
                priority=1,
                estimated_duration=5.0,
                dependencies=[],
                resources=["scanner_config"],
                success_criteria=["detection_rate > 0.9"]
            ))
            actions.append(TacticalAction(
                id="detect_002",
                name="Add New Payloads",
                description="Expand payload library with new attack vectors",
                priority=2,
                estimated_duration=15.0,
                dependencies=["detect_001"],
                resources=["payload_library"],
                success_criteria=["payload_count > 200"]
            ))
        
        elif objective.goal == StrategicGoal.MINIMIZE_FALSE_POSITIVES:
            actions.append(TacticalAction(
                id="fp_001",
                name="Implement Validation",
                description="Add confirmation step for each finding",
                priority=1,
                estimated_duration=10.0,
                dependencies=[],
                resources=["validator"],
                success_criteria=["false_positive_rate < 0.05"]
            ))
            actions.append(TacticalAction(
                id="fp_002",
                name="Improve Context Analysis",
                description="Better context detection for reducing false positives",
                priority=2,
                estimated_duration=20.0,
                dependencies=["fp_001"],
                resources=["context_analyzer"],
                success_criteria=["context_accuracy > 0.9"]
            ))
        
        elif objective.goal == StrategicGoal.OPTIMIZE_RESOURCES:
            actions.append(TacticalAction(
                id="res_001",
                name="Adjust Concurrency",
                description="Optimize number of concurrent scans",
                priority=1,
                estimated_duration=5.0,
                dependencies=[],
                resources=["runtime_config"],
                success_criteria=["cpu_usage < 0.7", "memory_usage < 0.8"]
            ))
            actions.append(TacticalAction(
                id="res_002",
                name="Enable Caching",
                description="Cache repeated results to save resources",
                priority=2,
                estimated_duration=10.0,
                dependencies=["res_001"],
                resources=["cache_manager"],
                success_criteria=["cache_hit_rate > 0.3"]
            ))
        
        elif objective.goal == StrategicGoal.MAXIMIZE_COVERAGE:
            actions.append(TacticalAction(
                id="cov_001",
                name="Increase Crawl Depth",
                description="Crawl more pages to find more entry points",
                priority=1,
                estimated_duration=30.0,
                dependencies=[],
                resources=["crawler"],
                success_criteria=["pages_crawled > 200"]
            ))
            actions.append(TacticalAction(
                id="cov_002",
                name="Enable JS Analysis",
                description="Analyze JavaScript for hidden endpoints",
                priority=2,
                estimated_duration=20.0,
                dependencies=["cov_001"],
                resources=["js_processor"],
                success_criteria=["js_endpoints_found > 50"]
            ))
        
        elif objective.goal == StrategicGoal.MINIMIZE_RESPONSE_TIME:
            actions.append(TacticalAction(
                id="resp_001",
                name="Implement Async Processing",
                description="Use asynchronous operations for faster response",
                priority=1,
                estimated_duration=15.0,
                dependencies=[],
                resources=["async_runtime"],
                success_criteria=["response_time < 10s"]
            ))
            actions.append(TacticalAction(
                id="resp_002",
                name="Optimize Database Queries",
                description="Add indexes and optimize slow queries",
                priority=2,
                estimated_duration=10.0,
                dependencies=["resp_001"],
                resources=["database"],
                success_criteria=["query_time < 0.5s"]
            ))
        
        elif objective.goal == StrategicGoal.ADAPT_TO_THREATS:
            actions.append(TacticalAction(
                id="adapt_001",
                name="Enable ML Learning",
                description="Turn on machine learning for threat adaptation",
                priority=1,
                estimated_duration=10.0,
                dependencies=[],
                resources=["learning_agent"],
                success_criteria=["learning_active = True"]
            ))
            actions.append(TacticalAction(
                id="adapt_002",
                name="Update Threat Model",
                description="Regularly update threat model with new patterns",
                priority=2,
                estimated_duration=30.0,
                dependencies=["adapt_001"],
                resources=["threat_model"],
                success_criteria=["model_updated"]
            ))
        
        return actions
    
    def _order_actions(self, actions: List[TacticalAction]) -> List[TacticalAction]:
        """ترتيب الإجراءات حسب الأولوية والتبعيات"""
        ordered = []
        executed = set()
        
        while len(ordered) < len(actions):
            for action in actions:
                if action.id in executed:
                    continue
                
                # التحقق من تلبية التبعيات
                deps_met = all(dep in executed for dep in action.dependencies)
                
                if deps_met:
                    ordered.append(action)
                    executed.add(action.id)
                    break
        
        return ordered
    
    async def get_tactical_plan(self, plan_id: str) -> Optional[TacticalPlan]:
        """الحصول على خطة تكتيكية"""
        return self._tactical_plans.get(plan_id)
    
    async def get_statistics(self) -> Dict:
        """إحصائيات المخطط"""
        total_actions = sum(len(p.actions) for p in self._tactical_plans.values())
        
        return {
            "total_tactical_plans": len(self._tactical_plans),
            "total_actions": total_actions,
            "average_actions_per_plan": total_actions / len(self._tactical_plans) if self._tactical_plans else 0,
            "action_types": {
                "detection": 2,
                "false_positive": 2,
                "resources": 2,
                "coverage": 2,
                "response_time": 2,
                "adaptation": 2
            }
        }

