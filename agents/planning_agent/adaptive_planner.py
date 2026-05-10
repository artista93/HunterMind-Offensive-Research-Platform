
import asyncio
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime

from .planning_agent import AttackPlan, PlanStep, PlanStatus
from ..reasoning_agent.objective_solver import ObjectiveType

import logging

logger = logging.getLogger(__name__)


@dataclass
class PlanAdjustment:
    """تعديل على الخطة"""
    plan_id: str
    original_step_id: str
    new_step: PlanStep
    reason: str
    timestamp: datetime = field(default_factory=datetime.now)


class AdaptivePlanner:
    """
    المخطط التكيفي المتقدم
    
    الميزات:
    - تعديل الخطط بناءً على نتائج التنفيذ
    - إضافة خطوات بديلة عند الفشل
    - تحسين الخطط بناءً على الخبرة السابقة
    - دمج الخطط المتوازية
    - تقييم فعالية التعديلات
    """
    
    def __init__(self):
        self._adjustments: List[PlanAdjustment] = []
        self._alternative_steps: Dict[str, List[PlanStep]] = {}
        self._planning_history: Dict[str, List[PlanAdjustment]] = {}
        
        # تهيئة الخطوات البديلة
        self._init_alternatives()
        
        logger.info("AdaptivePlanner initialized")
    
    def _init_alternatives(self):
        """تهيئة الخطوات البديلة"""
        self._alternative_steps = {
            "scan_parameters": [
                PlanStep(
                    id="alt_1",
                    action="fuzz_parameters",
                    agent="scanner_agent",
                    parameters={"method": "fuzzing", "wordlist": "common_params"}
                ),
                PlanStep(
                    id="alt_2",
                    action="analyze_js",
                    agent="recon_agent",
                    parameters={"action": "extract_params_from_js"}
                )
            ],
            "extract_schema": [
                PlanStep(
                    id="alt_1",
                    action="blind_extraction",
                    agent="sqli_agent",
                    parameters={"technique": "boolean_based"}
                ),
                PlanStep(
                    id="alt_2",
                    action="time_based_extraction",
                    agent="sqli_agent",
                    parameters={"technique": "time_based"}
                )
            ],
            "escalate_privileges": [
                PlanStep(
                    id="alt_1",
                    action="jwt_escalation",
                    agent="auth_agent",
                    parameters={"technique": "jwt_manipulation"}
                ),
                PlanStep(
                    id="alt_2",
                    action="session_hijacking",
                    agent="exploitation_agent",
                    parameters={"technique": "session_fixation"}
                )
            ]
        }
    
    async def adapt_plan(
        self,
        plan: AttackPlan,
        failed_step: PlanStep,
        failure_reason: str
    ) -> Optional[AttackPlan]:
        """
        تكييف الخطة بعد فشل خطوة
        
        Args:
            plan: الخطة الأصلية
            failed_step: الخطوة الفاشلة
            failure_reason: سبب الفشل
        
        Returns:
            الخطة المعدلة أو None
        """
        logger.info(f"Adapting plan {plan.name} after failure: {failure_reason}")
        
        # البحث عن خطوات بديلة
        alternatives = self._alternative_steps.get(failed_step.action, [])
        
        if not alternatives:
            logger.warning(f"No alternatives found for {failed_step.action}")
            return None
        
        # اختيار أفضل بديل
        best_alternative = alternatives[0]
        
        # إنشاء خطة جديدة معدلة
        adapted_plan = AttackPlan(
            id=f"{plan.id}_adapted",
            name=f"{plan.name}_adapted",
            objective=plan.objective,
            steps=[],
            metadata={
                "original_plan_id": plan.id,
                "failed_step": failed_step.id,
                "failure_reason": failure_reason,
                "adaptation_time": datetime.now().isoformat()
            }
        )
        
        # نسخ الخطوات الناجحة
        for step in plan.steps:
            if step.id == failed_step.id:
                # إضافة الخطوة البديلة
                adapted_plan.steps.append(best_alternative)
            elif step.status == PlanStatus.COMPLETED:
                adapted_plan.steps.append(step)
            elif step.id > failed_step.id:
                # إضافة الخطوات المتبقية
                adapted_plan.steps.append(step)
        
        # تسجيل التعديل
        adjustment = PlanAdjustment(
            plan_id=plan.id,
            original_step_id=failed_step.id,
            new_step=best_alternative,
            reason=failure_reason
        )
        self._adjustments.append(adjustment)
        
        if plan.id not in self._planning_history:
            self._planning_history[plan.id] = []
        self._planning_history[plan.id].append(adjustment)
        
        logger.info(f"Plan adapted: replaced {failed_step.action} with {best_alternative.action}")
        
        return adapted_plan
    
    async def optimize_plan(
        self,
        plan: AttackPlan,
        execution_history: List[Dict]
    ) -> AttackPlan:
        """
        تحسين الخطة بناءً على تاريخ التنفيذ
        
        Args:
            plan: الخطة الأصلية
            execution_history: تاريخ تنفيذ الخطوات
        
        Returns:
            الخطة المحسنة
        """
        optimized_steps = []
        
        for step in plan.steps:
            # البحث عن وقت تنفيذ مشابه
            similar_steps = [
                h for h in execution_history
                if h.get("action") == step.action
            ]
            
            if similar_steps:
                avg_time = sum(s.get("duration", 0) for s in similar_steps) / len(similar_steps)
                
                # إذا كانت الخطوة بطيئة جداً، حاول تحسينها
                if avg_time > 10.0 and step.action in self._alternative_steps:
                    faster_alternative = await self._find_faster_alternative(step, similar_steps)
                    if faster_alternative:
                        optimized_steps.append(faster_alternative)
                        continue
            
            optimized_steps.append(step)
        
        plan.steps = optimized_steps
        plan.updated_at = datetime.now()
        
        logger.info(f"Plan optimized: {len(optimized_steps)} steps")
        
        return plan
    
    async def _find_faster_alternative(
        self,
        original_step: PlanStep,
        execution_history: List[Dict]
    ) -> Optional[PlanStep]:
        """البحث عن بديل أسرع"""
        alternatives = self._alternative_steps.get(original_step.action, [])
        
        for alt in alternatives:
            # محاكاة وقت التنفيذ المتوقع
            alt.parameters["estimated_time"] = 5.0  # وقت أقل
            return alt
        
        return None
    
    async def merge_parallel_plans(
        self,
        plans: List[AttackPlan]
    ) -> Optional[AttackPlan]:
        """
        دمج خطط متوازية في خطة واحدة
        
        Args:
            plans: قائمة الخطط المتوازية
        
        Returns:
            خطة مدمجة
        """
        if len(plans) < 2:
            return plans[0] if plans else None
        
        # دمج الأهداف
        merged_objective = plans[0].objective
        
        # جمع جميع الخطوات
        all_steps = []
        for plan in plans:
            all_steps.extend(plan.steps)
        
        # إزالة التكرارات
        unique_steps = []
        seen_actions = set()
        
        for step in all_steps:
            if step.action not in seen_actions:
                seen_actions.add(step.action)
                unique_steps.append(step)
        
        merged_plan = AttackPlan(
            id=f"merged_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            name=f"Merged_Plan_{len(plans)}_plans",
            objective=merged_objective,
            steps=unique_steps,
            metadata={
                "original_plans": [p.id for p in plans],
                "merged_count": len(plans)
            }
        )
        
        logger.info(f"Merged {len(plans)} plans into one with {len(unique_steps)} steps")
        
        return merged_plan
    
    async def get_adjustment_history(self, plan_id: str = None) -> List[Dict]:
        """الحصول على تاريخ التعديلات"""
        if plan_id:
            adjustments = self._planning_history.get(plan_id, [])
            return [
                {
                    "original_step": a.original_step_id,
                    "new_step_action": a.new_step.action,
                    "reason": a.reason,
                    "timestamp": a.timestamp.isoformat()
                }
                for a in adjustments
            ]
        
        return [
            {
                "plan_id": a.plan_id,
                "original_step": a.original_step_id,
                "new_step_action": a.new_step.action,
                "reason": a.reason,
                "timestamp": a.timestamp.isoformat()
            }
            for a in self._adjustments
        ]
    
    async def get_statistics(self) -> Dict:
        """إحصائيات المخطط التكيفي"""
        successful_adaptations = sum(
            1 for a in self._adjustments
            if "succeeded" in a.reason.lower()
        )
        
        return {
            "total_adjustments": len(self._adjustments),
            "successful_adaptations": successful_adaptations,
            "adaptation_success_rate": successful_adaptations / len(self._adjustments) if self._adjustments else 0,
            "plans_adapted": len(self._planning_history),
            "alternative_steps_available": len(self._alternative_steps),
            "total_alternatives": sum(len(v) for v in self._alternative_steps.values())
        }

