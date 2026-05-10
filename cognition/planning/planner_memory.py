
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from collections import defaultdict

from .strategic_planner import StrategicPlan
from .tactical_planner import TacticalPlan
from .execution_planner import ExecutionPlan

import logging

logger = logging.getLogger(__name__)


@dataclass
class PlanRecord:
    """سجل خطة"""
    plan_id: str
    plan_type: str  # strategic, tactical, execution
    name: str
    success: bool
    execution_time: float
    created_at: datetime
    completed_at: Optional[datetime] = None
    metrics: Dict[str, float] = field(default_factory=dict)
    lessons: List[str] = field(default_factory=list)


class PlannerMemory:
    """
    ذاكرة المخطط المتقدم
    
    الميزات:
    - تخزين الخطط السابقة
    - تحليل نجاح الخطط
    - اقتراح تحسينات للخطط المستقبلية
    - استرجاع الخطط المماثلة
    - تعلم من الأخطاء
    """
    
    def __init__(self):
        self._strategic_records: List[PlanRecord] = []
        self._tactical_records: List[PlanRecord] = []
        self._execution_records: List[PlanRecord] = []
        
        # فهارس للبحث السريع
        self._successful_plans: Set[str] = set()
        self._failed_plans: Set[str] = set()
        
        logger.info("PlannerMemory initialized")
    
    async def store_plan(
        self,
        plan: Any,
        plan_type: str,
        success: bool,
        execution_time: float,
        metrics: Dict = None,
        lessons: List[str] = None
    ):
        """
        تخزين سجل خطة
        
        Args:
            plan: الخطة (StrategicPlan, TacticalPlan, أو ExecutionPlan)
            plan_type: نوع الخطة
            success: نجاح الخطة
            execution_time: وقت التنفيذ
            metrics: مقاييس الأداء
            lessons: الدروس المستفادة
        """
        record = PlanRecord(
            plan_id=plan.id,
            plan_type=plan_type,
            name=plan.name,
            success=success,
            execution_time=execution_time,
            created_at=plan.created_at,
            completed_at=datetime.now(),
            metrics=metrics or {},
            lessons=lessons or []
        )
        
        if plan_type == "strategic":
            self._strategic_records.append(record)
        elif plan_type == "tactical":
            self._tactical_records.append(record)
        else:
            self._execution_records.append(record)
        
        if success:
            self._successful_plans.add(plan.id)
        else:
            self._failed_plans.add(plan.id)
        
        # الحفاظ على آخر 1000 سجل فقط
        max_records = 1000
        if len(self._strategic_records) > max_records:
            removed = self._strategic_records.pop(0)
            self._successful_plans.discard(removed.plan_id)
            self._failed_plans.discard(removed.plan_id)
        
        logger.debug(f"Plan stored: {plan.name} ({plan_type}, success={success})")
    
    async def get_successful_plans(
        self,
        plan_type: str = None,
        limit: int = 10
    ) -> List[PlanRecord]:
        """
        الحصول على الخطط الناجحة
        
        Args:
            plan_type: نوع الخطة (الكل إذا None)
            limit: عدد النتائج
        
        Returns:
            قائمة بالخطط الناجحة
        """
        records = []
        
        if plan_type is None or plan_type == "strategic":
            records.extend([r for r in self._strategic_records if r.success])
        if plan_type is None or plan_type == "tactical":
            records.extend([r for r in self._tactical_records if r.success])
        if plan_type is None or plan_type == "execution":
            records.extend([r for r in self._execution_records if r.success])
        
        # ترتيب حسب الأحدث أولاً
        records.sort(key=lambda x: x.completed_at, reverse=True)
        
        return records[:limit]
    
    async def get_failed_plans(
        self,
        plan_type: str = None,
        limit: int = 10
    ) -> List[PlanRecord]:
        """
        الحصول على الخطط الفاشلة
        
        Args:
            plan_type: نوع الخطة (الكل إذا None)
            limit: عدد النتائج
        
        Returns:
            قائمة بالخطط الفاشلة
        """
        records = []
        
        if plan_type is None or plan_type == "strategic":
            records.extend([r for r in self._strategic_records if not r.success])
        if plan_type is None or plan_type == "tactical":
            records.extend([r for r in self._tactical_records if not r.success])
        if plan_type is None or plan_type == "execution":
            records.extend([r for r in self._execution_records if not r.success])
        
        records.sort(key=lambda x: x.completed_at, reverse=True)
        
        return records[:limit]
    
    async def find_similar_plans(
        self,
        plan_name: str,
        plan_type: str = None,
        limit: int = 5
    ) -> List[PlanRecord]:
        """
        البحث عن خطط مماثلة
        
        Args:
            plan_name: اسم الخطة للبحث
            plan_type: نوع الخطة
            limit: عدد النتائج
        
        Returns:
            قائمة بالخطط المماثلة
        """
        similar = []
        
        if plan_type is None or plan_type == "strategic":
            for record in self._strategic_records:
                if plan_name.lower() in record.name.lower():
                    similar.append(record)
        
        if plan_type is None or plan_type == "tactical":
            for record in self._tactical_records:
                if plan_name.lower() in record.name.lower():
                    similar.append(record)
        
        if plan_type is None or plan_type == "execution":
            for record in self._execution_records:
                if plan_name.lower() in record.name.lower():
                    similar.append(record)
        
        # ترتيب حسب النجاح أولاً، ثم حسب الحداثة
        similar.sort(key=lambda x: (x.success, x.completed_at), reverse=True)
        
        return similar[:limit]
    
    async def get_plan_metrics(self) -> Dict:
        """الحصول على مقاييس أداء الخطط"""
        total_strategic = len(self._strategic_records)
        total_tactical = len(self._tactical_records)
        total_execution = len(self._execution_records)
        
        successful_strategic = len([r for r in self._strategic_records if r.success])
        successful_tactical = len([r for r in self._tactical_records if r.success])
        successful_execution = len([r for r in self._execution_records if r.success])
        
        # متوسط وقت التنفيذ للخطط الناجحة
        avg_time_success = 0.0
        success_records = [r for r in self._strategic_records + self._tactical_records + self._execution_records if r.success]
        if success_records:
            avg_time_success = sum(r.execution_time for r in success_records) / len(success_records)
        
        # الدروس المستفادة الشائعة
        common_lessons = defaultdict(int)
        for record in self._strategic_records + self._tactical_records + self._execution_records:
            for lesson in record.lessons:
                common_lessons[lesson] += 1
        
        return {
            "total_plans": total_strategic + total_tactical + total_execution,
            "by_type": {
                "strategic": total_strategic,
                "tactical": total_tactical,
                "execution": total_execution
            },
            "success_rate": {
                "strategic": successful_strategic / total_strategic if total_strategic > 0 else 0,
                "tactical": successful_tactical / total_tactical if total_tactical > 0 else 0,
                "execution": successful_execution / total_execution if total_execution > 0 else 0
            },
            "average_execution_time_success": avg_time_success,
            "common_lessons": dict(sorted(common_lessons.items(), key=lambda x: x[1], reverse=True)[:5]),
            "total_lessons_learned": sum(len(r.lessons) for r in self._strategic_records + self._tactical_records + self._execution_records)
        }
    
    async def get_statistics(self) -> Dict:
        """إحصائيات الذاكرة"""
        return {
            "strategic_plans": len(self._strategic_records),
            "tactical_plans": len(self._tactical_records),
            "execution_plans": len(self._execution_records),
            "successful_plans": len(self._successful_plans),
            "failed_plans": len(self._failed_plans),
            "success_rate": len(self._successful_plans) / (len(self._successful_plans) + len(self._failed_plans)) if (self._successful_plans or self._failed_plans) else 0
        }

