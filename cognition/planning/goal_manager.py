
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

import logging

logger = logging.getLogger(__name__)


class GoalStatus(Enum):
    """حالة الهدف"""
    ACTIVE = "active"
    COMPLETED = "completed"
    FAILED = "failed"
    SUSPENDED = "suspended"
    ARCHIVED = "archived"


class GoalPriority(Enum):
    """أولوية الهدف"""
    CRITICAL = 1
    HIGH = 2
    MEDIUM = 3
    LOW = 4
    TRIVIAL = 5


@dataclass
class SubGoal:
    """هدف فرعي"""
    id: str
    description: str
    status: GoalStatus
    priority: GoalPriority
    parent_goal_id: str
    created_at: datetime = field(default_factory=datetime.now)
    completed_at: Optional[datetime] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Goal:
    """هدف رئيسي"""
    id: str
    name: str
    description: str
    status: GoalStatus
    priority: GoalPriority
    target_value: float
    current_value: float = 0.0
    sub_goals: List[SubGoal] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    deadline: Optional[datetime] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


class GoalManager:
    """
    مدير الأهداف المتقدم
    
    الميزات:
    - إدارة الأهداف الرئيسية والفرعية
    - تتبع التقدم نحو الأهداف
    - تحديث الأولويات ديناميكياً
    - تحليل تباعد الأهداف
    """
    
    def __init__(self):
        self._goals: Dict[str, Goal] = {}
        self._active_goal_id: Optional[str] = None
        
        # تهيئة الأهداف الافتراضية
        self._init_default_goals()
        
        logger.info("GoalManager initialized")
    
    def _init_default_goals(self):
        """تهيئة الأهداف الافتراضية"""
        
        import uuid
        
        # الهدف الرئيسي: اكتشاف الثغرات
        main_goal = Goal(
            id=str(uuid.uuid4())[:8],
            name="Vulnerability Discovery",
            description="Discover as many vulnerabilities as possible",
            status=GoalStatus.ACTIVE,
            priority=GoalPriority.CRITICAL,
            target_value=0.9,
            current_value=0.0
        )
        
        # أهداف فرعية
        sub1 = SubGoal(
            id=str(uuid.uuid4())[:8],
            description="Complete initial reconnaissance",
            status=GoalStatus.ACTIVE,
            priority=GoalPriority.HIGH,
            parent_goal_id=main_goal.id
        )
        
        sub2 = SubGoal(
            id=str(uuid.uuid4())[:8],
            description="Scan for common vulnerabilities",
            status=GoalStatus.ACTIVE,
            priority=GoalPriority.HIGH,
            parent_goal_id=main_goal.id
        )
        
        sub3 = SubGoal(
            id=str(uuid.uuid4())[:8],
            description="Perform deep vulnerability analysis",
            status=GoalStatus.PENDING,
            priority=GoalPriority.MEDIUM,
            parent_goal_id=main_goal.id
        )
        
        main_goal.sub_goals = [sub1, sub2, sub3]
        self._goals[main_goal.id] = main_goal
        self._active_goal_id = main_goal.id
        
        # الهدف الثانوي: استغلال الثغرات
        exploit_goal = Goal(
            id=str(uuid.uuid4())[:8],
            name="Vulnerability Exploitation",
            description="Successfully exploit discovered vulnerabilities",
            status=GoalStatus.PENDING,
            priority=GoalPriority.HIGH,
            target_value=0.8,
            current_value=0.0
        )
        
        self._goals[exploit_goal.id] = exploit_goal
    
    async def create_goal(
        self,
        name: str,
        description: str,
        target_value: float,
        priority: GoalPriority = GoalPriority.MEDIUM,
        deadline: datetime = None,
        metadata: Dict = None
    ) -> str:
        """
        إنشاء هدف جديد
        
        Args:
            name: اسم الهدف
            description: وصف الهدف
            target_value: القيمة المستهدفة
            priority: الأولوية
            deadline: الموعد النهائي
            metadata: بيانات إضافية
        
        Returns:
            معرف الهدف
        """
        import uuid
        goal_id = str(uuid.uuid4())[:8]
        
        goal = Goal(
            id=goal_id,
            name=name,
            description=description,
            status=GoalStatus.ACTIVE,
            priority=priority,
            target_value=target_value,
            deadline=deadline,
            metadata=metadata or {}
        )
        
        self._goals[goal_id] = goal
        
        logger.info(f"Goal created: {name} ({goal_id})")
        return goal_id
    
    async def update_progress(self, goal_id: str, new_value: float) -> bool:
        """
        تحديث التقدم نحو هدف
        
        Args:
            goal_id: معرف الهدف
            new_value: القيمة الجديدة
        
        Returns:
            نجاح العملية
        """
        if goal_id not in self._goals:
            return False
        
        goal = self._goals[goal_id]
        goal.current_value = new_value
        goal.updated_at = datetime.now()
        
        # التحقق من اكتمال الهدف
        if goal.current_value >= goal.target_value:
            goal.status = GoalStatus.COMPLETED
            logger.info(f"Goal {goal.name} completed!")
        
        logger.debug(f"Goal {goal.name} progress updated to {new_value}/{goal.target_value}")
        return True
    
    async def update_subgoal_status(
        self,
        parent_goal_id: str,
        subgoal_id: str,
        status: GoalStatus
    ) -> bool:
        """
        تحديث حالة هدف فرعي
        
        Args:
            parent_goal_id: معرف الهدف الرئيسي
            subgoal_id: معرف الهدف الفرعي
            status: الحالة الجديدة
        
        Returns:
            نجاح العملية
        """
        if parent_goal_id not in self._goals:
            return False
        
        goal = self._goals[parent_goal_id]
        
        for subgoal in goal.sub_goals:
            if subgoal.id == subgoal_id:
                subgoal.status = status
                if status == GoalStatus.COMPLETED:
                    subgoal.completed_at = datetime.now()
                    
                    # تحديث التقدم الإجمالي
                    completed = sum(1 for sg in goal.sub_goals if sg.status == GoalStatus.COMPLETED)
                    goal.current_value = completed / len(goal.sub_goals) if goal.sub_goals else 0
                    
                    if goal.current_value >= goal.target_value:
                        goal.status = GoalStatus.COMPLETED
                
                logger.debug(f"Subgoal {subgoal.description} status updated to {status.value}")
                return True
        
        return False
    
    async def get_active_goal(self) -> Optional[Goal]:
        """الحصول على الهدف النشط الحالي"""
        if self._active_goal_id:
            return self._goals.get(self._active_goal_id)
        
        # العثور على أول هدف نشط
        for goal in self._goals.values():
            if goal.status == GoalStatus.ACTIVE:
                self._active_goal_id = goal.id
                return goal
        
        return None
    
    async def set_active_goal(self, goal_id: str) -> bool:
        """تعيين هدف نشط"""
        if goal_id in self._goals:
            self._active_goal_id = goal_id
            logger.info(f"Active goal set to {self._goals[goal_id].name}")
            return True
        return False
    
    async def get_goal_summary(self) -> Dict:
        """ملخص الأهداف"""
        active_goals = [g for g in self._goals.values() if g.status == GoalStatus.ACTIVE]
        completed_goals = [g for g in self._goals.values() if g.status == GoalStatus.COMPLETED]
        
        return {
            "total_goals": len(self._goals),
            "active_goals": len(active_goals),
            "completed_goals": len(completed_goals),
            "completion_rate": len(completed_goals) / len(self._goals) if self._goals else 0,
            "goals": [
                {
                    "id": g.id,
                    "name": g.name,
                    "status": g.status.value,
                    "progress": f"{g.current_value}/{g.target_value}",
                    "progress_percent": (g.current_value / g.target_value * 100) if g.target_value > 0 else 0
                }
                for g in self._goals.values()
            ],
            "active_goal": self._active_goal_id
        }
    
    async def get_statistics(self) -> Dict:
        """إحصائيات المدير"""
        return {
            "total_goals": len(self._goals),
            "active_goal": self._active_goal_id,
            "goal_priority_distribution": {
                p.name: len([g for g in self._goals.values() if g.priority == p])
                for p in GoalPriority
            },
            "goal_status_distribution": {
                s.name: len([g for g in self._goals.values() if g.status == s])
                for s in GoalStatus
            },
            "average_progress": sum(g.current_value / g.target_value for g in self._goals.values() if g.target_value > 0) / len(self._goals) if self._goals else 0
        }

