
from enum import Enum
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass, field
from datetime import datetime
from collections import defaultdict

import logging

logger = logging.getLogger(__name__)


class AgentStateEnum(Enum):
    """حالات الوكيل"""
    CREATED = "created"
    INITIALIZING = "initializing"
    IDLE = "idle"
    BUSY = "busy"
    WAITING = "waiting"
    PAUSED = "paused"
    ERROR = "error"
    STOPPING = "stopping"
    STOPPED = "stopped"
    RECOVERING = "recovering"


@dataclass
class StateTransition:
    """تحول حالة"""
    from_state: AgentStateEnum
    to_state: AgentStateEnum
    timestamp: datetime
    reason: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AgentStateInfo:
    """معلومات حالة الوكيل"""
    current_state: AgentStateEnum
    previous_state: Optional[AgentStateEnum]
    state_history: List[StateTransition] = field(default_factory=list)
    state_durations: Dict[AgentStateEnum, float] = field(default_factory=dict)
    last_change: datetime = field(default_factory=datetime.now)
    error_message: Optional[str] = None


class AgentStateManager:
    """
    مدير حالة الوكيل
    
    الميزات:
    - تتبع حالات الوكيل
    - التحقق من صحة التحولات بين الحالات
    - تسجيل تاريخ التحولات
    - حساب المدة في كل حالة
    - استدعاءات عند تغيير الحالة
    """
    
    # التحولات المسموحة بين الحالات
    ALLOWED_TRANSITIONS = {
        AgentStateEnum.CREATED: [AgentStateEnum.INITIALIZING, AgentStateEnum.ERROR],
        AgentStateEnum.INITIALIZING: [AgentStateEnum.IDLE, AgentStateEnum.ERROR],
        AgentStateEnum.IDLE: [AgentStateEnum.BUSY, AgentStateEnum.PAUSED, AgentStateEnum.STOPPING, AgentStateEnum.ERROR],
        AgentStateEnum.BUSY: [AgentStateEnum.IDLE, AgentStateEnum.WAITING, AgentStateEnum.ERROR, AgentStateEnum.STOPPING],
        AgentStateEnum.WAITING: [AgentStateEnum.IDLE, AgentStateEnum.BUSY, AgentStateEnum.ERROR, AgentStateEnum.STOPPING],
        AgentStateEnum.PAUSED: [AgentStateEnum.IDLE, AgentStateEnum.STOPPING],
        AgentStateEnum.ERROR: [AgentStateEnum.RECOVERING, AgentStateEnum.STOPPING],
        AgentStateEnum.RECOVERING: [AgentStateEnum.IDLE, AgentStateEnum.ERROR, AgentStateEnum.STOPPING],
        AgentStateEnum.STOPPING: [AgentStateEnum.STOPPED],
        AgentStateEnum.STOPPED: [],
    }
    
    def __init__(self, agent_id: str, agent_name: str):
        self._agent_id = agent_id
        self._agent_name = agent_name
        self._state_info = AgentStateInfo(
            current_state=AgentStateEnum.CREATED,
            previous_state=None,
            last_change=datetime.now()
        )
        self._callbacks: Dict[AgentStateEnum, List[callable]] = defaultdict(list)
        self._global_callbacks: List[callable] = []
        
        logger.debug(f"AgentStateManager initialized for {agent_name}")
    
    def transition_to(
        self,
        new_state: AgentStateEnum,
        reason: str = None,
        metadata: Dict = None
    ) -> bool:
        """
        الانتقال إلى حالة جديدة
        
        Args:
            new_state: الحالة الجديدة
            reason: سبب الانتقال
            metadata: بيانات إضافية
        
        Returns:
            نجاح الانتقال
        """
        current = self._state_info.current_state
        
        # التحقق من صحة الانتقال
        if not self._is_transition_allowed(current, new_state):
            logger.warning(
                f"Invalid state transition for {self._agent_name}: "
                f"{current.value} -> {new_state.value}"
            )
            return False
        
        # تسجيل التحول
        transition = StateTransition(
            from_state=current,
            to_state=new_state,
            timestamp=datetime.now(),
            reason=reason,
            metadata=metadata or {}
        )
        
        # حساب المدة في الحالة السابقة
        now = datetime.now()
        duration = (now - self._state_info.last_change).total_seconds()
        self._state_info.state_durations[current] = \
            self._state_info.state_durations.get(current, 0) + duration
        
        # تحديث الحالة
        self._state_info.previous_state = current
        self._state_info.current_state = new_state
        self._state_info.state_history.append(transition)
        self._state_info.last_change = now
        
        if new_state == AgentStateEnum.ERROR:
            self._state_info.error_message = reason
        
        logger.info(f"Agent {self._agent_name} state: {current.value} -> {new_state.value}")
        
        # استدعاء المعالجات
        self._call_callbacks(new_state, transition)
        
        return True
    
    def _is_transition_allowed(self, from_state: AgentStateEnum, to_state: AgentStateEnum) -> bool:
        """التحقق من صحة الانتقال"""
        return to_state in self.ALLOWED_TRANSITIONS.get(from_state, [])
    
    def _call_callbacks(self, new_state: AgentStateEnum, transition: StateTransition):
        """استدعاء معالجات الحالة"""
        # معالجات الحالة المحددة
        for callback in self._callbacks.get(new_state, []):
            try:
                callback(self._agent_id, transition)
            except Exception as e:
                logger.error(f"State callback error: {e}")
        
        # معالجات عامة
        for callback in self._global_callbacks:
            try:
                callback(self._agent_id, new_state, transition)
            except Exception as e:
                logger.error(f"Global callback error: {e}")
    
    def on_state(self, state: AgentStateEnum, callback: callable):
        """
        تسجيل معالج لحالة محددة
        
        Args:
            state: الحالة
            callback: دالة معالج (agent_id, transition)
        """
        self._callbacks[state].append(callback)
    
    def on_any_state(self, callback: callable):
        """
        تسجيل معالج لأي حالة
        
        Args:
            callback: دالة معالج (agent_id, new_state, transition)
        """
        self._global_callbacks.append(callback)
    
    def get_current_state(self) -> AgentStateEnum:
        """الحصول على الحالة الحالية"""
        return self._state_info.current_state
    
    def get_previous_state(self) -> Optional[AgentStateEnum]:
        """الحصول على الحالة السابقة"""
        return self._state_info.previous_state
    
    def get_state_history(self, limit: int = 100) -> List[StateTransition]:
        """الحصول على تاريخ التحولات"""
        return self._state_info.state_history[-limit:]
    
    def get_state_duration(self, state: AgentStateEnum) -> float:
        """الحصول على المدة الإجمالية في حالة معينة"""
        return self._state_info.state_durations.get(state, 0.0)
    
    def get_current_state_duration(self) -> float:
        """الحصول على المدة في الحالة الحالية"""
        return (datetime.now() - self._state_info.last_change).total_seconds()
    
    def is_in_state(self, state: AgentStateEnum) -> bool:
        """التحقق من أن الوكيل في حالة معينة"""
        return self._state_info.current_state == state
    
    def is_operational(self) -> bool:
        """هل الوكيل في حالة تشغيلية؟"""
        return self._state_info.current_state in [
            AgentStateEnum.IDLE,
            AgentStateEnum.BUSY,
            AgentStateEnum.WAITING,
            AgentStateEnum.RECOVERING
        ]
    
    def is_available(self) -> bool:
        """هل الوكيل متاح لاستقبال المهام؟"""
        return self._state_info.current_state in [
            AgentStateEnum.IDLE,
            AgentStateEnum.RECOVERING
        ]
    
    def is_error(self) -> bool:
        """هل الوكيل في حالة خطأ؟"""
        return self._state_info.current_state == AgentStateEnum.ERROR
    
    def get_error_message(self) -> Optional[str]:
        """الحصول على رسالة الخطأ"""
        return self._state_info.error_message
    
    def reset_error(self):
        """إعادة تعيين حالة الخطأ"""
        if self._state_info.current_state == AgentStateEnum.ERROR:
            self.transition_to(AgentStateEnum.RECOVERING, reason="Error reset")
            self._state_info.error_message = None
    
    def get_summary(self) -> Dict:
        """ملخص الحالة"""
        return {
            "current_state": self._state_info.current_state.value,
            "previous_state": self._state_info.previous_state.value if self._state_info.previous_state else None,
            "current_duration": self.get_current_state_duration(),
            "total_transitions": len(self._state_info.state_history),
            "state_durations": {
                state.value: duration for state, duration in self._state_info.state_durations.items()
            },
            "is_operational": self.is_operational(),
            "is_available": self.is_available(),
            "has_error": self.is_error(),
            "error_message": self._state_info.error_message
        }
    
    def get_transition_stats(self) -> Dict:
        """إحصائيات التحولات"""
        transition_counts = defaultdict(int)
        
        for transition in self._state_info.state_history:
            key = f"{transition.from_state.value}->{transition.to_state.value}"
            transition_counts[key] += 1
        
        return {
            "total": len(self._state_info.state_history),
            "transitions": dict(transition_counts),
            "most_common": max(transition_counts.items(), key=lambda x: x[1])[0] if transition_counts else None
        }

