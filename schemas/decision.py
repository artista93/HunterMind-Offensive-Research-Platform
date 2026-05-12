from enum import Enum
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from datetime import datetime
from .world_state import WorldState
from .vulnerability import Vulnerability


class DecisionType(Enum):
    STRATEGIC = "strategic"
    TACTICAL = "tactical"
    EXECUTION = "execution"
    ADAPTIVE = "adaptive"
    EMERGENCY = "emergency"


class DecisionSource(Enum):
    COGNITIVE_CORE = "cognitive_core"
    STRATEGIC_PLANNER = "strategic_planner"
    TACTICAL_PLANNER = "tactical_planner"
    EXECUTION_PLANNER = "execution_planner"
    META_LEARNER = "meta_learner"
    SEQUENCE_LEARNER = "sequence_learner"
    AGENT = "agent"
    USER = "user"
    EMERGENCY = "emergency"


class DecisionPriority(Enum):
    CRITICAL = 1
    HIGH = 2
    NORMAL = 3
    LOW = 4
    BACKGROUND = 5


class DecisionStatus(Enum):
    PENDING = "pending"
    APPROVED = "approved"
    EXECUTING = "executing"
    COMPLETED = "completed"
    FAILED = "failed"
    REJECTED = "rejected"
    CANCELLED = "cancelled"


class ExecutionStrategy(Enum):
    IMMEDIATE = "immediate"
    SCHEDULED = "scheduled"
    CONDITIONAL = "conditional"
    BATCH = "batch"
    DEFERRED = "deferred"


def _generate_id() -> str:
    """توليد ID فريد للقرار (دالة مساعدة لتجنب تكرار الكود)"""
    import uuid
    return f"DEC-{uuid.uuid4().hex[:8].upper()}"


@dataclass
class DecisionConfidence:
    score: float = 0.0
    based_on: List[str] = field(default_factory=list)
    uncertainty: float = 0.0
    alternatives: List[str] = field(default_factory=list)
    
    def is_confident(self) -> bool:
        return self.score >= 0.7
    
    def is_uncertain(self) -> bool:
        return self.uncertainty > 0.5


@dataclass
class DecisionImpact:
    risk_delta: float = 0.0
    reward_delta: float = 0.0
    cost_estimate: float = 0.0
    time_estimate: float = 0.0
    detection_risk: float = 0.0
    
    @property
    def net_value(self) -> float:
        return self.reward_delta - abs(self.risk_delta) - self.cost_estimate


@dataclass
class DecisionContext:
    world_state: Optional[WorldState] = None
    current_phase: str = ""
    current_goal: str = ""
    available_resources: Dict[str, Any] = field(default_factory=dict)
    recent_decisions: List['Decision'] = field(default_factory=list)
    active_threats: List[str] = field(default_factory=list)
    constraints: List[str] = field(default_factory=list)


@dataclass
class Decision:
    """
    قرار يتخذه النظام
    
    ✅ جميع الحقول المطلوبة (بدون قيم افتراضية) تأتي أولاً
    ✅ ثم الحقول الاختيارية (بقيم افتراضية)
    """
    
    # ===== الحقول المطلوبة (required) =====
    id: str
    decision_type: DecisionType      # تم تغيير الاسم من 'type' لتجنب التعارض
    source: DecisionSource
    action: str
    
    # ===== الحقول الاختيارية (optional) =====
    target: Any = None
    parameters: Dict[str, Any] = field(default_factory=dict)
    priority: DecisionPriority = DecisionPriority.NORMAL
    strategy: ExecutionStrategy = ExecutionStrategy.IMMEDIATE
    scheduled_time: Optional[datetime] = None
    timestamp: datetime = field(default_factory=datetime.now)
    confidence: DecisionConfidence = field(default_factory=DecisionConfidence)
    impact: DecisionImpact = field(default_factory=DecisionImpact)
    reasoning: str = ""
    evidence: List[str] = field(default_factory=list)
    status: DecisionStatus = DecisionStatus.PENDING
    result: Any = None
    error: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    # ===== Fluent Interface Methods (return self) =====
    def approve(self) -> 'Decision':
        self.status = DecisionStatus.APPROVED
        return self
    
    def reject(self, reason: str = "") -> 'Decision':
        self.status = DecisionStatus.REJECTED
        self.error = reason
        return self
    
    def execute(self) -> 'Decision':
        self.status = DecisionStatus.EXECUTING
        return self
    
    def complete(self, result: Any = None) -> 'Decision':
        self.status = DecisionStatus.COMPLETED
        self.result = result
        return self
    
    def fail(self, error: str) -> 'Decision':
        self.status = DecisionStatus.FAILED
        self.error = error
        return self
    
    def is_executable(self) -> bool:
        return self.status == DecisionStatus.APPROVED
    
    def is_done(self) -> bool:
        return self.status in [DecisionStatus.COMPLETED, DecisionStatus.FAILED, DecisionStatus.CANCELLED]
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "type": self.decision_type.value,
            "source": self.source.value,
            "timestamp": self.timestamp.isoformat(),
            "action": self.action,
            "target": str(self.target) if self.target else None,
            "parameters": self.parameters,
            "priority": self.priority.name,
            "strategy": self.strategy.value,
            "confidence": self.confidence.score,
            "uncertainty": self.confidence.uncertainty,
            "reasoning": self.reasoning,
            "status": self.status.value,
            "error": self.error
        }
    
    @classmethod
    def create(cls, decision_type: DecisionType, source: DecisionSource, action: str, **kwargs) -> 'Decision':
        """طريقة مصنع لإنشاء قرارات بشكل آمن"""
        return cls(
            id=_generate_id(),
            decision_type=decision_type,
            source=source,
            action=action,
            **kwargs
        )


@dataclass
class DecisionProposal:
    source: DecisionSource
    decision: Decision
    weight: float = 1.0
    reasoning: str = ""


@dataclass
class FusedDecision:
    original_decisions: List[Decision]
    fused_action: str
    fused_confidence: float
    consensus_level: float
    reasoning: str
    conflicts: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict:
        return {
            "fused_action": self.fused_action,
            "confidence": self.fused_confidence,
            "consensus": self.consensus_level,
            "reasoning": self.reasoning,
            "sources": [d.source.value for d in self.original_decisions],
            "conflicts": self.conflicts
        }


class CommonDecisions:
    """قرارات شائعة الاستخدام - تستخدم طريقة المصنع لتجنب تكرار الكود"""
    
    @staticmethod
    def create_scan_decision(target_url: str, parameters: Dict = None) -> Decision:
        return Decision.create(
            decision_type=DecisionType.STRATEGIC,
            source=DecisionSource.COGNITIVE_CORE,
            action="start_scan",
            target=target_url,
            parameters=parameters or {},
            priority=DecisionPriority.HIGH,
            reasoning="Initiating security assessment of target"
        )
    
    @staticmethod
    def create_exploit_decision(vulnerability: Vulnerability) -> Decision:
        return Decision.create(
            decision_type=DecisionType.TACTICAL,
            source=DecisionSource.AGENT,
            action="exploit",
            target=vulnerability.url,
            parameters={
                "vulnerability_id": vulnerability.id,
                "vulnerability_type": vulnerability.type.value,
                "payload": vulnerability.payload
            },
            priority=DecisionPriority.HIGH,
            reasoning=f"Exploiting {vulnerability.type.value} at {vulnerability.url}"
        )
    
    @staticmethod
    def create_adapt_decision(current_strategy: str, reason: str) -> Decision:
        new_strategy = "stealth" if "detected" in reason else "aggressive"
        return Decision.create(
            decision_type=DecisionType.ADAPTIVE,
            source=DecisionSource.META_LEARNER,
            action="adapt_strategy",
            target=current_strategy,
            parameters={"new_strategy": new_strategy},
            priority=DecisionPriority.NORMAL,
            reasoning=reason
        )
    
    @staticmethod
    def create_emergency_stop_decision(reason: str) -> Decision:
        return Decision.create(
            decision_type=DecisionType.EMERGENCY,
            source=DecisionSource.EMERGENCY,
            action="emergency_stop",
            priority=DecisionPriority.CRITICAL,
            strategy=ExecutionStrategy.IMMEDIATE,
            reasoning=reason
        )


def generate_decision_id() -> str:
    return _generate_id()
