
from enum import Enum
from typing import List, Dict, Any, Optional, Union
from dataclasses import dataclass, field
from datetime import datetime
from .world_state import WorldState
from .vulnerability import Vulnerability


class DecisionType(Enum):
    """أنواع القرارات"""
    STRATEGIC = "strategic"      # قرار استراتيجي (طويل المدى)
    TACTICAL = "tactical"        # قرار تكتيكي (قصير المدى)
    EXECUTION = "execution"      # قرار تنفيذي (فوري)
    ADAPTIVE = "adaptive"        # قرار تكيفي (رد فعل)
    EMERGENCY = "emergency"      # قرار طارئ


class DecisionSource(Enum):
    """مصدر القرار"""
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
    """أولوية القرار"""
    CRITICAL = 1   # حرج - يجب التنفيذ فوراً
    HIGH = 2       # عالي
    NORMAL = 3     # عادي
    LOW = 4        # منخفض
    BACKGROUND = 5 # خلفية


class DecisionStatus(Enum):
    """حالة القرار"""
    PENDING = "pending"
    APPROVED = "approved"
    EXECUTING = "executing"
    COMPLETED = "completed"
    FAILED = "failed"
    REJECTED = "rejected"
    CANCELLED = "cancelled"


class ExecutionStrategy(Enum):
    """استراتيجية التنفيذ"""
    IMMEDIATE = "immediate"      # تنفيذ فوري
    SCHEDULED = "scheduled"      # مجدول
    CONDITIONAL = "conditional"  # مشروط
    BATCH = "batch"              # دفعة
    DEFERRED = "deferred"        # مؤجل


@dataclass
class DecisionConfidence:
    """ثقة القرار"""
    score: float = 0.0           # 0-1
    based_on: List[str] = field(default_factory=list)  # مصادر الثقة
    uncertainty: float = 0.0     # درجة عدم اليقين
    alternatives: List[str] = field(default_factory=list)  # بدائل محتملة
    
    def is_confident(self) -> bool:
        return self.score >= 0.7
    
    def is_uncertain(self) -> bool:
        return self.uncertainty > 0.5


@dataclass
class DecisionImpact:
    """تأثير القرار المتوقع"""
    risk_delta: float = 0.0       # تغير في المخاطر (-1 إلى 1)
    reward_delta: float = 0.0     # تغير في المكافأة
    cost_estimate: float = 0.0    # التكلفة المتوقعة
    time_estimate: float = 0.0    # الوقت المتوقع (ثواني)
    detection_risk: float = 0.0   # خطر الاكتشاف
    
    @property
    def net_value(self) -> float:
        """صافي القيمة (reward - risk - cost)"""
        return self.reward_delta - abs(self.risk_delta) - self.cost_estimate


@dataclass
class DecisionContext:
    """سياق القرار"""
    world_state: Optional[WorldState] = None
    current_phase: str = ""
    current_goal: str = ""
    available_resources: Dict[str, Any] = field(default_factory=dict)
    recent_decisions: List['Decision'] = field(default_factory=list)
    active_threats: List[str] = field(default_factory=list)
    constraints: List[str] = field(default_factory=list)


@dataclass
class Decision:
    """قرار يتخذه النظام"""
    
    # معلومات أساسية
    id: str
    type: DecisionType
    source: DecisionSource
    timestamp: datetime = field(default_factory=datetime.now)
    
    # محتوى القرار
    action: str
    target: Any = None
    parameters: Dict[str, Any] = field(default_factory=dict)
    
    # الأولوية والاستراتيجية
    priority: DecisionPriority = DecisionPriority.NORMAL
    strategy: ExecutionStrategy = ExecutionStrategy.IMMEDIATE
    scheduled_time: Optional[datetime] = None
    
    # الثقة والتأثير
    confidence: DecisionConfidence = field(default_factory=DecisionConfidence)
    impact: DecisionImpact = field(default_factory=DecisionImpact)
    
    # الأسباب
    reasoning: str = ""
    evidence: List[str] = field(default_factory=list)
    
    # الحالة
    status: DecisionStatus = DecisionStatus.PENDING
    result: Any = None
    error: Optional[str] = None
    
    # ميتاداتا
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def approve(self):
        """الموافقة على القرار"""
        self.status = DecisionStatus.APPROVED
    
    def reject(self, reason: str = ""):
        """رفض القرار"""
        self.status = DecisionStatus.REJECTED
        self.error = reason
    
    def execute(self):
        """بدء تنفيذ القرار"""
        self.status = DecisionStatus.EXECUTING
    
    def complete(self, result: Any = None):
        """إكمال القرار بنجاح"""
        self.status = DecisionStatus.COMPLETED
        self.result = result
    
    def fail(self, error: str):
        """فشل القرار"""
        self.status = DecisionStatus.FAILED
        self.error = error
    
    def is_executable(self) -> bool:
        """هل القرار قابل للتنفيذ؟"""
        return self.status == DecisionStatus.APPROVED
    
    def is_done(self) -> bool:
        """هل انتهى القرار؟"""
        return self.status in [DecisionStatus.COMPLETED, DecisionStatus.FAILED, DecisionStatus.CANCELLED]
    
    def to_dict(self) -> Dict[str, Any]:
        """تحويل إلى قاموس"""
        return {
            "id": self.id,
            "type": self.type.value,
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


@dataclass
class DecisionProposal:
    """اقتراح قرار (من مكون قبل التصويت)"""
    source: DecisionSource
    decision: Decision
    weight: float = 1.0
    reasoning: str = ""


@dataclass
class FusedDecision:
    """قرار مدمج من مصادر متعددة"""
    original_decisions: List[Decision]
    fused_action: str
    fused_confidence: float
    consensus_level: float  # نسبة الاتفاق بين المصادر
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


# أنواع القرارات الشائعة
class CommonDecisions:
    """قرارات شائعة الاستخدام"""
    
    @staticmethod
    def create_scan_decision(target_url: str, parameters: Dict = None) -> Decision:
        """قرار بدء المسح"""
        import uuid
        return Decision(
            id=f"DEC-{uuid.uuid4().hex[:8].upper()}",
            type=DecisionType.STRATEGIC,
            source=DecisionSource.COGNITIVE_CORE,
            action="start_scan",
            target=target_url,
            parameters=parameters or {},
            priority=DecisionPriority.HIGH,
            reasoning="Initiating security assessment of target"
        )
    
    @staticmethod
    def create_exploit_decision(vulnerability: Vulnerability) -> Decision:
        """قرار استغلال ثغرة"""
        import uuid
        return Decision(
            id=f"DEC-{uuid.uuid4().hex[:8].upper()}",
            type=DecisionType.TACTICAL,
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
        """قرار تكييف الاستراتيجية"""
        import uuid
        return Decision(
            id=f"DEC-{uuid.uuid4().hex[:8].upper()}",
            type=DecisionType.ADAPTIVE,
            source=DecisionSource.META_LEARNER,
            action="adapt_strategy",
            target=current_strategy,
            parameters={"new_strategy": "stealth" if "detected" in reason else "aggressive"},
            priority=DecisionPriority.NORMAL,
            reasoning=reason
        )
    
    @staticmethod
    def create_emergency_stop_decision(reason: str) -> Decision:
        """قرار إيقاف طارئ"""
        import uuid
        return Decision(
            id=f"DEC-{uuid.uuid4().hex[:8].upper()}",
            type=DecisionType.EMERGENCY,
            source=DecisionSource.EMERGENCY,
            action="emergency_stop",
            target=None,
            parameters={"reason": reason},
            priority=DecisionPriority.CRITICAL,
            strategy=ExecutionStrategy.IMMEDIATE,
            reasoning=reason
        )


# دالة مساعدة لتوليد ID فريد
def generate_decision_id() -> str:
    """توليد ID فريد للقرار"""
    import uuid
    return f"DEC-{uuid.uuid4().hex[:8].upper()}"

