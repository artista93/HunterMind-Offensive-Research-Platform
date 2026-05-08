

from enum import Enum
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from datetime import datetime
from .vulnerability import Vulnerability, VulnerabilityType, Severity


class ChainStepStatus(Enum):
    """حالة خطوة في سلسلة الهجوم"""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    SUCCESS = "success"
    FAILED = "failed"
    SKIPPED = "skipped"
    BLOCKED = "blocked"


class ChainType(Enum):
    """أنواع سلاسل الهجوم"""
    XSS_TO_SESSION = "xss_to_session_hijacking"
    SQLI_TO_DATA = "sqli_to_data_exfiltration"
    IDOR_TO_PRIVESC = "idor_to_privilege_escalation"
    CSRF_TO_ACTION = "csrf_to_unauthorized_action"
    LFI_TO_RCE = "lfi_to_rce"
    SSRF_TO_INTERNAL = "ssrf_to_internal_access"
    CHAIN_REACTION = "chain_reaction"
    FULL_COMPROMISE = "full_compromise"
    CUSTOM = "custom"


class PrerequisiteStatus(Enum):
    """حالة المتطلبات المسبقة"""
    MET = "met"
    NOT_MET = "not_met"
    PARTIALLY_MET = "partially_met"
    UNKNOWN = "unknown"


@dataclass
class Prerequisite:
    """متطلب مسبق لخطوة في السلسلة"""
    description: str
    type: str  # vulnerability, auth, endpoint, data, etc.
    value: Any
    status: PrerequisiteStatus = PrerequisiteStatus.UNKNOWN
    satisfied_by: Optional[str] = None  # ID of the step that satisfies this


@dataclass
class StepOutcome:
    """نتيجة متوقعة من خطوة"""
    description: str
    type: str  # data, access, token, shell, etc.
    value: Any
    achieved: bool = False
    captured_at: Optional[datetime] = None


@dataclass
class AttackStep:
    """خطوة واحدة في سلسلة الهجوم"""
    step_id: int
    name: str
    description: str
    
    # الثغرة المستخدمة
    vulnerability: Optional[Vulnerability] = None
    vulnerability_type: Optional[VulnerabilityType] = None
    
    # التنفيذ
    payload: Optional[str] = None
    target_url: Optional[str] = None
    target_parameter: Optional[str] = None
    
    # المتطلبات والنتائج
    prerequisites: List[Prerequisite] = field(default_factory=list)
    outcomes: List[StepOutcome] = field(default_factory=list)
    
    # الحالة
    status: ChainStepStatus = ChainStepStatus.PENDING
    execution_time: Optional[float] = None
    error_message: Optional[str] = None
    
    # الأدلة
    request_sent: Optional[str] = None
    response_received: Optional[str] = None
    evidence: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """تحويل إلى قاموس"""
        return {
            "step_id": self.step_id,
            "name": self.name,
            "description": self.description,
            "vulnerability_id": self.vulnerability.id if self.vulnerability else None,
            "vulnerability_type": self.vulnerability_type.value if self.vulnerability_type else None,
            "payload": self.payload,
            "target_url": self.target_url,
            "target_parameter": self.target_parameter,
            "prerequisites": [
                {
                    "description": p.description,
                    "type": p.type,
                    "value": p.value,
                    "status": p.status.value
                }
                for p in self.prerequisites
            ],
            "outcomes": [
                {
                    "description": o.description,
                    "type": o.type,
                    "value": o.value,
                    "achieved": o.achieved
                }
                for o in self.outcomes
            ],
            "status": self.status.value,
            "execution_time": self.execution_time,
            "error_message": self.error_message
        }
    
    def is_successful(self) -> bool:
        """هل نجحت الخطوة؟"""
        return self.status == ChainStepStatus.SUCCESS
    
    def get_outcome_value(self, outcome_type: str) -> Optional[Any]:
        """الحصول على قيمة نتيجة معينة"""
        for outcome in self.outcomes:
            if outcome.type == outcome_type and outcome.achieved:
                return outcome.value
        return None


@dataclass
class AttackChain:
    """سلسلة هجوم كاملة"""
    
    # معلومات أساسية
    id: str
    name: str
    chain_type: ChainType
    description: str
    
    # الخطوات
    steps: List[AttackStep] = field(default_factory=list)
    
    # تقييم المخاطر
    total_risk_score: float = 0.0
    success_probability: float = 0.0
    estimated_impact: str = ""
    
    # الحالة
    is_executed: bool = False
    is_successful: bool = False
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    
    # معلومات إضافية
    target: str = ""
    created_at: datetime = field(default_factory=datetime.now)
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def add_step(self, step: AttackStep):
        """إضافة خطوة إلى السلسلة"""
        self.steps.append(step)
    
    def get_step_by_id(self, step_id: int) -> Optional[AttackStep]:
        """الحصول على خطوة حسب المعرف"""
        for step in self.steps:
            if step.step_id == step_id:
                return step
        return None
    
    def get_current_step(self) -> Optional[AttackStep]:
        """الحصول على الخطوة الحالية (أول خطوة لم تكتمل)"""
        for step in self.steps:
            if step.status in [ChainStepStatus.PENDING, ChainStepStatus.IN_PROGRESS]:
                return step
        return None
    
    def get_completed_steps(self) -> List[AttackStep]:
        """الحصول على الخطوات المكتملة"""
        return [s for s in self.steps if s.status == ChainStepStatus.SUCCESS]
    
    def get_failed_steps(self) -> List[AttackStep]:
        """الحصول على الخطوات الفاشلة"""
        return [s for s in self.steps if s.status == ChainStepStatus.FAILED]
    
    def calculate_success_probability(self) -> float:
        """حساب احتمالية نجاح السلسلة"""
        if not self.steps:
            return 0.0
        
        # متوسط ثقة الخطوات
        step_confidences = []
        for step in self.steps:
            if step.vulnerability:
                step_confidences.append(step.vulnerability.confidence)
            else:
                step_confidences.append(0.5)
        
        avg_confidence = sum(step_confidences) / len(step_confidences)
        
        # ضرب احتمالية نجاح كل خطوة
        chain_probability = avg_confidence ** len(self.steps)
        
        self.success_probability = min(1.0, chain_probability)
        return self.success_probability
    
    def calculate_risk_score(self) -> float:
        """حساب درجة المخاطر الإجمالية للسلسلة"""
        if not self.steps:
            return 0.0
        
        total_risk = 0.0
        for step in self.steps:
            if step.vulnerability:
                total_risk += step.vulnerability.get_risk_score()
            else:
                total_risk += 0.5
        
        self.total_risk_score = min(10.0, total_risk / len(self.steps) * 2)
        return self.total_risk_score
    
    def to_dict(self) -> Dict[str, Any]:
        """تحويل السلسلة إلى قاموس"""
        return {
            "id": self.id,
            "name": self.name,
            "chain_type": self.chain_type.value,
            "description": self.description,
            "steps": [step.to_dict() for step in self.steps],
            "total_risk_score": self.total_risk_score,
            "success_probability": self.success_probability,
            "estimated_impact": self.estimated_impact,
            "is_executed": self.is_executed,
            "is_successful": self.is_successful,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "target": self.target,
            "created_at": self.created_at.isoformat(),
            "tags": self.tags
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'AttackChain':
        """إنشاء سلسلة من قاموس"""
        chain = cls(
            id=data["id"],
            name=data["name"],
            chain_type=ChainType(data["chain_type"]),
            description=data["description"],
            target=data.get("target", ""),
            tags=data.get("tags", [])
        )
        
        # إضافة الخطوات (سيتم ملؤها لاحقاً بالثغرات الفعلية)
        for step_data in data.get("steps", []):
            step = AttackStep(
                step_id=step_data["step_id"],
                name=step_data["name"],
                description=step_data["description"],
                payload=step_data.get("payload"),
                target_url=step_data.get("target_url"),
                target_parameter=step_data.get("target_parameter")
            )
            chain.add_step(step)
        
        return chain
    
    def get_execution_summary(self) -> Dict[str, Any]:
        """ملخص تنفيذ السلسلة"""
        return {
            "total_steps": len(self.steps),
            "completed_steps": len(self.get_completed_steps()),
            "failed_steps": len(self.get_failed_steps()),
            "success_rate": len(self.get_completed_steps()) / max(1, len(self.steps)),
            "current_step": self.get_current_step().step_id if self.get_current_step() else None,
            "is_successful": self.is_successful,
            "is_complete": all(s.status == ChainStepStatus.SUCCESS for s in self.steps)
        }


@dataclass
class AttackChainTemplate:
    """قالب لسلسلة هجوم (قابل لإعادة الاستخدام)"""
    name: str
    chain_type: ChainType
    description: str
    vulnerability_sequence: List[VulnerabilityType]
    estimated_difficulty: str  # easy, medium, hard, expert
    prerequisites: List[str] = field(default_factory=list)
    typical_steps: List[Dict] = field(default_factory=list)
    
    def create_chain(self, target: str, vulnerabilities: List[Vulnerability]) -> Optional[AttackChain]:
        """إنشاء سلسلة هجوم من القالب باستخدام الثغرات المتاحة"""
        import uuid
        
        # مطابقة الثغرات مع التسلسل المطلوب
        matched_vulns = []
        for required_type in self.vulnerability_sequence:
            found = False
            for vuln in vulnerabilities:
                if vuln.type == required_type and vuln.is_confirmed():
                    matched_vulns.append(vuln)
                    found = True
                    break
            if not found:
                return None  # لا يمكن إنشاء السلسلة
        
        # بناء الخطوات
        steps = []
        for i, (vuln, step_template) in enumerate(zip(matched_vulns, self.typical_steps)):
            step = AttackStep(
                step_id=i + 1,
                name=step_template.get("name", f"Step {i+1}: Exploit {vuln.type.value}"),
                description=step_template.get("description", f"Exploit {vuln.type.value} at {vuln.url}"),
                vulnerability=vuln,
                vulnerability_type=vuln.type,
                payload=vuln.payload,
                target_url=vuln.url,
                target_parameter=vuln.parameter
            )
            steps.append(step)
        
        chain = AttackChain(
            id=f"CHAIN-{uuid.uuid4().hex[:8].upper()}",
            name=self.name,
            chain_type=self.chain_type,
            description=self.description,
            steps=steps,
            target=target,
            tags=[self.estimated_difficulty]
        )
        
        chain.calculate_risk_score()
        chain.calculate_success_probability()
        
        return chain


# قوالب سلاسل الهجوم الشائعة
COMMON_ATTACK_CHAINS = [
    AttackChainTemplate(
        name="Session Hijacking Chain",
        chain_type=ChainType.XSS_TO_SESSION,
        description="Use XSS to steal session tokens and hijack user sessions",
        vulnerability_sequence=[VulnerabilityType.XSS_REFLECTED, VulnerabilityType.IDOR],
        estimated_difficulty="medium",
        typical_steps=[
            {"name": "Inject XSS Payload", "description": "Inject JavaScript to steal cookies"},
            {"name": "Extract Session Token", "description": "Capture session token from stolen cookies"},
            {"name": "Hijack Session", "description": "Use token to access user account"}
        ]
    ),
    AttackChainTemplate(
        name="Database Compromise Chain",
        chain_type=ChainType.SQLI_TO_DATA,
        description="Extract sensitive data from database via SQL injection",
        vulnerability_sequence=[VulnerabilityType.SQLI_UNION],
        estimated_difficulty="medium",
        typical_steps=[
            {"name": "Identify SQLi", "description": "Confirm SQL injection vulnerability"},
            {"name": "Extract Schema", "description": "Discover database structure"},
            {"name": "Dump Data", "description": "Extract sensitive information"}
        ]
    ),
    AttackChainTemplate(
        name="Privilege Escalation Chain",
        chain_type=ChainType.IDOR_TO_PRIVESC,
        description="Use IDOR to escalate privileges",
        vulnerability_sequence=[VulnerabilityType.IDOR],
        estimated_difficulty="hard",
        typical_steps=[
            {"name": "Enumerate IDs", "description": "Discover valid user/object IDs"},
            {"name": "Access Other Users", "description": "Access data of higher privilege users"},
            {"name": "Escalate Privileges", "description": "Gain administrative access"}
        ]
    )
]


# دالة مساعدة لتوليد ID فريد للسلسلة
def generate_chain_id() -> str:
    """توليد ID فريد للسلسلة"""
    import uuid
    return f"CHAIN-{uuid.uuid4().hex[:8].upper()}"

