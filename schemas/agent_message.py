
from enum import Enum
from typing import List, Dict, Any, Optional, Union
from dataclasses import dataclass, field
from datetime import datetime
from .vulnerability import Vulnerability
from .attack_chain import AttackChain
from .world_state import WorldState
from .decision import Decision


class MessageType(Enum):
    """أنواع الرسائل"""
    # رسائل الأوامر
    COMMAND_SCAN = "command_scan"
    COMMAND_EXPLOIT = "command_exploit"
    COMMAND_STOP = "command_stop"
    COMMAND_PAUSE = "command_pause"
    COMMAND_RESUME = "command_resume"
    
    # رسائل البيانات
    DATA_VULNERABILITY = "data_vulnerability"
    DATA_ATTACK_CHAIN = "data_attack_chain"
    DATA_WORLD_STATE = "data_world_state"
    DATA_ENDPOINT = "data_endpoint"
    DATA_TECHNOLOGY = "data_technology"
    
    # رسائل الأحداث
    EVENT_SCAN_STARTED = "event_scan_started"
    EVENT_SCAN_COMPLETED = "event_scan_completed"
    EVENT_VULNERABILITY_FOUND = "event_vulnerability_found"
    EVENT_EXPLOIT_SUCCESS = "event_exploit_success"
    EVENT_EXPLOIT_FAILED = "event_exploit_failed"
    EVENT_ERROR = "event_error"
    EVENT_WARNING = "event_warning"
    
    # رسائل الطلبات
    REQUEST_STATUS = "request_status"
    REQUEST_HELP = "request_help"
    REQUEST_COORDINATION = "request_coordination"
    
    # رسائل الردود
    RESPONSE_STATUS = "response_status"
    RESPONSE_ACK = "response_ack"
    RESPONSE_ERROR = "response_error"


class MessagePriority(Enum):
    """أولوية الرسالة"""
    CRITICAL = 1   # حرج - يجب معالجتها فوراً
    HIGH = 2       # عالية
    NORMAL = 3     # عادية
    LOW = 4        # منخفضة
    BACKGROUND = 5 # خلفية


class MessageStatus(Enum):
    """حالة الرسالة"""
    SENT = "sent"
    DELIVERED = "delivered"
    PROCESSED = "processed"
    FAILED = "failed"
    EXPIRED = "expired"


@dataclass
class MessageHeader:
    """رأس الرسالة"""
    message_id: str
    sender: str
    recipient: str
    message_type: MessageType
    priority: MessagePriority = MessagePriority.NORMAL
    correlation_id: Optional[str] = None  # لربط الطلب بالرد
    reply_to: Optional[str] = None        # عنوان الرد
    ttl: int = 60  # Time To Live (ثواني)
    timestamp: datetime = field(default_factory=datetime.now)
    
    def is_expired(self) -> bool:
        """هل انتهت صلاحية الرسالة؟"""
        if self.ttl <= 0:
            return False
        elapsed = (datetime.now() - self.timestamp).total_seconds()
        return elapsed > self.ttl


@dataclass
class MessagePayload:
    """محتوى الرسالة"""
    data: Any = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    attachments: List[Any] = field(default_factory=list)
    
    def to_dict(self) -> Dict:
        return {
            "metadata": self.metadata,
            "attachments_count": len(self.attachments)
        }


@dataclass
class AgentMessage:
    """رسالة بين الوكلاء"""
    
    # الرأس والمحتوى
    header: MessageHeader
    payload: MessagePayload = field(default_factory=MessagePayload)
    
    # الحالة
    status: MessageStatus = MessageStatus.SENT
    delivered_at: Optional[datetime] = None
    processed_at: Optional[datetime] = None
    error: Optional[str] = None
    
    def deliver(self):
        """تسليم الرسالة"""
        self.status = MessageStatus.DELIVERED
        self.delivered_at = datetime.now()
    
    def process(self):
        """معالجة الرسالة"""
        self.status = MessageStatus.PROCESSED
        self.processed_at = datetime.now()
    
    def fail(self, error: str):
        """فشل الرسالة"""
        self.status = MessageStatus.FAILED
        self.error = error
    
    def is_expired(self) -> bool:
        """هل انتهت صلاحية الرسالة؟"""
        return self.header.is_expired()
    
    def create_reply(self, message_type: MessageType, data: Any = None) -> 'AgentMessage':
        """إنشاء رد على هذه الرسالة"""
        import uuid
        return AgentMessage(
            header=MessageHeader(
                message_id=str(uuid.uuid4())[:8],
                sender=self.header.recipient,
                recipient=self.header.sender,
                message_type=message_type,
                correlation_id=self.header.message_id,
                priority=self.header.priority
            ),
            payload=MessagePayload(data=data)
        )
    
    def to_dict(self) -> Dict:
        """تحويل إلى قاموس"""
        return {
            "id": self.header.message_id,
            "sender": self.header.sender,
            "recipient": self.header.recipient,
            "type": self.header.message_type.value,
            "priority": self.header.priority.name,
            "status": self.status.value,
            "timestamp": self.header.timestamp.isoformat(),
            "error": self.error
        }


# ============================================
# رسائل مخصصة لأنواع مختلفة
# ============================================

@dataclass
class ScanCommandPayload:
    """حمولة أمر المسح"""
    target_url: str
    max_pages: int = 100
    max_depth: int = 3
    use_auth: bool = False
    scan_profile: str = "standard"  # quick, standard, deep, stealth
    parameters: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ExploitCommandPayload:
    """حمولة أمر الاستغلال"""
    vulnerability_id: str
    target_url: str
    payload: Optional[str] = None
    parameters: Dict[str, Any] = field(default_factory=dict)
    safe_mode: bool = True


@dataclass
class VulnerabilityDataPayload:
    """حمولة بيانات الثغرة"""
    vulnerability: Vulnerability
    source: str = "scanner"
    verified: bool = False


@dataclass
class AttackChainDataPayload:
    """حمولة بيانات سلسلة الهجوم"""
    attack_chain: AttackChain
    source: str = "planner"
    executable: bool = False


@dataclass
class WorldStateDataPayload:
    """حمولة بيانات حالة العالم"""
    world_state: WorldState
    delta: bool = False  # هل هذا تحديث جزئي؟
    changed_fields: List[str] = field(default_factory=list)


@dataclass
class StatusResponsePayload:
    """حمولة الرد على طلب الحالة"""
    agent_name: str
    status: str
    current_task: Optional[str] = None
    tasks_completed: int = 0
    tasks_pending: int = 0
    uptime: float = 0.0
    metrics: Dict[str, Any] = field(default_factory=dict)


# دالة مساعدة لإنشاء رسالة
def create_message(
    sender: str,
    recipient: str,
    message_type: MessageType,
    data: Any = None,
    priority: MessagePriority = MessagePriority.NORMAL,
    correlation_id: str = None
) -> AgentMessage:
    """إنشاء رسالة جديدة"""
    import uuid
    return AgentMessage(
        header=MessageHeader(
            message_id=str(uuid.uuid4())[:8],
            sender=sender,
            recipient=recipient,
            message_type=message_type,
            priority=priority,
            correlation_id=correlation_id
        ),
        payload=MessagePayload(data=data)
    )


# دالة لإنشاء رسالة استجابة
def create_response(original_message: AgentMessage, data: Any = None, success: bool = True) -> AgentMessage:
    """إنشاء رسالة رد"""
    response_type = MessageType.RESPONSE_ACK if success else MessageType.RESPONSE_ERROR
    return original_message.create_reply(response_type, data)


# دالة لتسلسل الرسالة (للتخزين أو الإرسال)
def serialize_message(message: AgentMessage) -> Dict:
    """تسلسل الرسالة إلى قاموس"""
    return {
        "header": {
            "message_id": message.header.message_id,
            "sender": message.header.sender,
            "recipient": message.header.recipient,
            "message_type": message.header.message_type.value,
            "priority": message.header.priority.name,
            "correlation_id": message.header.correlation_id,
            "timestamp": message.header.timestamp.isoformat()
        },
        "status": message.status.value,
        "error": message.error
    }


# دالة لإلغاء تسلسل الرسالة
def deserialize_message(data: Dict) -> AgentMessage:
    """إلغاء تسلسل الرسالة من قاموس"""
    header = MessageHeader(
        message_id=data["header"]["message_id"],
        sender=data["header"]["sender"],
        recipient=data["header"]["recipient"],
        message_type=MessageType(data["header"]["message_type"]),
        priority=MessagePriority[data["header"]["priority"]],
        correlation_id=data["header"].get("correlation_id"),
        timestamp=datetime.fromisoformat(data["header"]["timestamp"])
    )
    
    return AgentMessage(
        header=header,
        status=MessageStatus(data.get("status", "sent")),
        error=data.get("error")
    )

