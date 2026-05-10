
from pydantic import BaseModel, Field, validator
from typing import Dict, List, Optional, Any, Union
from datetime import datetime
from enum import Enum


class Severity(str, Enum):
    """شدة الثغرة"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Confidence(str, Enum):
    """مستوى الثقة"""
    CERTAIN = "certain"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    TENTATIVE = "tentative"


class ScanType(str, Enum):
    """نوع الفحص"""
    FULL = "full"
    QUICK = "quick"
    CUSTOM = "custom"


class AttackType(str, Enum):
    """نوع الهجوم"""
    XSS = "xss"
    SQLI = "sqli"
    IDOR = "idor"
    RCE = "rce"
    SSRF = "ssrf"
    CSRF = "csrf"


# ============================================
# نماذج الفحص (Scan)
# ============================================

class ScanRequest(BaseModel):
    """طلب فحص"""
    target_url: str = Field(..., description="الرابط المستهدف")
    scan_type: ScanType = Field(default=ScanType.FULL, description="نوع الفحص")
    max_depth: int = Field(default=3, ge=1, le=10, description="أقصى عمق للزحف")
    max_pages: int = Field(default=100, ge=1, le=1000, description="الحد الأقصى للصفحات")
    options: Dict[str, Any] = Field(default_factory=dict, description="خيارات إضافية")
    
    @validator('target_url')
    def validate_url(cls, v):
        """التحقق من صحة الرابط"""
        if not v.startswith(('http://', 'https://')):
            raise ValueError('URL must start with http:// or https://')
        return v


class ScanResponse(BaseModel):
    """استجابة فحص"""
    scan_id: str = Field(..., description="معرف الفحص")
    status: str = Field(..., description="حالة الفحص")
    message: str = Field(..., description="رسالة الحالة")
    started_at: datetime = Field(default_factory=datetime.now, description="وقت البدء")


class ScanResult(BaseModel):
    """نتيجة فحص"""
    scan_id: str = Field(..., description="معرف الفحص")
    target_url: str = Field(..., description="الرابط المستهدف")
    status: str = Field(..., description="حالة الفحص")
    started_at: datetime = Field(..., description="وقت البدء")
    completed_at: Optional[datetime] = Field(None, description="وقت الانتهاء")
    findings: List['Finding'] = Field(default_factory=list, description="النتائج")
    error: Optional[str] = Field(None, description="رسالة خطأ")


# ============================================
# نماذج الثغرات (Finding)
# ============================================

class Finding(BaseModel):
    """ثغرة مكتشفة"""
    id: str = Field(..., description="معرف الثغرة")
    type: str = Field(..., description="نوع الثغرة")
    severity: Severity = Field(..., description="شدة الثغرة")
    confidence: Confidence = Field(..., description="مستوى الثقة")
    url: str = Field(..., description="الرابط")
    parameter: Optional[str] = Field(None, description="المعامل")
    payload: Optional[str] = Field(None, description="الحمولة المستخدمة")
    evidence: Optional[str] = Field(None, description="الدليل")
    description: str = Field(..., description="وصف الثغرة")
    remediation: str = Field(..., description="طريقة الإصلاح")
    cvss_score: float = Field(default=0.0, ge=0.0, le=10.0, description="درجة CVSS")
    discovered_at: datetime = Field(default_factory=datetime.now, description="وقت الاكتشاف")


# ============================================
# نماذج الهجوم (Attack)
# ============================================

class AttackRequest(BaseModel):
    """طلب هجوم"""
    target_url: str = Field(..., description="الرابط المستهدف")
    vulnerability_type: str = Field(..., description="نوع الثغرة")
    parameter: Optional[str] = Field(None, description="المعامل المستهدف")
    payload: Optional[str] = Field(None, description="الحمولة المخصصة")
    options: Dict[str, Any] = Field(default_factory=dict, description="خيارات إضافية")
    
    @validator('target_url')
    def validate_url(cls, v):
        if not v.startswith(('http://', 'https://')):
            raise ValueError('URL must start with http:// or https://')
        return v


class AttackResponse(BaseModel):
    """استجابة هجوم"""
    attack_id: str = Field(..., description="معرف الهجوم")
    status: str = Field(..., description="حالة الهجوم")
    message: str = Field(..., description="رسالة الحالة")
    started_at: datetime = Field(default_factory=datetime.now, description="وقت البدء")


class AttackResult(BaseModel):
    """نتيجة هجوم"""
    attack_id: str = Field(..., description="معرف الهجوم")
    target_url: str = Field(..., description="الرابط المستهدف")
    vulnerability_type: str = Field(..., description="نوع الثغرة")
    status: str = Field(..., description="حالة الهجوم")
    started_at: datetime = Field(..., description="وقت البدء")
    completed_at: Optional[datetime] = Field(None, description="وقت الانتهاء")
    result: Optional[Dict[str, Any]] = Field(None, description="نتيجة الهجوم")
    error: Optional[str] = Field(None, description="رسالة خطأ")


# ============================================
# نماذج الاستغلال (Exploit)
# ============================================

class ExploitRequest(BaseModel):
    """طلب استغلال"""
    target_url: str = Field(..., description="الرابط المستهدف")
    vulnerability_type: str = Field(..., description="نوع الثغرة")
    parameter: Optional[str] = Field(None, description="المعامل المستهدف")
    technique: str = Field(default="auto", description="تقنية الاستغلال")
    
    @validator('target_url')
    def validate_url(cls, v):
        if not v.startswith(('http://', 'https://')):
            raise ValueError('URL must start with http:// or https://')
        return v


class ExploitResult(BaseModel):
    """نتيجة استغلال"""
    exploit_id: str = Field(..., description="معرف الاستغلال")
    target_url: str = Field(..., description="الرابط المستهدف")
    success: bool = Field(..., description="نجاح الاستغلال")
    output: Optional[str] = Field(None, description="مخرجات الاستغلال")
    extracted_data: Optional[Dict[str, Any]] = Field(None, description="البيانات المستخرجة")
    execution_time: float = Field(..., description="وقت التنفيذ بالثواني")
    timestamp: datetime = Field(default_factory=datetime.now, description="وقت التنفيذ")


# ============================================
# نماذج إضافية
# ============================================

class HealthResponse(BaseModel):
    """استجابة فحص الصحة"""
    status: str = Field(..., description="حالة الخدمة")
    timestamp: datetime = Field(default_factory=datetime.now, description="الوقت الحالي")
    version: str = Field(..., description="إصدار API")


class ErrorResponse(BaseModel):
    """استجابة خطأ"""
    error: str = Field(..., description="رسالة الخطأ")
    detail: Optional[str] = Field(None, description="تفاصيل إضافية")
    timestamp: datetime = Field(default_factory=datetime.now, description="وقت الخطأ")


class ListResponse(BaseModel):
    """استجابة قائمة"""
    items: List[Any] = Field(..., description="قائمة العناصر")
    total: int = Field(..., description="إجمالي العناصر")
    offset: int = Field(default=0, description="الإزاحة")
    limit: int = Field(default=100, description="الحد الأقصى")


# ============================================
# نماذج WebSocket
# ============================================

class WebSocketMessage(BaseModel):
    """رسالة WebSocket"""
    type: str = Field(..., description="نوع الرسالة")
    data: Any = Field(..., description="بيانات الرسالة")
    client_id: Optional[str] = Field(None, description="معرف العميل")
    channel: Optional[str] = Field(None, description="القناة")
    timestamp: datetime = Field(default_factory=datetime.now, description="الوقت")


class WebSocketStats(BaseModel):
    """إحصائيات WebSocket"""
    total_connections: int = Field(..., description="إجمالي الاتصالات")
    channels: Dict[str, int] = Field(default_factory=dict, description="القنوات وعدد الاتصالات")


# ============================================
# نماذج gRPC
# ============================================

class GRPCHealthRequest(BaseModel):
    """طلب صحة gRPC"""
    pass


class GRPCHealthResponse(BaseModel):
    """استجابة صحة gRPC"""
    status: str
    timestamp: str
    version: str


class GRPCScanRequest(BaseModel):
    """طلب فحص gRPC"""
    target_url: str
    scan_type: str = "full"
    max_depth: int = 3
    max_pages: int = 100


class GRPCScanResponse(BaseModel):
    """استجابة فحص gRPC"""
    scan_id: str
    status: str


class GRPCGetResultsRequest(BaseModel):
    """طلب نتائج gRPC"""
    scan_id: str


# تحديث المراجع
Finding.update_forward_refs()
ScanResult.update_forward_refs()

