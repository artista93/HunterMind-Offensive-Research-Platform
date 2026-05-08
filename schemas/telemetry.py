
from enum import Enum
from typing import List, Dict, Any, Optional, Union
from dataclasses import dataclass, field
from datetime import datetime
from .vulnerability import Vulnerability, Severity
from .decision import Decision


class MetricType(Enum):
    """أنواع المقاييس"""
    COUNTER = "counter"      # عداد متزايد
    GAUGE = "gauge"          # قيمة قابلة للتغيير صعوداً وهبوطاً
    HISTOGRAM = "histogram"  # توزيع القيم
    TIMER = "timer"          # قياس الوقت


class EventSeverity(Enum):
    """شدة الحدث"""
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class TraceSpanType(Enum):
    """نوع المقطع في التتبع"""
    TASK = "task"
    DECISION = "decision"
    SCAN = "scan"
    EXPLOIT = "exploit"
    LEARNING = "learning"
    COMMUNICATION = "communication"


@dataclass
class MetricPoint:
    """نقطة قياس فردية"""
    name: str
    value: float
    metric_type: MetricType
    timestamp: datetime = field(default_factory=datetime.now)
    tags: Dict[str, str] = field(default_factory=dict)
    unit: str = ""
    
    def to_dict(self) -> Dict:
        return {
            "name": self.name,
            "value": self.value,
            "type": self.metric_type.value,
            "timestamp": self.timestamp.isoformat(),
            "tags": self.tags,
            "unit": self.unit
        }


@dataclass
class Event:
    """حدث في النظام"""
    name: str
    severity: EventSeverity
    message: str
    source: str
    timestamp: datetime = field(default_factory=datetime.now)
    data: Dict[str, Any] = field(default_factory=dict)
    trace_id: Optional[str] = None
    
    def to_dict(self) -> Dict:
        return {
            "name": self.name,
            "severity": self.severity.value,
            "message": self.message,
            "source": self.source,
            "timestamp": self.timestamp.isoformat(),
            "data": self.data,
            "trace_id": self.trace_id
        }


@dataclass
class TraceSpan:
    """مقطع في التتبع"""
    span_id: str
    name: str
    span_type: TraceSpanType
    start_time: datetime
    end_time: Optional[datetime] = None
    parent_span_id: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    events: List[Event] = field(default_factory=list)
    
    @property
    def duration_ms(self) -> float:
        if self.end_time:
            return (self.end_time - self.start_time).total_seconds() * 1000
        return 0.0
    
    def finish(self):
        """إنهاء المقطع"""
        self.end_time = datetime.now()
    
    def to_dict(self) -> Dict:
        return {
            "span_id": self.span_id,
            "name": self.name,
            "type": self.span_type.value,
            "parent_span_id": self.parent_span_id,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "duration_ms": self.duration_ms,
            "metadata": self.metadata,
            "events_count": len(self.events)
        }


@dataclass
class Trace:
    """تتبع كامل لعملية"""
    trace_id: str
    name: str
    start_time: datetime = field(default_factory=datetime.now)
    end_time: Optional[datetime] = None
    spans: List[TraceSpan] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def add_span(self, span: TraceSpan):
        """إضافة مقطع"""
        self.spans.append(span)
    
    def finish(self):
        """إنهاء التتبع"""
        self.end_time = datetime.now()
    
    @property
    def duration_ms(self) -> float:
        if self.end_time:
            return (self.end_time - self.start_time).total_seconds() * 1000
        return 0.0
    
    def to_dict(self) -> Dict:
        return {
            "trace_id": self.trace_id,
            "name": self.name,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "duration_ms": self.duration_ms,
            "spans_count": len(self.spans),
            "metadata": self.metadata
        }


@dataclass
class PerformanceMetrics:
    """مقاييس أداء النظام"""
    # مقاييس المسح
    scan_speed_pages_per_sec: float = 0.0
    avg_response_time_ms: float = 0.0
    success_rate: float = 0.0
    
    # مقاييس الاكتشاف
    vulnerabilities_per_minute: float = 0.0
    false_positive_rate: float = 0.0
    detection_accuracy: float = 0.0
    
    # مقاييس الموارد
    cpu_usage_percent: float = 0.0
    memory_usage_mb: float = 0.0
    active_connections: int = 0
    
    # مقاييس التعلم
    learning_curve_slope: float = 0.0
    adaptation_speed: float = 0.0
    strategy_effectiveness: float = 0.0
    
    def to_dict(self) -> Dict:
        return {
            "scan_speed": self.scan_speed_pages_per_sec,
            "avg_response_time_ms": self.avg_response_time_ms,
            "success_rate": self.success_rate,
            "vulns_per_minute": self.vulnerabilities_per_minute,
            "false_positive_rate": self.false_positive_rate,
            "cpu_usage": self.cpu_usage_percent,
            "memory_usage_mb": self.memory_usage_mb,
            "learning_speed": self.learning_curve_slope
        }


@dataclass
class ScanMetrics:
    """مقاييس المسح"""
    scan_id: str
    target: str
    start_time: datetime
    end_time: Optional[datetime] = None
    
    # المقاييس
    pages_crawled: int = 0
    endpoints_discovered: int = 0
    forms_found: int = 0
    api_calls_detected: int = 0
    js_files_analyzed: int = 0
    
    # الثغرات
    vulnerabilities_found: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    
    # السلوك
    requests_sent: int = 0
    requests_failed: int = 0
    blocks_detected: int = 0
    waf_interactions: int = 0
    
    # التعلم
    strategies_used: List[str] = field(default_factory=list)
    successful_strategies: List[str] = field(default_factory=list)
    failed_strategies: List[str] = field(default_factory=list)
    
    @property
    def duration_seconds(self) -> float:
        if self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        return 0.0
    
    @property
    def success_rate(self) -> float:
        if self.requests_sent == 0:
            return 0.0
        return (self.requests_sent - self.requests_failed) / self.requests_sent
    
    def finish(self):
        """إنهاء المسح وتسجيل النتائج"""
        self.end_time = datetime.now()
    
    def add_vulnerability(self, vuln: Vulnerability):
        """إضافة ثغرة إلى الإحصائيات"""
        self.vulnerabilities_found += 1
        if vuln.severity == Severity.CRITICAL:
            self.critical_count += 1
        elif vuln.severity == Severity.HIGH:
            self.high_count += 1
        elif vuln.severity == Severity.MEDIUM:
            self.medium_count += 1
        else:
            self.low_count += 1
    
    def to_dict(self) -> Dict:
        return {
            "scan_id": self.scan_id,
            "target": self.target,
            "duration_seconds": self.duration_seconds,
            "pages_crawled": self.pages_crawled,
            "endpoints_discovered": self.endpoints_discovered,
            "vulnerabilities_found": self.vulnerabilities_found,
            "critical": self.critical_count,
            "high": self.high_count,
            "medium": self.medium_count,
            "low": self.low_count,
            "success_rate": self.success_rate,
            "waf_interactions": self.waf_interactions,
            "strategies_used": len(self.strategies_used)
        }


@dataclass
class LearningMetrics:
    """مقاييس التعلم"""
    episode: int = 0
    total_reward: float = 0.0
    avg_reward: float = 0.0
    epsilon: float = 1.0
    
    # مقاييس متقدمة
    q_table_size: int = 0
    replay_buffer_size: int = 0
    successful_sequences: int = 0
    failed_sequences: int = 0
    
    # المنحنى
    reward_history: List[float] = field(default_factory=list)
    loss_history: List[float] = field(default_factory=list)
    
    def update(self, reward: float, loss: float = 0.0):
        """تحديث المقاييس"""
        self.episode += 1
        self.total_reward += reward
        self.avg_reward = self.total_reward / self.episode
        self.reward_history.append(reward)
        if loss > 0:
            self.loss_history.append(loss)
        
        # الاحتفاظ بآخر 1000
        if len(self.reward_history) > 1000:
            self.reward_history = self.reward_history[-1000:]
        if len(self.loss_history) > 1000:
            self.loss_history = self.loss_history[-1000:]
    
    @property
    def reward_trend(self) -> float:
        """اتجاه المكافأة (صاعد/هابط)"""
        if len(self.reward_history) < 10:
            return 0.0
        recent = sum(self.reward_history[-5:]) / 5
        older = sum(self.reward_history[-10:-5]) / 5
        return recent - older
    
    def to_dict(self) -> Dict:
        return {
            "episode": self.episode,
            "total_reward": self.total_reward,
            "avg_reward": self.avg_reward,
            "epsilon": self.epsilon,
            "q_table_size": self.q_table_size,
            "replay_buffer_size": self.replay_buffer_size,
            "successful_sequences": self.successful_sequences,
            "reward_trend": self.reward_trend
        }


@dataclass
class TelemetryData:
    """بيانات القياس الكاملة"""
    timestamp: datetime = field(default_factory=datetime.now)
    metrics: List[MetricPoint] = field(default_factory=list)
    events: List[Event] = field(default_factory=list)
    traces: List[Trace] = field(default_factory=list)
    performance: PerformanceMetrics = field(default_factory=PerformanceMetrics)
    
    def add_metric(self, metric: MetricPoint):
        """إضافة مقياس"""
        self.metrics.append(metric)
        # الاحتفاظ بآخر 1000 مقياس
        if len(self.metrics) > 1000:
            self.metrics = self.metrics[-1000:]
    
    def add_event(self, event: Event):
        """إضافة حدث"""
        self.events.append(event)
        if len(self.events) > 500:
            self.events = self.events[-500:]
    
    def add_trace(self, trace: Trace):
        """إضافة تتبع"""
        self.traces.append(trace)
        if len(self.traces) > 100:
            self.traces = self.traces[-100:]
    
    def to_dict(self) -> Dict:
        return {
            "timestamp": self.timestamp.isoformat(),
            "metrics_count": len(self.metrics),
            "events_count": len(self.events),
            "traces_count": len(self.traces),
            "performance": self.performance.to_dict()
        }


# دوال مساعدة لإنشاء المقاييس
def create_counter_metric(name: str, value: float = 1.0, tags: Dict = None) -> MetricPoint:
    """إنشاء مقياس عداد"""
    return MetricPoint(
        name=name,
        value=value,
        metric_type=MetricType.COUNTER,
        tags=tags or {}
    )


def create_gauge_metric(name: str, value: float, tags: Dict = None) -> MetricPoint:
    """إنشاء مقياس قيمة متغيرة"""
    return MetricPoint(
        name=name,
        value=value,
        metric_type=MetricType.GAUGE,
        tags=tags or {}
    )


def create_timer_metric(name: str, duration_ms: float, tags: Dict = None) -> MetricPoint:
    """إنشاء مقياس وقت"""
    return MetricPoint(
        name=name,
        value=duration_ms,
        metric_type=MetricType.TIMER,
        tags=tags or {},
        unit="ms"
    )


def create_event(name: str, severity: EventSeverity, message: str, source: str, data: Dict = None) -> Event:
    """إنشاء حدث"""
    return Event(
        name=name,
        severity=severity,
        message=message,
        source=source,
        data=data or {}
    )


def start_trace(name: str, metadata: Dict = None) -> Trace:
    """بدء تتبع جديد"""
    import uuid
    return Trace(
        trace_id=str(uuid.uuid4())[:8],
        name=name,
        metadata=metadata or {}
    )


def start_span(trace: Trace, name: str, span_type: TraceSpanType, parent_span_id: str = None) -> TraceSpan:
    """بدء مقطع جديد في التتبع"""
    import uuid
    span = TraceSpan(
        span_id=str(uuid.uuid4())[:8],
        name=name,
        span_type=span_type,
        start_time=datetime.now(),
        parent_span_id=parent_span_id
    )
    trace.add_span(span)
    return span

