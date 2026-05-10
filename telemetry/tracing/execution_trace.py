
import asyncio
import time
import uuid
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
from datetime import datetime
from contextlib import asynccontextmanager

import logging

logger = logging.getLogger(__name__)


@dataclass
class Span:
    """شريحة تنفيذ"""
    id: str
    name: str
    parent_id: Optional[str]
    start_time: datetime
    end_time: Optional[datetime] = None
    duration_ms: Optional[float] = None
    tags: Dict[str, Any] = field(default_factory=dict)
    logs: List[Dict] = field(default_factory=list)


@dataclass
class Trace:
    """تتبع كامل"""
    id: str
    name: str
    start_time: datetime
    end_time: Optional[datetime] = None
    spans: List[Span] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


class ExecutionTracer:
    """
    تتبع التنفيذ المتقدم
    
    الميزات:
    - تتبع مسارات التنفيذ
    - قياس زمن العمليات
    - تسجيل الأحداث
    - تحليل الأداء
    """
    
    def __init__(self, max_traces: int = 1000):
        self.traces: Dict[str, Trace] = {}
        self.active_spans: Dict[str, Span] = {}
        self.max_traces = max_traces
        self._lock = asyncio.Lock()
        
        logger.info(f"ExecutionTracer initialized (max_traces={max_traces})")
    
    async def start_trace(self, name: str, metadata: Dict = None) -> str:
        """
        بدء تتبع جديد
        
        Args:
            name: اسم التتبع
            metadata: بيانات وصفية
        
        Returns:
            معرف التتبع
        """
        trace_id = str(uuid.uuid4())[:8]
        
        trace = Trace(
            id=trace_id,
            name=name,
            start_time=datetime.now(),
            metadata=metadata or {}
        )
        
        async with self._lock:
            self.traces[trace_id] = trace
            
            # الحفاظ على الحد الأقصى
            if len(self.traces) > self.max_traces:
                oldest = min(self.traces.keys(), key=lambda k: self.traces[k].start_time)
                del self.traces[oldest]
        
        logger.debug(f"Trace started: {name} ({trace_id})")
        return trace_id
    
    async def end_trace(self, trace_id: str):
        """إنهاء تتبع"""
        async with self._lock:
            if trace_id not in self.traces:
                logger.warning(f"Trace {trace_id} not found")
                return
            
            trace = self.traces[trace_id]
            trace.end_time = datetime.now()
        
        logger.debug(f"Trace ended: {trace.name} ({trace_id})")
    
    @asynccontextmanager
    async def trace_context(self, name: str, metadata: Dict = None):
        """سياق التتبع"""
        trace_id = await self.start_trace(name, metadata)
        try:
            yield trace_id
        finally:
            await self.end_trace(trace_id)
    
    async def start_span(
        self,
        name: str,
        trace_id: str,
        parent_id: str = None,
        tags: Dict = None
    ) -> str:
        """
        بدء شريحة تنفيذ جديدة
        
        Args:
            name: اسم الشريحة
            trace_id: معرف التتبع
            parent_id: معرف الشريحة الأب
            tags: علامات إضافية
        
        Returns:
            معرف الشريحة
        """
        span_id = str(uuid.uuid4())[:8]
        
        span = Span(
            id=span_id,
            name=name,
            parent_id=parent_id,
            start_time=datetime.now(),
            tags=tags or {}
        )
        
        async with self._lock:
            if trace_id in self.traces:
                self.traces[trace_id].spans.append(span)
            
            self.active_spans[span_id] = span
        
        logger.debug(f"Span started: {name} ({span_id})")
        return span_id
    
    async def end_span(self, span_id: str, logs: List[Dict] = None):
        """إنهاء شريحة تنفيذ"""
        async with self._lock:
            if span_id not in self.active_spans:
                logger.warning(f"Span {span_id} not found")
                return
            
            span = self.active_spans[span_id]
            span.end_time = datetime.now()
            span.duration_ms = (span.end_time - span.start_time).total_seconds() * 1000
            
            if logs:
                span.logs.extend(logs)
            
            del self.active_spans[span_id]
        
        logger.debug(f"Span ended: {span.name} ({span_id}) - {span.duration_ms:.2f}ms")
    
    @asynccontextmanager
    async def span_context(
        self,
        name: str,
        trace_id: str,
        parent_id: str = None,
        tags: Dict = None
    ):
        """سياق الشريحة"""
        span_id = await self.start_span(name, trace_id, parent_id, tags)
        try:
            yield span_id
        finally:
            await self.end_span(span_id)
    
    async def add_span_log(self, span_id: str, message: str, level: str = "info"):
        """إضافة سجل إلى شريحة"""
        async with self._lock:
            if span_id in self.active_spans:
                self.active_spans[span_id].logs.append({
                    "timestamp": datetime.now().isoformat(),
                    "message": message,
                    "level": level
                })
    
    async def get_trace(self, trace_id: str) -> Optional[Trace]:
        """الحصول على تتبع بالمعرف"""
        async with self._lock:
            return self.traces.get(trace_id)
    
    async def get_traces(self, limit: int = 50) -> List[Trace]:
        """الحصول على قائمة التتبعات"""
        async with self._lock:
            traces = list(self.traces.values())
            traces.sort(key=lambda x: x.start_time, reverse=True)
            return traces[:limit]
    
    async def get_slow_spans(self, min_duration_ms: float = 1000) -> List[Span]:
        """الحصول على الشرائح البطيئة"""
        slow_spans = []
        
        async with self._lock:
            for trace in self.traces.values():
                for span in trace.spans:
                    if span.duration_ms and span.duration_ms >= min_duration_ms:
                        slow_spans.append(span)
        
        slow_spans.sort(key=lambda x: x.duration_ms or 0, reverse=True)
        return slow_spans
    
    async def get_statistics(self) -> Dict:
        """إحصائيات التتبع"""
        async with self._lock:
            total_traces = len(self.traces)
            total_spans = sum(len(t.spans) for t in self.traces.values())
            active_spans = len(self.active_spans)
            
            # حساب متوسط مدة التتبع
            durations = []
            for trace in self.traces.values():
                if trace.end_time:
                    duration = (trace.end_time - trace.start_time).total_seconds() * 1000
                    durations.append(duration)
            
            avg_duration = sum(durations) / len(durations) if durations else 0
            
            return {
                "total_traces": total_traces,
                "total_spans": total_spans,
                "active_spans": active_spans,
                "average_trace_duration_ms": avg_duration,
                "slow_spans_count": len(await self.get_slow_spans()),
                "max_traces": self.max_traces
            }


# نسخة عالمية
_default_tracer = None


async def get_execution_tracer() -> ExecutionTracer:
    """الحصول على نسخة عالمية من تتبع التنفيذ"""
    global _default_tracer
    if _default_tracer is None:
        _default_tracer = ExecutionTracer()
    return _default_tracer

