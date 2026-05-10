
import asyncio
import uuid
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime

import logging

logger = logging.getLogger(__name__)


@dataclass
class AttackStep:
    """خطوة هجومية"""
    id: str
    name: str
    parent_id: Optional[str]
    action: str
    parameters: Dict[str, Any]
    result: Any
    success: bool
    duration_ms: float
    timestamp: datetime = field(default_factory=datetime.now)
    error: Optional[str] = None


@dataclass
class AttackTrace:
    """تتبع هجوم"""
    id: str
    name: str
    target: str
    vulnerability_type: str
    start_time: datetime
    end_time: Optional[datetime] = None
    steps: List[AttackStep] = field(default_factory=list)
    success: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)


class AttackTracer:
    """
    تتبع الهجمات المتقدم
    
    الميزات:
    - تتبع تفاصيل الهجمات خطوة بخطوة
    - تسجيل المعاملات والنتائج
    - تحليل سلاسل الهجوم
    - تقييم فعالية الهجمات
    """
    
    def __init__(self, max_traces: int = 1000):
        self.traces: Dict[str, AttackTrace] = {}
        self.active_steps: Dict[str, AttackStep] = {}
        self.max_traces = max_traces
        self._lock = asyncio.Lock()
        
        logger.info(f"AttackTracer initialized (max_traces={max_traces})")
    
    async def start_trace(
        self,
        name: str,
        target: str,
        vulnerability_type: str,
        metadata: Dict = None
    ) -> str:
        """
        بدء تتبع هجوم جديد
        
        Args:
            name: اسم الهجوم
            target: الهدف
            vulnerability_type: نوع الثغرة
            metadata: بيانات وصفية
        
        Returns:
            معرف التتبع
        """
        trace_id = str(uuid.uuid4())[:8]
        
        trace = AttackTrace(
            id=trace_id,
            name=name,
            target=target,
            vulnerability_type=vulnerability_type,
            start_time=datetime.now(),
            metadata=metadata or {}
        )
        
        async with self._lock:
            self.traces[trace_id] = trace
            
            if len(self.traces) > self.max_traces:
                oldest = min(self.traces.keys(), key=lambda k: self.traces[k].start_time)
                del self.traces[oldest]
        
        logger.debug(f"Attack trace started: {name} ({trace_id})")
        return trace_id
    
    async def end_trace(self, trace_id: str, success: bool):
        """
        إنهاء تتبع الهجوم
        
        Args:
            trace_id: معرف التتبع
            success: نجاح الهجوم
        """
        async with self._lock:
            if trace_id not in self.traces:
                logger.warning(f"Attack trace {trace_id} not found")
                return
            
            trace = self.traces[trace_id]
            trace.end_time = datetime.now()
            trace.success = success
        
        logger.debug(f"Attack trace ended: {trace_id} (success={success})")
    
    async def add_step(
        self,
        trace_id: str,
        name: str,
        action: str,
        parameters: Dict,
        result: Any,
        success: bool,
        duration_ms: float,
        parent_id: str = None,
        error: str = None
    ) -> str:
        """
        إضافة خطوة هجومية
        
        Args:
            trace_id: معرف التتبع
            name: اسم الخطوة
            action: الإجراء
            parameters: المعاملات
            result: النتيجة
            success: نجاح الخطوة
            duration_ms: المدة بالمللي ثانية
            parent_id: معرف الخطوة الأب
            error: رسالة خطأ
        
        Returns:
            معرف الخطوة
        """
        step_id = str(uuid.uuid4())[:8]
        
        step = AttackStep(
            id=step_id,
            name=name,
            parent_id=parent_id,
            action=action,
            parameters=parameters,
            result=result,
            success=success,
            duration_ms=duration_ms,
            error=error
        )
        
        async with self._lock:
            if trace_id in self.traces:
                self.traces[trace_id].steps.append(step)
            
            self.active_steps[step_id] = step
        
        logger.debug(f"Attack step added: {name} ({step_id})")
        return step_id
    
    async def get_trace(self, trace_id: str) -> Optional[AttackTrace]:
        """الحصول على تتبع هجوم بالمعرف"""
        async with self._lock:
            return self.traces.get(trace_id)
    
    async def get_traces(self, limit: int = 50) -> List[AttackTrace]:
        """الحصول على قائمة تتبعات الهجمات"""
        async with self._lock:
            traces = list(self.traces.values())
            traces.sort(key=lambda x: x.start_time, reverse=True)
            return traces[:limit]
    
    async def get_attack_chain(self, trace_id: str) -> Dict:
        """الحصول على سلسلة الهجوم للتتبع"""
        trace = await self.get_trace(trace_id)
        if not trace or not trace.steps:
            return {}
        
        # بناء شجرة الخطوات
        steps_by_parent = {}
        for step in trace.steps:
            parent = step.parent_id or "root"
            if parent not in steps_by_parent:
                steps_by_parent[parent] = []
            steps_by_parent[parent].append(step)
        
        def build_chain(parent_id: str) -> List[Dict]:
            children = steps_by_parent.get(parent_id, [])
            return [
                {
                    "id": step.id,
                    "name": step.name,
                    "action": step.action,
                    "success": step.success,
                    "duration_ms": step.duration_ms,
                    "error": step.error,
                    "children": build_chain(step.id)
                }
                for step in children
            ]
        
        return {
            "trace_id": trace_id,
            "name": trace.name,
            "target": trace.target,
            "vulnerability_type": trace.vulnerability_type,
            "success": trace.success,
            "start_time": trace.start_time.isoformat(),
            "end_time": trace.end_time.isoformat() if trace.end_time else None,
            "total_duration_ms": (trace.end_time - trace.start_time).total_seconds() * 1000 if trace.end_time else 0,
            "total_steps": len(trace.steps),
            "chain": build_chain("root")
        }
    
    async def analyze_attack_effectiveness(self, trace_id: str) -> Dict:
        """
        تحليل فعالية الهجوم
        
        Args:
            trace_id: معرف التتبع
        
        Returns:
            تحليل الفعالية
        """
        trace = await self.get_trace(trace_id)
        if not trace or not trace.steps:
            return {"has_data": False}
        
        # حساب معدل نجاح الخطوات
        successful_steps = len([s for s in trace.steps if s.success])
        step_success_rate = successful_steps / len(trace.steps) if trace.steps else 0
        
        # حساب متوسط وقت الخطوة
        avg_step_time = sum(s.duration_ms for s in trace.steps) / len(trace.steps) if trace.steps else 0
        
        # تحديد الخطوات الفاشلة
        failed_steps = [s for s in trace.steps if not s.success]
        
        return {
            "has_data": True,
            "success": trace.success,
            "total_steps": len(trace.steps),
            "successful_steps": successful_steps,
            "step_success_rate": step_success_rate,
            "average_step_duration_ms": avg_step_time,
            "total_duration_ms": (trace.end_time - trace.start_time).total_seconds() * 1000 if trace.end_time else 0,
            "failed_steps": [
                {
                    "name": s.name,
                    "action": s.action,
                    "error": s.error
                }
                for s in failed_steps
            ]
        }
    
    async def get_successful_attacks(self) -> List[AttackTrace]:
        """الحصول على الهجمات الناجحة"""
        async with self._lock:
            return [t for t in self.traces.values() if t.success]
    
    async def get_failed_attacks(self) -> List[AttackTrace]:
        """الحصول على الهجمات الفاشلة"""
        async with self._lock:
            return [t for t in self.traces.values() if not t.success]
    
    async def get_statistics(self) -> Dict:
        """إحصائيات تتبع الهجمات"""
        async with self._lock:
            total_traces = len(self.traces)
            successful = len([t for t in self.traces.values() if t.success])
            failed = total_traces - successful
            
            total_steps = sum(len(t.steps) for t in self.traces.values())
            
            return {
                "total_traces": total_traces,
                "successful_attacks": successful,
                "failed_attacks": failed,
                "success_rate": successful / total_traces if total_traces > 0 else 0,
                "total_steps": total_steps,
                "average_steps_per_attack": total_steps / total_traces if total_traces > 0 else 0,
                "active_steps": len(self.active_steps),
                "max_traces": self.max_traces
            }


# نسخة عالمية
_default_tracer = None


async def get_attack_tracer() -> AttackTracer:
    """الحصول على نسخة عالمية من تتبع الهجمات"""
    global _default_tracer
    if _default_tracer is None:
        _default_tracer = AttackTracer()
    return _default_tracer

