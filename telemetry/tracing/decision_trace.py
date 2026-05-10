
import asyncio
import uuid
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime

import logging

logger = logging.getLogger(__name__)


@dataclass
class DecisionNode:
    """عقدة قرار"""
    id: str
    name: str
    parent_id: Optional[str]
    context: Dict[str, Any]
    options: List[Dict]
    selected_option: Dict
    reasoning: str
    confidence: float
    timestamp: datetime = field(default_factory=datetime.now)
    outcome: Optional[Dict] = None


@dataclass
class DecisionTrace:
    """تتبع القرارات"""
    id: str
    name: str
    start_time: datetime
    end_time: Optional[datetime] = None
    nodes: List[DecisionNode] = field(default_factory=list)
    final_decision: Optional[Dict] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


class DecisionTracer:
    """
    تتبع القرارات المتقدم
    
    الميزات:
    - تتبع سلسلة القرارات
    - توثيق خيارات القرار والأسباب
    - تحليل جودة القرارات
    - تقييم نتائج القرارات
    """
    
    def __init__(self, max_traces: int = 1000):
        self.traces: Dict[str, DecisionTrace] = {}
        self.active_nodes: Dict[str, DecisionNode] = {}
        self.max_traces = max_traces
        self._lock = asyncio.Lock()
        
        logger.info(f"DecisionTracer initialized (max_traces={max_traces})")
    
    async def start_trace(self, name: str, metadata: Dict = None) -> str:
        """
        بدء تتبع قرارات جديد
        
        Args:
            name: اسم التتبع
            metadata: بيانات وصفية
        
        Returns:
            معرف التتبع
        """
        trace_id = str(uuid.uuid4())[:8]
        
        trace = DecisionTrace(
            id=trace_id,
            name=name,
            start_time=datetime.now(),
            metadata=metadata or {}
        )
        
        async with self._lock:
            self.traces[trace_id] = trace
            
            if len(self.traces) > self.max_traces:
                oldest = min(self.traces.keys(), key=lambda k: self.traces[k].start_time)
                del self.traces[oldest]
        
        logger.debug(f"Decision trace started: {name} ({trace_id})")
        return trace_id
    
    async def end_trace(self, trace_id: str, final_decision: Dict = None):
        """
        إنهاء تتبع القرارات
        
        Args:
            trace_id: معرف التتبع
            final_decision: القرار النهائي
        """
        async with self._lock:
            if trace_id not in self.traces:
                logger.warning(f"Decision trace {trace_id} not found")
                return
            
            trace = self.traces[trace_id]
            trace.end_time = datetime.now()
            trace.final_decision = final_decision
        
        logger.debug(f"Decision trace ended: {trace_id}")
    
    async def add_decision(
        self,
        trace_id: str,
        name: str,
        context: Dict,
        options: List[Dict],
        selected_option: Dict,
        reasoning: str,
        confidence: float,
        parent_id: str = None
    ) -> str:
        """
        إضافة قرار إلى التتبع
        
        Args:
            trace_id: معرف التتبع
            name: اسم القرار
            context: سياق القرار
            options: الخيارات المتاحة
            selected_option: الخيار المختار
            reasoning: سبب الاختيار
            confidence: مستوى الثقة
            parent_id: معرف القرار الأب
        
        Returns:
            معرف القرار
        """
        node_id = str(uuid.uuid4())[:8]
        
        node = DecisionNode(
            id=node_id,
            name=name,
            parent_id=parent_id,
            context=context,
            options=options,
            selected_option=selected_option,
            reasoning=reasoning,
            confidence=confidence
        )
        
        async with self._lock:
            if trace_id in self.traces:
                self.traces[trace_id].nodes.append(node)
            
            self.active_nodes[node_id] = node
        
        logger.debug(f"Decision added: {name} ({node_id})")
        return node_id
    
    async def record_outcome(self, node_id: str, outcome: Dict):
        """
        تسجيل نتيجة القرار
        
        Args:
            node_id: معرف القرار
            outcome: نتيجة القرار
        """
        async with self._lock:
            if node_id in self.active_nodes:
                self.active_nodes[node_id].outcome = outcome
        
        logger.debug(f"Outcome recorded for decision {node_id}")
    
    async def get_trace(self, trace_id: str) -> Optional[DecisionTrace]:
        """الحصول على تتبع قرارات بالمعرف"""
        async with self._lock:
            return self.traces.get(trace_id)
    
    async def get_traces(self, limit: int = 50) -> List[DecisionTrace]:
        """الحصول على قائمة تتبعات القرارات"""
        async with self._lock:
            traces = list(self.traces.values())
            traces.sort(key=lambda x: x.start_time, reverse=True)
            return traces[:limit]
    
    async def get_decision_tree(self, trace_id: str) -> Dict:
        """الحصول على شجرة القرارات للتتبع"""
        trace = await self.get_trace(trace_id)
        if not trace:
            return {}
        
        # بناء الشجرة
        nodes_by_parent = {}
        for node in trace.nodes:
            parent = node.parent_id or "root"
            if parent not in nodes_by_parent:
                nodes_by_parent[parent] = []
            nodes_by_parent[parent].append(node)
        
        def build_tree(parent_id: str) -> List[Dict]:
            children = nodes_by_parent.get(parent_id, [])
            return [
                {
                    "id": node.id,
                    "name": node.name,
                    "selected_option": node.selected_option,
                    "confidence": node.confidence,
                    "outcome": node.outcome,
                    "children": build_tree(node.id)
                }
                for node in children
            ]
        
        return {
            "trace_id": trace_id,
            "name": trace.name,
            "start_time": trace.start_time.isoformat(),
            "end_time": trace.end_time.isoformat() if trace.end_time else None,
            "final_decision": trace.final_decision,
            "tree": build_tree("root")
        }
    
    async def analyze_decision_quality(self, trace_id: str) -> Dict:
        """
        تحليل جودة القرارات في التتبع
        
        Args:
            trace_id: معرف التتبع
        
        Returns:
            تحليل الجودة
        """
        trace = await self.get_trace(trace_id)
        if not trace or not trace.nodes:
            return {"has_data": False}
        
        # حساب متوسط الثقة
        avg_confidence = sum(n.confidence for n in trace.nodes) / len(trace.nodes)
        
        # حساب نسبة النجاح
        successful = len([n for n in trace.nodes if n.outcome and n.outcome.get("success", False)])
        success_rate = successful / len(trace.nodes) if trace.nodes else 0
        
        # عمق القرارات
        depths = []
        for node in trace.nodes:
            depth = 0
            current = node
            while current.parent_id:
                depth += 1
                current = next((n for n in trace.nodes if n.id == current.parent_id), None)
                if not current:
                    break
            depths.append(depth)
        
        return {
            "has_data": True,
            "total_decisions": len(trace.nodes),
            "average_confidence": avg_confidence,
            "success_rate": success_rate,
            "max_depth": max(depths) if depths else 0,
            "average_depth": sum(depths) / len(depths) if depths else 0
        }
    
    async def get_statistics(self) -> Dict:
        """إحصائيات تتبع القرارات"""
        async with self._lock:
            total_traces = len(self.traces)
            total_decisions = sum(len(t.nodes) for t in self.traces.values())
            
            return {
                "total_traces": total_traces,
                "total_decisions": total_decisions,
                "active_decisions": len(self.active_nodes),
                "average_decisions_per_trace": total_decisions / total_traces if total_traces > 0 else 0,
                "max_traces": self.max_traces
            }


# نسخة عالمية
_default_tracer = None


async def get_decision_tracer() -> DecisionTracer:
    """الحصول على نسخة عالمية من تتبع القرارات"""
    global _default_tracer
    if _default_tracer is None:
        _default_tracer = DecisionTracer()
    return _default_tracer

