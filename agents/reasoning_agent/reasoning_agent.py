
import asyncio
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

from ..base.base_agent import BaseAgent, AgentPriority, AgentMessage
from ..base.agent_state import AgentStateEnum

import logging

logger = logging.getLogger(__name__)


class ReasoningType(Enum):
    """أنواع التفكير"""
    DEDUCTIVE = "deductive"      # استنتاجي
    INDUCTIVE = "inductive"      # استقرائي
    ABDUCTIVE = "abductive"      # استنباطي
    ANALOGICAL = "analogical"    # تماثلي
    CAUSAL = "causal"            # سببي


@dataclass
class ReasoningStep:
    """خطوة تفكير"""
    type: ReasoningType
    premise: str
    conclusion: str
    confidence: float
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class ReasoningResult:
    """نتيجة التفكير"""
    conclusion: str
    confidence: float
    steps: List[ReasoningStep]
    metadata: Dict[str, Any] = field(default_factory=dict)


class ReasoningAgent(BaseAgent):
    """
    وكيل التفكير المنطقي المتقدم
    
    الميزات:
    - 5 أنواع من التفكير (استنتاجي، استقرائي، استنباطي، تماثلي، سببي)
    - تحليل الثغرات المكتشفة
    - اقتراح استراتيجيات الهجوم
    - تتبع سلسلة التفكير
    - تقييم الثقة في القرارات
    """
    
    def __init__(
        self,
        name: str = "ReasoningAgent",
        priority: AgentPriority = AgentPriority.HIGH
    ):
        super().__init__(name, priority)
        
        self._reasoning_history: List[ReasoningResult] = []
        
        logger.info(f"ReasoningAgent initialized: {name}")
    
    async def _on_initialize(self):
        """تهيئة الوكيل"""
        logger.info("ReasoningAgent components initialized")
    
    async def _on_start(self):
        """بدء تشغيل الوكيل"""
        logger.info("ReasoningAgent started")
    
    async def _on_stop(self):
        """إيقاف تشغيل الوكيل"""
        logger.info("ReasoningAgent stopped")
    
    async def _handle_message(self, message: AgentMessage) -> Optional[AgentMessage]:
        """معالجة الرسائل الواردة"""
        if message.type == "analyze_vulnerabilities":
            result = await self.analyze_vulnerabilities(message.content)
            return AgentMessage(
                id="",
                sender=self.name,
                receiver=message.sender,
                type="analysis_result",
                content=result
            )
        
        elif message.type == "suggest_strategy":
            result = await self.suggest_attack_strategy(message.content)
            return AgentMessage(
                id="",
                sender=self.name,
                receiver=message.sender,
                type="strategy_suggestion",
                content=result
            )
        
        elif message.type == "evaluate_decision":
            result = await self.evaluate_decision(message.content)
            return AgentMessage(
                id="",
                sender=self.name,
                receiver=message.sender,
                type="evaluation_result",
                content=result
            )
        
        return await super()._handle_message(message)
    
    async def analyze_vulnerabilities(
        self,
        data: Dict[str, Any]
    ) -> ReasoningResult:
        """
        تحليل الثغرات المكتشفة وإصدار استنتاجات
        
        Args:
            data: بيانات الثغرات (findings, target_info)
        
        Returns:
            نتيجة التفكير
        """
        findings = data.get("findings", [])
        target_info = data.get("target_info", {})
        
        steps = []
        
        # 1. تفكير استنتاجي: إذا كانت هناك ثغرة XSS، يمكن تنفيذ هجوم XSS
        if any("XSS" in str(f) for f in findings):
            step = ReasoningStep(
                type=ReasoningType.DEDUCTIVE,
                premise="XSS vulnerability detected",
                conclusion="Can execute JavaScript in victim's browser",
                confidence=0.9
            )
            steps.append(step)
        
        # 2. تفكير استقرائي: بناءً على الثغرات السابقة
        vulnerability_types = [str(f) for f in findings]
        if "SQL Injection" in vulnerability_types:
            step = ReasoningStep(
                type=ReasoningType.INDUCTIVE,
                premise="SQL injection found in multiple parameters",
                conclusion="Database may be vulnerable to data extraction",
                confidence=0.85
            )
            steps.append(step)
        
        # 3. تفكير سببي: تحليل العلاقات
        if "IDOR" in vulnerability_types and "Authentication" in vulnerability_types:
            step = ReasoningStep(
                type=ReasoningType.CAUSAL,
                premise="IDOR + weak authentication",
                conclusion="Account takeover possible",
                confidence=0.8
            )
            steps.append(step)
        
        # تجميع النتائج
        if "RCE" in vulnerability_types:
            conclusion = "Remote code execution possible - critical risk"
            confidence = 0.95
        elif "SQL Injection" in vulnerability_types:
            conclusion = "Database compromise possible - high risk"
            confidence = 0.9
        elif "XSS" in vulnerability_types:
            conclusion = "Client-side attacks possible - medium risk"
            confidence = 0.85
        else:
            conclusion = "No critical vulnerabilities detected"
            confidence = 0.7
        
        result = ReasoningResult(
            conclusion=conclusion,
            confidence=confidence,
            steps=steps,
            metadata={
                "vulnerability_count": len(findings),
                "target_type": target_info.get("type", "unknown")
            }
        )
        
        self._reasoning_history.append(result)
        
        return result
    
    async def suggest_attack_strategy(
        self,
        data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        اقتراح استراتيجية هجوم بناءً على التحليل
        
        Args:
            data: بيانات التحليل (analysis_result, findings)
        
        Returns:
            استراتيجية الهجوم المقترحة
        """
        analysis = data.get("analysis_result", {})
        findings = data.get("findings", [])
        
        strategies = []
        
        for finding in findings:
            finding_str = str(finding).lower()
            
            if "xss" in finding_str:
                strategies.append({
                    "type": "XSS Attack",
                    "steps": ["Inject malicious script", "Steal session cookies", "Hijack user session"],
                    "priority": "high"
                })
            
            elif "sql" in finding_str:
                strategies.append({
                    "type": "SQL Injection",
                    "steps": ["Extract database schema", "Retrieve sensitive data", "Bypass authentication"],
                    "priority": "critical"
                })
            
            elif "idor" in finding_str:
                strategies.append({
                    "type": "IDOR Attack",
                    "steps": ["Enumerate object IDs", "Access unauthorized resources", "Extract sensitive information"],
                    "priority": "high"
                })
            
            elif "rce" in finding_str:
                strategies.append({
                    "type": "Remote Code Execution",
                    "steps": ["Execute system commands", "Establish reverse shell", "Full system compromise"],
                    "priority": "critical"
                })
        
        # ترتيب الاستراتيجيات حسب الأولوية
        priority_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        strategies.sort(key=lambda x: priority_order.get(x["priority"], 4))
        
        return {
            "recommended_strategy": strategies[0] if strategies else None,
            "all_strategies": strategies,
            "total_strategies": len(strategies)
        }
    
    async def evaluate_decision(
        self,
        data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        تقييم قرار قبل التنفيذ
        
        Args:
            data: بيانات القرار (action, context, expected_outcome)
        
        Returns:
            تقييم القرار
        """
        action = data.get("action", "")
        context = data.get("context", {})
        expected_outcome = data.get("expected_outcome", "")
        
        score = 0.0
        reasons = []
        
        # تقييم بناءً على السياق
        if "vulnerability_confirmed" in context:
            score += 30
            reasons.append("Vulnerability confirmed (+30)")
        
        if "has_waf" in context and context["has_waf"]:
            score -= 20
            reasons.append("WAF detected (-20)")
        
        if "authentication_required" in context and context["authentication_required"]:
            score -= 10
            reasons.append("Authentication required (-10)")
        
        # تقييم بناءً على الإجراء
        if action in ["exploit", "attack"]:
            score += 10
            reasons.append("Direct exploit action (+10)")
        
        # تحديد مستوى الثقة
        if score >= 50:
            confidence = "high"
            recommendation = "execute"
        elif score >= 20:
            confidence = "medium"
            recommendation = "consider"
        else:
            confidence = "low"
            recommendation = "avoid"
        
        return {
            "decision": action,
            "score": score,
            "confidence": confidence,
            "recommendation": recommendation,
            "reasons": reasons,
            "expected_outcome": expected_outcome
        }
    
    async def get_reasoning_history(self, limit: int = 50) -> List[Dict]:
        """الحصول على تاريخ التفكير"""
        return [
            {
                "conclusion": r.conclusion,
                "confidence": r.confidence,
                "steps": len(r.steps),
                "timestamp": r.timestamp.isoformat()
            }
            for r in self._reasoning_history[-limit:]
        ]
    
    async def get_statistics(self) -> Dict:
        """إحصائيات الوكيل"""
        base_stats = await super().get_statistics()
        
        reasoning_types = {}
        for result in self._reasoning_history:
            for step in result.steps:
                reasoning_types[step.type.value] = reasoning_types.get(step.type.value, 0) + 1
        
        return {
            **base_stats,
            "reasoning_specific": {
                "total_reasoning_results": len(self._reasoning_history),
                "average_confidence": sum(r.confidence for r in self._reasoning_history) / len(self._reasoning_history) if self._reasoning_history else 0,
                "reasoning_types_used": reasoning_types
            }
        }


_default_reasoning_agent = None

async def get_reasoning_agent() -> ReasoningAgent:
    global _default_reasoning_agent
    if _default_reasoning_agent is None:
        _default_reasoning_agent = ReasoningAgent()
        await _default_reasoning_agent.initialize()
        await _default_reasoning_agent.start()
    return _default_reasoning_agent

