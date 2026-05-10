
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime

from .world_state import WorldState
from .goal_manager import GoalManager, GoalStatus
from .risk_engine import RiskEngine, RiskLevel

import logging

logger = logging.getLogger(__name__)


@dataclass
class StrategyRule:
    """قاعدة استراتيجية"""
    condition: str
    action: str
    priority: int
    active: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AdaptationEvent:
    """حدث تكيف"""
    timestamp: datetime
    reason: str
    old_strategy: str
    new_strategy: str
    success: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)


class AdaptiveStrategy:
    """
    الاستراتيجية التكيفية المتقدمة
    
    الميزات:
    - تعديل الاستراتيجيات بناءً على ظروف البيئة
    - قواعد تكيف ديناميكية
    - تتبع أحداث التكيف
    - تقييم فعالية التكيف
    """
    
    def __init__(
        self,
        world_state: WorldState,
        goal_manager: GoalManager,
        risk_engine: RiskEngine
    ):
        self._world_state = world_state
        self._goal_manager = goal_manager
        self._risk_engine = risk_engine
        
        self._current_strategy: str = "balanced"
        self._rules: List[StrategyRule] = []
        self._adaptation_history: List[AdaptationEvent] = []
        
        # تهيئة القواعد الافتراضية
        self._init_default_rules()
        
        logger.info("AdaptiveStrategy initialized")
    
    def _init_default_rules(self):
        """تهيئة القواعد الافتراضية"""
        
        self._rules = [
            StrategyRule(
                condition="high_load",
                action="reduce_concurrency",
                priority=1
            ),
            StrategyRule(
                condition="low_performance",
                action="optimize_resources",
                priority=2
            ),
            StrategyRule(
                condition="high_risk",
                action="switch_to_stealth",
                priority=1
            ),
            StrategyRule(
                condition="poor_detection",
                action="increase_sensitivity",
                priority=2
            ),
            StrategyRule(
                condition="waf_detected",
                action="enable_bypass",
                priority=1
            ),
            StrategyRule(
                condition="target_critical",
                action="increase_caution",
                priority=1
            ),
            StrategyRule(
                condition="high_success_rate",
                action="maintain_current",
                priority=3
            )
        ]
    
    async def evaluate_and_adapt(self) -> Tuple[str, bool]:
        """
        تقييم الوضع الحالي وتطبيق التكيفات اللازمة
        
        Returns:
            (الاستراتيجية الجديدة, هل تم التكيف)
        """
        old_strategy = self._current_strategy
        triggered_rules = []
        
        # فحص جميع القواعد
        for rule in sorted(self._rules, key=lambda x: x.priority):
            if not rule.active:
                continue
            
            if await self._evaluate_condition(rule.condition):
                triggered_rules.append(rule)
                await self._apply_action(rule.action)
        
        # تحديث الاستراتيجية الحالية
        self._current_strategy = await self._determine_strategy()
        
        if self._current_strategy != old_strategy:
            # تسجيل حدث التكيف
            event = AdaptationEvent(
                timestamp=datetime.now(),
                reason=f"Triggered rules: {[r.condition for r in triggered_rules]}",
                old_strategy=old_strategy,
                new_strategy=self._current_strategy
            )
            self._adaptation_history.append(event)
            
            logger.info(f"Strategy adapted: {old_strategy} -> {self._current_strategy}")
            return self._current_strategy, True
        
        return self._current_strategy, False
    
    async def _evaluate_condition(self, condition: str) -> bool:
        """
        تقييم شرط القاعدة
        
        Args:
            condition: اسم الشرط
        
        Returns:
            نتيجة التقييم
        """
        if condition == "high_load":
            load = await self._world_state.get_attribute("current_load", 0)
            return load > 0.7
        
        elif condition == "low_performance":
            # محاكاة: التحقق من تأخر الاستجابات
            latency = await self._world_state.get_attribute("network_latency", 0)
            return latency > 200
        
        elif condition == "high_risk":
            # محاكاة: التحقق من المخاطر
            risk_profile = await self._risk_engine.get_current_risk_profile()
            return risk_profile.get("overall_score", 0) > 60
        
        elif condition == "poor_detection":
            vulnerabilities = await self._world_state.get_attribute("vulnerabilities_found", 0)
            targets = await self._world_state.get_attribute("targets_analyzed", 1)
            detection_rate = vulnerabilities / targets if targets > 0 else 0
            return detection_rate < 0.1
        
        elif condition == "waf_detected":
            return await self._world_state.get_attribute("waf_detected", False)
        
        elif condition == "target_critical":
            # محاكاة: التحقق من وجود أهداف حرجة
            return False
        
        elif condition == "high_success_rate":
            vulnerabilities = await self._world_state.get_attribute("vulnerabilities_found", 0)
            targets = await self._world_state.get_attribute("targets_analyzed", 1)
            success_rate = vulnerabilities / targets if targets > 0 else 0
            return success_rate > 0.3
        
        return False
    
    async def _apply_action(self, action: str):
        """
        تطبيق إجراء القاعدة
        
        Args:
            action: اسم الإجراء
        """
        if action == "reduce_concurrency":
            await self._world_state.update_attribute("max_concurrent", 3)
            logger.debug("Action applied: reduce_concurrency")
        
        elif action == "optimize_resources":
            await self._world_state.update_attribute("cache_enabled", True)
            logger.debug("Action applied: optimize_resources")
        
        elif action == "switch_to_stealth":
            await self._world_state.update_attribute("stealth_mode", True)
            logger.debug("Action applied: switch_to_stealth")
        
        elif action == "increase_sensitivity":
            await self._world_state.update_attribute("scan_sensitivity", 0.9)
            logger.debug("Action applied: increase_sensitivity")
        
        elif action == "enable_bypass":
            await self._world_state.update_attribute("waf_bypass_enabled", True)
            logger.debug("Action applied: enable_bypass")
        
        elif action == "increase_caution":
            await self._world_state.update_attribute("caution_level", "high")
            logger.debug("Action applied: increase_caution")
    
    async def _determine_strategy(self) -> str:
        """تحديد الاستراتيجية الحالية بناءً على الحالة"""
        if await self._world_state.get_attribute("stealth_mode", False):
            return "stealth"
        
        if await self._world_state.get_attribute("waf_bypass_enabled", False):
            return "bypass"
        
        load = await self._world_state.get_attribute("current_load", 0)
        if load > 0.8:
            return "conservative"
        
        risk = await self._risk_engine.get_current_risk_profile()
        if risk.get("overall_score", 0) > 70:
            return "cautious"
        
        return "balanced"
    
    async def add_rule(self, rule: StrategyRule):
        """إضافة قاعدة جديدة"""
        self._rules.append(rule)
        logger.info(f"Rule added: {rule.condition} -> {rule.action}")
    
    async def get_current_strategy(self) -> str:
        """الحصول على الاستراتيجية الحالية"""
        return self._current_strategy
    
    async def get_adaptation_history(self, limit: int = 20) -> List[Dict]:
        """الحصول على تاريخ التكيفات"""
        return [
            {
                "timestamp": e.timestamp.isoformat(),
                "reason": e.reason,
                "old_strategy": e.old_strategy,
                "new_strategy": e.new_strategy,
                "success": e.success
            }
            for e in self._adaptation_history[-limit:]
        ]
    
    async def get_statistics(self) -> Dict:
        """إحصائيات الاستراتيجية التكيفية"""
        return {
            "current_strategy": self._current_strategy,
            "total_adaptations": len(self._adaptation_history),
            "active_rules": len([r for r in self._rules if r.active]),
            "total_rules": len(self._rules),
            "recent_adaptations": len([e for e in self._adaptation_history if e.timestamp.timestamp() > datetime.now().timestamp() - 3600])
        }

