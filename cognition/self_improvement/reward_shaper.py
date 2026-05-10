
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime

import logging

logger = logging.getLogger(__name__)


@dataclass
class RewardRule:
    """قاعدة مكافأة"""
    condition: str
    base_reward: float
    multiplier: float
    active: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ShapingFunction:
    """دالة تشكيل المكافأة"""
    name: str
    function: str
    parameters: Dict[str, float]
    active: bool = True


class RewardShaper:
    """
    مشكل المكافآت المتقدم
    
    الميزات:
    - ضبط المكافآت بناءً على الأداء
    - مكافآت إضافية للسلوك المرغوب
    - عقوبات للسلوك غير المرغوب
    - تكيف ديناميكي لنظام المكافآت
    """
    
    def __init__(self):
        self._rules: List[RewardRule] = []
        self._shaping_functions: List[ShapingFunction] = []
        self._reward_history: List[Dict] = []
        
        # تهيئة القواعد الافتراضية
        self._init_default_rules()
        
        # تهيئة دوال التشكيل
        self._init_shaping_functions()
        
        logger.info("RewardShaper initialized")
    
    def _init_default_rules(self):
        """تهيئة القواعد الافتراضية"""
        
        self._rules = [
            RewardRule(
                condition="vulnerability_found",
                base_reward=10.0,
                multiplier=1.0
            ),
            RewardRule(
                condition="exploit_success",
                base_reward=20.0,
                multiplier=1.0
            ),
            RewardRule(
                condition="data_extracted",
                base_reward=15.0,
                multiplier=1.0
            ),
            RewardRule(
                condition="waf_bypassed",
                base_reward=25.0,
                multiplier=1.0
            ),
            RewardRule(
                condition="false_positive",
                base_reward=-5.0,
                multiplier=1.0
            ),
            RewardRule(
                condition="timeout",
                base_reward=-2.0,
                multiplier=1.0
            ),
            RewardRule(
                condition="blocked",
                base_reward=-10.0,
                multiplier=1.0
            )
        ]
    
    def _init_shaping_functions(self):
        """تهيئة دوال تشكيل المكافأة"""
        
        self._shaping_functions = [
            ShapingFunction(
                name="time_bonus",
                function="reward * (1 + (target_time - actual_time) / target_time)",
                parameters={"target_time": 5.0},
                active=True
            ),
            ShapingFunction(
                name="novelty_bonus",
                function="reward * (1 + novelty_score)",
                parameters={"novelty_weight": 0.3},
                active=True
            ),
            ShapingFunction(
                name="consistency_penalty",
                function="reward * (1 - repeat_penalty)",
                parameters={"repeat_penalty": 0.1},
                active=True
            )
        ]
    
    async def calculate_reward(
        self,
        condition: str,
        context: Dict[str, Any]
    ) -> float:
        """
        حساب المكافأة بناءً على الشرط والسياق
        
        Args:
            condition: شرط المكافأة
            context: سياق الحدث
        
        Returns:
            قيمة المكافأة
        """
        # البحث عن القاعدة
        rule = None
        for r in self._rules:
            if r.condition == condition and r.active:
                rule = r
                break
        
        if not rule:
            return 0.0
        
        base_reward = rule.base_reward * rule.multiplier
        
        # تطبيق دوال التشكيل
        shaped_reward = base_reward
        
        for func in self._shaping_functions:
            if func.active:
                shaped_reward = await self._apply_shaping_function(
                    func, shaped_reward, context
                )
        
        # تسجيل المكافأة
        self._reward_history.append({
            "condition": condition,
            "base_reward": base_reward,
            "shaped_reward": shaped_reward,
            "context": context,
            "timestamp": datetime.now().isoformat()
        })
        
        # الحفاظ على آخر 1000 سجل
        if len(self._reward_history) > 1000:
            self._reward_history.pop(0)
        
        logger.debug(f"Reward calculated: {condition} = {shaped_reward:.2f}")
        return shaped_reward
    
    async def _apply_shaping_function(
        self,
        func: ShapingFunction,
        reward: float,
        context: Dict[str, Any]
    ) -> float:
        """تطبيق دالة تشكيل المكافأة"""
        
        if func.name == "time_bonus":
            actual_time = context.get("execution_time", 0)
            target_time = func.parameters.get("target_time", 5.0)
            
            if actual_time > 0 and actual_time < target_time:
                bonus = 1 + (target_time - actual_time) / target_time
                return reward * bonus
        
        elif func.name == "novelty_bonus":
            novelty_score = context.get("novelty_score", 0)
            weight = func.parameters.get("novelty_weight", 0.3)
            return reward * (1 + novelty_score * weight)
        
        elif func.name == "consistency_penalty":
            repeat_count = context.get("repeat_count", 0)
            penalty = func.parameters.get("repeat_penalty", 0.1)
            return reward * (1 - min(0.5, repeat_count * penalty))
        
        return reward
    
    async def update_rule_multiplier(
        self,
        condition: str,
        new_multiplier: float
    ) -> bool:
        """
        تحديث مضاعف قاعدة المكافأة
        
        Args:
            condition: شرط المكافأة
            new_multiplier: المضاعف الجديد
        
        Returns:
            نجاح العملية
        """
        for rule in self._rules:
            if rule.condition == condition:
                rule.multiplier = new_multiplier
                logger.debug(f"Rule multiplier updated: {condition} = {new_multiplier}")
                return True
        return False
    
    async def add_rule(self, rule: RewardRule):
        """إضافة قاعدة جديدة"""
        self._rules.append(rule)
        logger.info(f"Reward rule added: {rule.condition}")
    
    async def add_shaping_function(self, function: ShapingFunction):
        """إضافة دالة تشكيل جديدة"""
        self._shaping_functions.append(function)
        logger.info(f"Shaping function added: {function.name}")
    
    async def get_reward_stats(self) -> Dict:
        """إحصائيات المكافآت"""
        if not self._reward_history:
            return {"total_rewards": 0}
        
        rewards = [h["shaped_reward"] for h in self._reward_history]
        
        return {
            "total_rewards": len(self._reward_history),
            "average_reward": sum(rewards) / len(rewards),
            "max_reward": max(rewards),
            "min_reward": min(rewards),
            "positive_rewards": len([r for r in rewards if r > 0]),
            "negative_rewards": len([r for r in rewards if r < 0]),
            "reward_distribution": {
                condition: sum(1 for h in self._reward_history if h["condition"] == condition)
                for condition in set(h["condition"] for h in self._reward_history)
            }
        }
    
    async def get_rule_performance(self) -> Dict:
        """أداء قواعد المكافأة"""
        performance = {}
        
        for rule in self._rules:
            rule_rewards = [h for h in self._reward_history if h["condition"] == rule.condition]
            if rule_rewards:
                avg_reward = sum(h["shaped_reward"] for h in rule_rewards) / len(rule_rewards)
                performance[rule.condition] = {
                    "count": len(rule_rewards),
                    "average_reward": avg_reward,
                    "multiplier": rule.multiplier,
                    "active": rule.active
                }
        
        return performance
    
    async def get_statistics(self) -> Dict:
        """إحصائيات المشكل"""
        return {
            "total_rules": len(self._rules),
            "active_rules": len([r for r in self._rules if r.active]),
            "shaping_functions": len(self._shaping_functions),
            "reward_history_size": len(self._reward_history),
            "reward_stats": await self.get_reward_stats(),
            "rule_performance": await self.get_rule_performance()
        }

