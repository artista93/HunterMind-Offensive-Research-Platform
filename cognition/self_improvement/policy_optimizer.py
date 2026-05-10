
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from collections import defaultdict

import logging

logger = logging.getLogger(__name__)


@dataclass
class PolicyRule:
    """قاعدة سياسة"""
    id: str
    condition: str
    action: str
    weight: float
    times_used: int = 0
    times_successful: int = 0
    last_used: Optional[datetime] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class OptimizationResult:
    """نتيجة التحسين"""
    rule_id: str
    old_weight: float
    new_weight: float
    improvement: float
    timestamp: datetime = field(default_factory=datetime.now)


class PolicyOptimizer:
    """
    محسن السياسات المتقدم
    
    الميزات:
    - تحسين أوزان القواعد بناءً على الأداء
    - إضافة قواعد جديدة
    - إزالة القواعد غير الفعالة
    - تتبع تأثير التحسينات
    """
    
    def __init__(self, learning_rate: float = 0.1):
        self._rules: Dict[str, PolicyRule] = {}
        self._optimization_history: List[OptimizationResult] = []
        self._learning_rate = learning_rate
        
        # تهيئة القواعد الافتراضية
        self._init_default_rules()
        
        logger.info("PolicyOptimizer initialized")
    
    def _init_default_rules(self):
        """تهيئة القواعد الافتراضية"""
        
        default_rules = [
            PolicyRule(
                id="rule_001",
                condition="vulnerability_detected",
                action="trigger_alert",
                weight=1.0
            ),
            PolicyRule(
                id="rule_002",
                condition="high_confidence",
                action="auto_exploit",
                weight=0.8
            ),
            PolicyRule(
                id="rule_003",
                condition="waf_detected",
                action="enable_stealth",
                weight=0.9
            ),
            PolicyRule(
                id="rule_004",
                condition="rate_limited",
                action="reduce_speed",
                weight=0.7
            ),
            PolicyRule(
                id="rule_005",
                condition="critical_target",
                action="increase_priority",
                weight=1.0
            ),
            PolicyRule(
                id="rule_006",
                condition="low_resources",
                action="reduce_concurrency",
                weight=0.6
            )
        ]
        
        for rule in default_rules:
            self._rules[rule.id] = rule
    
    async def record_rule_outcome(self, rule_id: str, success: bool):
        """
        تسجيل نتيجة تطبيق قاعدة
        
        Args:
            rule_id: معرف القاعدة
            success: نجاح القاعدة
        """
        if rule_id not in self._rules:
            logger.warning(f"Rule {rule_id} not found")
            return
        
        rule = self._rules[rule_id]
        rule.times_used += 1
        if success:
            rule.times_successful += 1
        rule.last_used = datetime.now()
        
        # تحديث الوزن بناءً على النتيجة
        await self._update_rule_weight(rule_id, success)
    
    async def _update_rule_weight(self, rule_id: str, success: bool):
        """
        تحديث وزن القاعدة بناءً على النتيجة
        
        Args:
            rule_id: معرف القاعدة
            success: نجاح القاعدة
        """
        rule = self._rules[rule_id]
        old_weight = rule.weight
        
        # حساب الوزن الجديد
        if rule.times_used > 0:
            success_rate = rule.times_successful / rule.times_used
            target_weight = success_rate
            
            # تحديث تدريجي
            new_weight = old_weight + self._learning_rate * (target_weight - old_weight)
            new_weight = max(0.1, min(1.0, new_weight))
        else:
            new_weight = old_weight
        
        if new_weight != old_weight:
            rule.weight = new_weight
            
            # تسجيل التحسين
            self._optimization_history.append(OptimizationResult(
                rule_id=rule_id,
                old_weight=old_weight,
                new_weight=new_weight,
                improvement=new_weight - old_weight
            ))
            
            logger.debug(f"Rule {rule_id} weight updated: {old_weight:.2f} -> {new_weight:.2f}")
    
    async def add_rule(self, condition: str, action: str, initial_weight: float = 0.5) -> str:
        """
        إضافة قاعدة جديدة
        
        Args:
            condition: شرط القاعدة
            action: إجراء القاعدة
            initial_weight: الوزن الأولي
        
        Returns:
            معرف القاعدة
        """
        import uuid
        rule_id = str(uuid.uuid4())[:8]
        
        rule = PolicyRule(
            id=rule_id,
            condition=condition,
            action=action,
            weight=initial_weight
        )
        
        self._rules[rule_id] = rule
        
        logger.info(f"Rule added: {condition} -> {action} (weight={initial_weight})")
        return rule_id
    
    async def remove_rule(self, rule_id: str) -> bool:
        """
        إزالة قاعدة غير فعالة
        
        Args:
            rule_id: معرف القاعدة
        
        Returns:
            نجاح الإزالة
        """
        if rule_id not in self._rules:
            return False
        
        rule = self._rules[rule_id]
        
        # التحقق من عدم الفعالية
        if rule.times_used > 10 and rule.times_successful / rule.times_used < 0.3:
            del self._rules[rule_id]
            logger.info(f"Rule removed: {rule.condition} -> {rule.action}")
            return True
        
        logger.warning(f"Rule {rule_id} is still effective, not removed")
        return False
    
    async def get_best_rule(self, condition: str) -> Optional[PolicyRule]:
        """
        الحصول على أفضل قاعدة لشرط معين
        
        Args:
            condition: الشرط
        
        Returns:
            أفضل قاعدة أو None
        """
        matching_rules = [r for r in self._rules.values() if r.condition == condition]
        
        if not matching_rules:
            return None
        
        # ترتيب حسب الوزن
        matching_rules.sort(key=lambda x: x.weight, reverse=True)
        return matching_rules[0]
    
    async def get_all_rules(self) -> List[PolicyRule]:
        """الحصول على جميع القواعد"""
        return list(self._rules.values())
    
    async def get_performance_summary(self) -> Dict:
        """ملخص أداء القواعد"""
        if not self._rules:
            return {"total_rules": 0}
        
        total_usage = sum(r.times_used for r in self._rules.values())
        total_success = sum(r.times_successful for r in self._rules.values())
        
        return {
            "total_rules": len(self._rules),
            "total_usage": total_usage,
            "total_success": total_success,
            "overall_success_rate": total_success / total_usage if total_usage > 0 else 0,
            "best_rule": max(self._rules.values(), key=lambda x: x.weight).id if self._rules else None,
            "worst_rule": min(self._rules.values(), key=lambda x: x.weight).id if self._rules else None,
            "average_weight": sum(r.weight for r in self._rules.values()) / len(self._rules),
            "rules_by_condition": {
                condition: len([r for r in self._rules.values() if r.condition == condition])
                for condition in set(r.condition for r in self._rules.values())
            }
        }
    
    async def get_optimization_history(self, limit: int = 20) -> List[Dict]:
        """الحصول على تاريخ التحسينات"""
        return [
            {
                "rule_id": o.rule_id,
                "old_weight": o.old_weight,
                "new_weight": o.new_weight,
                "improvement": o.improvement,
                "timestamp": o.timestamp.isoformat()
            }
            for o in self._optimization_history[-limit:]
        ]
    
    async def get_statistics(self) -> Dict:
        """إحصائيات المحسن"""
        return {
            "total_rules": len(self._rules),
            "total_optimizations": len(self._optimization_history),
            "average_improvement": sum(o.improvement for o in self._optimization_history) / len(self._optimization_history) if self._optimization_history else 0,
            "performance_summary": await self.get_performance_summary(),
            "learning_rate": self._learning_rate
        }

