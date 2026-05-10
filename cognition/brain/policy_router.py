
import asyncio
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

import logging

logger = logging.getLogger(__name__)


class PolicyType(Enum):
    """أنواع السياسات"""
    AGGRESSIVE = "aggressive"
    STEALTH = "stealth"
    BALANCED = "balanced"
    EXPLORATORY = "exploratory"
    CONSERVATIVE = "conservative"


@dataclass
class PolicyRule:
    """قاعدة سياسة"""
    condition: str
    action: str
    priority: int
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Policy:
    """سياسة"""
    name: str
    type: PolicyType
    rules: List[PolicyRule]
    created_at: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)


class PolicyRouter:
    """
    موجه السياسات المتقدم
    
    الميزات:
    - تحديد السياسة المناسبة للسياق
    - تطبيق قواعد السياسة
    - تحديث السياسات ديناميكياً
    - تقييم فعالية السياسات
    """
    
    def __init__(self):
        self._policies: Dict[PolicyType, Policy] = {}
        self._current_policy: Optional[PolicyType] = None
        self._policy_history: List[Dict] = []
        
        # تهيئة السياسات الافتراضية
        self._init_default_policies()
        
        logger.info("PolicyRouter initialized")
    
    def _init_default_policies(self):
        """تهيئة السياسات الافتراضية"""
        
        # سياسة هجومية
        self._policies[PolicyType.AGGRESSIVE] = Policy(
            name="Aggressive Policy",
            type=PolicyType.AGGRESSIVE,
            rules=[
                PolicyRule(condition="vulnerability_confirmed", action="exploit_immediately", priority=1),
                PolicyRule(condition="has_waf", action="use_bypass_techniques", priority=2),
                PolicyRule(condition="target_critical", action="deploy_all_resources", priority=3)
            ]
        )
        
        # سياسة التخفي
        self._policies[PolicyType.STEALTH] = Policy(
            name="Stealth Policy",
            type=PolicyType.STEALTH,
            rules=[
                PolicyRule(condition="vulnerability_confirmed", action="recon_first", priority=1),
                PolicyRule(condition="has_waf", action="avoid_triggering", priority=2),
                PolicyRule(condition="target_critical", action="slow_approach", priority=3)
            ]
        )
        
        # سياسة متوازنة
        self._policies[PolicyType.BALANCED] = Policy(
            name="Balanced Policy",
            type=PolicyType.BALANCED,
            rules=[
                PolicyRule(condition="vulnerability_confirmed", action="assess_then_exploit", priority=1),
                PolicyRule(condition="has_waf", action="test_bypass", priority=2),
                PolicyRule(condition="target_critical", action="allocate_resources", priority=3)
            ]
        )
        
        # سياسة استكشافية
        self._policies[PolicyType.EXPLORATORY] = Policy(
            name="Exploratory Policy",
            type=PolicyType.EXPLORATORY,
            rules=[
                PolicyRule(condition="vulnerability_confirmed", action="test_all_methods", priority=1),
                PolicyRule(condition="has_waf", action="collect_info", priority=2),
                PolicyRule(condition="target_critical", action="analyze_thoroughly", priority=3)
            ]
        )
        
        # سياسة محافظة
        self._policies[PolicyType.CONSERVATIVE] = Policy(
            name="Conservative Policy",
            type=PolicyType.CONSERVATIVE,
            rules=[
                PolicyRule(condition="vulnerability_confirmed", action="verify_safety", priority=1),
                PolicyRule(condition="has_waf", action="avoid_detection", priority=2),
                PolicyRule(condition="target_critical", action="report_only", priority=3)
            ]
        )
    
    async def select_policy(
        self,
        context: Dict[str, Any]
    ) -> PolicyType:
        """
        اختيار السياسة المناسبة للسياق
        
        Args:
            context: سياق التشغيل (نوع الهدف، وجود WAF، مستوى الخطر)
        
        Returns:
            نوع السياسة المختارة
        """
        # عوامل الاختيار
        risk_level = context.get("risk_level", "medium")
        has_waf = context.get("has_waf", False)
        target_critical = context.get("target_critical", False)
        stealth_required = context.get("stealth_required", False)
        
        if stealth_required:
            policy = PolicyType.STEALTH
        elif has_waf and target_critical:
            policy = PolicyType.BALANCED
        elif has_waf:
            policy = PolicyType.EXPLORATORY
        elif risk_level == "high":
            policy = PolicyType.AGGRESSIVE
        else:
            policy = PolicyType.BALANCED
        
        self._current_policy = policy
        
        self._policy_history.append({
            "timestamp": datetime.now().isoformat(),
            "selected_policy": policy.value,
            "context": context
        })
        
        logger.info(f"Policy selected: {policy.value}")
        
        return policy
    
    async def apply_rules(
        self,
        policy_type: PolicyType,
        context: Dict[str, Any]
    ) -> List[str]:
        """
        تطبيق قواعد السياسة
        
        Args:
            policy_type: نوع السياسة
            context: سياق التشغيل
        
        Returns:
            قائمة بالإجراءات المطلوبة
        """
        policy = self._policies.get(policy_type)
        if not policy:
            return []
        
        actions = []
        
        for rule in sorted(policy.rules, key=lambda x: x.priority):
            if await self._evaluate_condition(rule.condition, context):
                actions.append(rule.action)
        
        logger.debug(f"Policy {policy_type.value} applied: {len(actions)} actions")
        
        return actions
    
    async def _evaluate_condition(self, condition: str, context: Dict) -> bool:
        """تقييم شرط القاعدة"""
        if condition == "vulnerability_confirmed":
            return context.get("vulnerability_confirmed", False)
        elif condition == "has_waf":
            return context.get("has_waf", False)
        elif condition == "target_critical":
            return context.get("target_critical", False)
        
        return False
    
    async def get_current_policy(self) -> Optional[PolicyType]:
        """الحصول على السياسة الحالية"""
        return self._current_policy
    
    async def get_policy_details(self, policy_type: PolicyType) -> Optional[Dict]:
        """الحصول على تفاصيل سياسة"""
        policy = self._policies.get(policy_type)
        if not policy:
            return None
        
        return {
            "name": policy.name,
            "type": policy.type.value,
            "rules": [
                {"condition": r.condition, "action": r.action, "priority": r.priority}
                for r in policy.rules
            ],
            "created_at": policy.created_at.isoformat()
        }
    
    async def get_policy_history(self, limit: int = 20) -> List[Dict]:
        """الحصول على تاريخ اختيار السياسات"""
        return self._policy_history[-limit:]
    
    async def get_statistics(self) -> Dict:
        """إحصائيات الموجه"""
        if not self._policy_history:
            return {"total_selections": 0}
        
        # توزيع السياسات المختارة
        policy_distribution = {}
        for entry in self._policy_history:
            policy = entry["selected_policy"]
            policy_distribution[policy] = policy_distribution.get(policy, 0) + 1
        
        return {
            "total_selections": len(self._policy_history),
            "current_policy": self._current_policy.value if self._current_policy else None,
            "policy_distribution": policy_distribution,
            "available_policies": [p.value for p in PolicyType]
        }

