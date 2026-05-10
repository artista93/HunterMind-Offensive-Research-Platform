
import math
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime

from ...offensive.scanners.base_scanner import Severity

import logging

logger = logging.getLogger(__name__)


@dataclass
class RewardSignal:
    """إشارة مكافأة"""
    value: float
    reason: str
    timestamp: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)


class RewardEngine:
    """
    محرك المكافآت المتقدم
    
    الميزات:
    - حساب المكافآت بناءً على عوامل متعددة
    - مكافآت إضافية للاستغلال الناجح
    - عقوبات للفشل
    - مكافآت زمنية (السرعة)
    - تكامل مع شدة الثغرة
    """
    
    # أوزان المكافآت
    WEIGHTS = {
        "exploit_success": 10.0,
        "high_severity": 5.0,
        "critical_severity": 8.0,
        "data_extracted": 7.0,
        "new_technique": 4.0,
        "bypassed_waf": 6.0
    }
    
    # عقوبات
    PENALTIES = {
        "exploit_failed": -2.0,
        "timeout": -1.0,
        "blocked": -3.0,
        "detected": -4.0
    }
    
    def __init__(self):
        self._reward_history: List[RewardSignal] = []
        
        logger.info("RewardEngine initialized")
    
    async def calculate_reward(
        self,
        success: bool,
        severity: str = None,
        data_extracted: bool = False,
        new_technique: bool = False,
        bypassed_waf: bool = False,
        response_time: float = 0.0,
        metadata: Dict = None
    ) -> RewardSignal:
        """
        حساب المكافأة بناءً على العوامل
        
        Args:
            success: نجاح الاستغلال
            severity: شدة الثغرة
            data_extracted: هل تم استخراج بيانات؟
            new_technique: هل تم استخدام تقنية جديدة؟
            bypassed_waf: هل تم تجاوز WAF؟
            response_time: وقت الاستجابة
            metadata: بيانات إضافية
        
        Returns:
            إشارة المكافأة
        """
        total_reward = 0.0
        reasons = []
        
        # مكافأة النجاح
        if success:
            total_reward += self.WEIGHTS["exploit_success"]
            reasons.append(f"Exploit successful (+{self.WEIGHTS['exploit_success']})")
        else:
            total_reward += self.PENALTIES["exploit_failed"]
            reasons.append(f"Exploit failed ({self.PENALTIES['exploit_failed']})")
        
        # مكافأة شدة الثغرة
        if severity:
            if severity.lower() == "critical":
                total_reward += self.WEIGHTS["critical_severity"]
                reasons.append(f"Critical severity (+{self.WEIGHTS['critical_severity']})")
            elif severity.lower() == "high":
                total_reward += self.WEIGHTS["high_severity"]
                reasons.append(f"High severity (+{self.WEIGHTS['high_severity']})")
        
        # مكافأة استخراج البيانات
        if data_extracted:
            total_reward += self.WEIGHTS["data_extracted"]
            reasons.append(f"Data extracted (+{self.WEIGHTS['data_extracted']})")
        
        # مكافأة التقنية الجديدة
        if new_technique:
            total_reward += self.WEIGHTS["new_technique"]
            reasons.append(f"New technique used (+{self.WEIGHTS['new_technique']})")
        
        # مكافأة تجاوز WAF
        if bypassed_waf:
            total_reward += self.WEIGHTS["bypassed_waf"]
            reasons.append(f"WAF bypassed (+{self.WEIGHTS['bypassed_waf']})")
        
        # مكافأة الوقت (كلما أسرع، زادت المكافأة)
        if response_time > 0:
            time_bonus = max(0, 2.0 - response_time / 5.0)
            total_reward += time_bonus
            reasons.append(f"Fast execution (+{time_bonus:.2f})")
        
        # عقوبة الحظر
        if metadata and metadata.get("blocked", False):
            total_reward += self.PENALTIES["blocked"]
            reasons.append(f"Request blocked ({self.PENALTIES['blocked']})")
        
        reward = RewardSignal(
            value=total_reward,
            reason=", ".join(reasons)
        )
        
        self._reward_history.append(reward)
        
        logger.debug(f"Reward calculated: {total_reward:.2f} - {reward.reason}")
        
        return reward
    
    async def calculate_episode_reward(
        self,
        steps: List[Dict],
        total_success: bool
    ) -> float:
        """
        حساب مكافأة حلقة كاملة من الاستغلال
        
        Args:
            steps: قائمة خطوات الاستغلال
            total_success: نجاح الحلقة بالكامل
        
        Returns:
            المكافأة الإجمالية
        """
        total_reward = 0.0
        
        for step in steps:
            reward = await self.calculate_reward(
                success=step.get("success", False),
                severity=step.get("severity"),
                data_extracted=step.get("data_extracted", False),
                response_time=step.get("response_time", 0)
            )
            total_reward += reward.value
        
        # مكافأة إضافية لنجاح الحلقة الكاملة
        if total_success:
            total_reward += 15.0
            logger.debug(f"Episode complete bonus: +15.0")
        
        return total_reward
    
    async def calculate_discovery_reward(
        self,
                vulnerabilities_found: int,
        new_vulnerabilities: int,
        critical_count: int
    ) -> float:
        """
        حساب مكافأة اكتشاف ثغرات جديدة
        
        Args:
            vulnerabilities_found: عدد الثغرات المكتشفة
            new_vulnerabilities: عدد الثغرات الجديدة
            critical_count: عدد الثغرات الحرجة
        
        Returns:
            المكافأة
        """
        reward = 0.0
        
        # مكافأة الثغرات المكتشفة
        reward += vulnerabilities_found * 2.0
        
        # مكافأة الثغرات الجديدة
        reward += new_vulnerabilities * 5.0
        
        # مكافأة الثغرات الحرجة
        reward += critical_count * 8.0
        
        logger.debug(f"Discovery reward: {reward:.2f}")
        return reward
    
    async def get_reward_statistics(self) -> Dict:
        """إحصائيات المكافآت"""
        if not self._reward_history:
            return {"total_rewards": 0}
        
        rewards = [r.value for r in self._reward_history]
        positive = [r for r in rewards if r > 0]
        negative = [r for r in rewards if r < 0]
        
        return {
            "total_rewards": len(self._reward_history),
            "average_reward": sum(rewards) / len(rewards),
            "max_reward": max(rewards),
            "min_reward": min(rewards),
            "positive_count": len(positive),
            "negative_count": len(negative),
            "success_rate": len(positive) / len(rewards) if rewards else 0
        }
    
    async def clear_history(self):
        """مسح تاريخ المكافآت"""
        self._reward_history.clear()
        logger.info("Reward history cleared")

