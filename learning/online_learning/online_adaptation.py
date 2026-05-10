
import numpy as np
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from collections import deque

import logging

logger = logging.getLogger(__name__)


@dataclass
class AdaptationRule:
    """قاعدة تكيف"""
    condition: str
    action: str
    threshold: float
    current_value: float = 0.0
    active: bool = True


class OnlineAdapter:
    """
    التكيف عبر الإنترنت المتقدم
    
    الميزات:
    - تكيف فوري مع تغيرات البيئة
    - تعديل معلمات النموذج في الوقت الفعلي
    - استراتيجيات تكيف متعددة
    - تتبع فعالية التكيف
    """
    
    def __init__(self):
        self.rules: List[AdaptationRule] = []
        self.adaptation_history: List[Dict] = []
        self.current_parameters: Dict[str, Any] = {}
        
        # تهيئة قواعد التكيف الافتراضية
        self._init_default_rules()
        
        logger.info("OnlineAdapter initialized")
    
    def _init_default_rules(self):
        """تهيئة قواعد التكيف الافتراضية"""
        
        self.rules = [
            AdaptationRule(
                condition="high_latency",
                action="reduce_timeout",
                threshold=1000  # ms
            ),
            AdaptationRule(
                condition="high_error_rate",
                action="increase_retries",
                threshold=0.1  # 10%
            ),
            AdaptationRule(
                condition="low_success_rate",
                action="switch_strategy",
                threshold=0.3  # 30%
            ),
            AdaptationRule(
                condition="resource_exhaustion",
                action="reduce_concurrency",
                threshold=0.8  # 80% usage
            ),
            AdaptationRule(
                condition="detection_warning",
                action="enable_stealth",
                threshold=0.5  # confidence
            )
        ]
    
    async def update_metrics(self, metrics: Dict[str, float]):
        """
        تحديث المقاييس الحالية وتطبيق التكيفات
        
        Args:
            metrics: المقاييس الحالية
        """
        adaptations = []
        
        for rule in self.rules:
            if not rule.active:
                continue
            
            # تحديث القيمة الحالية من المقاييس
            if rule.condition == "high_latency" and "latency" in metrics:
                rule.current_value = metrics["latency"]
            elif rule.condition == "high_error_rate" and "error_rate" in metrics:
                rule.current_value = metrics["error_rate"]
            elif rule.condition == "low_success_rate" and "success_rate" in metrics:
                rule.current_value = 1 - metrics["success_rate"]
            elif rule.condition == "resource_exhaustion" and "resource_usage" in metrics:
                rule.current_value = metrics["resource_usage"]
            elif rule.condition == "detection_warning" and "detection_probability" in metrics:
                rule.current_value = metrics["detection_probability"]
            
            # التحقق من تجاوز العتبة
            if rule.current_value >= rule.threshold:
                await self._apply_adaptation(rule)
                adaptations.append({
                    "rule": rule.condition,
                    "action": rule.action,
                    "current_value": rule.current_value,
                    "threshold": rule.threshold,
                    "timestamp": datetime.now().isoformat()
                })
        
        if adaptations:
            self.adaptation_history.extend(adaptations)
            logger.info(f"Applied {len(adaptations)} adaptations")
    
    async def _apply_adaptation(self, rule: AdaptationRule):
        """
        تطبيق التكيف
        
        Args:
            rule: قاعدة التكيف
        """
        if rule.action == "reduce_timeout":
            self.current_parameters["timeout"] = max(5, self.current_parameters.get("timeout", 30) * 0.8)
            logger.debug(f"Adaptation: reduced timeout to {self.current_parameters['timeout']}")
        
        elif rule.action == "increase_retries":
            self.current_parameters["retries"] = min(5, self.current_parameters.get("retries", 3) + 1)
            logger.debug(f"Adaptation: increased retries to {self.current_parameters['retries']}")
        
        elif rule.action == "switch_strategy":
            self.current_parameters["strategy"] = "conservative"
            logger.debug("Adaptation: switched to conservative strategy")
        
        elif rule.action == "reduce_concurrency":
            self.current_parameters["concurrency"] = max(1, self.current_parameters.get("concurrency", 10) // 2)
            logger.debug(f"Adaptation: reduced concurrency to {self.current_parameters['concurrency']}")
        
        elif rule.action == "enable_stealth":
            self.current_parameters["stealth_mode"] = True
            logger.debug("Adaptation: enabled stealth mode")
        
        # تحديث حالة القاعدة لمنع التكرار المفرط
        rule.active = False
        # (سيتم إعادة تنشيطها بعد فترة)
    
    async def reset_adaptations(self):
        """إعادة تعيين التكيفات"""
        for rule in self.rules:
            rule.active = True
            rule.current_value = 0.0
        
        self.current_parameters = {}
        logger.info("Adaptations reset")
    
    async def get_current_parameters(self) -> Dict[str, Any]:
        """الحصول على المعلمات الحالية بعد التكيف"""
        return self.current_parameters
    
    async def get_adaptation_history(self, limit: int = 20) -> List[Dict]:
        """الحصول على تاريخ التكيفات"""
        return self.adaptation_history[-limit:]
    
    async def get_statistics(self) -> Dict:
        """إحصائيات التكيف"""
        active_rules = len([r for r in self.rules if r.active])
        total_adaptations = len(self.adaptation_history)
        
        return {
            "total_rules": len(self.rules),
            "active_rules": active_rules,
            "total_adaptations": total_adaptations,
            "current_parameters": self.current_parameters,
            "adaptations_by_rule": {
                rule: len([a for a in self.adaptation_history if a["rule"] == rule])
                for rule in {a["rule"] for a in self.adaptation_history}
            }
        }

