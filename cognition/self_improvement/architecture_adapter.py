
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime

import logging

logger = logging.getLogger(__name__)


@dataclass
class ArchitectureConfig:
    """تكوين البنية"""
    component: str
    parameter: str
    current_value: Any
    recommended_value: Any
    reason: str
    impact: str  # high, medium, low
    applied: bool = False
    applied_at: Optional[datetime] = None


class ArchitectureAdapter:
    """
    محول البنية المتقدم
    
    الميزات:
    - تحليل أداء المكونات
    - اقتراح تغييرات في البنية
    - تطبيق التعديلات ديناميكياً
    - تتبع تأثير التغييرات
    """
    
    def __init__(self):
        self._configs: List[ArchitectureConfig] = []
        self._adaptation_history: List[Dict] = []
        
        logger.info("ArchitectureAdapter initialized")
    
    async def analyze_and_adapt(
        self,
        performance_metrics: Dict[str, Any],
        current_config: Dict[str, Any]
    ) -> List[ArchitectureConfig]:
        """
        تحليل الأداء واقتراح تكيفات البنية
        
        Args:
            performance_metrics: مقاييس الأداء
            current_config: التكوين الحالي
        
        Returns:
            قائمة بتكوينات البنية المقترحة
        """
        configs = []
        
        # تحليل استخدام الموارد
        if performance_metrics.get("cpu_usage", 0) > 80:
            configs.append(ArchitectureConfig(
                component="runtime",
                parameter="max_concurrent",
                current_value=current_config.get("max_concurrent", 10),
                recommended_value=current_config.get("max_concurrent", 10) // 2,
                reason="High CPU usage detected",
                impact="high"
            ))
        
        if performance_metrics.get("memory_usage", 0) > 85:
            configs.append(ArchitectureConfig(
                component="cache",
                parameter="max_size",
                current_value=current_config.get("cache_size", 1000),
                recommended_value=current_config.get("cache_size", 1000) // 2,
                reason="High memory usage detected",
                impact="high"
            ))
        
        # تحليل زمن الاستجابة
        if performance_metrics.get("response_time", 0) > 10:
            configs.append(ArchitectureConfig(
                component="database",
                parameter="pool_size",
                current_value=current_config.get("pool_size", 5),
                recommended_value=current_config.get("pool_size", 5) + 5,
                reason="High response time detected",
                impact="medium"
            ))
        
        # تحليل معدل الخطأ
        if performance_metrics.get("error_rate", 0) > 0.1:
            configs.append(ArchitectureConfig(
                component="retry",
                parameter="max_attempts",
                current_value=current_config.get("retry_attempts", 3),
                recommended_value=current_config.get("retry_attempts", 3) + 2,
                reason="High error rate detected",
                impact="medium"
            ))
        
        self._configs = configs
        return configs
    
    async def apply_config(self, config: ArchitectureConfig) -> bool:
        """
        تطبيق تكوين بنية
        
        Args:
            config: تكوين البنية
        
        Returns:
            نجاح التطبيق
        """
        try:
            # محاكاة تطبيق التكوين
            config.applied = True
            config.applied_at = datetime.now()
            
            self._adaptation_history.append({
                "component": config.component,
                "parameter": config.parameter,
                "old_value": config.current_value,
                "new_value": config.recommended_value,
                "reason": config.reason,
                "timestamp": datetime.now().isoformat(),
                "success": True
            })
            
            logger.info(f"Architecture config applied: {config.component}.{config.parameter} = {config.recommended_value}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to apply config: {e}")
            self._adaptation_history.append({
                "component": config.component,
                "parameter": config.parameter,
                "error": str(e),
                "timestamp": datetime.now().isoformat(),
                "success": False
            })
            return False
    
    async def get_applied_configs(self) -> List[ArchitectureConfig]:
        """الحصول على التكوينات المطبقة"""
        return [c for c in self._configs if c.applied]
    
    async def get_adaptation_history(self, limit: int = 20) -> List[Dict]:
        """الحصول على تاريخ التكيفات"""
        return self._adaptation_history[-limit:]
    
    async def get_statistics(self) -> Dict:
        """إحصائيات المحول"""
        applied = len([c for c in self._configs if c.applied])
        successful = len([h for h in self._adaptation_history if h.get("success", False)])
        
        return {
            "total_configs_proposed": len(self._configs),
            "applied_configs": applied,
            "successful_adaptations": successful,
            "adaptation_success_rate": successful / len(self._adaptation_history) if self._adaptation_history else 0,
            "adaptations_by_component": {
                comp: len([h for h in self._adaptation_history if h.get("component") == comp])
                for comp in set(h.get("component") for h in self._adaptation_history)
            }
        }

