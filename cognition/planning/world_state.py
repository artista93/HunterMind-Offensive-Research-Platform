
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime

import logging

logger = logging.getLogger(__name__)


@dataclass
class WorldAttribute:
    """سمة في حالة العالم"""
    name: str
    value: Any
    confidence: float
    last_updated: datetime = field(default_factory=datetime.now)
    source: str = "system"


class WorldState:
    """
    حالة العالم المتقدمة
    
    الميزات:
    - تمثيل الحالة الحالية للبيئة
    - تحديث السمات ديناميكياً
    - تتبع تاريخ التغييرات
    - استعلام عن السمات
    """
    
    def __init__(self):
        self._attributes: Dict[str, WorldAttribute] = {}
        self._history: List[Dict] = []
        
        # تهيئة السمات الافتراضية
        self._init_default_attributes()
        
        logger.info("WorldState initialized")
    
    def _init_default_attributes(self):
        """تهيئة السمات الافتراضية"""
        
        default_attributes = {
            "system_status": WorldAttribute(
                name="system_status",
                value="operational",
                confidence=1.0,
                source="system"
            ),
            "current_load": WorldAttribute(
                name="current_load",
                value=0.3,
                confidence=0.9,
                source="system"
            ),
            "active_scans": WorldAttribute(
                name="active_scans",
                value=0,
                confidence=1.0,
                source="system"
            ),
            "vulnerabilities_found": WorldAttribute(
                name="vulnerabilities_found",
                value=0,
                confidence=1.0,
                source="system"
            ),
            "targets_analyzed": WorldAttribute(
                name="targets_analyzed",
                value=0,
                confidence=1.0,
                source="system"
            ),
            "waf_detected": WorldAttribute(
                name="waf_detected",
                value=False,
                confidence=0.8,
                source="system"
            ),
            "network_latency": WorldAttribute(
                name="network_latency",
                value=50.0,
                confidence=0.9,
                source="system"
            ),
            "available_memory": WorldAttribute(
                name="available_memory",
                value=2048,
                confidence=0.95,
                source="system"
            ),
            "available_cpu": WorldAttribute(
                name="available_cpu",
                value=4,
                confidence=0.95,
                source="system"
            )
        }
        
        self._attributes.update(default_attributes)
    
    async def update_attribute(
        self,
        name: str,
        value: Any,
        confidence: float = 0.9,
        source: str = "system"
    ) -> bool:
        """
        تحديث سمة في حالة العالم
        
        Args:
            name: اسم السمة
            value: القيمة الجديدة
            confidence: مستوى الثقة
            source: مصدر التحديث
        
        Returns:
            نجاح العملية
        """
        old_value = None
        if name in self._attributes:
            old_value = self._attributes[name].value
        
        attribute = WorldAttribute(
            name=name,
            value=value,
            confidence=confidence,
            source=source
        )
        
        self._attributes[name] = attribute
        
        # تسجيل التغيير في التاريخ
        self._history.append({
            "attribute": name,
            "old_value": old_value,
            "new_value": value,
            "timestamp": datetime.now().isoformat(),
            "source": source
        })
        
        # الحفاظ على آخر 1000 تغيير فقط
        if len(self._history) > 1000:
            self._history.pop(0)
        
        logger.debug(f"World attribute updated: {name} = {value}")
        return True
    
    async def get_attribute(self, name: str, default: Any = None) -> Any:
        """
        الحصول على قيمة سمة
        
        Args:
            name: اسم السمة
            default: القيمة الافتراضية إذا لم توجد السمة
        
        Returns:
            قيمة السمة أو القيمة الافتراضية
        """
        if name in self._attributes:
            return self._attributes[name].value
        return default
    
    async def get_attribute_with_confidence(self, name: str) -> Optional[Tuple[Any, float]]:
        """
        الحصول على قيمة سمة مع مستوى الثقة
        
        Args:
            name: اسم السمة
        
        Returns:
            (القيمة, الثقة) أو None
        """
        if name in self._attributes:
            attr = self._attributes[name]
            return (attr.value, attr.confidence)
        return None
    
    async def get_all_attributes(self) -> Dict[str, Any]:
        """الحصول على جميع السمات (قيم فقط)"""
        return {name: attr.value for name, attr in self._attributes.items()}
    
    async def get_all_attributes_with_metadata(self) -> Dict[str, Dict]:
        """الحصول على جميع السمات مع البيانات الوصفية"""
        return {
            name: {
                "value": attr.value,
                "confidence": attr.confidence,
                "last_updated": attr.last_updated.isoformat(),
                "source": attr.source
            }
            for name, attr in self._attributes.items()
        }
    
    async def get_history(self, attribute_name: str = None, limit: int = 50) -> List[Dict]:
        """
        الحصول على تاريخ التغييرات
        
        Args:
            attribute_name: اسم السمة (الكل إذا None)
            limit: عدد النتائج
        
        Returns:
            قائمة بالتغييرات
        """
        history = self._history
        
        if attribute_name:
            history = [h for h in history if h["attribute"] == attribute_name]
        
        return history[-limit:]
    
    async def get_system_status(self) -> Dict:
        """الحصول على حالة النظام الحالية"""
        return {
            "status": await self.get_attribute("system_status"),
            "load": await self.get_attribute("current_load"),
            "active_scans": await self.get_attribute("active_scans"),
            "vulnerabilities_found": await self.get_attribute("vulnerabilities_found"),
            "targets_analyzed": await self.get_attribute("targets_analyzed"),
            "available_memory_mb": await self.get_attribute("available_memory"),
            "available_cpu_cores": await self.get_attribute("available_cpu"),
            "network_latency_ms": await self.get_attribute("network_latency"),
            "waf_detected": await self.get_attribute("waf_detected")
        }
    
    async def increment_counter(self, name: str, delta: int = 1) -> int:
        """
        زيادة عداد
        
        Args:
            name: اسم العداد
            delta: مقدار الزيادة
        
        Returns:
            القيمة الجديدة
        """
        current = await self.get_attribute(name, 0)
        new_value = current + delta
        await self.update_attribute(name, new_value)
        return new_value
    
    async def get_statistics(self) -> Dict:
        """إحصائيات حالة العالم"""
        return {
            "total_attributes": len(self._attributes),
            "history_size": len(self._history),
            "attributes": list(self._attributes.keys()),
            "high_confidence_attributes": sum(1 for a in self._attributes.values() if a.confidence >= 0.9),
            "low_confidence_attributes": sum(1 for a in self._attributes.values() if a.confidence <= 0.5)
        }

