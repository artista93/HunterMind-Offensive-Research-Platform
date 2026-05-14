"""
Base Storage - الواجهة الموحدة لجميع أنظمة التخزين
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

import logging

logger = logging.getLogger(__name__)


class StorageType(Enum):
    """أنظمة التخزين المدعومة"""
    SQLITE = "sqlite"
    VECTOR = "vector"
    GRAPH = "graph"
    OBJECT = "object"
    CHECKPOINT = "checkpoint"


class StorageStatus(Enum):
    """حالة نظام التخزين"""
    ACTIVE = "active"
    DEGRADED = "degraded"
    READONLY = "readonly"
    OFFLINE = "offline"
    ERROR = "error"


@dataclass
class StorageStats:
    """إحصائيات نظام التخزين"""
    total_items: int
    total_size_bytes: int
    status: StorageStatus
    last_accessed: datetime
    created_at: datetime
    metadata: Dict[str, Any] = field(default_factory=dict)


class BaseStorage(ABC):
    """
    الواجهة الموحدة لجميع أنظمة التخزين
    
    الميزات:
    - دوال موحدة لجميع أنواع التخزين (CRUD)
    - إدارة الاتصال
    - إحصائيات موحدة
    - فحص الصحة
    """
    
    def __init__(self, name: str, storage_type: StorageType):
        self.name = name
        self.storage_type = storage_type
        self._status = StorageStatus.ACTIVE
        self._initialized = False
        self._created_at = datetime.now()
        
        logger.info(f"Storage initialized: {name} ({storage_type.value})")
    
    @abstractmethod
    async def initialize(self) -> bool:
        """
        تهيئة نظام التخزين
        
        Returns:
            نجاح التهيئة
        """
        pass
    
    @abstractmethod
    async def save(self, key: str, data: Any, metadata: Dict = None) -> bool:
        """
        حفظ بيانات
        
        Args:
            key: مفتاح البيانات
            data: البيانات المراد حفظها
            metadata: بيانات وصفية إضافية
        
        Returns:
            نجاح الحفظ
        """
        pass
    
    @abstractmethod
    async def load(self, key: str) -> Optional[Any]:
        """
        تحميل بيانات
        
        Args:
            key: مفتاح البيانات
        
        Returns:
            البيانات أو None
        """
        pass
    
    @abstractmethod
    async def delete(self, key: str) -> bool:
        """
        حذف بيانات
        
        Args:
            key: مفتاح البيانات
        
        Returns:
            نجاح الحذف
        """
        pass
    
    @abstractmethod
    async def list_keys(self, prefix: str = None, limit: int = 100) -> List[str]:
        """
        قائمة المفاتيح
        
        Args:
            prefix: بادئة البحث (اختياري)
            limit: الحد الأقصى للنتائج
        
        Returns:
            قائمة المفاتيح
        """
        pass
    
    @abstractmethod
    async def exists(self, key: str) -> bool:
        """
        التحقق من وجود بيانات
        
        Args:
            key: مفتاح البيانات
        
        Returns:
            وجود البيانات
        """
        pass
    
    @abstractmethod
    async def search(self, query: Dict[str, Any], limit: int = 50) -> List[Any]:
        """
        بحث متقدم في البيانات
        
        Args:
            query: معايير البحث
            limit: الحد الأقصى للنتائج
        
        Returns:
            قائمة النتائج
        """
        pass
    
    @abstractmethod
    async def get_stats(self) -> StorageStats:
        """
        الحصول على إحصائيات نظام التخزين
        
        Returns:
            إحصائيات التخزين
        """
        pass
    
    @abstractmethod
    async def health_check(self) -> bool:
        """
        فحص صحة نظام التخزين
        
        Returns:
            صحة النظام
        """
        pass
    
    @abstractmethod
    async def clear(self) -> bool:
        """
        مسح جميع البيانات
        
        Returns:
            نجاح المسح
        """
        pass
    
    @abstractmethod
    async def close(self):
        """
        إغلاق نظام التخزين وتنظيف الموارد
        """
        pass
    
    async def batch_save(self, items: Dict[str, Any]) -> Dict[str, bool]:
        """
        حفظ مجموعة من البيانات دفعة واحدة
        
        Args:
            items: قاموس المفاتيح والبيانات
        
        Returns:
            نتائج الحفظ لكل مفتاح
        """
        results = {}
        for key, data in items.items():
            results[key] = await self.save(key, data)
        return results
    
    async def batch_load(self, keys: List[str]) -> Dict[str, Any]:
        """
        تحميل مجموعة من البيانات دفعة واحدة
        
        Args:
            keys: قائمة المفاتيح
        
        Returns:
            قاموس البيانات المحملة
        """
        results = {}
        for key in keys:
            data = await self.load(key)
            if data is not None:
                results[key] = data
        return results
    
    def get_status(self) -> StorageStatus:
        """الحصول على حالة نظام التخزين"""
        return self._status
    
    def set_status(self, status: StorageStatus):
        """تعيين حالة نظام التخزين"""
        self._status = status
        logger.warning(f"Storage {self.name} status changed to {status.value}")
    
    def is_initialized(self) -> bool:
        """هل النظام مهيأ؟"""
        return self._initialized
    
    def get_uptime(self) -> float:
        """مدة تشغيل النظام بالثواني"""
        return (datetime.now() - self._created_at).total_seconds()
    
    async def __aenter__(self):
        """سياق for async with"""
        await self.initialize()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """خروج من السياق"""
        await self.close()
    
    def to_dict(self) -> Dict:
        """تحويل إلى قاموس"""
        return {
            "name": self.name,
            "type": self.storage_type.value,
            "status": self._status.value,
            "initialized": self._initialized,
            "uptime": self.get_uptime(),
            "created_at": self._created_at.isoformat()
        }


# نسخة عالمية للتخزين الافتراضي
_default_storage = None


async def get_default_storage() -> Optional[BaseStorage]:
    """الحصول على نظام التخزين الافتراضي"""
    global _default_storage
    if _default_storage is None:
        # محاولة استخدام SQLite كتخزين افتراضي
        try:
            from storage.sqlite.persistence import PersistenceManager
            _default_storage = PersistenceManager()
            await _default_storage.initialize()
        except Exception as e:
            logger.error(f"Failed to initialize default storage: {e}")
            return None
    return _default_storage
