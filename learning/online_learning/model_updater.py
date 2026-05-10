
import asyncio
import numpy as np
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from collections import deque

import logging

logger = logging.getLogger(__name__)


@dataclass
class ModelVersion:
    """إصدار نموذج"""
    version: int
    timestamp: datetime
    metrics: Dict[str, float]
    filepath: str


class ModelUpdater:
    """
    محدث النماذج المتقدم
    
    الميزات:
    - تحديث النماذج في الخلفية
    - تتبع إصدارات النماذج
    - التراجع إلى الإصدارات السابقة
    - اختبار النماذج الجديدة قبل النشر
    """
    
    def __init__(self, update_interval: int = 3600, validation_split: float = 0.2):
        self.update_interval = update_interval
        self.validation_split = validation_split
        self.models: Dict[str, List[ModelVersion]] = {}
        self.current_versions: Dict[str, int] = {}
        self.update_task: Optional[asyncio.Task] = None
        self.running = False
        
        logger.info(f"ModelUpdater initialized (interval={update_interval}s)")
    
    async def start(self):
        """بدء عملية التحديث الدورية"""
        if self.running:
            return
        
        self.running = True
        self.update_task = asyncio.create_task(self._update_loop())
        logger.info("ModelUpdater started")
    
    async def stop(self):
        """إيقاف عملية التحديث"""
        self.running = False
        
        if self.update_task:
            self.update_task.cancel()
            try:
                await self.update_task
            except asyncio.CancelledError:
                pass
        
        logger.info("ModelUpdater stopped")
    
    async def register_model(self, model_name: str, model, metrics: Dict[str, float]):
        """
        تسجيل نموذج جديد
        
        Args:
            model_name: اسم النموذج
            model: كائن النموذج
            metrics: مقاييس الأداء
        """
        if model_name not in self.models:
            self.models[model_name] = []
        
        version = len(self.models[model_name]) + 1
        timestamp = datetime.now()
        filepath = f"models/{model_name}_v{version}.h5"
        
        # حفظ النموذج
        await self._save_model(model, filepath)
        
        model_version = ModelVersion(
            version=version,
            timestamp=timestamp,
            metrics=metrics,
            filepath=filepath
        )
        
        self.models[model_name].append(model_version)
        
        # تحديث الإصدار الحالي
        self.current_versions[model_name] = version
        
        logger.info(f"Model registered: {model_name} v{version}")
    
    async def update_model(self, model_name: str, new_model, new_metrics: Dict[str, float]) -> bool:
        """
        تحديث نموذج إلى إصدار جديد
        
        Args:
            model_name: اسم النموذج
            new_model: النموذج الجديد
            new_metrics: مقاييس النموذج الجديد
        
        Returns:
            نجاح التحديث
        """
        if model_name not in self.models:
            return False
        
        # التحقق من أن النموذج الجديد أفضل
        current_version = self.current_versions.get(model_name, 0)
        if current_version > 0:
            current = self.models[model_name][current_version - 1]
            
            # مقارنة المقاييس
            if new_metrics.get("accuracy", 0) <= current.metrics.get("accuracy", 0):
                logger.warning(f"New model not better than current, skipping update")
                return False
        
        # تسجيل النموذج الجديد
        await self.register_model(model_name, new_model, new_metrics)
        
        logger.info(f"Model updated: {model_name} v{self.current_versions[model_name]}")
        return True
    
    async def rollback(self, model_name: str) -> bool:
        """
        التراجع إلى الإصدار السابق
        
        Args:
            model_name: اسم النموذج
        
        Returns:
            نجاح التراجع
        """
        if model_name not in self.models:
            return False
        
        current = self.current_versions.get(model_name, 0)
        if current <= 1:
            logger.warning(f"Cannot rollback {model_name}: no previous version")
            return False
        
        # تقليل الإصدار الحالي
        self.current_versions[model_name] = current - 1
        
        logger.info(f"Rolled back {model_name} to v{current - 1}")
        return True
    
    async def get_current_model(self, model_name: str):
        """
        الحصول على النموذج الحالي
        
        Args:
            model_name: اسم النموذج
        """
        if model_name not in self.models:
            return None
        
        current_version = self.current_versions.get(model_name, 0)
        if current_version == 0:
            return None
        
        model_version = self.models[model_name][current_version - 1]
        return await self._load_model(model_version.filepath)
    
    async def _save_model(self, model, filepath: str):
        """حفظ النموذج إلى ملف"""
        try:
            model.save(filepath)
            logger.debug(f"Model saved to {filepath}")
        except Exception as e:
            logger.error(f"Failed to save model: {e}")
    
    async def _load_model(self, filepath: str):
        """تحميل النموذج من ملف"""
        try:
            import tensorflow as tf
            model = tf.keras.models.load_model(filepath)
            logger.debug(f"Model loaded from {filepath}")
            return model
        except Exception as e:
            logger.error(f"Failed to load model: {e}")
            return None
    
    async def _update_loop(self):
        """حلقة التحديث الدورية"""
        while self.running:
            await asyncio.sleep(self.update_interval)
            await self._check_for_updates()
    
    async def _check_for_updates(self):
        """التحقق من وجود تحديثات متاحة"""
        # في الإصدار الكامل، سيتم التحقق من وجود نماذج جديدة
        logger.debug("Checking for model updates...")
    
    async def get_model_versions(self, model_name: str) -> List[Dict]:
        """الحصول على إصدارات النموذج"""
        if model_name not in self.models:
            return []
        
        return [
            {
                "version": v.version,
                "timestamp": v.timestamp.isoformat(),
                "metrics": v.metrics,
                "current": v.version == self.current_versions.get(model_name, 0)
            }
            for v in self.models[model_name]
        ]
    
    async def get_statistics(self) -> Dict:
        """إحصائيات المحدث"""
        return {
            "total_models": len(self.models),
            "total_versions": sum(len(v) for v in self.models.values()),
            "current_versions": self.current_versions,
            "running": self.running,
            "update_interval": self.update_interval
        }

