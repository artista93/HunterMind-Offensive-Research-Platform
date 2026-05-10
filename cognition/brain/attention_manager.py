
import asyncio
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from collections import defaultdict

import logging

logger = logging.getLogger(__name__)


@dataclass
class AttentionItem:
    """عنصر انتباه"""
    id: str
    name: str
    priority: int  # 1-10 (10 أعلى)
    required_resources: List[str]
    current_focus: float = 0.0
    last_updated: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)


class AttentionManager:
    """
    مدير الانتباه المتقدم
    
    الميزات:
    - توزيع الانتباه بين المهام المتعددة
    - تحديث الأولويات ديناميكياً
    - تجنب إرهاق الموارد
    - تتبع تاريخ الانتباه
    """
    
    def __init__(self, total_attention: float = 100.0):
        self._total_attention = total_attention
        self._items: Dict[str, AttentionItem] = {}
        self._attention_history: List[Dict] = []
        self._update_task: Optional[asyncio.Task] = None
        self._running = False
        
        logger.info(f"AttentionManager initialized (total_attention={total_attention})")
    
    async def start(self):
        """بدء تشغيل المدير"""
        if self._running:
            return
        
        self._running = True
        self._update_task = asyncio.create_task(self._update_loop())
        
        logger.info("AttentionManager started")
    
    async def stop(self):
        """إيقاف تشغيل المدير"""
        self._running = False
        
        if self._update_task:
            self._update_task.cancel()
            try:
                await self._update_task
            except asyncio.CancelledError:
                pass
        
        logger.info("AttentionManager stopped")
    
    async def register_item(
        self,
        item_id: str,
        name: str,
        priority: int,
        required_resources: List[str] = None
    ):
        """
        تسجيل عنصر انتباه جديد
        
        Args:
            item_id: معرف العنصر
            name: اسم العنصر
            priority: الأولوية (1-10)
            required_resources: الموارد المطلوبة
        """
        if item_id in self._items:
            logger.warning(f"Item {item_id} already registered")
            return
        
        item = AttentionItem(
            id=item_id,
            name=name,
            priority=min(max(priority, 1), 10),
            required_resources=required_resources or []
        )
        
        self._items[item_id] = item
        
        logger.info(f"Attention item registered: {name} (priority={priority})")
    
    async def update_priority(self, item_id: str, new_priority: int):
        """
        تحديث أولوية عنصر
        
        Args:
            item_id: معرف العنصر
            new_priority: الأولوية الجديدة (1-10)
        """
        if item_id not in self._items:
            logger.warning(f"Item {item_id} not found")
            return
        
        self._items[item_id].priority = min(max(new_priority, 1), 10)
        self._items[item_id].last_updated = datetime.now()
        
        logger.debug(f"Priority updated for {self._items[item_id].name}: {new_priority}")
    
    async def allocate_attention(self) -> Dict[str, float]:
        """
        توزيع الانتباه على العناصر المسجلة
        
        Returns:
            قاموس بتوزيع الانتباه
        """
        if not self._items:
            return {}
        
        # حساب الوزن لكل عنصر
        total_weight = sum(item.priority for item in self._items.values())
        
        if total_weight == 0:
            return {item_id: 0.0 for item_id in self._items}
        
        allocation = {}
        for item_id, item in self._items.items():
            # تخصيص الانتباه حسب الأولوية
            attention = (item.priority / total_weight) * self._total_attention
            item.current_focus = attention
            allocation[item_id] = attention
        
        # تسجيل التوزيع في التاريخ
        self._attention_history.append({
            "timestamp": datetime.now().isoformat(),
            "allocation": allocation.copy()
        })
        
        # الحفاظ على آخر 100 توزيع فقط
        if len(self._attention_history) > 100:
            self._attention_history.pop(0)
        
        return allocation
    
    async def get_focus(self, item_id: str) -> float:
        """
        الحصول على مستوى التركيز لعنصر معين
        
        Args:
            item_id: معرف العنصر
        
        Returns:
            مستوى التركيز (0-100)
        """
        if item_id not in self._items:
            return 0.0
        
        await self.allocate_attention()
        return self._items[item_id].current_focus
    
    async def _update_loop(self):
        """حلقة تحديث الانتباه"""
        while self._running:
            await asyncio.sleep(5)  # تحديث كل 5 ثواني
            await self.allocate_attention()
    
    async def get_statistics(self) -> Dict:
        """إحصائيات المدير"""
        if not self._items:
            return {"total_items": 0}
        
        allocation = await self.allocate_attention()
        
        return {
            "total_items": len(self._items),
            "total_attention": self._total_attention,
            "current_allocation": allocation,
            "items_by_priority": {
                item.name: item.priority
                for item in self._items.values()
            },
            "history_size": len(self._attention_history),
            "running": self._running
        }

