
import asyncio
from typing import Dict, List, Optional, Any, Callable, Pattern
import re
from dataclasses import dataclass, field
from datetime import datetime
from collections import defaultdict

import logging

logger = logging.getLogger(__name__)


@dataclass
class Message:
    """رسالة"""
    id: str
    type: str
    content: Any
    source: str
    destination: Optional[str] = None
    timestamp: datetime = field(default_factory=datetime.now)
    priority: int = 3
    headers: Dict[str, str] = field(default_factory=dict)


@dataclass
class RouteRule:
    """قاعدة توجيه"""
    id: str
    pattern: str
    destination: str
    priority: int
    active: bool = True


class MessageRouter:
    """
    موجه الرسائل المتقدم
    
    الميزات:
    - توجيه الرسائل بناءً على الأنماط
    - قواعد توجيه متعددة
    - ترتيب القواعد حسب الأولوية
    - تتبع تاريخ التوجيه
    """
    
    def __init__(self):
        self.rules: List[RouteRule] = []
        self.handlers: Dict[str, Callable] = {}
        self.routing_history: List[Dict] = []
        self._lock = asyncio.Lock()
        
        logger.info("MessageRouter initialized")
    
    def add_rule(
        self,
        pattern: str,
        destination: str,
        priority: int = 0,
        active: bool = True
    ) -> str:
        """
        إضافة قاعدة توجيه جديدة
        
        Args:
            pattern: النمط (regex)
            destination: الوجهة
            priority: الأولوية (أقل رقم أعلى أولوية)
            active: نشطة أم لا
        
        Returns:
            معرف القاعدة
        """
        import uuid
        rule_id = str(uuid.uuid4())[:8]
        
        rule = RouteRule(
            id=rule_id,
            pattern=pattern,
            destination=destination,
            priority=priority,
            active=active
        )
        
        self.rules.append(rule)
        # ترتيب القواعد حسب الأولوية
        self.rules.sort(key=lambda x: x.priority)
        
        logger.debug(f"Route rule added: {pattern} -> {destination}")
        return rule_id
    
    def remove_rule(self, rule_id: str) -> bool:
        """
        إزالة قاعدة توجيه
        
        Args:
            rule_id: معرف القاعدة
        
        Returns:
            نجاح الإزالة
        """
        for i, rule in enumerate(self.rules):
            if rule.id == rule_id:
                self.rules.pop(i)
                logger.debug(f"Route rule removed: {rule_id}")
                return True
        return False
    
    def register_handler(self, destination: str, handler: Callable):
        """
        تسجيل معالج لوجهة معينة
        
        Args:
            destination: الوجهة
            handler: دالة معالجة الرسالة
        """
        self.handlers[destination] = handler
        logger.debug(f"Handler registered for destination: {destination}")
    
    async def route(self, message: Message) -> Optional[Any]:
        """
        توجيه رسالة إلى الوجهة المناسبة
        
        Args:
            message: الرسالة
        
        Returns:
            نتيجة المعالجة
        """
        # البحث عن الوجهة المناسبة
        destination = None
        matched_rule = None
        
        for rule in self.rules:
            if not rule.active:
                continue
            
            if re.search(rule.pattern, message.type, re.I):
                destination = rule.destination
                matched_rule = rule
                break
        
        if destination is None:
            logger.warning(f"No route found for message type: {message.type}")
            return None
        
        # تسجيل التوجيه
        self.routing_history.append({
            "message_id": message.id,
            "message_type": message.type,
            "source": message.source,
            "destination": destination,
            "rule_id": matched_rule.id if matched_rule else None,
            "timestamp": datetime.now().isoformat()
        })
        
        # الحفاظ على آخر 1000 توجيه
        if len(self.routing_history) > 1000:
            self.routing_history.pop(0)
        
        # معالجة الرسالة
        if destination in self.handlers:
            handler = self.handlers[destination]
            if asyncio.iscoroutinefunction(handler):
                return await handler(message)
            else:
                return handler(message)
        
        logger.warning(f"No handler for destination: {destination}")
        return None
    
    async def route_batch(self, messages: List[Message]) -> List[Any]:
        """
        توجيه مجموعة من الرسائل بشكل متوازي
        
        Args:
            messages: قائمة الرسائل
        
        Returns:
            قائمة بنتائج المعالجة
        """
        tasks = [self.route(msg) for msg in messages]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return results
    
    async def get_routing_stats(self) -> Dict:
        """إحصائيات التوجيه"""
        if not self.routing_history:
            return {"total_routes": 0}
        
        # إحصائيات حسب الوجهة
        dest_counts = defaultdict(int)
        for entry in self.routing_history:
            dest_counts[entry["destination"]] += 1
        
        return {
            "total_routes": len(self.routing_history),
            "routes_by_destination": dict(dest_counts),
            "total_rules": len(self.rules),
            "active_rules": len([r for r in self.rules if r.active]),
            "registered_handlers": len(self.handlers)
        }

