
import asyncio
from typing import Dict, List, Optional, Any, Callable, Awaitable
from dataclasses import dataclass, field
from datetime import datetime
from collections import defaultdict

import logging

logger = logging.getLogger(__name__)


@dataclass
class Command:
    """أمر"""
    name: str
    payload: Any
    source: str
    id: str = ""
    timestamp: datetime = field(default_factory=datetime.now)
    response: Optional[Any] = None
    error: Optional[str] = None


class CommandBus:
    """
    ناقل الأوامر المتقدم
    
    الميزات:
    - تسجيل معالجات الأوامر
    - تنفيذ الأوامر غير المتزامنة
    - تتبع تاريخ الأوامر
    - مهلات زمنية للتنفيذ
    """
    
    def __init__(self, default_timeout: float = 30.0):
        self.handlers: Dict[str, Callable] = {}
        self.command_history: List[Command] = []
        self.default_timeout = default_timeout
        self._lock = asyncio.Lock()
        
        logger.info("CommandBus initialized")
    
    def register_handler(self, command_name: str, handler: Callable):
        """
        تسجيل معالج لأمر معين
        
        Args:
            command_name: اسم الأمر
            handler: دالة معالجة الأمر (async)
        """
        self.handlers[command_name] = handler
        logger.debug(f"Handler registered for command: {command_name}")
    
    async def send(
        self,
        command: Command,
        timeout: float = None
    ) -> Any:
        """
        إرسال أمر وتنفيذه
        
        Args:
            command: الأمر المرسل
            timeout: مهلة التنفيذ
        
        Returns:
            نتيجة تنفيذ الأمر
        """
        import uuid
        command.id = str(uuid.uuid4())[:8]
        
        if command.name not in self.handlers:
            command.error = f"No handler registered for command: {command.name}"
            await self._store_command(command)
            raise ValueError(command.error)
        
        handler = self.handlers[command.name]
        timeout = timeout or self.default_timeout
        
        try:
            if asyncio.iscoroutinefunction(handler):
                result = await asyncio.wait_for(
                    handler(command.payload, source=command.source),
                    timeout=timeout
                )
            else:
                result = handler(command.payload, source=command.source)
            
            command.response = result
            await self._store_command(command)
            
            logger.debug(f"Command executed: {command.name} ({command.id})")
            return result
            
        except asyncio.TimeoutError:
            command.error = f"Command timeout after {timeout}s"
            await self._store_command(command)
            raise
        except Exception as e:
            command.error = str(e)
            await self._store_command(command)
            raise
    
    async def send_many(
        self,
        commands: List[Command],
        timeout: float = None
    ) -> List[Any]:
        """
        إرسال أوامر متعددة بشكل متوازي
        
        Args:
            commands: قائمة الأوامر
            timeout: مهلة التنفيذ
        
        Returns:
            قائمة بنتائج الأوامر
        """
        tasks = [self.send(cmd, timeout) for cmd in commands]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        return results
    
    async def _store_command(self, command: Command):
        """تخزين الأمر في التاريخ"""
        async with self._lock:
            self.command_history.append(command)
            if len(self.command_history) > 1000:
                self.command_history.pop(0)
    
    async def get_history(
        self,
        command_name: str = None,
        limit: int = 100
    ) -> List[Command]:
        """
        الحصول على تاريخ الأوامر
        
        Args:
            command_name: اسم الأمر (اختياري)
            limit: عدد النتائج
        
        Returns:
            قائمة بالأوامر
        """
        async with self._lock:
            commands = self.command_history
            if command_name:
                commands = [c for c in commands if c.name == command_name]
            return commands[-limit:]
    
    async def clear_history(self):
        """مسح تاريخ الأوامر"""
        async with self._lock:
            self.command_history.clear()
            logger.info("Command history cleared")
    
    async def get_statistics(self) -> Dict:
        """إحصائيات ناقل الأوامر"""
        async with self._lock:
            total = len(self.command_history)
            successful = len([c for c in self.command_history if c.error is None])
            failed = total - successful
            
            command_counts = defaultdict(int)
            for cmd in self.command_history:
                command_counts[cmd.name] += 1
            
            return {
                "total_commands": total,
                "successful_commands": successful,
                "failed_commands": failed,
                "success_rate": successful / total if total > 0 else 0,
                "command_distribution": dict(command_counts),
                "registered_handlers": len(self.handlers),
                "default_timeout": self.default_timeout
            }

