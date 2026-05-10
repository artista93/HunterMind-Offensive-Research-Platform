
import json
import logging
import traceback
from typing import Dict, Any, Optional, List
from datetime import datetime
from functools import wraps
import time

import logging

logger = logging.getLogger(__name__)


class DebugLogger:
    """
    مسجل التصحيح المتقدم
    
    الميزات:
    - تسجيل تفاصيل التنفيذ الداخلية
    - تتبع استدعاءات الدوال
    - قياس وقت التنفيذ
    - تسجيل الاستثناءات
    """
    
    def __init__(self, name: str, log_file: Optional[str] = None, enabled: bool = True):
        self.name = name
        self.enabled = enabled
        self.logger = logging.getLogger(f"debug.{name}")
        self.logger.setLevel(logging.DEBUG)
        
        # إضافة معالج console
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.DEBUG)
        self.logger.addHandler(console_handler)
        
        # إضافة معالج ملف إذا تم تحديده
        if log_file:
            file_handler = logging.FileHandler(log_file)
            file_handler.setLevel(logging.DEBUG)
            self.logger.addHandler(file_handler)
        
        logger.info(f"DebugLogger initialized: {name}")
    
    def debug(self, message: str, **kwargs):
        """تسجيل رسالة DEBUG"""
        if not self.enabled:
            return
        
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "logger": self.name,
            "message": message,
            "details": kwargs
        }
        self.logger.debug(json.dumps(log_entry))
    
    def info(self, message: str, **kwargs):
        """تسجيل رسالة INFO"""
        if not self.enabled:
            return
        
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "logger": self.name,
            "message": message,
            "details": kwargs
        }
        self.logger.info(json.dumps(log_entry))
    
    def warning(self, message: str, **kwargs):
        """تسجيل رسالة WARNING"""
        if not self.enabled:
            return
        
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "logger": self.name,
            "message": message,
            "details": kwargs
        }
        self.logger.warning(json.dumps(log_entry))
    
    def error(self, message: str, exc_info: bool = False, **kwargs):
        """تسجيل رسالة ERROR"""
        if not self.enabled:
            return
        
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "logger": self.name,
            "message": message,
            "details": kwargs
        }
        
        if exc_info:
            log_entry["traceback"] = traceback.format_exc()
        
        self.logger.error(json.dumps(log_entry))
    
    def trace_function(self, func):
        """ديكوراتور لتتبع استدعاءات الدوال"""
        if not self.enabled:
            return func
        
        @wraps(func)
        async def async_wrapper(*args, **kwargs):
            start_time = time.time()
            self.debug(f"Calling {func.__name__}", args=str(args)[:200], kwargs=str(kwargs)[:200])
            
            try:
                result = await func(*args, **kwargs)
                duration = (time.time() - start_time) * 1000
                self.debug(f"Completed {func.__name__}", duration_ms=f"{duration:.2f}")
                return result
            except Exception as e:
                duration = (time.time() - start_time) * 1000
                self.error(f"Failed {func.__name__}", error=str(e), duration_ms=f"{duration:.2f}", exc_info=True)
                raise
        
        @wraps(func)
        def sync_wrapper(*args, **kwargs):
            start_time = time.time()
            self.debug(f"Calling {func.__name__}", args=str(args)[:200], kwargs=str(kwargs)[:200])
            
            try:
                result = func(*args, **kwargs)
                duration = (time.time() - start_time) * 1000
                self.debug(f"Completed {func.__name__}", duration_ms=f"{duration:.2f}")
                return result
            except Exception as e:
                duration = (time.time() - start_time) * 1000
                self.error(f"Failed {func.__name__}", error=str(e), duration_ms=f"{duration:.2f}", exc_info=True)
                raise
        
        return async_wrapper if asyncio.iscoroutinefunction(func) else sync_wrapper
    
    def log_method_call(self, method_name: str, args: tuple, kwargs: dict, result: Any = None, duration_ms: float = None):
        """تسجيل استدعاء دالة"""
        self.debug(
            f"Method call: {method_name}",
            args=str(args)[:200],
            kwargs=str(kwargs)[:200],
            result=str(result)[:200] if result else None,
            duration_ms=f"{duration_ms:.2f}" if duration_ms else None
        )
    
    def log_state_change(self, component: str, old_state: str, new_state: str, **kwargs):
        """تسجيل تغيير الحالة"""
        self.info(
            f"State change: {component}",
            old_state=old_state,
            new_state=new_state,
            **kwargs
        )
    
    def log_data_flow(self, source: str, destination: str, data_size: int, data_type: str):
        """تسجيل تدفق البيانات"""
        self.debug(
            f"Data flow: {source} -> {destination}",
            data_size_bytes=data_size,
            data_type=data_type
        )
    
    def log_performance(self, operation: str, duration_ms: float, **kwargs):
        """تسجيل أداء العملية"""
        self.debug(
            f"Performance: {operation}",
            duration_ms=f"{duration_ms:.2f}",
            **kwargs
        )
    
    def set_enabled(self, enabled: bool):
        """تمكين أو تعطيل تسجيل التصحيح"""
        self.enabled = enabled
        logger.info(f"Debug logging {'enabled' if enabled else 'disabled'} for {self.name}")


# نسخة عالمية
_default_debug_loggers: Dict[str, DebugLogger] = {}


def get_debug_logger(name: str, log_file: Optional[str] = None) -> DebugLogger:
    """الحصول على مسجل تصحيح بالاسم"""
    global _default_debug_loggers
    if name not in _default_debug_loggers:
        _default_debug_loggers[name] = DebugLogger(name, log_file)
    return _default_debug_loggers[name]

