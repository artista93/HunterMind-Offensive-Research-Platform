
import json
import logging
import sys
from typing import Dict, Any, Optional
from datetime import datetime
from enum import Enum

import logging

# إعداد الـ logger الأساسي
logger = logging.getLogger(__name__)


class LogLevel(Enum):
    """مستويات التسجيل"""
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class StructuredLogger:
    """
    المسجل المنظم المتقدم
    
    الميزات:
    - تسجيل الأحداث بتنسيق JSON
    - دعم المستويات المختلفة
    - إضافة سياق تلقائي
    - تصدير إلى ملفات
    """
    
    def __init__(self, name: str, log_file: Optional[str] = None):
        self.name = name
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.DEBUG)
        
        # إضافة معالج console
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.DEBUG)
        self.logger.addHandler(console_handler)
        
        # إضافة معالج ملف إذا تم تحديده
        if log_file:
            file_handler = logging.FileHandler(log_file)
            file_handler.setLevel(logging.DEBUG)
            self.logger.addHandler(file_handler)
        
        self.context: Dict[str, Any] = {}
        
        logger.info(f"StructuredLogger initialized: {name}")
    
    def set_context(self, **kwargs):
        """تعيين سياق ثابت للتسجيل"""
        self.context.update(kwargs)
    
    def clear_context(self):
        """مسح السياق"""
        self.context.clear()
    
    def _format_message(self, message: str, level: LogLevel, extra: Dict = None) -> str:
        """تنسيق الرسالة بتنسيق JSON"""
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "logger": self.name,
            "level": level.value,
            "message": message,
            "context": self.context.copy()
        }
        
        if extra:
            log_entry["extra"] = extra
        
        return json.dumps(log_entry)
    
    def debug(self, message: str, extra: Dict = None):
        """تسجيل رسالة DEBUG"""
        formatted = self._format_message(message, LogLevel.DEBUG, extra)
        self.logger.debug(formatted)
    
    def info(self, message: str, extra: Dict = None):
        """تسجيل رسالة INFO"""
        formatted = self._format_message(message, LogLevel.INFO, extra)
        self.logger.info(formatted)
    
    def warning(self, message: str, extra: Dict = None):
        """تسجيل رسالة WARNING"""
        formatted = self._format_message(message, LogLevel.WARNING, extra)
        self.logger.warning(formatted)
    
    def error(self, message: str, extra: Dict = None):
        """تسجيل رسالة ERROR"""
        formatted = self._format_message(message, LogLevel.ERROR, extra)
        self.logger.error(formatted)
    
    def critical(self, message: str, extra: Dict = None):
        """تسجيل رسالة CRITICAL"""
        formatted = self._format_message(message, LogLevel.CRITICAL, extra)
        self.logger.critical(formatted)
    
    def log_event(self, event_type: str, data: Dict, level: LogLevel = LogLevel.INFO):
        """تسجيل حدث منظم"""
        extra = {
            "event_type": event_type,
            "event_data": data
        }
        
        if level == LogLevel.DEBUG:
            self.debug(f"Event: {event_type}", extra)
        elif level == LogLevel.INFO:
            self.info(f"Event: {event_type}", extra)
        elif level == LogLevel.WARNING:
            self.warning(f"Event: {event_type}", extra)
        elif level == LogLevel.ERROR:
            self.error(f"Event: {event_type}", extra)
        else:
            self.critical(f"Event: {event_type}", extra)
    
    def log_scan_start(self, scan_id: str, target: str, options: Dict):
        """تسجيل بدء الفحص"""
        self.log_event("scan_start", {
            "scan_id": scan_id,
            "target": target,
            "options": options
        })
    
    def log_scan_complete(self, scan_id: str, findings_count: int, duration: float):
        """تسجيل اكتمال الفحص"""
        self.log_event("scan_complete", {
            "scan_id": scan_id,
            "findings_count": findings_count,
            "duration_seconds": duration
        })
    
    def log_attack_start(self, attack_id: str, target: str, vuln_type: str):
        """تسجيل بدء الهجوم"""
        self.log_event("attack_start", {
            "attack_id": attack_id,
            "target": target,
            "vulnerability_type": vuln_type
        })
    
    def log_attack_result(self, attack_id: str, success: bool, output: str = ""):
        """تسجيل نتيجة الهجوم"""
        self.log_event("attack_result", {
            "attack_id": attack_id,
            "success": success,
            "output": output[:500] if output else ""
        })
    
    def log_vulnerability(self, vulnerability: Dict):
        """تسجيل ثغرة مكتشفة"""
        self.log_event("vulnerability_found", vulnerability, LogLevel.WARNING)
    
    def log_error(self, error_type: str, error_message: str, context: Dict = None):
        """تسجيل خطأ"""
        self.log_event("error", {
            "error_type": error_type,
            "error_message": error_message,
            "context": context or {}
        }, LogLevel.ERROR)
    
    def log_performance(self, component: str, metric: str, value: float):
        """تسجيل مقياس أداء"""
        self.log_event("performance", {
            "component": component,
            "metric": metric,
            "value": value
        }, LogLevel.DEBUG)


# نسخة عالمية
_default_loggers: Dict[str, StructuredLogger] = {}


def get_structured_logger(name: str, log_file: Optional[str] = None) -> StructuredLogger:
    """الحصول على مسجل منظم بالاسم"""
    global _default_loggers
    if name not in _default_loggers:
        _default_loggers[name] = StructuredLogger(name, log_file)
    return _default_loggers[name]

