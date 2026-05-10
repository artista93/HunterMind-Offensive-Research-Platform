
import json
import logging
from typing import Dict, Any, Optional, List
from datetime import datetime
from enum import Enum
import hashlib

import logging

logger = logging.getLogger(__name__)


class AuditAction(Enum):
    """أنواع إجراءات التدقيق"""
    LOGIN = "login"
    LOGOUT = "logout"
    SCAN_START = "scan_start"
    SCAN_STOP = "scan_stop"
    ATTACK_START = "attack_start"
    ATTACK_STOP = "attack_stop"
    CONFIG_CHANGE = "config_change"
    DATA_ACCESS = "data_access"
    DATA_EXPORT = "data_export"
    USER_CREATE = "user_create"
    USER_DELETE = "user_delete"
    PERMISSION_CHANGE = "permission_change"


class AuditSeverity(Enum):
    """شدة حدث التدقيق"""
    INFO = "info"
    WARNING = "warning"
    ALERT = "alert"
    CRITICAL = "critical"


class AuditLogger:
    """
    مسجل التدقيق المتقدم
    
    الميزات:
    - تسجيل الأحداث الأمنية
    - تتبع العمليات الحساسة
    - توقيع السجلات (checksum)
    - تصدير سجل التدقيق
    """
    
    def __init__(self, log_file: str = "audit.log"):
        self.log_file = log_file
        self.audit_records: List[Dict] = []
        self._lock = asyncio.Lock()
        
        logger.info(f"AuditLogger initialized (file={log_file})")
    
    async def log(
        self,
        action: AuditAction,
        user: str,
        details: Dict,
        severity: AuditSeverity = AuditSeverity.INFO,
        ip_address: str = None,
        session_id: str = None
    ):
        """
        تسجيل حدث تدقيق
        
        Args:
            action: نوع الإجراء
            user: اسم المستخدم
            details: تفاصيل الحدث
            severity: شدة الحدث
            ip_address: عنوان IP
            session_id: معرف الجلسة
        """
        record = {
            "timestamp": datetime.now().isoformat(),
            "action": action.value,
            "user": user,
            "severity": severity.value,
            "details": details,
            "ip_address": ip_address,
            "session_id": session_id
        }
        
        # حساب checksum للتوقيع
        record_str = json.dumps(record, sort_keys=True)
        record["checksum"] = hashlib.sha256(record_str.encode()).hexdigest()[:16]
        
        async with self._lock:
            self.audit_records.append(record)
            
            # كتابة إلى الملف
            with open(self.log_file, 'a') as f:
                f.write(json.dumps(record) + '\n')
            
            # الاحتفاظ بآخر 10000 سجل فقط
            if len(self.audit_records) > 10000:
                self.audit_records = self.audit_records[-10000:]
        
        # تسجيل في logger النظام حسب الشدة
        log_message = f"[AUDIT] {action.value} by {user}: {json.dumps(details)}"
        
        if severity == AuditSeverity.CRITICAL:
            logger.critical(log_message)
        elif severity == AuditSeverity.ALERT:
            logger.warning(log_message)
        else:
            logger.info(log_message)
    
    async def log_login(self, user: str, success: bool, ip_address: str = None, details: Dict = None):
        """تسجيل محاولة تسجيل الدخول"""
        severity = AuditSeverity.ALERT if not success else AuditSeverity.INFO
        await self.log(
            action=AuditAction.LOGIN,
            user=user,
            details={
                "success": success,
                "details": details or {}
            },
            severity=severity,
            ip_address=ip_address
        )
    
    async def log_scan(self, user: str, scan_id: str, target: str, action: str, details: Dict = None):
        """تسجيل حدث فحص"""
        audit_action = AuditAction.SCAN_START if action == "start" else AuditAction.SCAN_STOP
        await self.log(
            action=audit_action,
            user=user,
            details={
                "scan_id": scan_id,
                "target": target,
                "action": action,
                "details": details or {}
            }
        )
    
    async def log_attack(self, user: str, attack_id: str, target: str, vuln_type: str, action: str):
        """تسجيل حدث هجوم"""
        audit_action = AuditAction.ATTACK_START if action == "start" else AuditAction.ATTACK_STOP
        severity = AuditSeverity.ALERT if action == "start" else AuditSeverity.INFO
        
        await self.log(
            action=audit_action,
            user=user,
            details={
                "attack_id": attack_id,
                "target": target,
                "vulnerability_type": vuln_type,
                "action": action
            },
            severity=severity
        )
    
    async def log_config_change(self, user: str, changes: Dict, old_config: Dict = None):
        """تسجيل تغيير في الإعدادات"""
        await self.log(
            action=AuditAction.CONFIG_CHANGE,
            user=user,
            details={
                "changes": changes,
                "old_config": old_config
            },
            severity=AuditSeverity.WARNING
        )
    
    async def log_data_access(self, user: str, data_type: str, data_id: str, access_type: str):
        """تسجيل الوصول إلى البيانات"""
        await self.log(
            action=AuditAction.DATA_ACCESS,
            user=user,
            details={
                "data_type": data_type,
                "data_id": data_id,
                "access_type": access_type
            }
        )
    
    async def get_audit_trail(
        self,
        user: str = None,
        action: AuditAction = None,
        severity: AuditSeverity = None,
        start_time: datetime = None,
        end_time: datetime = None,
        limit: int = 100
    ) -> List[Dict]:
        """
        الحصول على سجل التدقيق
        
        Args:
            user: تصفية حسب المستخدم
            action: تصفية حسب الإجراء
            severity: تصفية حسب الشدة
            start_time: وقت البدء
            end_time: وقت النهاية
            limit: عدد النتائج
        
        Returns:
            قائمة بسجلات التدقيق
        """
        async with self._lock:
            records = self.audit_records
        
        # تطبيق التصفية
        if user:
            records = [r for r in records if r.get("user") == user]
        
        if action:
            records = [r for r in records if r.get("action") == action.value]
        
        if severity:
            records = [r for r in records if r.get("severity") == severity.value]
        
        if start_time:
            records = [r for r in records if datetime.fromisoformat(r["timestamp"]) >= start_time]
        
        if end_time:
            records = [r for r in records if datetime.fromisoformat(r["timestamp"]) <= end_time]
        
        return records[-limit:]
    
    async def verify_checksums(self) -> List[Dict]:
        """التحقق من سلامة سجلات التدقيق"""
        tampered = []
        
        async with self._lock:
            for record in self.audit_records:
                if "checksum" not in record:
                    tampered.append(record)
                    continue
                
                # إعادة حساب checksum
                record_copy = record.copy()
                record_copy.pop("checksum", None)
                record_str = json.dumps(record_copy, sort_keys=True)
                expected_checksum = hashlib.sha256(record_str.encode()).hexdigest()[:16]
                
                if record["checksum"] != expected_checksum:
                    tampered.append(record)
        
        if tampered:
            logger.warning(f"Found {len(tampered)} tampered audit records")
        
        return tampered
    
    async def export_audit(self, output_file: str, format: str = "json"):
        """تصدير سجل التدقيق إلى ملف"""
        async with self._lock:
            records = self.audit_records
        
        if format == "json":
            with open(output_file, 'w') as f:
                json.dump(records, f, indent=2)
        elif format == "csv":
            import csv
            with open(output_file, 'w', newline='') as f:
                if records:
                    writer = csv.DictWriter(f, fieldnames=records[0].keys())
                    writer.writeheader()
                    writer.writerows(records)
        
        logger.info(f"Audit log exported to {output_file} ({format})")
    
    async def get_statistics(self) -> Dict:
        """إحصائيات سجل التدقيق"""
        async with self._lock:
            total = len(self.audit_records)
            
            # إحصائيات حسب الإجراء
            by_action = {}
            for record in self.audit_records:
                action = record.get("action", "unknown")
                by_action[action] = by_action.get(action, 0) + 1
            
            # إحصائيات حسب الشدة
            by_severity = {}
            for record in self.audit_records:
                severity = record.get("severity", "info")
                by_severity[severity] = by_severity.get(severity, 0) + 1
            
            return {
                "total_records": total,
                "by_action": by_action,
                "by_severity": by_severity,
                "tampered_records": len(await self.verify_checksums())
            }


# نسخة عالمية
_default_audit_logger = None


async def get_audit_logger() -> AuditLogger:
    """الحصول على نسخة عالمية من مسجل التدقيق"""
    global _default_audit_logger
    if _default_audit_logger is None:
        _default_audit_logger = AuditLogger()
    return _default_audit_logger

