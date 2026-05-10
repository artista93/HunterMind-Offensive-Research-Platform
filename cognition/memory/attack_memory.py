
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from collections import defaultdict

import logging

logger = logging.getLogger(__name__)


@dataclass
class AttackRecord:
    """سجل هجوم"""
    id: str
    target_type: str
    vulnerability_type: str
    payload_used: str
    success: bool
    response_time: float
    timestamp: datetime = field(default_factory=datetime.now)
    waf_bypassed: bool = False
    data_extracted: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AttackPattern:
    """نمط هجوم"""
    name: str
    vulnerability_type: str
    common_payloads: List[str]
    success_rate: float
    last_used: Optional[datetime] = None
    tags: List[str] = field(default_factory=list)


class AttackMemory:
    """
    ذاكرة الهجمات المتقدمة
    
    الميزات:
    - تخزين سجلات الهجمات السابقة
    - تحليل أنماط الهجمات الناجحة
    - اقتراح هجمات مشابهة
    - تتبع فعالية الحمولات
    """
    
    def __init__(self, max_records: int = 1000):
        self._records: List[AttackRecord] = []
        self._patterns: Dict[str, AttackPattern] = {}
        self._max_records = max_records
        
        # تهيئة أنماط هجوم افتراضية
        self._init_default_patterns()
        
        logger.info(f"AttackMemory initialized (max_records={max_records})")
    
    def _init_default_patterns(self):
        """تهيئة أنماط الهجوم الافتراضية"""
        
        self._patterns["xss_reflected"] = AttackPattern(
            name="Reflected XSS",
            vulnerability_type="XSS",
            common_payloads=[
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert(1)>",
                "\"><script>alert(1)</script>"
            ],
            success_rate=0.75,
            tags=["xss", "reflected", "client-side"]
        )
        
        self._patterns["xss_stored"] = AttackPattern(
            name="Stored XSS",
            vulnerability_type="XSS",
            common_payloads=[
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert(1)>",
                "{{constructor.constructor('alert(1)')()}}"
            ],
            success_rate=0.65,
            tags=["xss", "stored", "persistent"]
        )
        
        self._patterns["sqli_boolean"] = AttackPattern(
            name="Boolean-based SQLi",
            vulnerability_type="SQL Injection",
            common_payloads=[
                "' OR '1'='1",
                "1' AND '1'='1",
                "' OR 1=1--"
            ],
            success_rate=0.85,
            tags=["sqli", "boolean", "blind"]
        )
        
        self._patterns["sqli_union"] = AttackPattern(
            name="Union-based SQLi",
            vulnerability_type="SQL Injection",
            common_payloads=[
                "' UNION SELECT NULL--",
                "' UNION SELECT NULL,NULL--",
                "1' UNION SELECT version()--"
            ],
            success_rate=0.8,
            tags=["sqli", "union", "in-band"]
        )
        
        self._patterns["rce_cmd"] = AttackPattern(
            name="Command Injection",
            vulnerability_type="RCE",
            common_payloads=[
                "; id",
                "| whoami",
                "&& cat /etc/passwd"
            ],
            success_rate=0.7,
            tags=["rce", "command", "system"]
        )
    
    async def add_record(
        self,
        target_type: str,
        vulnerability_type: str,
        payload_used: str,
        success: bool,
        response_time: float,
        waf_bypassed: bool = False,
        data_extracted: str = None,
        metadata: Dict = None
    ) -> str:
        """
        إضافة سجل هجوم جديد
        
        Args:
            target_type: نوع الهدف
            vulnerability_type: نوع الثغرة
            payload_used: الحمولة المستخدمة
            success: نجاح الهجوم
            response_time: وقت الاستجابة
            waf_bypassed: هل تم تجاوز WAF؟
            data_extracted: البيانات المستخرجة
            metadata: بيانات إضافية
        
        Returns:
            معرف السجل
        """
        import uuid
        record_id = str(uuid.uuid4())[:8]
        
        record = AttackRecord(
            id=record_id,
            target_type=target_type,
            vulnerability_type=vulnerability_type,
            payload_used=payload_used,
            success=success,
            response_time=response_time,
            waf_bypassed=waf_bypassed,
            data_extracted=data_extracted,
            metadata=metadata or {}
        )
        
        self._records.append(record)
        
        # تحديث أنماط الهجوم
        await self._update_patterns(record)
        
        # تنظيف السجلات القديمة
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records:]
        
        logger.debug(f"Attack record added: {vulnerability_type} ({record_id})")
        return record_id
    
    async def _update_patterns(self, record: AttackRecord):
        """تحديث أنماط الهجوم بناءً على السجل الجديد"""
        for pattern in self._patterns.values():
            if pattern.vulnerability_type == record.vulnerability_type:
                # تحديث معدل النجاح
                total = 0
                successes = 0
                
                # حساب معدل النجاح من السجلات السابقة
                for r in self._records:
                    if r.vulnerability_type == pattern.vulnerability_type:
                        total += 1
                        if r.success:
                            successes += 1
                
                if total > 0:
                    pattern.success_rate = successes / total
                
                # تحديث آخر استخدام
                if record.success:
                    pattern.last_used = record.timestamp
                
                # إضافة حمولة جديدة إذا كانت ناجحة
                if record.success and record.payload_used not in pattern.common_payloads:
                    pattern.common_payloads.insert(0, record.payload_used)
                    # الاحتفاظ بأحدث 10 حمولات فقط
                    pattern.common_payloads = pattern.common_payloads[:10]
    
    async def get_successful_attacks(
        self,
        vulnerability_type: str = None,
        limit: int = 50
    ) -> List[AttackRecord]:
        """
        الحصول على الهجمات الناجحة
        
        Args:
            vulnerability_type: نوع الثغرة (اختياري)
            limit: عدد النتائج
        
        Returns:
            قائمة بسجلات الهجمات الناجحة
        """
        successful = [r for r in self._records if r.success]
        
        if vulnerability_type:
            successful = [r for r in successful if r.vulnerability_type == vulnerability_type]
        
        # ترتيب حسب التاريخ (الأحدث أولاً)
        successful.sort(key=lambda x: x.timestamp, reverse=True)
        
        return successful[:limit]
    
    async def get_best_payloads(
        self,
        vulnerability_type: str,
        limit: int = 5
    ) -> List[Tuple[str, float]]:
        """
        الحصول على أفضل الحمولات لنوع ثغرة معين
        
        Args:
            vulnerability_type: نوع الثغرة
            limit: عدد النتائج
        
        Returns:
            قائمة (الحمولة, معدل النجاح)
        """
        payload_stats = defaultdict(lambda: {"total": 0, "success": 0})
        
        for record in self._records:
            if record.vulnerability_type == vulnerability_type:
                payload_stats[record.payload_used]["total"] += 1
                if record.success:
                    payload_stats[record.payload_used]["success"] += 1
        
        # حساب معدل النجاح
        payload_rates = []
        for payload, stats in payload_stats.items():
            rate = stats["success"] / stats["total"] if stats["total"] > 0 else 0
            payload_rates.append((payload, rate))
        
        payload_rates.sort(key=lambda x: x[1], reverse=True)
        
        return payload_rates[:limit]
    
    async def suggest_attack(
        self,
        vulnerability_type: str,
        has_waf: bool = False
    ) -> Optional[AttackPattern]:
        """
        اقتراح هجوم مناسب
        
        Args:
            vulnerability_type: نوع الثغرة
            has_waf: وجود WAF
        
        Returns:
            نمط الهجوم المقترح
        """
        candidates = [
            p for p in self._patterns.values()
            if p.vulnerability_type == vulnerability_type
        ]
        
        if not candidates:
            return None
        
        # ترتيب حسب معدل النجاح
        candidates.sort(key=lambda x: x.success_rate, reverse=True)
        
        # إذا كان هناك WAF، إعطاء أولوية لحمولات مختلفة
        if has_waf:
            candidates = [
                p for p in candidates
                if any("encoded" in tag or "bypass" in tag for tag in p.tags)
            ] or candidates
        
        return candidates[0]
    
    async def get_patterns(self) -> List[AttackPattern]:
        """الحصول على جميع أنماط الهجوم"""
        return list(self._patterns.values())
    
    async def add_pattern(self, pattern: AttackPattern):
        """إضافة نمط هجوم جديد"""
        self._patterns[pattern.name] = pattern
        logger.info(f"Attack pattern added: {pattern.name}")
    
    async def get_statistics(self) -> Dict:
        """إحصائيات ذاكرة الهجمات"""
        total_attacks = len(self._records)
        successful = sum(1 for r in self._records if r.success)
        
        # إحصائيات حسب نوع الثغرة
        by_vulnerability = defaultdict(lambda: {"total": 0, "success": 0})
        for record in self._records:
            by_vulnerability[record.vulnerability_type]["total"] += 1
            if record.success:
                by_vulnerability[record.vulnerability_type]["success"] += 1
        
        # إحصائيات حسب نوع الهدف
        by_target = defaultdict(lambda: {"total": 0, "success": 0})
        for record in self._records:
            by_target[record.target_type]["total"] += 1
            if record.success:
                by_target[record.target_type]["success"] += 1
        
        return {
            "total_attacks": total_attacks,
            "successful_attacks": successful,
            "success_rate": successful / total_attacks if total_attacks > 0 else 0,
            "by_vulnerability": dict(by_vulnerability),
            "by_target": dict(by_target),
            "total_patterns": len(self._patterns),
            "max_records": self._max_records
        }

