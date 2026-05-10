
import re
import json
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

import logging

logger = logging.getLogger(__name__)


class BlockReason(Enum):
    """سبب الحظر"""
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    PATH_TRAVERSAL = "path_traversal"
    COMMAND_INJECTION = "command_injection"
    USER_AGENT = "user_agent"
    RATE_LIMIT = "rate_limit"
    GENERAL = "general"
    UNKNOWN = "unknown"


class BlockSeverity(Enum):
    """شدة الحظر"""
    TEMPORARY = "temporary"
    PERMANENT = "permanent"
    CHALLENGE = "challenge"
    CAPTCHA = "captcha"
    UNKNOWN = "unknown"


@dataclass
class WAFResponse:
    """تحليل استجابة WAF"""
    is_blocked: bool
    block_reason: BlockReason
    severity: BlockSeverity
    confidence: float
    evidence: List[str]
    waf_type: Optional[str] = None
    analyzed_at: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)


class ResponseClassifier:
    """
    مصنف استجابات WAF المتقدم
    
    الميزات:
    - كشف ما إذا كان الطلب محظوراً
    - تحديد سبب الحظر
    - تحديد شدة الحظر
    - تحليل رموز الحالة
    - تحليل رسائل الخطأ
    - كشف صفحات التحدي
    """
    
    # أنماط كشف الحظر
    BLOCK_PATTERNS = {
        BlockReason.SQL_INJECTION: [
            r"SQL syntax",
            r"mysql_fetch",
            r"Invalid query",
            r"SQL injection detected",
            r"SQLi",
            r"mysql error",
            r"postgresql error",
            r"sqlite error",
        ],
        BlockReason.XSS: [
            r"XSS detected",
            r"cross-site scripting",
            r"script injection",
            r"<script> blocked",
            r"XSS attempt",
        ],
        BlockReason.PATH_TRAVERSAL: [
            r"path traversal",
            r"directory traversal",
            r"\.\./ blocked",
            r"LFI detected",
            r"file inclusion",
        ],
        BlockReason.COMMAND_INJECTION: [
            r"command injection",
            r"RCE detected",
            r"system call blocked",
            r"eval detected",
            r"code injection",
        ],
        BlockReason.USER_AGENT: [
            r"User-Agent blocked",
            r"invalid user agent",
            r"bot detected",
        ],
        BlockReason.RATE_LIMIT: [
            r"rate limit",
            r"too many requests",
            r"429",
            r"slow down",
            r"try again later",
        ],
    }
    
    # أنماط كشف شدة الحظر
    SEVERITY_PATTERNS = {
        BlockSeverity.TEMPORARY: [
            r"try again later",
            r"temporarily blocked",
            r"please try again",
            r"retry after",
        ],
        BlockSeverity.PERMANENT: [
            r"permanently blocked",
            r"access denied",
            r"forbidden",
            r"not authorized",
        ],
        BlockSeverity.CHALLENGE: [
            r"challenge",
            r"verify",
            r"captcha",
            r"complete the security check",
            r"checking your browser",
        ],
        BlockSeverity.CAPTCHA: [
            r"captcha",
            r"recaptcha",
            r"i'm not a robot",
            r"verify you are human",
        ],
    }
    
    # أنماط كشف نوع WAF من الاستجابة
    WAF_TYPE_PATTERNS = {
        "Cloudflare": [
            r"cloudflare", r"cf-ray", r"cdn-cgi", r"__cfduid",
            r"Checking your browser", r"Please stand by"
        ],
        "AWS WAF": [
            r"awswaf", r"x-amzn-RequestId", r"AWS WAF"
        ],
        "ModSecurity": [
            r"ModSecurity", r"OWASP", r"Request rejected"
        ],
        "Imperva": [
            r"Incapsula", r"Imperva", r"visid_incap"
        ],
        "Sucuri": [
            r"Sucuri", r"CloudProxy", r"x-sucuri"
        ],
        "Akamai": [
            r"Akamai", r"EdgeControl", r"ak_bmsc"
        ]
    }
    
    def __init__(self):
        self._classifications: List[WAFResponse] = []
        
        logger.info("ResponseClassifier initialized")
    
    async def classify(
        self,
        status_code: int,
        response_text: str,
        headers: Dict[str, str],
        elapsed_time: float = 0.0
    ) -> WAFResponse:
        """
        تصنيف استجابة WAF
        
        Args:
            status_code: كود الحالة
            response_text: نص الاستجابة
            headers: هيدرات الاستجابة
            elapsed_time: وقت الاستجابة
        
        Returns:
            تحليل استجابة WAF
        """
        is_blocked = await self._is_blocked(status_code, response_text)
        
        if not is_blocked:
            return WAFResponse(
                is_blocked=False,
                block_reason=BlockReason.UNKNOWN,
                severity=BlockSeverity.UNKNOWN,
                confidence=1.0,
                evidence=["Request succeeded"]
            )
        
        # تحديد سبب الحظر
        block_reason, reason_evidence = await self._determine_block_reason(response_text)
        
        # تحديد شدة الحظر
        severity, severity_evidence = await self._determine_severity(
            status_code, response_text
        )
        
        # تحديد نوع WAF
        waf_type, waf_evidence = await self._detect_waf_type(response_text, headers)
        
        # حساب الثقة
        confidence = await self._calculate_confidence(
            is_blocked, block_reason, severity, waf_type
        )
        
        result = WAFResponse(
            is_blocked=is_blocked,
            block_reason=block_reason,
            severity=severity,
            confidence=confidence,
            evidence=reason_evidence + severity_evidence + waf_evidence,
            waf_type=waf_type
        )
        
        self._classifications.append(result)
        
        logger.info(f"Response classified: blocked={is_blocked}, reason={block_reason.value}, waf={waf_type}")
        
        return result
    
    async def _is_blocked(self, status_code: int, response_text: str) -> bool:
        """
        التحقق مما إذا كان الطلب محظوراً
        
        Args:
            status_code: كود الحالة
            response_text: نص الاستجابة
        
        Returns:
            True إذا كان محظوراً
        """
        # رموز الحالة الشائعة للحظر
        if status_code in [403, 406, 429, 503]:
            return True
        
        # فحص النص بحثاً عن أنماط الحظر
        response_lower = response_text.lower()
        
        block_indicators = [
            "blocked", "denied", "forbidden", "rejected",
            "security check", "attack detected", "suspicious",
            "bot detected", "access denied", "request rejected"
        ]
        
        for indicator in block_indicators:
            if indicator in response_lower:
                return True
        
        return False
    
    async def _determine_block_reason(
        self,
        response_text: str
    ) -> Tuple[BlockReason, List[str]]:
        """
        تحديد سبب الحظر
        
        Args:
            response_text: نص الاستجابة
        
        Returns:
            (سبب الحظر, الأدلة)
        """
        response_lower = response_text.lower()
        evidence = []
        
        for reason, patterns in self.BLOCK_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, response_lower, re.I):
                    evidence.append(f"Pattern matched: {pattern}")
                    return reason, evidence
        
        return BlockReason.GENERAL, ["No specific pattern matched"]
    
    async def _determine_severity(
        self,
        status_code: int,
        response_text: str
    ) -> Tuple[BlockSeverity, List[str]]:
        """
        تحديد شدة الحظر
        
        Args:
            status_code: كود الحالة
            response_text: نص الاستجابة
        
        Returns:
            (شدة الحظر, الأدلة)
        """
        response_lower = response_text.lower()
        evidence = []
        
        # رموز الحالة المؤقتة
        if status_code == 429:
            return BlockSeverity.TEMPORARY, ["Rate limit exceeded (429)"]
        
        # رموز الحالة الدائمة
        if status_code == 403:
            return BlockSeverity.PERMANENT, ["Forbidden (403)"]
        
        # فحص الأنماط النصية
        for severity, patterns in self.SEVERITY_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, response_lower, re.I):
                    evidence.append(f"Pattern matched: {pattern}")
                    return severity, evidence
        
        return BlockSeverity.UNKNOWN, ["Unknown severity"]
    
    async def _detect_waf_type(
        self,
        response_text: str,
        headers: Dict[str, str]
    ) -> Tuple[Optional[str], List[str]]:
        """
        تحديد نوع WAF
        
        Args:
            response_text: نص الاستجابة
            headers: هيدرات الاستجابة
        
        Returns:
            (نوع WAF, الأدلة)
        """
        evidence = []
        combined_text = response_text.lower() + " " + str(headers).lower()
        
        for waf_name, patterns in self.WAF_TYPE_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, combined_text, re.I):
                    evidence.append(f"Pattern matched: {pattern}")
                    return waf_name, evidence
        
        return None, ["No WAF type detected"]
    
    async def _calculate_confidence(
        self,
        is_blocked: bool,
        block_reason: BlockReason,
        severity: BlockSeverity,
        waf_type: Optional[str]
    ) -> float:
        """
        حساب مستوى الثقة في التصنيف
        
        Args:
            is_blocked: هل الطلب محظور؟
            block_reason: سبب الحظر
            severity: شدة الحظر
            waf_type: نوع WAF
        
        Returns:
            مستوى الثقة (0-1)
        """
        if not is_blocked:
            return 1.0
        
        confidence = 0.5
        
        if block_reason != BlockReason.UNKNOWN:
            confidence += 0.2
        
        if severity != BlockSeverity.UNKNOWN:
            confidence += 0.1
        
        if waf_type:
            confidence += 0.2
        
        return min(confidence, 1.0)
    
    async def get_recent_classifications(self, limit: int = 50) -> List[Dict]:
        """الحصول على التصنيفات الأخيرة"""
        return [
            {
                "is_blocked": c.is_blocked,
                "block_reason": c.block_reason.value,
                "severity": c.severity.value,
                "confidence": c.confidence,
                "waf_type": c.waf_type,
                "evidence": c.evidence,
                "analyzed_at": c.analyzed_at.isoformat()
            }
            for c in self._classifications[-limit:]
        ]
    
    async def get_statistics(self) -> Dict:
        """إحصائيات المصنف"""
        if not self._classifications:
            return {"total_classifications": 0}
        
        blocked_count = sum(1 for c in self._classifications if c.is_blocked)
        reason_counts = {}
        severity_counts = {}
        waf_counts = {}
        
        for c in self._classifications:
            if c.is_blocked:
                reason_counts[c.block_reason.value] = reason_counts.get(c.block_reason.value, 0) + 1
                severity_counts[c.severity.value] = severity_counts.get(c.severity.value, 0) + 1
                if c.waf_type:
                    waf_counts[c.waf_type] = waf_counts.get(c.waf_type, 0) + 1
        
        return {
            "total_classifications": len(self._classifications),
            "blocked_count": blocked_count,
            "block_rate": blocked_count / len(self._classifications),
            "block_reasons": reason_counts,
            "severity_distribution": severity_counts,
            "waf_distribution": waf_counts,
            "average_confidence": sum(c.confidence for c in self._classifications) / len(self._classifications)
        }
    
    async def clear_classifications(self):
        """مسح التصنيفات"""
        self._classifications.clear()
        logger.info("Response classifications cleared")

