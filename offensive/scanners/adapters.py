"""
Scanner Adapters - محولات بين مخرجات الـ Scanners و Schemas المنصة

يحول Finding (من scanners) → Vulnerability (للـ schemas)
ويوحد الـ enums المختلفة بين الطبقتين
"""

from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from datetime import datetime

# من الـ scanners
from offensive.scanners.base_scanner import (
    Finding, Severity as ScannerSeverity, 
    Confidence as ScannerConfidence, ScanContext
)

# من الـ schemas
from schemas.vulnerability import (
    Vulnerability, VulnerabilityType, Severity as SchemaSeverity,
    VerificationStatus, ExploitationStatus,
    VulnerabilityEvidence, HttpRequest, HttpResponse,
    generate_vulnerability_id
)
from schemas.payload import (
    Payload, PayloadType, PayloadContext, PayloadStatus, BypassLevel,
    create_xss_payload, create_sqli_payload, create_idor_payload
)

import logging

logger = logging.getLogger(__name__)


class ScannerAdapter:
    """
    محول رئيسي من Finding (scanner) → Vulnerability (schema)
    
    يحل مشكلة اختلاف الـ enums وفرق هيكل البيانات بين الطبقتين
    """
    
    # === خرائط التحويل ===
    
    SEVERITY_MAP = {
        ScannerSeverity.CRITICAL: SchemaSeverity.CRITICAL,
        ScannerSeverity.HIGH: SchemaSeverity.HIGH,
        ScannerSeverity.MEDIUM: SchemaSeverity.MEDIUM,
        ScannerSeverity.LOW: SchemaSeverity.LOW,
        ScannerSeverity.INFO: SchemaSeverity.INFO,
    }
    
    CONFIDENCE_MAP = {
        ScannerConfidence.CERTAIN: 1.0,
        ScannerConfidence.HIGH: 0.8,
        ScannerConfidence.MEDIUM: 0.5,
        ScannerConfidence.LOW: 0.3,
        ScannerConfidence.TENTATIVE: 0.1,
    }
    
    VULNERABILITY_TYPE_MAP = {
        # XSS
        "Cross-Site Scripting (XSS)": VulnerabilityType.XSS_REFLECTED,
        "Reflected XSS": VulnerabilityType.XSS_REFLECTED,
        "Stored XSS": VulnerabilityType.XSS_STORED,
        "DOM-based XSS": VulnerabilityType.XSS_DOM,
        
        # SQLi
        "SQL Injection (Boolean-based Blind)": VulnerabilityType.SQLI_BOOLEAN,
        "SQL Injection (Time-based Blind)": VulnerabilityType.SQLI_TIME,
        "SQL Injection (Error-based)": VulnerabilityType.SQLI_ERROR,
        "SQL Injection (Union-based)": VulnerabilityType.SQLI_UNION,
        
        # IDOR
        "Insecure Direct Object Reference (IDOR)": VulnerabilityType.IDOR,
        
        # CSRF
        "Cross-Site Request Forgery (CSRF)": VulnerabilityType.CSRF,
        "Missing CSRF Protection on Sensitive Action": VulnerabilityType.CSRF,
        
        # SSRF
        "Server-Side Request Forgery (SSRF)": VulnerabilityType.SSRF,
        
        # RCE
        "Remote Code Execution (RCE)": VulnerabilityType.RCE,
        "Remote Code Execution (Time-based)": VulnerabilityType.RCE,
        
        # Auth
        "Weak Credentials": VulnerabilityType.UNKNOWN,
        "Weak Session Identifier": VulnerabilityType.UNKNOWN,
        "JWT Algorithm Confusion (None Algorithm)": VulnerabilityType.UNKNOWN,
        "Sensitive Information in JWT": VulnerabilityType.UNKNOWN,
        "Expired JWT Token": VulnerabilityType.UNKNOWN,
        "Session Fixation Vulnerability": VulnerabilityType.UNKNOWN,
        "Weak Password Policy": VulnerabilityType.UNKNOWN,
        "Unauthenticated Access to Sensitive Endpoint": VulnerabilityType.UNKNOWN,
        
        # GraphQL
        "GraphQL Introspection Enabled": VulnerabilityType.UNKNOWN,
        "GraphQL Complexity Attack (DoS)": VulnerabilityType.UNKNOWN,
        "GraphQL Resource Exhaustion": VulnerabilityType.UNKNOWN,
        "Sensitive Fields Exposed in GraphQL Schema": VulnerabilityType.UNKNOWN,
        
        # API
        "Unsafe HTTP Method Enabled": VulnerabilityType.UNKNOWN,
        "IDOR in API": VulnerabilityType.IDOR,
        "Mass Assignment Vulnerability": VulnerabilityType.UNKNOWN,
        "Sensitive Information Leakage": VulnerabilityType.UNKNOWN,
        "Missing Rate Limiting": VulnerabilityType.UNKNOWN,
        "Exposed API Documentation": VulnerabilityType.UNKNOWN,
    }
    
    @classmethod
    def finding_to_vulnerability(
        cls,
        finding: Finding,
        scanner_name: str = "unknown",
        request_method: str = "GET",
        request_headers: Dict = None,
        response_status: int = 0,
        response_headers: Dict = None,
    ) -> Vulnerability:
        """
        تحويل Finding (من scanner) → Vulnerability (لـ schema)
        
        Args:
            finding: نتيجة الفحص من الـ scanner
            scanner_name: اسم الـ scanner اللي اكتشف الثغرة
            request_method: طريقة HTTP المستخدمة
            request_headers: headers الطلب
            response_status: كود حالة الاستجابة
            response_headers: headers الاستجابة
        
        Returns:
            Vulnerability جاهزة للاستخدام في المنصة
        """
        # 1. تحويل النوع
        vuln_type = cls._map_vulnerability_type(finding.vulnerability_type)
        
        # 2. تحويل الخطورة
        severity = cls._map_severity(finding.severity)
        
        # 3. تحويل الثقة
        confidence = cls._map_confidence(finding.confidence)
        
        # 4. بناء الأدلة
        evidence_list = []
        if finding.evidence or finding.payload:
            evidence = VulnerabilityEvidence(
                request=HttpRequest(
                    method=request_method,
                    url=finding.url,
                    headers=request_headers or {},
                    parameters={finding.parameter: finding.payload} if finding.parameter else {},
                    body=finding.payload
                ),
                response=HttpResponse(
                    status_code=response_status,
                    headers=response_headers or {},
                    body=finding.evidence or "",
                    body_length=len(finding.evidence) if finding.evidence else 0
                ),
                reflection_point=finding.evidence,
                additional_data=finding.metadata or {}
            )
            evidence_list.append(evidence)
        
        # 5. بناء Vulnerability
        vulnerability = Vulnerability(
            id=generate_vulnerability_id(),
            type=vuln_type,
            title=finding.vulnerability_type,
            description=finding.description or f"{finding.vulnerability_type} discovered at {finding.url}",
            url=finding.url,
            parameter=finding.parameter,
            host=None,  # ممكن استخراجه من URL
            path=None,   # ممكن استخراجه من URL
            payload=finding.payload,
            payload_context=cls._infer_payload_context(finding.vulnerability_type),
            severity=severity,
            cvss_score=finding.cvss_score or cls._estimate_cvss(severity),
            confidence=confidence,
            verification_status=VerificationStatus.UNVERIFIED,
            exploitation_status=ExploitationStatus.NOT_EXPLOITED,
            evidence=evidence_list,
            remediation=finding.remediation or "",
            discovered_by=scanner_name,
            discovered_at=finding.discovered_at,
            tags=cls._generate_tags(finding),
            metadata=finding.metadata or {}
        )
        
        return vulnerability
    
    @classmethod
    def batch_convert(
        cls,
        findings: List[Finding],
        scanner_name: str = "unknown",
        **kwargs
    ) -> List[Vulnerability]:
        """
        تحويل مجموعة Findings إلى Vulnerabilities
        
        Args:
            findings: قائمة نتائج الفحص
            scanner_name: اسم الـ scanner
            **kwargs: معاملات إضافية لـ finding_to_vulnerability
        
        Returns:
            قائمة Vulnerabilities
        """
        vulnerabilities = []
        for finding in findings:
            try:
                vuln = cls.finding_to_vulnerability(finding, scanner_name, **kwargs)
                vulnerabilities.append(vuln)
            except Exception as e:
                logger.error(f"Failed to convert finding: {e}")
        return vulnerabilities
    
    # === دوال مساعدة داخلية ===
    
    @classmethod
    def _map_severity(cls, scanner_severity: ScannerSeverity) -> SchemaSeverity:
        """تحويل Severity من scanner → schema"""
        return cls.SEVERITY_MAP.get(scanner_severity, SchemaSeverity.MEDIUM)
    
    @classmethod
    def _map_confidence(cls, scanner_confidence: ScannerConfidence) -> float:
        """تحويل Confidence من scanner enum → schema float"""
        return cls.CONFIDENCE_MAP.get(scanner_confidence, 0.5)
    
    @classmethod
    def _map_vulnerability_type(cls, finding_type: str) -> VulnerabilityType:
        """تحويل نص نوع الثغرة → VulnerabilityType enum"""
        # بحث مباشر
        if finding_type in cls.VULNERABILITY_TYPE_MAP:
            return cls.VULNERABILITY_TYPE_MAP[finding_type]
        
        # بحث جزئي
        finding_lower = finding_type.lower()
        
        if "xss" in finding_lower:
            return VulnerabilityType.XSS_REFLECTED
        elif "sqli" in finding_lower or "sql injection" in finding_lower:
            if "boolean" in finding_lower:
                return VulnerabilityType.SQLI_BOOLEAN
            elif "time" in finding_lower:
                return VulnerabilityType.SQLI_TIME
            elif "error" in finding_lower:
                return VulnerabilityType.SQLI_ERROR
            elif "union" in finding_lower:
                return VulnerabilityType.SQLI_UNION
            return VulnerabilityType.SQLI_BOOLEAN
        elif "idor" in finding_lower:
            return VulnerabilityType.IDOR
        elif "csrf" in finding_lower:
            return VulnerabilityType.CSRF
        elif "ssrf" in finding_lower:
            return VulnerabilityType.SSRF
        elif "rce" in finding_lower or "code execution" in finding_lower:
            return VulnerabilityType.RCE
        elif "open redirect" in finding_lower:
            return VulnerabilityType.OPEN_REDIRECT
        
        return VulnerabilityType.UNKNOWN
    
    @classmethod
    def _infer_payload_context(cls, vulnerability_type: str) -> Optional[str]:
        """استنتاج سياق الحمولة من نوع الثغرة"""
        type_lower = vulnerability_type.lower()
        
        if "xss" in type_lower:
            if "dom" in type_lower:
                return "javascript"
            elif "attribute" in type_lower:
                return "attribute"
            return "html"
        elif "sqli" in type_lower or "sql" in type_lower:
            return "sql"
        elif "idor" in type_lower:
            return "url"
        elif "ssrf" in type_lower:
            return "url"
        elif "rce" in type_lower:
            return "header"
        
        return None
    
    @classmethod
    def _estimate_cvss(cls, severity: SchemaSeverity) -> float:
        """تقدير CVSS بناءً على الخطورة"""
        estimates = {
            SchemaSeverity.CRITICAL: 9.8,
            SchemaSeverity.HIGH: 7.5,
            SchemaSeverity.MEDIUM: 5.3,
            SchemaSeverity.LOW: 3.1,
            SchemaSeverity.INFO: 0.0,
        }
        return estimates.get(severity, 5.0)
    
    @classmethod
    def _generate_tags(cls, finding: Finding) -> List[str]:
        """توليد tags من finding"""
        tags = []
        type_lower = finding.vulnerability_type.lower()
        
        if "xss" in type_lower:
            tags.extend(["xss", "injection", "client-side"])
        elif "sql" in type_lower:
            tags.extend(["sqli", "injection", "database"])
        elif "idor" in type_lower:
            tags.extend(["idor", "authorization", "access-control"])
        elif "csrf" in type_lower:
            tags.extend(["csrf", "session", "cross-site"])
        elif "ssrf" in type_lower:
            tags.extend(["ssrf", "server-side", "request-forgery"])
        elif "rce" in type_lower:
            tags.extend(["rce", "code-execution", "critical"])
        elif "auth" in type_lower or "jwt" in type_lower or "session" in type_lower:
            tags.extend(["authentication", "session"])
        elif "graphql" in type_lower:
            tags.extend(["graphql", "api"])
        elif "api" in type_lower:
            tags.extend(["api", "rest"])
        
        if finding.severity == ScannerSeverity.CRITICAL:
            tags.append("critical")
        elif finding.severity == ScannerSeverity.HIGH:
            tags.append("high-severity")
        
        return tags


class PayloadAdapter:
    """
    محول الحمولات من scanners → schema Payload
    
    يربط حمولات الـ scanners بمكتبة PayloadLibrary المركزية
    """
    
    @classmethod
    def xss_payload_to_schema(cls, content: str, context: str = "html") -> Payload:
        """تحويل حمولة XSS إلى Payload schema"""
        payload_context = PayloadContext.HTML
        if context == "attribute":
            payload_context = PayloadContext.ATTRIBUTE
        elif context == "javascript":
            payload_context = PayloadContext.JAVASCRIPT
        elif context in ["url", "url_encoded"]:
            payload_context = PayloadContext.URL
        
        return create_xss_payload(content, payload_context)
    
    @classmethod
    def sqli_payload_to_schema(cls, content: str) -> Payload:
        """تحويل حمولة SQLi إلى Payload schema"""
        return create_sqli_payload(content)
    
    @classmethod
    def idor_payload_to_schema(cls, content: str) -> Payload:
        """تحويل حمولة IDOR إلى Payload schema"""
        return create_idor_payload(content)
    
    @classmethod
    def scanner_finding_to_payload(cls, finding: Finding) -> Optional[Payload]:
        """
        تحويل Finding إلى Payload schema (للتتبع)
        
        Args:
            finding: نتيجة الفحص
        
        Returns:
            Payload schema أو None
        """
        if not finding.payload:
            return None
        
        payload_type = None
        finding_lower = finding.vulnerability_type.lower()
        
        if "xss" in finding_lower:
            payload_type = PayloadType.XSS
        elif "sql" in finding_lower:
            payload_type = PayloadType.SQLI
        elif "idor" in finding_lower:
            payload_type = PayloadType.IDOR
        elif "ssrf" in finding_lower:
            payload_type = PayloadType.SSRF
        elif "rce" in finding_lower:
            payload_type = PayloadType.RCE
        else:
            payload_type = PayloadType.CUSTOM
        
        import uuid
        return Payload(
            id=f"PLS-{uuid.uuid4().hex[:8].upper()}",
            content=finding.payload,
            payload_type=payload_type,
            context=PayloadContext.URL,
            name=f"scanner_{finding.vulnerability_type[:30]}",
            description=f"Payload discovered by scanner: {finding.vulnerability_type}",
            tags=[finding.vulnerability_type.lower().replace(' ', '-')],
            effectiveness=1.0 if finding.confidence == ScannerConfidence.CERTAIN else 0.5,
            status=PayloadStatus.VERIFIED
        )


class ConfigLoader:
    """
    محمل الإعدادات للـ scanners
    
    يقرأ الإعدادات من configs/offensive/ ويطبقها على الـ scanners
    """
    
    @classmethod
    def load_scanner_config(cls, scanner_name: str) -> Dict[str, Any]:
        """
        تحميل إعدادات scanner محدد
        
        Args:
            scanner_name: اسم الـ scanner (xss, sqli, idor, ...)
        
        Returns:
            قاموس الإعدادات
        """
        try:
            from configs.offensive import SCANNERS_CONFIG
            return SCANNERS_CONFIG.get(scanner_name, {})
        except ImportError:
            logger.warning(f"Cannot import configs, using defaults for {scanner_name}")
            return {}
    
    @classmethod
    def is_scanner_enabled(cls, scanner_name: str) -> bool:
        """
        التحقق إذا كان الـ scanner مفعل في الإعدادات
        
        Args:
            scanner_name: اسم الـ scanner
        
        Returns:
            True إذا كان مفعلاً
        """
        config = cls.load_scanner_config(scanner_name)
        return config.get("enabled", True)  # افتراضياً مفعل
    
    @classmethod
    def get_enabled_scanners(cls) -> List[str]:
        """
        الحصول على قائمة الـ scanners المفعلة
        
        Returns:
            قائمة أسماء الـ scanners
        """
        try:
            from configs.offensive import SCANNERS_CONFIG
            return [
                name for name, config in SCANNERS_CONFIG.items()
                if isinstance(config, dict) and config.get("enabled", True)
            ]
        except ImportError:
            # إذا مش متاح configs، نرجع كل الـ scanners
            return ["xss", "sqli", "idor", "rce", "ssrf", "csrf", "auth", "graphql", "api"]


# دوال مساعدة سريعة
def quick_convert(finding: Finding, scanner_name: str = "unknown") -> Vulnerability:
    """تحويل سريع من Finding → Vulnerability"""
    return ScannerAdapter.finding_to_vulnerability(finding, scanner_name)


def batch_convert(findings: List[Finding], scanner_name: str = "unknown") -> List[Vulnerability]:
    """تحويل سريع لمجموعة Findings"""
    return ScannerAdapter.batch_convert(findings, scanner_name)
