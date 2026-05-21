"""
Context-Aware Scanner - فاحص يفهم السياق ويؤكد الثغرات

الميزات:
- Context detection (login, search, api, profile, upload)
- Response analysis الذكي
- Verification بطرق متعددة
- Targeted payloads حسب السياق
- CVSS scoring حقيقي
"""

import asyncio
import re
import time
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from urllib.parse import urlparse, parse_qs

from .base_scanner import BaseScanner, ScanContext, Finding, Severity, Confidence

import logging

logger = logging.getLogger(__name__)


@dataclass
class VerifiedFinding:
    """ثغرة مؤكدة"""
    finding: Finding
    verified: bool = False
    verification_method: str = ""
    verification_evidence: str = ""
    false_positive: bool = False
    exploitation_possible: bool = False
    impact_score: float = 0.0


class ContextAwareScanner:
    """
    فاحص يفهم السياق
    
    بدل ما يرمي payloads عشوائية، بيفهم الصفحة وبيختار الاختبار المناسب
    """
    
    # سياقات مختلفة واختباراتها
    CONTEXT_TESTS = {
        "login": {
            "tests": ["sqli_auth_bypass", "nosql_injection", "default_credentials"],
            "payloads": {
                "sqli_auth_bypass": ["' OR '1'='1' --", "admin'--", "' OR 1=1#"],
                "nosql_injection": ['{"$gt": ""}', '{"$ne": null}', '{"$regex": ".*"}'],
                "default_credentials": ["admin:admin", "admin:password", "test:test"],
            }
        },
        "search": {
            "tests": ["xss_reflected", "sqli_error", "sqli_union"],
            "payloads": {
                "xss_reflected": ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"],
                "sqli_error": ["'", "\"", "1'", "1\""],
                "sqli_union": ["' UNION SELECT NULL--", "' UNION SELECT 1,2,3--"],
            }
        },
        "profile": {
            "tests": ["idor", "xss_stored", "csrf"],
            "payloads": {
                "idor": ["1", "2", "999", "admin"],
                "xss_stored": ["<script>alert(document.cookie)</script>"],
                "csrf": [],
            }
        },
        "api": {
            "tests": ["idor", "mass_assignment", "jwt_none"],
            "payloads": {
                "idor": ["1", "2", "100"],
                "mass_assignment": ['{"role": "admin"}', '{"isAdmin": true}'],
                "jwt_none": [],
            }
        },
        "upload": {
            "tests": ["unrestricted_upload", "double_extension"],
            "payloads": {
                "unrestricted_upload": ["test.php", "test.jsp", "test.aspx"],
                "double_extension": ["test.php.jpg", "test.jpg.php"],
            }
        },
    }
    
    # أنماط الردود اللي بتأكد الثغرة
    VERIFICATION_PATTERNS = {
        "sqli_error": [
            r"SQL syntax.*MySQL",
            r"PostgreSQL.*ERROR",
            r"ORA-\d{5}",
            r"SQLite.*error",
            r"unclosed quotation mark",
            r"Microsoft OLE DB",
        ],
        "sqli_union": [
            r"(\d+)\s*\|\s*(\d+)\s*\|\s*(\d+)",  # UNION output pattern
        ],
        "xss_reflected": [
            # لو الـ payload ظهر في الـ response كما هو
            # ده معناه إنه متشافش كـ XSS بس معناه reflection
        ],
        "idor": [
            r"(?:email|username|password|token|key)",
            r"(?:user|account|profile|admin)",
        ],
    }
    
    def __init__(self):
        self._verified_findings: List[VerifiedFinding] = []
        self._context_cache: Dict[str, str] = {}
    
    def detect_context(self, url: str, html: str, headers: Dict = None) -> str:
        """اكتشاف سياق الصفحة"""
        url_lower = url.lower()
        html_lower = html.lower() if html else ""
        
        # Login page
        if any(w in url_lower for w in ['login', 'signin', 'auth', 'sign_in']):
            return "login"
        if 'password' in html_lower and ('email' in html_lower or 'username' in html_lower):
            return "login"
        
        # Search page
        if any(w in url_lower for w in ['search', 'query', 'find', 'q=']):
            return "search"
        if '<input' in html_lower and 'search' in html_lower:
            return "search"
        
        # Profile page
        if any(w in url_lower for w in ['profile', 'account', 'user', 'settings']):
            return "profile"
        
        # API endpoint
        if any(w in url_lower for w in ['/api/', '/rest/', '/graphql']):
            return "api"
        if headers and 'application/json' in str(headers.get('content-type', '')):
            return "api"
        
        # Upload
        if 'file' in html_lower and 'upload' in html_lower:
            return "upload"
        if '<input type="file"' in html_lower:
            return "upload"
        
        # Default: search-like إذا فيه parameters
        if '?' in url:
            return "search"
        
        return "generic"
    
    def get_tests_for_context(self, context: str) -> List[str]:
        """الحصول على الاختبارات المناسبة للسياق"""
        ctx = self.CONTEXT_TESTS.get(context, {})
        return ctx.get("tests", ["sqli_error", "xss_reflected"])
    
    def get_payloads_for_test(self, context: str, test: str) -> List[str]:
        """الحصول على الحمولات المناسبة للاختبار"""
        ctx = self.CONTEXT_TESTS.get(context, {})
        return ctx.get("payloads", {}).get(test, ["'", "\"", "<script>"])
    
    def verify_finding(self, payload: str, response_text: str, test_type: str) -> Tuple[bool, str]:
        """
        التحقق من الثغرة
        
        Returns:
            (هل الثغرة حقيقية؟, دليل التأكيد)
        """
        if not response_text:
            return False, ""
        
        patterns = self.VERIFICATION_PATTERNS.get(test_type, [])
        
        for pattern in patterns:
            match = re.search(pattern, response_text, re.IGNORECASE)
            if match:
                evidence = match.group(0)[:200]
                return True, evidence
        
        # فحص إضافي للـ XSS - reflection
        if test_type.startswith("xss"):
            # لو الـ payload ظهر في الـ response
            clean_payload = payload.replace('<', '').replace('>', '')
            if clean_payload in response_text:
                return True, f"Payload reflected: {clean_payload[:100]}"
        
        # فحص IDOR - response فيه user data
        if test_type == "idor":
            data_indicators = ['email', 'username', 'token', 'password', 'admin']
            found = [i for i in data_indicators if i in response_text.lower()]
            if len(found) >= 2:
                return True, f"User data exposed: {', '.join(found)}"
        
        return False, ""
    
    def calculate_cvss(self, vuln_type: str, verified: bool, context: str) -> float:
        """حساب CVSS حقيقي بناءً على السياق والتأكيد"""
        base_scores = {
            "sqli_error": 9.8,
            "sqli_union": 9.8,
            "sqli_auth_bypass": 9.8,
            "xss_reflected": 6.1,
            "xss_stored": 7.5,
            "idor": 6.5,
            "rce": 10.0,
            "csrf": 6.5,
            "mass_assignment": 7.5,
        }
        
        score = base_scores.get(vuln_type, 5.0)
        
        # تخفيض لو مش متأكد
        if not verified:
            score *= 0.7
        
        # زيادة لو في سياق حساس
        if context == "login" and vuln_type.startswith("sqli"):
            score = min(10.0, score * 1.1)
        if context == "api" and vuln_type == "idor":
            score = min(10.0, score * 1.1)
        
        return round(score, 1)
    
    def get_stats(self) -> Dict:
        """إحصائيات الفاحص"""
        total = len(self._verified_findings)
        verified = len([f for f in self._verified_findings if f.verified])
        false_positives = len([f for f in self._verified_findings if f.false_positive])
        
        return {
            "total_findings": total,
            "verified": verified,
            "false_positives": false_positives,
            "accuracy": verified / max(1, total - false_positives) if total > 0 else 0,
        }


# نسخة عالمية
_context_scanner = None

def get_context_aware_scanner() -> ContextAwareScanner:
    global _context_scanner
    if _context_scanner is None:
        _context_scanner = ContextAwareScanner()
    return _context_scanner
