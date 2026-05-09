"""
CSRF Scanner - فاحص ثغرات CSRF
يكتشف ثغرات Cross-Site Request Forgery
"""

import asyncio
import re
import hashlib
import secrets
from typing import Dict, List, Optional, Any, Set, Tuple
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from dataclasses import dataclass
from collections import defaultdict

from .base_scanner import BaseScanner, ScanContext, Finding, Severity, Confidence

try:
    import httpx
    HTTPX_AVAILABLE = True
except ImportError:
    HTTPX_AVAILABLE = False
    import aiohttp

import logging

logger = logging.getLogger(__name__)


@dataclass
class CSRFTokenInfo:
    """معلومات عن توكن CSRF"""
    name: str
    value: str
    location: str  # header, form, query
    pattern: str  # regex pattern
    strength: str  # strong, weak, none


class CSRFScanner(BaseScanner):
    """
    فاحص ثغرات Cross-Site Request Forgery (CSRF)
    
    الميزات:
    - اكتشاف وجود توكنات CSRF
    - تحليل قوة التوكنات (عشوائية، قابلية التخمين)
    - اختبار إمكانية تجاوز حماية CSRF
    - اكتشاف SameSite Cookie attributes
    - تحليل الـ Referer/Origin headers
    - اختبار عدم وجود توكنات في الطلبات الحساسة
    """
    
    # أنماط توكنات CSRF الشائعة
    TOKEN_PATTERNS = {
        "csrf_token": re.compile(r'name=["\']?csrf[_\-]?token["\']?\s+value=["\']?([^"\']+)["\']?', re.I),
        "authenticity_token": re.compile(r'name=["\']?authenticity[_\-]?token["\']?\s+value=["\']?([^"\']+)["\']?', re.I),
        "_token": re.compile(r'name=["\']?_token["\']?\s+value=["\']?([^"\']+)["\']?', re.I),
        "csrfmiddlewaretoken": re.compile(r'name=["\']?csrfmiddlewaretoken["\']?\s+value=["\']?([^"\']+)["\']?', re.I),
        "X-CSRF-TOKEN": re.compile(r'X-CSRF-TOKEN:\s*([^\s]+)', re.I),
        "X-CSRFToken": re.compile(r'X-CSRFToken:\s*([^\s]+)', re.I),
        "CSRF-TOKEN": re.compile(r'CSRF-TOKEN:\s*([^\s]+)', re.I),
        "_csrf": re.compile(r'name=["\']?_csrf["\']?\s+value=["\']?([^"\']+)["\']?', re.I),
    }
    
    # أنماط SameSite Cookies
    SAMESITE_PATTERNS = {
        "Strict": re.compile(r'SameSite=Strict', re.I),
        "Lax": re.compile(r'SameSite=Lax', re.I),
        "None": re.compile(r'SameSite=None', re.I),
        "Missing": re.compile(r'^((?!SameSite).)*$', re.MULTILINE),
    }
    
    # الطلبات الحساسة التي يجب حمايتها
    SENSITIVE_ACTIONS = [
        "login", "logout", "register", "signup",
        "password", "change-password", "reset-password",
        "delete", "remove", "update", "edit",
        "transfer", "withdraw", "deposit",
        "admin", "settings", "profile",
        "email", "phone", "address",
    ]
    
    def __init__(
        self,
        rate_limit: float = 2.0,
        timeout: int = 30,
        max_retries: int = 2,
        test_all_forms: bool = True,
        check_samesite: bool = True,
        token_strength_check: bool = True
    ):
        super().__init__(
            name="CSRFScanner",
            rate_limit=rate_limit,
            timeout=timeout,
            max_retries=max_retries
        )
        self._test_all_forms = test_all_forms
        self._check_samesite = check_samesite
        self._token_strength_check = token_strength_check
        self._session = None
        self._tested_forms: Set[str] = set()
        self._discovered_tokens: Dict[str, CSRFTokenInfo] = {}
    
    async def _get_session(self):
        """الحصول على جلسة HTTP"""
        if not self._session:
            if HTTPX_AVAILABLE:
                self._session = httpx.AsyncClient(
                    timeout=self.timeout,
                    follow_redirects=True,
                    verify=False
                )
            else:
                self._session = aiohttp.ClientSession()
        return self._session
    
    async def can_scan(self, context: ScanContext) -> bool:
        """التحقق من وجود نماذج أو طلبات حساسة"""
        url = context.target.url.lower()
        
        # التحقق من وجود كلمات حساسة في URL
        for action in self.SENSITIVE_ACTIONS:
            if action in url:
                return True
        
        return True  # نفحص بشكل افتراضي
    
    async def scan(self, context: ScanContext) -> List[Finding]:
        """تنفيذ فحص CSRF"""
        findings = []
        session = await self._get_session()
        
        # 1. الحصول على الصفحة الرئيسية وتحليل النماذج
        try:
            if HTTPX_AVAILABLE:
                response = await session.get(context.target.url, headers=context.target.headers)
                body = response.text
                cookies = response.cookies
            else:
                async with session.get(context.target.url, headers=context.target.headers) as resp:
                    body = await resp.text()
                    cookies = resp.cookies
            
            # 2. تحليل وجود توكنات CSRF
            tokens = await self._analyze_tokens(body, cookies)
            
            # 3. تحليل SameSite cookies
            if self._check_samesite:
                samesite_findings = await self._analyze_samesite(cookies)
                findings.extend(samesite_findings)
            
            # 4. اختبار النماذج
            if self._test_all_forms:
                forms = await self._extract_forms(body, context.target.url)
                
                for form in forms:
                    form_findings = await self._test_form_csrf(context, form, tokens)
                    findings.extend(form_findings)
            
            # 5. تقييم قوة التوكنات
            if self._token_strength_check and tokens:
                token_findings = await self._assess_token_strength(tokens)
                findings.extend(token_findings)
            
            # 6. التحقق من الطلبات الحساسة
            sensitive_findings = await self._check_sensitive_requests(context)
            findings.extend(sensitive_findings)
            
        except Exception as e:
            logger.error(f"CSRF scan error: {e}")
        
        return findings
    
    async def _analyze_tokens(self, body: str, cookies) -> List[CSRFTokenInfo]:
        """تحليل وجود توكنات CSRF"""
        tokens = []
        
        # البحث في HTML
        for token_name, pattern in self.TOKEN_PATTERNS.items():
            matches = pattern.findall(body)
            for match in matches:
                token_info = CSRFTokenInfo(
                    name=token_name,
                    value=match,
                    location="form" if "name=" in pattern.pattern else "header",
                    pattern=token_name,
                    strength="unknown"
                )
                tokens.append(token_info)
                self._discovered_tokens[token_name] = token_info
        
        # البحث في Cookies
        for cookie in cookies:
            if "csrf" in cookie.lower() or "token" in cookie.lower():
                token_info = CSRFTokenInfo(
                    name=cookie,
                    value=str(cookies[cookie]),
                    location="cookie",
                    pattern="cookie",
                    strength="unknown"
                )
                tokens.append(token_info)
        
        return tokens
    
    async def _extract_forms(self, html: str, base_url: str) -> List[Dict]:
        """استخراج النماذج من HTML"""
        forms = []
        
        # نمط استخراج النماذج البسيط
        form_pattern = re.compile(r'<form[^>]*>(.*?)</form>', re.DOTALL | re.IGNORECASE)
        
        for form_match in form_pattern.finditer(html):
            form_html = form_match.group(0)
            
            # استخراج action
            action_match = re.search(r'action=["\']?([^"\'\s>]+)', form_html, re.I)
            action = action_match.group(1) if action_match else base_url
            
            # استخراج method
            method_match = re.search(r'method=["\']?([^"\'\s>]+)', form_html, re.I)
            method = method_match.group(1).upper() if method_match else "GET"
            
            # استخراج inputs
            inputs = []
            input_pattern = re.compile(r'<input[^>]*name=["\']?([^"\'\s>]+)[^>]*>', re.I)
            for input_match in input_pattern.finditer(form_html):
                name = input_match.group(1)
                inputs.append(name)
            
            forms.append({
                "html": form_html,
                "action": action,
                "method": method,
                "inputs": inputs,
                "has_csrf": any("csrf" in inp.lower() or "token" in inp.lower() for inp in inputs)
            })
        
        return forms
    
    async def _test_form_csrf(
        self,
        context: ScanContext,
        form: Dict,
        existing_tokens: List[CSRFTokenInfo]
    ) -> List[Finding]:
        """اختبار نموذج لوجود ثغرة CSRF"""
        findings = []
        
        # إذا كان النموذج لا يحتوي على توكن CSRF
        if not form["has_csrf"] and form["method"] == "POST":
            # هذا قد يكون ثغرة CSRF
            finding = self.add_finding(
                vulnerability_type="Cross-Site Request Forgery (CSRF)",
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                url=form["action"],
                description=f"Form submission to {form['action']} lacks CSRF token protection",
                remediation="Implement CSRF tokens for all state-changing requests. Use SameSite cookies. Validate Origin/Referer headers.",
                cvss_score=6.5,
                metadata={
                    "form_action": form["action"],
                    "form_method": form["method"],
                    "inputs": form["inputs"]
                }
            )
            findings.append(finding)
        
        # اختبار إمكانية إعادة استخدام التوكن
        if existing_tokens:
            # محاكاة طلب بدون توكن CSRF
            test_finding = await self._test_request_without_token(context, form)
            if test_finding:
                findings.append(test_finding)
        
        return findings
    
    async def _test_request_without_token(
        self,
        context: ScanContext,
        form: Dict
    ) -> Optional[Finding]:
        """اختبار ما إذا كان الطلب يعمل بدون توكن CSRF"""
        session = await self._get_session()
        
        # إزالة جميع التوكنات من الطلب
        test_data = {}
        
        # بناء بيانات POST بدون توكنات
        # (محاكاة طلب من موقع ضار)
        
        try:
            # إرسال طلب بدون توكن CSRF
            if form["method"] == "POST":
                if HTTPX_AVAILABLE:
                    response = await session.post(
                        form["action"],
                        data=test_data,
                        headers=context.target.headers
                    )
                else:
                    async with session.post(
                        form["action"],
                        data=test_data,
                        headers=context.target.headers
                    ) as resp:
                        response = resp
            
            # التحقق من نجاح الطلب
            if response.status_code in [200, 302, 303]:
                # قد يكون هناك ثغرة CSRF
                finding = self.add_finding(
                    vulnerability_type="Cross-Site Request Forgery (CSRF)",
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    url=form["action"],
                    payload="Request submitted without CSRF token",
                    evidence=f"Request succeeded with status {response.status_code}",
                    description="CSRF protection missing or bypassable. Request accepted without valid CSRF token.",
                    remediation="Implement proper CSRF tokens. Use anti-CSRF libraries. Enable SameSite cookies.",
                    cvss_score=8.0,
                    metadata={"status_code": response.status_code}
                )
                return finding
                
        except Exception as e:
            logger.debug(f"CSRF test error: {e}")
        
        return None
    
    async def _analyze_samesite(self, cookies) -> List[Finding]:
        """تحليل SameSite attribute في cookies"""
        findings = []
        
        for cookie in cookies:
            cookie_str = str(cookies[cookie])
            
            # التحقق من وجود SameSite
            if "SameSite" not in cookie_str:
                finding = self.add_finding(
                    vulnerability_type="Missing SameSite Cookie Attribute",
                    severity=Severity.LOW,
                    confidence=Confidence.HIGH,
                    url="",
                    description=f"Cookie '{cookie}' is missing SameSite attribute",
                    remediation="Set SameSite=Lax or SameSite=Strict for session cookies. Use SameSite=None only for cross-site cookies with Secure flag.",
                    cvss_score=4.3,
                    metadata={"cookie": cookie, "issue": "missing_samesite"}
                )
                findings.append(finding)
            else:
                # التحقق من SameSite=None بدون Secure
                if "SameSite=None" in cookie_str and "Secure" not in cookie_str:
                    finding = self.add_finding(
                        vulnerability_type="Insecure SameSite Configuration",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.HIGH,
                        url="",
                        description=f"Cookie '{cookie}' uses SameSite=None without Secure flag",
                        remediation="Always use Secure flag with SameSite=None. Consider using SameSite=Lax instead.",
                        cvss_score=5.3,
                        metadata={"cookie": cookie, "issue": "samesite_none_missing_secure"}
                    )
                    findings.append(finding)
        
        return findings
    
    async def _assess_token_strength(self, tokens: List[CSRFTokenInfo]) -> List[Finding]:
        """تقييم قوة توكنات CSRF"""
        findings = []
        
        for token in tokens:
            # تحليل قوة التوكن
            entropy = self._calculate_entropy(token.value)
            is_random = self._is_random_enough(token.value)
            
            if entropy < 3.0 or not is_random:
                finding = self.add_finding(
                    vulnerability_type="Weak CSRF Token",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    url="",
                    description=f"CSRF token '{token.name}' has low entropy ({entropy:.2f} bits) and may be predictable",
                    remediation="Use cryptographically secure random tokens (minimum 128 bits). Regenerate tokens after each request.",
                    cvss_score=5.0,
                    metadata={
                        "token_name": token.name,
                        "entropy": entropy,
                        "token_length": len(token.value)
                    }
                )
                findings.append(finding)
        
        return findings
    
    def _calculate_entropy(self, token: str) -> float:
        """حساب إنتروبيا التوكن"""
        if not token:
            return 0.0
        
        # حساب تردد الأحرف
        freq = {}
        for char in token:
            freq[char] = freq.get(char, 0) + 1
        
        # حساب الإنتروبيا
        entropy = 0.0
        length = len(token)
        for count in freq.values():
            probability = count / length
            entropy -= probability * (probability.bit_length() if probability > 0 else 0)
        
        return entropy
    
    def _is_random_enough(self, token: str) -> bool:
        """التحقق من عشوائية التوكن"""
        # التحقق من وجود أنماط متكررة
        if re.search(r'(.)\1{3,}', token):  # 4 أحرف متكررة
            return False
        
        # التحقق من وجود تسلسلات رقمية
        if re.search(r'\d{6,}', token):  # 6 أرقام متتالية
            return False
        
        # التحقق من وجود توكنات قصيرة جداً
        if len(token) < 16:
            return False
        
        return True
    
    async def _check_sensitive_requests(self, context: ScanContext) -> List[Finding]:
        """التحقق من الطلبات الحساسة"""
        findings = []
        
        url_lower = context.target.url.lower()
        
        for action in self.SENSITIVE_ACTIONS:
            if action in url_lower:
                # هذه عملية حساسة، تحقق من وجود حماية CSRF
                if not self._discovered_tokens:
                    finding = self.add_finding(
                        vulnerability_type="Missing CSRF Protection on Sensitive Action",
                        severity=Severity.HIGH,
                        confidence=Confidence.MEDIUM,
                        url=context.target.url,
                        description=f"Sensitive action '{action}' may lack CSRF protection",
                        remediation="Implement CSRF protection for all state-changing operations.",
                        cvss_score=7.5,
                        metadata={"sensitive_action": action}
                    )
                    findings.append(finding)
                break
        
        return findings
    
    async def generate_test_poc(self, url: str, form_action: str, method: str) -> str:
        """
        توليد PoC لثغرة CSRF
        
        Returns:
            HTML PoC
        """
        poc = f'''<!DOCTYPE html>
<html>
<head>
    <title>CSRF PoC</title>
</head>
<body>
    <h1>CSRF Proof of Concept</h1>
    <p>This form will automatically submit a request to {form_action}</p>
    
    <form action="{form_action}" method="{method}" id="csrf-form">
        <!-- Add any required parameters here -->
        <input type="hidden" name="action" value="exploit">
    </form>
    
    <script>
        document.getElementById('csrf-form').submit();
    </script>
</body>
</html>'''
        
        return poc
    
    async def close(self):
        """إغلاق الجلسة"""
        if self._session:
            if HTTPX_AVAILABLE:
                await self._session.aclose()
            else:
                await self._session.close()
            self._session = None

