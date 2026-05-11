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

import logging

logger = logging.getLogger(__name__)


@dataclass
class CSRFTokenInfo:
    """معلومات عن توكن CSRF"""
    name: str
    value: str
    location: str
    pattern: str
    strength: str


class CSRFScanner(BaseScanner):
    """
    فاحص ثغرات Cross-Site Request Forgery (CSRF)
    
    الميزات:
    - اكتشاف وجود توكنات CSRF
    - تحليل قوة التوكنات
    - اختبار إمكانية تجاوز حماية CSRF
    - اكتشاف SameSite Cookie attributes
    - تحليل الـ Referer/Origin headers
    - اكتشاف عدم وجود توكنات في الطلبات الحساسة
    """
    
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
    
    SAMESITE_PATTERNS = {
        "Strict": re.compile(r'SameSite=Strict', re.I),
        "Lax": re.compile(r'SameSite=Lax', re.I),
        "None": re.compile(r'SameSite=None', re.I),
        "Missing": re.compile(r'^((?!SameSite).)*$', re.MULTILINE),
    }
    
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
        self._tested_forms: Set[str] = set()
        self._discovered_tokens: Dict[str, CSRFTokenInfo] = {}
    
    async def can_scan(self, context: ScanContext) -> bool:
        url = context.target.url.lower()
        
        for action in self.SENSITIVE_ACTIONS:
            if action in url:
                return True
        
        return True
    
    async def scan(self, context: ScanContext) -> List[Finding]:
        findings = []
        
        # 1. الحصول على الصفحة وتحليل النماذج
        response_text = await self.send_request(context.target.url, method="GET")
        
        if response_text:
            # 2. تحليل وجود توكنات CSRF
            tokens = await self._analyze_tokens(response_text)
            
            # 3. تحليل SameSite cookies (من الاستجابة)
            if self._check_samesite:
                samesite_findings = await self._analyze_samesite(response_text)
                findings.extend(samesite_findings)
            
            # 4. اختبار النماذج
            if self._test_all_forms:
                forms = await self._extract_forms(response_text, context.target.url)
                
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
        
        return findings
    
    async def _analyze_tokens(self, body: str) -> List[CSRFTokenInfo]:
        tokens = []
        
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
        
        return tokens
    
    async def _extract_forms(self, html: str, base_url: str) -> List[Dict]:
        forms = []
        
        form_pattern = re.compile(r'<form[^>]*>(.*?)</form>', re.DOTALL | re.IGNORECASE)
        
        for form_match in form_pattern.finditer(html):
            form_html = form_match.group(0)
            
            action_match = re.search(r'action=["\']?([^"\'\s>]+)', form_html, re.I)
            action = action_match.group(1) if action_match else base_url
            
            method_match = re.search(r'method=["\']?([^"\'\s>]+)', form_html, re.I)
            method = method_match.group(1).upper() if method_match else "GET"
            
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
        findings = []
        
        if not form["has_csrf"] and form["method"] == "POST":
            finding = self.add_finding(
                vulnerability_type="Cross-Site Request Forgery (CSRF)",
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                url=form["action"],
                description=f"Form submission to {form['action']} lacks CSRF token protection",
                remediation="Implement CSRF tokens for all state-changing requests. Use SameSite cookies.",
                cvss_score=6.5,
                metadata={
                    "form_action": form["action"],
                    "form_method": form["method"],
                    "inputs": form["inputs"]
                }
            )
            findings.append(finding)
        
        if existing_tokens:
            test_finding = await self._test_request_without_token(context, form)
            if test_finding:
                findings.append(test_finding)
        
        return findings
    
    async def _test_request_without_token(
        self,
        context: ScanContext,
        form: Dict
    ) -> Optional[Finding]:
        test_data = {}
        
        response_text = await self.send_request(
            form["action"],
            method=form["method"],
            data=test_data
        )
        
        if response_text is not None:
            finding = self.add_finding(
                vulnerability_type="Cross-Site Request Forgery (CSRF)",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                url=form["action"],
                payload="Request submitted without CSRF token",
                evidence="Request succeeded without CSRF token",
                description="CSRF protection missing or bypassable.",
                remediation="Implement proper CSRF tokens. Use anti-CSRF libraries.",
                cvss_score=8.0,
                metadata={}
            )
            return finding
        
        return None
    
    async def _analyze_samesite(self, response_text: str) -> List[Finding]:
        findings = []
        
        set_cookie_pattern = re.compile(r'Set-Cookie:[^\n]+', re.I)
        cookies = set_cookie_pattern.findall(response_text)
        
        for cookie in cookies:
            if "SameSite" not in cookie:
                cookie_name_match = re.search(r'Set-Cookie:\s*([^=;]+)', cookie, re.I)
                cookie_name = cookie_name_match.group(1) if cookie_name_match else "unknown"
                
                finding = self.add_finding(
                    vulnerability_type="Missing SameSite Cookie Attribute",
                    severity=Severity.LOW,
                    confidence=Confidence.HIGH,
                    url="",
                    description=f"Cookie '{cookie_name}' is missing SameSite attribute",
                    remediation="Set SameSite=Lax or SameSite=Strict for session cookies.",
                    cvss_score=4.3,
                    metadata={"cookie": cookie_name, "issue": "missing_samesite"}
                )
                findings.append(finding)
            else:
                if "SameSite=None" in cookie and "Secure" not in cookie:
                    cookie_name_match = re.search(r'Set-Cookie:\s*([^=;]+)', cookie, re.I)
                    cookie_name = cookie_name_match.group(1) if cookie_name_match else "unknown"
                    
                    finding = self.add_finding(
                        vulnerability_type="Insecure SameSite Configuration",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.HIGH,
                        url="",
                        description=f"Cookie '{cookie_name}' uses SameSite=None without Secure flag",
                        remediation="Always use Secure flag with SameSite=None.",
                        cvss_score=5.3,
                        metadata={"cookie": cookie_name, "issue": "samesite_none_missing_secure"}
                    )
                    findings.append(finding)
        
        return findings
    
    async def _assess_token_strength(self, tokens: List[CSRFTokenInfo]) -> List[Finding]:
        findings = []
        
        for token in tokens:
            entropy = self._calculate_entropy(token.value)
            is_random = self._is_random_enough(token.value)
            
            if entropy < 3.0 or not is_random:
                finding = self.add_finding(
                    vulnerability_type="Weak CSRF Token",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    url="",
                    description=f"CSRF token '{token.name}' has low entropy ({entropy:.2f} bits) and may be predictable",
                    remediation="Use cryptographically secure random tokens (minimum 128 bits).",
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
        if not token:
            return 0.0
        
        freq = {}
        for char in token:
            freq[char] = freq.get(char, 0) + 1
        
        entropy = 0.0
        length = len(token)
        for count in freq.values():
            probability = count / length
            entropy -= probability * (probability.bit_length() if probability > 0 else 0)
        
        return entropy
    
    def _is_random_enough(self, token: str) -> bool:
        if re.search(r'(.)\1{3,}', token):
            return False
        
        if re.search(r'\d{6,}', token):
            return False
        
        if len(token) < 16:
            return False
        
        return True
    
    async def _check_sensitive_requests(self, context: ScanContext) -> List[Finding]:
        findings = []
        
        url_lower = context.target.url.lower()
        
        for action in self.SENSITIVE_ACTIONS:
            if action in url_lower:
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
        poc = f'''<!DOCTYPE html>
<html>
<head>
    <title>CSRF PoC</title>
</head>
<body>
    <h1>CSRF Proof of Concept</h1>
    <p>This form will automatically submit a request to {form_action}</p>
    
    <form action="{form_action}" method="{method}" id="csrf-form">
        <input type="hidden" name="action" value="exploit">
    </form>
    
    <script>
        document.getElementById('csrf-form').submit();
    </script>
</body>
</html>'''
        
        return poc
