
import asyncio
import re
import jwt
import json
import hashlib
import secrets
from typing import Dict, List, Optional, Any, Set, Tuple
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from datetime import datetime, timedelta
from dataclasses import dataclass

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
class TokenInfo:
    """معلومات عن التوكن"""
    token: str
    type: str  # jwt, bearer, basic, session
    location: str  # header, cookie, body
    decoded: Optional[Dict] = None
    algorithm: Optional[str] = None
    expiration: Optional[datetime] = None


class AuthScanner(BaseScanner):
    """
    فاحص ثغرات المصادقة والجلسات
    
    الميزات:
    - تحليل قوة كلمات المرور
    - اختبار المصادقة متعددة العوامل (MFA)
    - تحليل توكنات JWT والجلسات
    - اكتشاف تسرب المصادقة
    - اختبار Session Fixation
    - تحليل سياسات كلمات المرور
    - اكتشاف نقاط النهاية غير المحمية
    """
    
    # كلمات مرور ضعيفة شائعة
    WEAK_PASSWORDS = [
        "password", "123456", "12345678", "1234", "qwerty", "abc123",
        "admin", "letmein", "welcome", "monkey", "dragon", "master",
        "login", "pass", "password123", "admin123", "user123", "test123"
    ]
    
    # العناوين ونقاط النهاية الحساسة
    SENSITIVE_ENDPOINTS = [
        # مصادقة
        "/login", "/logout", "/signin", "/signout", "/auth",
        "/api/login", "/api/auth", "/oauth/token",
        "/admin/login", "/admin/auth",
        
        # تسجيل
        "/register", "/signup", "/api/register", "/api/signup",
        "/admin/register",
        
        # إدارة كلمة المرور
        "/reset-password", "/forgot-password", "/change-password",
        "/api/reset-password", "/api/forgot-password", "/api/change-password",
        
        # إدارة المستخدمين
        "/profile", "/account", "/settings", "/user",
        "/api/profile", "/api/account", "/api/settings", "/api/user",
        "/admin/users", "/admin/user",
    ]
    
    # نقاط النهاية العامة (لا تحتاج مصادقة)
    PUBLIC_ENDPOINTS = [
        "/", "/index", "/home", "/about", "/contact",
        "/api/health", "/api/status", "/metrics", "/robots.txt",
        "/favicon.ico", "/css/", "/js/", "/images/"
    ]
    
    def __init__(
        self,
        rate_limit: float = 1.0,
        timeout: int = 30,
        max_retries: int = 2,
        test_weak_passwords: bool = True,
        analyze_jwt: bool = True,
        check_session_fixation: bool = True
    ):
        super().__init__(
            name="AuthScanner",
            rate_limit=rate_limit,
            timeout=timeout,
            max_retries=max_retries
        )
        self._test_weak_passwords = test_weak_passwords
        self._analyze_jwt = analyze_jwt
        self._check_session_fixation = check_session_fixation
        self._session = None
        self._tested_endpoints: Set[str] = set()
        self._discovered_tokens: List[TokenInfo] = []
    
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
        """التحقق من وجود نقاط نهاية مصادقة"""
        url = context.target.url.lower()
        
        for endpoint in self.SENSITIVE_ENDPOINTS:
            if endpoint in url:
                return True
        
        return False
    
    async def scan(self, context: ScanContext) -> List[Finding]:
        """تنفيذ فحص المصادقة"""
        findings = []
        base_url = context.target.url.rstrip('/')
        
        # 1. فحص نقاط النهاية الحساسة
        sensitive_findings = await self._check_sensitive_endpoints(base_url)
        findings.extend(sensitive_findings)
        
        # 2. تحليل توكنات المصادقة
        token_findings = await self._analyze_auth_tokens(context)
        findings.extend(token_findings)
        
        # 3. فحص قوة كلمات المرور
        if self._test_weak_passwords:
            weak_password_findings = await self._test_weak_passwords_on_endpoints(base_url)
            findings.extend(weak_password_findings)
        
        # 4. فحص Session Fixation
        if self._check_session_fixation:
            fixation_findings = await self._test_session_fixation(base_url)
            findings.extend(fixation_fixation)
        
        # 5. تحليل سياسات كلمة المرور
        policy_findings = await self._analyze_password_policy(base_url)
        findings.extend(policy_findings)
        
        return findings
    
    async def _check_sensitive_endpoints(self, base_url: str) -> List[Finding]:
        """فحص نقاط النهاية الحساسة للوصول بدون مصادقة"""
        findings = []
        session = await self._get_session()
        
        for endpoint in self.SENSITIVE_ENDPOINTS:
            if endpoint in self._tested_endpoints:
                continue
            
            test_url = f"{base_url}{endpoint}"
            
            # تخطي نقاط النهاية العامة
            is_public = False
            for public in self.PUBLIC_ENDPOINTS:
                if public in endpoint:
                    is_public = True
                    break
            
            if is_public:
                continue
            
            self._tested_endpoints.add(endpoint)
            
            try:
                # إرسال طلب بدون مصادقة
                if HTTPX_AVAILABLE:
                    response = await session.get(test_url)
                    status_code = response.status_code
                else:
                    async with session.get(test_url) as resp:
                        status_code = resp.status
                
                # إذا كان الوصول ناجحاً بدون مصادقة
                if status_code == 200:
                    finding = self.add_finding(
                        vulnerability_type="Unauthenticated Access to Sensitive Endpoint",
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        url=test_url,
                        description=f"Sensitive endpoint {endpoint} accessible without authentication",
                        remediation="Implement authentication and authorization checks for all sensitive endpoints. Use role-based access control (RBAC).",
                        cvss_score=7.5,
                        metadata={"endpoint": endpoint, "status_code": status_code}
                    )
                    findings.append(finding)
                    
            except Exception as e:
                logger.debug(f"Error checking {test_url}: {e}")
        
        return findings
    
    async def _analyze_auth_tokens(self, context: ScanContext) -> List[Finding]:
        """تحليل توكنات المصادقة"""
        findings = []
        
        # استخراج التوكنات من الـ Headers
        auth_header = context.target.headers.get("Authorization", "")
        if auth_header:
            token_info = self._parse_auth_header(auth_header)
            if token_info:
                self._discovered_tokens.append(token_info)
                
                if token_info.type == "jwt":
                    jwt_findings = await self._analyze_jwt_token(token_info)
                    findings.extend(jwt_findings)
        
        # استخراج التوكنات من الـ Cookies
        for cookie_name, cookie_value in context.target.cookies.items():
            if "session" in cookie_name.lower() or "token" in cookie_name.lower():
                token_info = TokenInfo(
                    token=cookie_value,
                    type="session",
                    location="cookie"
                )
                self._discovered_tokens.append(token_info)
                
                # تحليل جلسة بسيط
                if self._is_weak_session_id(cookie_value):
                    finding = self.add_finding(
                        vulnerability_type="Weak Session Identifier",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.HIGH,
                        url="",
                        description=f"Session cookie '{cookie_name}' uses predictable session identifier: {cookie_value[:20]}...",
                        remediation="Use cryptographically secure random session identifiers. Regenerate session IDs after authentication.",
                        cvss_score=5.3,
                        metadata={"cookie_name": cookie_name, "session_id": cookie_value[:20]}
                    )
                    findings.append(finding)
        
        return findings
    
    def _parse_auth_header(self, header: str) -> Optional[TokenInfo]:
        """تحليل Header المصادقة"""
        # Bearer token
        bearer_match = re.match(r'Bearer\s+(.+)', header, re.I)
        if bearer_match:
            token = bearer_match.group(1)
            return TokenInfo(token=token, type="bearer", location="header")
        
        # Basic auth
        basic_match = re.match(r'Basic\s+(.+)', header, re.I)
        if basic_match:
            token = basic_match.group(1)
            return TokenInfo(token=token, type="basic", location="header")
        
        return None
    
    async def _analyze_jwt_token(self, token_info: TokenInfo) -> List[Finding]:
        """تحليل توكن JWT"""
        findings = []
        
        try:
            # فك تشفير JWT بدون تحقق
            decoded = jwt.decode(token_info.token, options={"verify_signature": False})
            token_info.decoded = decoded
            
            # التحقق من الخوارزمية
            headers = jwt.get_unverified_header(token_info.token)
            algorithm = headers.get("alg", "unknown")
            token_info.algorithm = algorithm
            
            # خوارزمية none (ضعيفة جداً)
            if algorithm == "none":
                finding = self.add_finding(
                    vulnerability_type="JWT Algorithm Confusion (None Algorithm)",
                    severity=Severity.CRITICAL,
                    confidence=Confidence.CERTAIN,
                    url="",
                    description="JWT token uses 'none' algorithm which allows token forgery",
                    remediation="Never use 'none' algorithm. Use strong algorithms like RS256 or HS256 with strong secrets.",
                    cvss_score=9.1,
                    metadata={"algorithm": algorithm}
                )
                findings.append(finding)
            
            # التحقق من وجود معلومات حساسة
            sensitive_fields = ["password", "secret", "key", "token", "credit", "ssn"]
            for field in sensitive_fields:
                if field in decoded:
                    finding = self.add_finding(
                        vulnerability_type="Sensitive Information in JWT",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.HIGH,
                        url="",
                        description=f"JWT contains sensitive field: {field}",
                        remediation="Avoid storing sensitive data in JWTs. Use server-side sessions for sensitive information.",
                        cvss_score=4.3,
                        metadata={"sensitive_field": field}
                    )
                    findings.append(finding)
                    break
            
            # التحقق من انتهاء الصلاحية
            exp = decoded.get("exp")
            if exp:
                expiration = datetime.fromtimestamp(exp)
                token_info.expiration = expiration
                
                if expiration < datetime.now():
                    finding = self.add_finding(
                        vulnerability_type="Expired JWT Token",
                        severity=Severity.LOW,
                        confidence=Confidence.HIGH,
                        url="",
                        description="JWT token has already expired",
                        remediation="Implement proper token refresh mechanism.",
                        cvss_score=2.0,
                        metadata={"expiration": expiration.isoformat()}
                    )
                    findings.append(finding)
            
        except Exception as e:
            logger.debug(f"JWT decode error: {e}")
        
        return findings
    
    async def _test_weak_passwords_on_endpoints(self, base_url: str) -> List[Finding]:
        """اختبار كلمات مرور ضعيفة على نقاط النهاية"""
        findings = []
        session = await self._get_session()
        
        # نقاط نهاية تسجيل الدخول المعروفة
        login_endpoints = ["/login", "/api/login", "/auth/login", "/signin"]
        
        for endpoint in login_endpoints:
            test_url = f"{base_url}{endpoint}"
            
            # كلمات مرور ضعيفة للاختبار
            test_credentials = [
                ("admin", "admin"),
                ("admin", "password"),
                ("admin", "123456"),
                ("test", "test"),
                ("user", "user"),
            ]
            
            for username, password in test_credentials:
                try:
                    # محاولة تسجيل الدخول
                    login_data = {
                        "username": username,
                        "password": password,
                        "email": f"{username}@example.com"
                    }
                    
                    if HTTPX_AVAILABLE:
                        response = await session.post(test_url, data=login_data)
                        status_code = response.status_code
                    else:
                        async with session.post(test_url, data=login_data) as resp:
                            status_code = resp.status
                    
                    if status_code == 200 or status_code == 302:
                        finding = self.add_finding(
                            vulnerability_type="Weak Credentials",
                            severity=Severity.HIGH,
                            confidence=Confidence.HIGH,
                            url=test_url,
                            payload=f"username={username}&password={password}",
                            description=f"Login successful with weak credentials: {username}/{password}",
                            remediation="Enforce strong password policy. Implement account lockout after failed attempts. Use multi-factor authentication.",
                            cvss_score=7.5,
                            metadata={"username": username, "password": password}
                        )
                        findings.append(finding)
                        break
                        
                except Exception as e:
                    logger.debug(f"Login test error: {e}")
        
        return findings
    
    async def _test_session_fixation(self, base_url: str) -> List[Finding]:
        """اختبار Session Fixation"""
        findings = []
        session = await self._get_session()
        
        # توليد Session ID مخصص
        custom_session = secrets.token_hex(16)
        
        # إعداد الـ Cookie المخصص
        cookies = {"SESSIONID": custom_session}
        
        try:
            # الوصول إلى نقطة نهاية تتطلب مصادقة
            protected_endpoints = ["/profile", "/account", "/dashboard", "/admin"]
            
            for endpoint in protected_endpoints:
                test_url = f"{base_url}{endpoint}"
                
                if HTTPX_AVAILABLE:
                    response = await session.get(test_url, cookies=cookies)
                    set_cookie = response.headers.get("set-cookie", "")
                else:
                    async with session.get(test_url, cookies=cookies) as resp:
                        set_cookie = resp.headers.get("set-cookie", "")
                
                # إذا تم قبول الـ Session ID المخصص، قد يكون هناك ثغرة
                if custom_session in set_cookie or "SESSIONID=" in set_cookie:
                    finding = self.add_finding(
                        vulnerability_type="Session Fixation Vulnerability",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.MEDIUM,
                        url=test_url,
                        description="Application accepts user-defined session identifiers",
                        remediation="Regenerate session IDs after authentication. Never accept session IDs from untrusted sources.",
                        cvss_score=6.5,
                        metadata={"tested_session": custom_session}
                    )
                    findings.append(finding)
                    break
                    
        except Exception as e:
            logger.debug(f"Session fixation test error: {e}")
        
        return findings
    
    async def _analyze_password_policy(self, base_url: str) -> List[Finding]:
        """تحليل سياسة كلمات المرور"""
        findings = []
        
        # التحقق من وجود صفحة تسجيل
        register_url = f"{base_url}/register"
        session = await self._get_session()
        
        try:
            if HTTPX_AVAILABLE:
                response = await session.get(register_url)
                body = response.text
            else:
                async with session.get(register_url) as resp:
                    body = await resp.text()
            
            # البحث عن متطلبات كلمة المرور
            requirements = {
                "length": r"length.{0,10}\d",
                "uppercase": r"uppercase|capital",
                "lowercase": r"lowercase",
                "number": r"number|digit",
                "special": r"special|symbol",
            }
            
            found_requirements = []
            for req_name, pattern in requirements.items():
                if re.search(pattern, body, re.I):
                    found_requirements.append(req_name)
            
            # إذا لم تكن هناك متطلبات كافية
            if len(found_requirements) < 3:
                finding = self.add_finding(
                    vulnerability_type="Weak Password Policy",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.MEDIUM,
                    url=register_url,
                    description=f"Weak password policy detected. Missing requirements: {', '.join(set(requirements.keys()) - set(found_requirements))}",
                    remediation="Enforce strong password policy: minimum 8 characters, uppercase, lowercase, numbers, and special characters.",
                    cvss_score=5.0,
                    metadata={"found_requirements": found_requirements}
                )
                findings.append(finding)
            
        except Exception as e:
            logger.debug(f"Password policy analysis error: {e}")
        
        return findings
    
    def _is_weak_session_id(self, session_id: str) -> bool:
        """التحقق من قوة معرف الجلسة"""
        # معرف قصير جداً
        if len(session_id) < 16:
            return True
        
        # معرف عددي فقط
        if session_id.isdigit():
            return True
        
        # معرف بترتيب بسيط
        if session_id in ["1", "2", "3", "admin", "user", "test"]:
            return True
        
        return False
    
    async def generate_login_failure_report(self, findings: List[Finding]) -> str:
        """توليد تقرير بالفشل في المصادقة"""
        report = "🔐 Authentication Security Report\n"
        report += "=" * 40 + "\n\n"
        
        if not findings:
            report += "✅ No authentication vulnerabilities found.\n"
        else:
            report += f"⚠️ Found {len(findings)} authentication issues:\n\n"
            for i, finding in enumerate(findings, 1):
                report += f"{i}. [{finding.severity.value.upper()}] {finding.vulnerability_type}\n"
                report += f"   URL: {finding.url}\n"
                report += f"   Description: {finding.description}\n"
                report += f"   Remediation: {finding.remediation}\n\n"
        
        return report
    
    async def close(self):
        """إغلاق الجلسة"""
        if self._session:
            if HTTPX_AVAILABLE:
                await self._session.aclose()
            else:
                await self._session.close()
            self._session = None

