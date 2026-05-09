
import asyncio
import re
import json
from typing import Dict, List, Optional, Any, Set, Tuple
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
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
class APITest:
    """اختبار API"""
    name: str
    method: str  # GET, POST, PUT, DELETE, PATCH
    endpoint: str
    description: str
    expected_status: List[int] = None
    payload: Optional[Dict] = None


class APIScanner(BaseScanner):
    """
    فاحص ثغرات REST API
    
    الميزات:
    - اكتشاف نقاط نهاية API
    - اختبار التحكم في الوصول (IDOR, privilege escalation)
    - اختبار Mass Assignment
    - اكتشاف Rate Limiting
    - تحليل استجابات API بحثاً عن معلومات حساسة
    - اختبار Methods غير آمنة (PUT, DELETE, PATCH)
    - اكتشاف نسخ قديمة من API (versioning)
    - اختبار الأمان عبر Swagger/OpenAPI
    """
    
    # نقاط نهاية API شائعة
    COMMON_API_ENDPOINTS = [
        # الإصدارات العامة
        "/api", "/api/v1", "/api/v2", "/api/v3",
        "/rest", "/rest/v1", "/rest/v2",
        "/v1", "/v2", "/v3",
        
        # موارد شائعة
        "/api/users", "/api/user", "/api/account", "/api/profile",
        "/api/posts", "/api/comments", "/api/products", "/api/orders",
        "/api/admin", "/api/config", "/api/settings", "/api/metrics",
        "/api/auth", "/api/login", "/api/register", "/api/logout",
        
        # IDOR endpoints
        "/api/user/", "/api/users/", "/api/account/",
        "/api/profile/", "/api/order/", "/api/orders/",
        
        # Endpoints إضافية
        "/api/swagger", "/api/swagger.json", "/api/swagger.yaml",
        "/api/docs", "/api/documentation", "/api/openapi.json",
        "/api/health", "/api/status", "/api/ping",
    ]
    
    # أنماط معلومات حساسة في الردود
    SENSITIVE_PATTERNS = [
        (r"eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+", "JWT Token"),
        (r"Bearer\s+[a-zA-Z0-9_-]+", "Bearer Token"),
        (r"api[_-]?key[\s]*[:=][\s]*['\"]?[a-zA-Z0-9]+", "API Key"),
        (r"secret[\s]*[:=][\s]*['\"]?[a-zA-Z0-9]+", "Secret"),
        (r"password[\s]*[:=][\s]*['\"]?[a-zA-Z0-9]+", "Password"),
        (r"token[\s]*[:=][\s]*['\"]?[a-zA-Z0-9_\-\.]+", "Token"),
        (r"credit[_]?card|cc[_]?number|pan", "Credit Card"),
        (r"ssn|social[_]?security", "SSN"),
        (r"email[\s]*[:=][\s]*['\"]?[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", "Email"),
        (r"\d{3}[-.]?\d{2}[-.]?\d{4}", "SSN Pattern"),
        (r"\b\d{16}\b", "Credit Card (16 digits)"),
    ]
    
    def __init__(
        self,
        rate_limit: float = 2.0,
        timeout: int = 30,
        max_retries: int = 2,
        test_idor: bool = True,
        test_mass_assignment: bool = True,
        detect_rate_limiting: bool = True,
        max_ids_to_test: int = 10
    ):
        super().__init__(
            name="APIScanner",
            rate_limit=rate_limit,
            timeout=timeout,
            max_retries=max_retries
        )
        self._test_idor = test_idor
        self._test_mass_assignment = test_mass_assignment
        self._detect_rate_limiting = detect_rate_limiting
        self._max_ids_to_test = max_ids_to_test
        self._session = None
        self._tested_endpoints: Set[str] = set()
        self._discovered_endpoints: Set[str] = set()
    
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
        """التحقق من وجود API endpoint"""
        url = context.target.url.lower()
        
        for endpoint in self.COMMON_API_ENDPOINTS:
            if endpoint in url:
                return True
        
        return "/api/" in url or "/rest/" in url or "/v1/" in url or "/v2/" in url
    
    async def scan(self, context: ScanContext) -> List[Finding]:
        """تنفيذ فحص API"""
        findings = []
        base_url = context.target.url.rstrip('/')
        parsed = urlparse(base_url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        
        # 1. اكتشاف نقاط نهاية API
        api_endpoints = await self._discover_api_endpoints(base, context)
        self._discovered_endpoints.update(api_endpoints)
        
        for endpoint in api_endpoints:
            if endpoint in self._tested_endpoints:
                continue
            
            self._tested_endpoints.add(endpoint)
            
            # 2. اختبار الأساليب HTTP المختلفة
            methods_findings = await self._test_http_methods(endpoint, context)
            findings.extend(methods_findings)
            
            # 3. اختبار IDOR (الوصول غير المصرح به)
            if self._test_idor and "{id}" in endpoint or "/user/" in endpoint or "/users/" in endpoint:
                idor_findings = await self._test_idor_vulnerability(endpoint, context)
                findings.extend(idor_findings)
            
            # 4. تحليل الردود بحثاً عن معلومات حساسة
            sensitive_findings = await self._analyze_response_for_sensitive_data(endpoint, context)
            findings.extend(sensitive_findings)
            
            # 5. اختبار Mass Assignment
            if self._test_mass_assignment and (endpoint.endswith("/user") or endpoint.endswith("/users") or "/profile" in endpoint):
                mass_findings = await self._test_mass_assignment(endpoint, context)
                findings.extend(mass_findings)
        
        # 6. اكتشاف Rate Limiting
        if self._detect_rate_limiting:
            rate_findings = await self._test_rate_limiting(base, context)
            findings.extend(rate_findings)
        
        # 7. فحص Swagger/OpenAPI documentation
        swagger_findings = await self._check_swagger_documentation(base, context)
        findings.extend(swagger_findings)
        
        return findings
    
    async def _discover_api_endpoints(self, base_url: str, context: ScanContext) -> List[str]:
        """اكتشاف نقاط نهاية API"""
        endpoints = []
        
        for endpoint in self.COMMON_API_ENDPOINTS:
            test_url = f"{base_url}{endpoint}"
            
            async with self._get_session() as session:
                try:
                    if HTTPX_AVAILABLE:
                        response = await session.get(test_url, headers=context.target.headers)
                        if response.status_code in [200, 201, 401, 403]:
                            endpoints.append(test_url)
                            logger.info(f"Discovered API endpoint: {test_url}")
                    else:
                        async with session.get(test_url, headers=context.target.headers) as resp:
                            if resp.status in [200, 201, 401, 403]:
                                endpoints.append(test_url)
                                logger.info(f"Discovered API endpoint: {test_url}")
                except:
                    pass
        
        return endpoints
    
    async def _test_http_methods(self, endpoint: str, context: ScanContext) -> List[Finding]:
        """اختبار أساليب HTTP المختلفة"""
        findings = []
        methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]
        
        for method in methods:
            async with self._get_session() as session:
                try:
                    if HTTPX_AVAILABLE:
                        response = await session.request(
                            method, endpoint,
                            headers=context.target.headers,
                            json={"test": "value"} if method in ["POST", "PUT", "PATCH"] else None
                        )
                        status_code = response.status_code
                    else:
                        # aiohttp fallback
                        if method in ["POST", "PUT", "PATCH"]:
                            async with session.request(method, endpoint, headers=context.target.headers, json={"test": "value"}) as resp:
                                status_code = resp.status
                        else:
                            async with session.request(method, endpoint, headers=context.target.headers) as resp:
                                status_code = resp.status
                    
                    # التحقق من الأساليب غير الآمنة المتاحة
                    if method in ["PUT", "DELETE", "PATCH"] and status_code in [200, 201, 202, 204]:
                        finding = self.add_finding(
                            vulnerability_type="Unsafe HTTP Method Enabled",
                            severity=Severity.MEDIUM,
                            confidence=Confidence.HIGH,
                            url=endpoint,
                            payload=method,
                            evidence=f"HTTP {method} method is enabled and returned {status_code}",
                            description=f"The API endpoint accepts {method} requests which may allow unauthorized modifications.",
                            remediation="Disable unused HTTP methods. Implement proper authentication and authorization for all methods.",
                            cvss_score=6.5,
                            metadata={"method": method, "status_code": status_code}
                        )
                        findings.append(finding)
                        
                except Exception as e:
                    logger.debug(f"Error testing {method} on {endpoint}: {e}")
        
        return findings
    
    async def _test_idor_vulnerability(self, endpoint: str, context: ScanContext) -> List[Finding]:
        """اختبار IDOR في API"""
        findings = []
        
        # استخراج معرفات رقمية من الـ URL
        numbers = re.findall(r'\b\d+\b', endpoint)
        
        for num in numbers[:self._max_ids_to_test]:
            num_int = int(num)
            
            # اختبار المعرف التالي
            next_id = str(num_int + 1)
            test_url = endpoint.replace(num, next_id)
            
            try:
                async with self._get_session() as session:
                    if HTTPX_AVAILABLE:
                        response = await session.get(test_url, headers=context.target.headers)
                        status_code = response.status_code
                        body = response.text
                    else:
                        async with session.get(test_url, headers=context.target.headers) as resp:
                            status_code = resp.status
                            body = await resp.text()
                    
                    # إذا نجح الوصول إلى معرف آخر
                    if status_code == 200 and len(body) > 0:
                        # التحقق من وجود بيانات لمستخدم آخر
                        if "user" in body.lower() or "email" in body.lower():
                            finding = self.add_finding(
                                vulnerability_type="IDOR in API",
                                severity=Severity.HIGH,
                                confidence=Confidence.HIGH,
                                url=test_url,
                                payload=f"ID changed from {num} to {next_id}",
                                evidence=f"Accessed resource with modified ID {next_id}. Status: {status_code}",
                                description=f"IDOR vulnerability discovered. Able to access other resources by changing ID from {num} to {next_id}.",
                                remediation="Implement proper authorization checks for each resource. Use UUIDs instead of sequential IDs.",
                                cvss_score=7.5,
                                metadata={"original_id": num, "tested_id": next_id}
                            )
                            findings.append(finding)
                            break
                            
            except Exception as e:
                logger.debug(f"IDOR test error on {test_url}: {e}")
        
        return findings
    
    async def _test_mass_assignment(self, endpoint: str, context: ScanContext) -> List[Finding]:
        """اختبار Mass Assignment في API"""
        findings = []
        
        # ميدانات إضافية للاختبار (قد تكون محظورة)
        extra_fields = [
            {"is_admin": True, "role": "admin"},
            {"is_admin": True},
            {"role": "admin"},
            {"is_active": True},
            {"is_verified": True},
            {"permissions": ["admin"]},
            {"is_superuser": True},
            {"is_staff": True},
        ]
        
        # الحصول على الميدانات الحالية من GET request أولاً (إذا أمكن)
        current_fields = {}
        try:
            async with self._get_session() as session:
                if HTTPX_AVAILABLE:
                    response = await session.get(endpoint, headers=context.target.headers)
                    if response.status_code == 200:
                        try:
                            data = response.json()
                            if isinstance(data, dict):
                                current_fields = data
                        except:
                            pass
                else:
                    async with session.get(endpoint, headers=context.target.headers) as resp:
                        if resp.status == 200:
                            try:
                                data = await resp.json()
                                if isinstance(data, dict):
                                    current_fields = data
                            except:
                                pass
        except:
            pass
        
        # اختبار كل مجموعة من الميدانات الإضافية
        for extra in extra_fields:
            test_data = current_fields.copy()
            test_data.update(extra)
            
            try:
                async with self._get_session() as session:
                    if HTTPX_AVAILABLE:
                        response = await session.put(endpoint, json=test_data, headers=context.target.headers)
                        status_code = response.status_code
                    else:
                        async with session.put(endpoint, json=test_data, headers=context.target.headers) as resp:
                            status_code = resp.status
                    
                    # إذا نجح الطلب، قد يكون هناك Mass Assignment
                    if status_code in [200, 201, 202, 204]:
                        finding = self.add_finding(
                            vulnerability_type="Mass Assignment Vulnerability",
                            severity=Severity.HIGH,
                            confidence=Confidence.MEDIUM,
                            url=endpoint,
                            payload=json.dumps(extra),
                            evidence=f"PUT request with extra fields succeeded. Status: {status_code}",
                            description=f"Potential mass assignment vulnerability. The API accepts extra fields: {list(extra.keys())}",
                            remediation="Use allowlists for allowed fields. Do not automatically bind all request data to models.",
                            cvss_score=7.5,
                            metadata={"extra_fields": list(extra.keys()), "status_code": status_code}
                        )
                        findings.append(finding)
                        break
                        
            except Exception as e:
                logger.debug(f"Mass assignment test error: {e}")
        
        return findings
    
    async def _analyze_response_for_sensitive_data(self, endpoint: str, context: ScanContext) -> List[Finding]:
        """تحليل استجابات API بحثاً عن معلومات حساسة"""
        findings = []
        
        try:
            async with self._get_session() as session:
                if HTTPX_AVAILABLE:
                    response = await session.get(endpoint, headers=context.target.headers)
                    body = response.text
                else:
                    async with session.get(endpoint, headers=context.target.headers) as resp:
                        body = await resp.text()
                
                # البحث عن أنماط معلومات حساسة
                for pattern, pattern_name in self.SENSITIVE_PATTERNS:
                    matches = re.findall(pattern, body, re.IGNORECASE)
                    if matches:
                        finding = self.add_finding(
                            vulnerability_type="Sensitive Information Leakage",
                            severity=Severity.MEDIUM,
                            confidence=Confidence.HIGH,
                            url=endpoint,
                            evidence=f"Found {len(matches)} instance(s) of {pattern_name}",
                            description=f"API response contains sensitive information: {pattern_name}",
                            remediation="Remove sensitive data from API responses. Implement data filtering for non-privileged users.",
                            cvss_score=5.3,
                            metadata={
                                "pattern": pattern_name,
                                "matches_count": len(matches),
                                "sample": matches[0] if matches else ""
                            }
                        )
                        findings.append(finding)
                        
        except Exception as e:
            logger.debug(f"Sensitive data analysis error on {endpoint}: {e}")
        
        return findings
    
    async def _test_rate_limiting(self, base_url: str, context: ScanContext) -> List[Finding]:
        """اختبار وجود Rate Limiting في API"""
        findings = []
        
        # نقطة نهاية للاختبار
        test_endpoint = f"{base_url}/api/users"
        
        success_count = 0
        rate_limited = False
        
        # إرسال 20 طلب سريعاً
        for i in range(20):
            try:
                async with self._get_session() as session:
                    if HTTPX_AVAILABLE:
                        response = await session.get(test_endpoint, headers=context.target.headers)
                        status_code = response.status_code
                    else:
                        async with session.get(test_endpoint, headers=context.target.headers) as resp:
                            status_code = resp.status
                    
                    if status_code == 200:
                        success_count += 1
                    elif status_code in [429, 503]:
                        rate_limited = True
                        break
                        
            except Exception:
                pass
        
        if not rate_limited and success_count == 20:
            finding = self.add_finding(
                vulnerability_type="Missing Rate Limiting",
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                url=test_endpoint,
                description="API endpoint does not implement rate limiting, making it vulnerable to brute force and DoS attacks.",
                remediation="Implement rate limiting using tools like Redis, NGINX rate limiting, or API gateway solutions.",
                cvss_score=5.3,
                metadata={"tested_requests": 20, "success_count": success_count}
            )
            findings.append(finding)
        
        return findings
    
    async def _check_swagger_documentation(self, base_url: str, context: ScanContext) -> List[Finding]:
        """التحقق من وجود Swagger/OpenAPI documentation"""
        findings = []
        
        swagger_paths = [
            "/swagger", "/swagger.json", "/swagger.yaml",
            "/openapi", "/openapi.json", "/openapi.yaml",
            "/api-docs", "/api-docs.json", "/api-docs.yaml",
            "/docs", "/documentation",
        ]
        
        for swagger_path in swagger_paths:
            test_url = f"{base_url}{swagger_path}"
            
            try:
                async with self._get_session() as session:
                    if HTTPX_AVAILABLE:
                        response = await session.get(test_url, headers=context.target.headers)
                        if response.status_code == 200:
                            finding = self.add_finding(
                                vulnerability_type="Exposed API Documentation",
                                severity=Severity.INFO,
                                confidence=Confidence.HIGH,
                                url=test_url,
                                description=f"API documentation exposed at {test_url}. This may reveal sensitive API endpoints.",
                                remediation="Restrict access to API documentation in production environments or implement authentication.",
                                cvss_score=2.0,
                                metadata={"documentation_path": swagger_path}
                            )
                            findings.append(finding)
                            break
                            
                    else:
                        async with session.get(test_url, headers=context.target.headers) as resp:
                            if resp.status == 200:
                                finding = self.add_finding(
                                    vulnerability_type="Exposed API Documentation",
                                    severity=Severity.INFO,
                                    confidence=Confidence.HIGH,
                                    url=test_url,
                                    description=f"API documentation exposed at {test_url}",
                                    remediation="Restrict access to API documentation in production.",
                                    cvss_score=2.0,
                                    metadata={"documentation_path": swagger_path}
                                )
                                findings.append(finding)
                                break
                                
            except Exception:
                pass
        
        return findings
    
    async def close(self):
        """إغلاق الجلسة"""
        if self._session:
            if HTTPX_AVAILABLE:
                await self._session.aclose()
            else:
                await self._session.close()
            self._session = None

