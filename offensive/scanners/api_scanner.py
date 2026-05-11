import asyncio
import re
import json
from typing import Dict, List, Optional, Any, Set, Tuple
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from dataclasses import dataclass

from .base_scanner import BaseScanner, ScanContext, Finding, Severity, Confidence

import logging

logger = logging.getLogger(__name__)


@dataclass
class APITest:
    """اختبار API"""
    name: str
    method: str
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
    
    COMMON_API_ENDPOINTS = [
        "/api", "/api/v1", "/api/v2", "/api/v3",
        "/rest", "/rest/v1", "/rest/v2",
        "/v1", "/v2", "/v3",
        "/api/users", "/api/user", "/api/account", "/api/profile",
        "/api/posts", "/api/comments", "/api/products", "/api/orders",
        "/api/admin", "/api/config", "/api/settings", "/api/metrics",
        "/api/auth", "/api/login", "/api/register", "/api/logout",
        "/api/user/", "/api/users/", "/api/account/",
        "/api/profile/", "/api/order/", "/api/orders/",
        "/api/swagger", "/api/swagger.json", "/api/swagger.yaml",
        "/api/docs", "/api/documentation", "/api/openapi.json",
        "/api/health", "/api/status", "/api/ping",
    ]
    
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
        self._tested_endpoints: Set[str] = set()
        self._discovered_endpoints: Set[str] = set()
    
    async def can_scan(self, context: ScanContext) -> bool:
        url = context.target.url.lower()
        
        for endpoint in self.COMMON_API_ENDPOINTS:
            if endpoint in url:
                return True
        
        return "/api/" in url or "/rest/" in url or "/v1/" in url or "/v2/" in url
    
    async def scan(self, context: ScanContext) -> List[Finding]:
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
            
            # 3. اختبار IDOR
            if self._test_idor and ("{id}" in endpoint or "/user/" in endpoint or "/users/" in endpoint):
                idor_findings = await self._test_idor_vulnerability(endpoint, context)
                findings.extend(idor_findings)
            
            # 4. تحليل الردود
            sensitive_findings = await self._analyze_response_for_sensitive_data(endpoint, context)
            findings.extend(sensitive_findings)
            
            # 5. اختبار Mass Assignment
            if self._test_mass_assignment and (endpoint.endswith("/user") or endpoint.endswith("/users") or "/profile" in endpoint):
                mass_findings = await self._test_mass_assignment(endpoint, context)
                findings.extend(mass_findings)
        
        # 6. Rate Limiting
        if self._detect_rate_limiting:
            rate_findings = await self._test_rate_limiting(base, context)
            findings.extend(rate_findings)
        
        # 7. Swagger
        swagger_findings = await self._check_swagger_documentation(base, context)
        findings.extend(swagger_findings)
        
        return findings
    
    async def _discover_api_endpoints(self, base_url: str, context: ScanContext) -> List[str]:
        endpoints = []
        
        for endpoint in self.COMMON_API_ENDPOINTS:
            test_url = f"{base_url}{endpoint}"
            
            response_text = await self.send_request(test_url, method="GET")
            
            if response_text is not None:
                endpoints.append(test_url)
                logger.info(f"Discovered API endpoint: {test_url}")
        
        return endpoints
    
    async def _test_http_methods(self, endpoint: str, context: ScanContext) -> List[Finding]:
        findings = []
        methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]
        
        for method in methods:
            try:
                response_text = await self.send_request(
                    endpoint, 
                    method=method,
                    json_data={"test": "value"} if method in ["POST", "PUT", "PATCH"] else None
                )
                
                if response_text is not None:
                    if method in ["PUT", "DELETE", "PATCH"]:
                        finding = self.add_finding(
                            vulnerability_type="Unsafe HTTP Method Enabled",
                            severity=Severity.MEDIUM,
                            confidence=Confidence.HIGH,
                            url=endpoint,
                            payload=method,
                            evidence=f"HTTP {method} method is enabled",
                            description=f"The API endpoint accepts {method} requests which may allow unauthorized modifications.",
                            remediation="Disable unused HTTP methods. Implement proper authentication and authorization for all methods.",
                            cvss_score=6.5,
                            metadata={"method": method}
                        )
                        findings.append(finding)
                        
            except Exception as e:
                logger.debug(f"Error testing {method} on {endpoint}: {e}")
        
        return findings
    
    async def _test_idor_vulnerability(self, endpoint: str, context: ScanContext) -> List[Finding]:
        findings = []
        numbers = re.findall(r'\b\d+\b', endpoint)
        
        for num in numbers[:self._max_ids_to_test]:
            num_int = int(num)
            next_id = str(num_int + 1)
            test_url = endpoint.replace(num, next_id)
            
            response_text = await self.send_request(test_url, method="GET")
            
            if response_text and len(response_text) > 0:
                if "user" in response_text.lower() or "email" in response_text.lower():
                    finding = self.add_finding(
                        vulnerability_type="IDOR in API",
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        url=test_url,
                        payload=f"ID changed from {num} to {next_id}",
                        evidence=f"Accessed resource with modified ID {next_id}",
                        description=f"IDOR vulnerability discovered. Able to access other resources by changing ID.",
                        remediation="Implement proper authorization checks for each resource. Use UUIDs instead of sequential IDs.",
                        cvss_score=7.5,
                        metadata={"original_id": num, "tested_id": next_id}
                    )
                    findings.append(finding)
                    break
        
        return findings
    
    async def _test_mass_assignment(self, endpoint: str, context: ScanContext) -> List[Finding]:
        findings = []
        
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
        
        current_fields = {}
        response_text = await self.send_request(endpoint, method="GET")
        
        if response_text:
            try:
                data = json.loads(response_text)
                if isinstance(data, dict):
                    current_fields = data
            except:
                pass
        
        for extra in extra_fields:
            test_data = current_fields.copy()
            test_data.update(extra)
            
            response_text = await self.send_request(
                endpoint, 
                method="PUT",
                json_data=test_data
            )
            
            if response_text is not None:
                finding = self.add_finding(
                    vulnerability_type="Mass Assignment Vulnerability",
                    severity=Severity.HIGH,
                    confidence=Confidence.MEDIUM,
                    url=endpoint,
                    payload=json.dumps(extra),
                    evidence=f"PUT request with extra fields succeeded",
                    description=f"Potential mass assignment vulnerability. The API accepts extra fields: {list(extra.keys())}",
                    remediation="Use allowlists for allowed fields. Do not automatically bind all request data to models.",
                    cvss_score=7.5,
                    metadata={"extra_fields": list(extra.keys())}
                )
                findings.append(finding)
                break
        
        return findings
    
    async def _analyze_response_for_sensitive_data(self, endpoint: str, context: ScanContext) -> List[Finding]:
        findings = []
        
        response_text = await self.send_request(endpoint, method="GET")
        
        if response_text:
            for pattern, pattern_name in self.SENSITIVE_PATTERNS:
                matches = re.findall(pattern, response_text, re.IGNORECASE)
                if matches:
                    finding = self.add_finding(
                        vulnerability_type="Sensitive Information Leakage",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.HIGH,
                        url=endpoint,
                        evidence=f"Found {len(matches)} instance(s) of {pattern_name}",
                        description=f"API response contains sensitive information: {pattern_name}",
                        remediation="Remove sensitive data from API responses.",
                        cvss_score=5.3,
                        metadata={
                            "pattern": pattern_name,
                            "matches_count": len(matches),
                            "sample": matches[0] if matches else ""
                        }
                    )
                    findings.append(finding)
        
        return findings
    
    async def _test_rate_limiting(self, base_url: str, context: ScanContext) -> List[Finding]:
        findings = []
        test_endpoint = f"{base_url}/api/users"
        
        success_count = 0
        rate_limited = False
        
        for i in range(20):
            response_text = await self.send_request(test_endpoint, method="GET")
            
            if response_text is not None:
                success_count += 1
            else:
                rate_limited = True
                break
        
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
        findings = []
        
        swagger_paths = [
            "/swagger", "/swagger.json", "/swagger.yaml",
            "/openapi", "/openapi.json", "/openapi.yaml",
            "/api-docs", "/api-docs.json", "/api-docs.yaml",
            "/docs", "/documentation",
        ]
        
        for swagger_path in swagger_paths:
            test_url = f"{base_url}{swagger_path}"
            
            response_text = await self.send_request(test_url, method="GET")
            
            if response_text:
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
        
        return findings
