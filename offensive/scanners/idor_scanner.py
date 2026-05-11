import asyncio
import re
import json
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
class IDORPattern:
    name: str
    pattern: str
    id_type: str
    examples: List[str]
    risk_level: str


class IDORScanner(BaseScanner):
    """
    فاحص ثغرات Insecure Direct Object References (IDOR)
    """
    
    ID_PATTERNS = {
        "numeric": re.compile(r'\b([0-9]{1,10})\b'),
        "uuid": re.compile(r'\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b', re.I),
        "hash_md5": re.compile(r'\b[0-9a-f]{32}\b', re.I),
        "hash_sha1": re.compile(r'\b[0-9a-f]{40}\b', re.I),
    }
    
    COMMON_ENDPOINTS = [
        "/user/", "/users/", "/profile/", "/account/",
        "/order/", "/orders/", "/invoice/", "/payment/",
        "/api/user/", "/api/users/", "/api/profile/",
        "/api/order/", "/api/orders/", "/api/invoice/",
    ]
    
    def __init__(
        self,
        rate_limit: float = 2.0,
        timeout: int = 30,
        max_retries: int = 2,
        test_increment: bool = True,
        test_decrement: bool = True,
        extract_ids_from_responses: bool = True
    ):
        super().__init__(
            name="IDORScanner",
            rate_limit=rate_limit,
            timeout=timeout,
            max_retries=max_retries
        )
        self._test_increment = test_increment
        self._test_decrement = test_decrement
        self._extract_ids_from_responses = extract_ids_from_responses
        self._session = None
        self._tested_endpoints: Set[str] = set()
        self._discovered_ids: Dict[str, Set[str]] = defaultdict(set)
    
    async def can_scan(self, context: ScanContext) -> bool:
        url = context.target.url
        parsed = urlparse(url)
        path = parsed.path
        
        for endpoint in self.COMMON_ENDPOINTS:
            if endpoint in path:
                return True
        
        params = parse_qs(parsed.query)
        for value in params.values():
            if value and value[0].isdigit():
                return True
        
        return False
    
    async def scan(self, context: ScanContext) -> List[Finding]:
        findings = []
        url = context.target.url
        
        # تحليل URL الحالي
        url_findings = await self._analyze_url(context, url)
        findings.extend(url_findings)
        
        # اختبار نقاط النهاية الشائعة
        endpoint_findings = await self._test_common_endpoints(context)
        findings.extend(endpoint_findings)
        
        # اختبار المعرفات التزايدية
        if self._test_increment or self._test_decrement:
            incremental_findings = await self._test_incremental_ids(context)
            findings.extend(incremental_findings)
        
        return findings
    
    async def _analyze_url(self, context: ScanContext, url: str) -> List[Finding]:
        findings = []
        parsed = urlparse(url)
        
        # فحص المعاملات
        params = parse_qs(parsed.query)
        for param_name, param_values in params.items():
            for value in param_values:
                for id_type, pattern in self.ID_PATTERNS.items():
                    match = pattern.search(value)
                    if match:
                        modified_finding = await self._test_id_modification(
                            context, param_name, value, match.group(), id_type
                        )
                        if modified_finding:
                            findings.append(modified_finding)
        
        # فحص مسار URL
        path_parts = parsed.path.split('/')
        for i, part in enumerate(path_parts):
            for id_type, pattern in self.ID_PATTERNS.items():
                match = pattern.search(part)
                if match and match.group().isdigit():
                    original_id = match.group()
                    num_int = int(original_id)
                    
                    if self._test_increment:
                        new_id = str(num_int + 1)
                        modified_parts = path_parts.copy()
                        modified_parts[i] = part.replace(original_id, new_id)
                        test_url = urlunparse(parsed._replace(path='/'.join(modified_parts)))
                        
                        response_text = await self.send_request(test_url, method="GET")
                        if response_text and len(response_text) > 50:
                            finding = self.add_finding(
                                vulnerability_type="Insecure Direct Object Reference (IDOR)",
                                severity=Severity.HIGH,
                                confidence=Confidence.HIGH,
                                url=test_url,
                                parameter=param_name,
                                payload=f"ID modified from {original_id} to {new_id}",
                                description=f"IDOR vulnerability discovered. Able to access other resources by changing ID.",
                                remediation="Implement proper access control checks.",
                                cvss_score=6.5,
                                metadata={"original_id": original_id, "modified_id": new_id}
                            )
                            findings.append(finding)
                    
                    if self._test_decrement and num_int > 1:
                        new_id = str(num_int - 1)
                        modified_parts = path_parts.copy()
                        modified_parts[i] = part.replace(original_id, new_id)
                        test_url = urlunparse(parsed._replace(path='/'.join(modified_parts)))
                        
                        response_text = await self.send_request(test_url, method="GET")
                        if response_text and len(response_text) > 50:
                            finding = self.add_finding(
                                vulnerability_type="Insecure Direct Object Reference (IDOR)",
                                severity=Severity.HIGH,
                                confidence=Confidence.HIGH,
                                url=test_url,
                                parameter=param_name,
                                payload=f"ID modified from {original_id} to {new_id}",
                                description=f"IDOR vulnerability discovered.",
                                remediation="Implement proper access control checks.",
                                cvss_score=6.5,
                                metadata={"original_id": original_id, "modified_id": new_id}
                            )
                            findings.append(finding)
        
        return findings
    
    async def _test_id_modification(
        self,
        context: ScanContext,
        param_name: str,
        original_value: str,
        extracted_id: str,
        id_type: str
    ) -> Optional[Finding]:
        if not extracted_id.isdigit():
            return None
        
        if self._test_increment:
            new_id = str(int(extracted_id) + 1)
            parsed = urlparse(context.target.url)
            params = parse_qs(parsed.query)
            
            if param_name in params:
                params[param_name] = [new_id]
                new_query = urlencode(params, doseq=True)
                test_url = urlunparse(parsed._replace(query=new_query))
                
                response_text = await self.send_request(test_url, method="GET")
                if response_text and len(response_text) > 50:
                    return self.add_finding(
                        vulnerability_type="Insecure Direct Object Reference (IDOR)",
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        url=test_url,
                        parameter=param_name,
                        payload=f"ID modified from {extracted_id} to {new_id}",
                        description="IDOR vulnerability discovered.",
                        remediation="Implement proper access control checks.",
                        cvss_score=6.5,
                        metadata={"original_id": extracted_id, "modified_id": new_id}
                    )
        
        return None
    
    async def _test_common_endpoints(self, context: ScanContext) -> List[Finding]:
        findings = []
        base_url = context.target.url.rstrip('/')
        
        for endpoint in self.COMMON_ENDPOINTS:
            test_ids = [1, 2, 3, 100]
            
            for test_id in test_ids:
                test_url = f"{base_url}{endpoint}{test_id}"
                
                response_text = await self.send_request(test_url, method="GET")
                
                if response_text and len(response_text) > 100:
                    if "user" in response_text.lower() or "email" in response_text.lower():
                        finding = self.add_finding(
                            vulnerability_type="Insecure Direct Object Reference (IDOR)",
                            severity=Severity.MEDIUM,
                            confidence=Confidence.TENTATIVE,
                            url=test_url,
                            description=f"Potential IDOR at {endpoint} with ID {test_id}",
                            remediation="Implement proper access control checks.",
                            cvss_score=5.3,
                            metadata={"endpoint": endpoint, "tested_id": test_id}
                        )
                        findings.append(finding)
        
        return findings
    
    async def _test_incremental_ids(self, context: ScanContext) -> List[Finding]:
        findings = []
        base_url = context.target.url
        parsed = urlparse(base_url)
        path = parsed.path
        
        numbers = re.findall(r'\b\d{3,}\b', path)
        
        for num in numbers:
            num_int = int(num)
            
            if self._test_increment:
                next_id = str(num_int + 1)
                test_url = base_url.replace(num, next_id)
                
                if test_url != base_url:
                    response_text = await self.send_request(test_url, method="GET")
                    if response_text and len(response_text) > 50:
                        finding = self.add_finding(
                            vulnerability_type="Insecure Direct Object Reference (IDOR)",
                            severity=Severity.HIGH,
                            confidence=Confidence.HIGH,
                            url=test_url,
                            description="IDOR vulnerability discovered.",
                            remediation="Implement proper access control checks.",
                            cvss_score=6.5,
                            metadata={"original_id": num, "modified_id": next_id}
                        )
                        findings.append(finding)
            
            if self._test_decrement and num_int > 1:
                prev_id = str(num_int - 1)
                test_url = base_url.replace(num, prev_id)
                
                if test_url != base_url:
                    response_text = await self.send_request(test_url, method="GET")
                    if response_text and len(response_text) > 50:
                        finding = self.add_finding(
                            vulnerability_type="Insecure Direct Object Reference (IDOR)",
                            severity=Severity.HIGH,
                            confidence=Confidence.HIGH,
                            url=test_url,
                            description="IDOR vulnerability discovered.",
                            remediation="Implement proper access control checks.",
                            cvss_score=6.5,
                            metadata={"original_id": num, "modified_id": prev_id}
                        )
                        findings.append(finding)
        
        return findings
    
    async def close(self):
        if self._session:
            if HTTPX_AVAILABLE:
                await self._session.aclose()
            else:
                await self._session.close()
            self._session = None
