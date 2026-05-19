"""
IDOR Scanner - فاحص ثغرات Insecure Direct Object References
"""

import asyncio
import re
import json
from typing import Dict, List, Optional, Any, Set, Tuple
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from dataclasses import dataclass
from collections import defaultdict

from .base_scanner import BaseScanner, ScanContext, Finding, Severity, Confidence

import logging

logger = logging.getLogger(__name__)


@dataclass
class IDORPattern:
    """نمط IDOR"""
    name: str
    pattern: str
    id_type: str
    examples: List[str]
    risk_level: str


class IDORScanner(BaseScanner):
    """
    فاحص ثغرات Insecure Direct Object References (IDOR)
    
    يفحص endpoints اللي فيها user IDs حقيقية فقط
    """
    
    # الكلمات اللي بتدل على user objects
    USER_PATTERNS = [
        '/user/', '/users/', '/profile/', '/account/',
        '/member/', '/customer/', '/admin/',
        '/api/user/', '/api/users/', '/api/profile/',
    ]
    
    # أسماء parameters اللي بتحتوي على user ID
    USER_ID_PARAMS = ['id', 'user_id', 'uid', 'user', 'account_id', 'customer_id']
    
    COMMON_ENDPOINTS = [
        "/user/", "/users/", "/profile/", "/account/",
        "/api/user/", "/api/users/", "/api/profile/",
    ]
    
    def __init__(
        self,
        rate_limit: float = 1.0,
        timeout: int = 15,
        max_retries: int = 1,
        test_increment: bool = True,
        test_decrement: bool = True
    ):
        super().__init__(
            name="IDORScanner",
            rate_limit=rate_limit,
            timeout=timeout,
            max_retries=max_retries
        )
        self._test_increment = test_increment
        self._test_decrement = test_decrement
        self._tested_endpoints: Set[str] = set()
    
    async def can_scan(self, context: ScanContext) -> bool:
        """نتأكد إن الـ URL محتمل يكون فيه IDOR حقيقي"""
        url = context.target.url.lower()
        parsed = urlparse(context.target.url)
        path = parsed.path.lower()
        
        # فحص الـ path
        for pattern in self.USER_PATTERNS:
            if pattern in path:
                return True
        
        # فحص الـ parameters
        params = parse_qs(parsed.query)
        for param in self.USER_ID_PARAMS:
            if param.lower() in [p.lower() for p in params.keys()]:
                return True
        
        return False
    
    async def scan(self, context: ScanContext) -> List[Finding]:
        findings = []
        url = context.target.url
        parsed = urlparse(url)
        
        # استخراج candidate IDs
        candidates = self._extract_id_candidates(parsed)
        
        if not candidates:
            return findings
        
        for param_name, current_value in candidates:
            if not current_value.isdigit():
                continue
            
            current_id = int(current_value)
            
            # تجربة IDs مختلفة
            test_deltas = []
            if self._test_increment:
                test_deltas.extend([1, 2])
            if self._test_decrement:
                test_deltas.extend([-1])
            
            for delta in test_deltas:
                test_id = current_id + delta
                if test_id <= 0:
                    continue
                
                test_url = self._build_test_url(parsed, param_name, str(test_id))
                
                try:
                    response_text = await self.send_request(test_url, method="GET")
                    
                    if response_text and len(response_text) > 100:
                        # فحص لو الاستجابة فيها بيانات مستخدم تاني
                        indicators = ['user', 'email', '@', 'username', 'profile', 'account']
                        found = [i for i in indicators if i in response_text.lower()]
                        
                        if len(found) >= 2:
                            finding = self.add_finding(
                                vulnerability_type="Insecure Direct Object Reference (IDOR)",
                                severity=Severity.HIGH,
                                confidence=Confidence.HIGH,
                                url=test_url,
                                parameter=param_name,
                                payload=f"ID: {current_value} → {test_id}",
                                evidence=f"Response contains: {', '.join(found)}",
                                description=f"IDOR: Accessing ID {test_id} returned user data",
                                remediation="Implement per-resource authorization checks",
                                cvss_score=7.5,
                                metadata={"original_id": current_value, "tested_id": test_id}
                            )
                            findings.append(finding)
                            break
                            
                except Exception as e:
                    logger.debug(f"IDOR test failed for {test_url}: {e}")
        
        return findings
    
    def _extract_id_candidates(self, parsed) -> List[tuple]:
        """استخراج candidate IDs من الـ URL"""
        candidates = []
        path = parsed.path.lower()
        
        # فحص الـ path - نبحث عن رقم بعد user patterns
        for pattern in self.USER_PATTERNS:
            if pattern in path:
                # استخراج الرقم اللي بعد الـ pattern
                idx = path.find(pattern) + len(pattern)
                remaining = path[idx:]
                parts = remaining.split('/')
                if parts and parts[0].isdigit():
                    candidates.append((f"path_{pattern}", parts[0]))
        
        # فحص الـ query parameters
        params = parse_qs(parsed.query)
        for param in self.USER_ID_PARAMS:
            if param in params:
                candidates.append((param, params[param][0]))
        
        return candidates
    
    def _build_test_url(self, parsed, param_name: str, new_value: str) -> str:
        """بناء URL مع ID جديد"""
        if param_name.startswith('path_'):
            pattern = param_name.replace('path_', '')
            path = parsed.path.lower()
            idx = path.find(pattern) + len(pattern)
            
            old_path = parsed.path
            remaining = old_path[idx:]
            parts = remaining.split('/')
            parts[0] = new_value
            new_path = old_path[:idx] + '/'.join(parts)
            
            return urlunparse(parsed._replace(path=new_path))
        else:
            params = parse_qs(parsed.query)
            params[param_name] = [new_value]
            new_query = urlencode(params, doseq=True)
            return urlunparse(parsed._replace(query=new_query))
