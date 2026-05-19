"""
API Scanner - فاحص ثغرات REST API (احترافي)
لا يخمّن endpoints - يفحص اللي موجود فقط
"""

import asyncio
import re
import json
from typing import Dict, List, Optional, Any, Set
from urllib.parse import urlparse
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


class APIScanner(BaseScanner):
    """
    فاحص ثغرات REST API - احترافي
    
    لا يخمّن endpoints عشوائية.
    يفحص فقط الـ endpoints اللي اكتشفها الـ crawler/smart orchestrator.
    """
    
    def __init__(
        self,
        rate_limit: float = 1.0,
        timeout: int = 15,
        max_retries: int = 1
    ):
        super().__init__(
            name="APIScanner",
            rate_limit=rate_limit,
            timeout=timeout,
            max_retries=max_retries
        )
    
    async def can_scan(self, context: ScanContext) -> bool:
        """نتأكد إن الـ URL فيه API endpoint حقيقي"""
        url = context.target.url.lower()
        # بنفحص بس لو الـ URL فعلاً فيه /api/ أو /rest/
        return '/api/' in url or '/rest/' in url or '/graphql' in url
    
    async def scan(self, context: ScanContext) -> List[Finding]:
        findings = []
        url = context.target.url
        
        # فحص بسيط: هل الـ endpoint بيرجع استجابة؟
        try:
            response_text = await self.send_request(url, method="GET")
            
            if response_text:
                # تحليل الردود
                sensitive = self._check_sensitive_data(response_text)
                if sensitive:
                    findings.append(sensitive)
                
                # فحص methods لو الـ endpoint شغال
                methods_findings = await self._check_methods(url)
                findings.extend(methods_findings)
                
        except Exception as e:
            logger.debug(f"API scan error for {url}: {e}")
        
        return findings
    
    def _check_sensitive_data(self, response_text: str) -> Optional[Finding]:
        """فحص وجود بيانات حساسة في الاستجابة"""
        sensitive_patterns = [
            (r"eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+", "JWT Token"),
            (r'"token"\s*:\s*"[^"]+"]', "Access Token"),
            (r'"password"\s*:\s*"[^"]+"]', "Password in Response"),
            (r'"secret"\s*:\s*"[^"]+"]', "Secret Key"),
            (r'"api[_-]?key"\s*:\s*"[^"]+"]', "API Key"),
        ]
        
        for pattern, name in sensitive_patterns:
            matches = re.findall(pattern, response_text, re.IGNORECASE)
            if matches:
                return self.add_finding(
                    vulnerability_type="Sensitive Information in API Response",
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    url="",
                    evidence=f"Found {name}",
                    description=f"API response contains {name}",
                    remediation="Remove sensitive data from API responses",
                    cvss_score=7.5,
                    metadata={"sensitive_type": name}
                )
        
        return None
    
    async def _check_methods(self, url: str) -> List[Finding]:
        """فحص methods غير آمنة"""
        findings = []
        unsafe_methods = ["PUT", "DELETE", "PATCH"]
        
        for method in unsafe_methods:
            try:
                response_text = await self.send_request(url, method=method)
                
                if response_text is not None:
                    # 405 = Method Not Allowed - ده طبيعي وآمن
                    # 200/201/204 = الطريقة شغالة - محتاجين نركز
                    # مش هنسجل findings دلوقتي عشان نقلل الـ noise
                    pass
                    
            except Exception:
                pass
        
        return findings
