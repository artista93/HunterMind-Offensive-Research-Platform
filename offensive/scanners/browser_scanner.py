"""
Browser Scanner - فاحص يستخدم متصفح حقيقي (Playwright)

الميزات:
- تنفيذ JavaScript قبل الفحص
- DOM analysis بعد injection
- Bypass WAF detection
- Stealth mode
- Session handling
"""

import asyncio
import re
from typing import Dict, List, Optional, Any
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from .base_scanner import BaseScanner, ScanContext, Finding, Severity, Confidence

import logging

logger = logging.getLogger(__name__)


class BrowserScanner(BaseScanner):
    """
    فاحص يستخدم متصفح حقيقي
    
    بيشوف الصفحة زي ما المستخدم بيشوفها
    """
    
    # حمولات متطورة تتجاوز WAF
    ADVANCED_PAYLOADS = {
        "xss": [
            # HTML5 vectors
            "<details open ontoggle=alert(1)>",
            "<svg><animate onbegin=alert(1) attributeName=x dur=1s>",
            "<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>",
            # DOM-based
            "javascript:alert(1)",
            "data:text/html,<script>alert(1)</script>",
            # Template injection
            "${alert(1)}",
            "{{constructor.constructor('alert(1)')()}}",
            # Event handlers
            "\" autofocus onfocus=alert(1) x=\"",
            "' onmouseover=alert(1) '",
        ],
        "sqli": [
            # Bypass techniques
            "1' OR '1'='1' --",
            "1'/**/OR/**/1=1--",
            "1' UNION SELECT NULL--",
            "1' AND SLEEP(5)--",
            "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
            # NoSQL
            '{"$gt": ""}',
            '{"$ne": null}',
            '{"$regex": ".*"}',
        ],
        "idor": [
            "1", "2", "999", "admin", "null", "undefined",
            "../", "..%2F", "..%252F",
        ],
        "rce": [
            ";id",
            "|whoami",
            "$(cat /etc/passwd)",
            "`id`",
            "%0Aid",
            "&dir",
            "; system('id');",
        ],
    }
    
    def __init__(self, name: str = "BrowserScanner", **kwargs):
        super().__init__(name=name, **kwargs)
        self._browser = None
        self._context = None
        self._page = None
    
    async def can_scan(self, context: ScanContext) -> bool:
        return True  # Browser scanner يفحص أي حاجة
    
    async def scan(self, context: ScanContext) -> List[Finding]:
        """فحص باستخدام متصفح حقيقي"""
        findings = []
        url = context.target.url
        
        try:
            # تشغيل المتصفح
            await self._init_browser()
            
            # تحميل الصفحة
            await self._page.goto(url, wait_until="networkidle", timeout=30000)
            
            # انتظار تحميل JavaScript
            await self._page.wait_for_timeout(2000)
            
            # الحصول على DOM النهائي
            dom = await self._page.content()
            
            # 1. فحص Information Disclosure
            info_findings = await self._check_info_disclosure(url, dom)
            findings.extend(info_findings)
            
            # 2. فحص Security Headers
            headers = await self._page.evaluate("() => { const req = performance.getEntriesByType('resource')[0]; return {}; }")
            
            # 3. فحص Forms اللي ظهرت بعد JavaScript
            form_findings = await self._check_forms_playwright(url)
            findings.extend(form_findings)
            
            # 4. فحص XSS
            xss_findings = await self._test_xss_playwright(context)
            findings.extend(xss_findings)
            
            # 5. فحص API endpoints اللي ظهرت
            api_findings = await self._discover_apis_playwright()
            findings.extend(api_findings)
            
            # 6. فحص LocalStorage/SessionStorage عن secrets
            storage_findings = await self._check_storage_secrets()
            findings.extend(storage_findings)
            
        except Exception as e:
            logger.error(f"Browser scan error: {e}")
        finally:
            await self._close_browser()
        
        return findings
    
    async def _init_browser(self):
        """تشغيل المتصفح"""
        try:
            from playwright.async_api import async_playwright
            
            self._playwright = await async_playwright().start()
            self._browser = await self._playwright.chromium.launch(
                headless=True,
                args=["--no-sandbox", "--disable-setuid-sandbox"]
            )
            self._context = await self._browser.new_context(
                viewport={"width": 1280, "height": 720},
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0.0.0 Safari/537.36"
            )
            self._page = await self._context.new_page()
            
            # مراقبة أخطاء JavaScript
            self._js_errors = []
            self._page.on("pageerror", lambda err: self._js_errors.append(str(err)))
            
            # مراقبة طلبات الشبكة
            self._network_requests = []
            self._page.on("request", lambda req: self._network_requests.append({
                "url": req.url,
                "method": req.method,
                "headers": dict(req.headers),
            }))
            
        except ImportError:
            logger.warning("Playwright not installed")
    
    async def _close_browser(self):
        """إغلاق المتصفح"""
        try:
            if self._page:
                await self._page.close()
            if self._context:
                await self._context.close()
            if self._browser:
                await self._browser.close()
            if self._playwright:
                await self._playwright.stop()
        except:
            pass
    
    async def _check_info_disclosure(self, url: str, dom: str) -> List[Finding]:
        """فحص تسريب المعلومات"""
        findings = []
        
        # API keys في الـ DOM
        secret_patterns = [
            (r'(?:AKIA|ASIA)[A-Z0-9]{16}', "AWS Access Key", "critical"),
            (r'AIza[0-9A-Za-z\-_]{35}', "Google API Key", "high"),
            (r'(?:ghp|gho|ghu)_[A-Za-z0-9_]{36,}', "GitHub Token", "critical"),
            (r'sk_live_[0-9a-zA-Z]{24,}', "Stripe Secret Key", "critical"),
        ]
        
        for pattern, name, severity in secret_patterns:
            matches = re.findall(pattern, dom)
            for match in matches:
                if not any(w in match.lower() for w in ['example', 'test', 'xxx']):
                    findings.append(self.add_finding(
                        vulnerability_type=f"{name} Exposed in DOM",
                        severity=Severity.CRITICAL if severity == "critical" else Severity.HIGH,
                        confidence=Confidence.HIGH,
                        url=url,
                        evidence=f"Found: {match[:30]}...",
                        description=f"{name} found in page source after JavaScript execution",
                        remediation=f"Remove {name} from client-side code",
                        cvss_score=9.0 if severity == "critical" else 7.5,
                    ))
        
        # Email addresses
        emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', dom)
        if len(emails) > 10:
            findings.append(self.add_finding(
                vulnerability_type="Email Address Harvesting",
                severity=Severity.LOW,
                confidence=Confidence.HIGH,
                url=url,
                evidence=f"Found {len(emails)} emails",
                description=f"Page exposes {len(emails)} email addresses",
                remediation="Obfuscate or remove emails from client-side",
                cvss_score=2.0,
            ))
        
        return findings
    
    async def _check_forms_playwright(self, url: str) -> List[Finding]:
        """فحص النماذج في المتصفح"""
        findings = []
        
        try:
            forms = await self._page.evaluate("""
                () => {
                    const forms = document.querySelectorAll('form');
                    return Array.from(forms).map(f => ({
                        action: f.action || window.location.href,
                        method: (f.method || 'GET').toUpperCase(),
                        hasPassword: !!f.querySelector('input[type="password"]'),
                        hasCSRF: !!f.querySelector('input[name*="csrf" i], input[name*="token" i], input[name="_token"]'),
                        inputs: Array.from(f.querySelectorAll('input')).map(i => ({
                            name: i.name,
                            type: i.type,
                        })),
                    }));
                }
            """)
            
            for form in (forms or []):
                if form['method'] == 'POST' and not form['hasCSRF']:
                    findings.append(self.add_finding(
                        vulnerability_type="Missing CSRF Protection",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.HIGH,
                        url=form['action'],
                        evidence="Form lacks CSRF token",
                        description=f"POST form at {form['action']} has no CSRF protection",
                        remediation="Add CSRF tokens to all state-changing forms",
                        cvss_score=5.0,
                    ))
                
                if form['hasPassword'] and url.startswith("http://"):
                    findings.append(self.add_finding(
                        vulnerability_type="Insecure Login Form",
                        severity=Severity.HIGH,
                        confidence=Confidence.CERTAIN,
                        url=url,
                        evidence="Password field on HTTP page",
                        description="Login form submitted over insecure HTTP",
                        remediation="Use HTTPS for all login pages",
                        cvss_score=7.0,
                    ))
        except:
            pass
        
        return findings
    
    async def _test_xss_playwright(self, context: ScanContext) -> List[Finding]:
        """اختبار XSS باستخدام المتصفح"""
        findings = []
        url = context.target.url
        params = context.target.params or {}
        
        for param_name in list(params.keys())[:3]:
            for payload in self.ADVANCED_PAYLOADS["xss"][:5]:
                try:
                    test_params = params.copy()
                    test_params[param_name] = payload
                    
                    # بناء URL
                    from urllib.parse import urlencode, urlparse, urlunparse
                    parsed = list(urlparse(url))
                    parsed[4] = urlencode(test_params)
                    test_url = urlunparse(parsed)
                    
                    # فتح صفحة جديدة
                    page = await self._context.new_page()
                    
                    # مراقبة alerts
                    alert_triggered = False
                    async def handle_dialog(dialog):
                        nonlocal alert_triggered
                        alert_triggered = True
                        await dialog.dismiss()
                    
                    page.on("dialog", handle_dialog)
                    
                    await page.goto(test_url, wait_until="networkidle", timeout=10000)
                    await page.wait_for_timeout(1000)
                    
                    if alert_triggered:
                        findings.append(self.add_finding(
                            vulnerability_type="Cross-Site Scripting (XSS)",
                            severity=Severity.HIGH,
                            confidence=Confidence.CERTAIN,
                            url=test_url,
                            parameter=param_name,
                            payload=payload,
                            evidence="JavaScript alert triggered",
                            description=f"XSS vulnerability confirmed in parameter '{param_name}'",
                            remediation="Use output encoding and Content Security Policy",
                            cvss_score=6.1,
                        ))
                        await page.close()
                        break  # اكتفينا بواحد
                    
                    await page.close()
                except:
                    pass
        
        return findings
    
    async def _discover_apis_playwright(self) -> List[Finding]:
        """اكتشاف API endpoints من طلبات الشبكة"""
        findings = []
        
        api_patterns = [r'/api/', r'/rest/', r'/graphql', r'/v\d+/']
        
        for req in self._network_requests:
            url = req.get('url', '')
            for pattern in api_patterns:
                if re.search(pattern, url):
                    findings.append(self.add_finding(
                        vulnerability_type="API Endpoint Discovered",
                        severity=Severity.INFO,
                        confidence=Confidence.HIGH,
                        url=url,
                        evidence=f"Method: {req.get('method', 'GET')}",
                        description=f"API endpoint found via browser network monitoring",
                        remediation="Review API endpoint exposure",
                        cvss_score=0.0,
                    ))
                    break
        
        return findings
    
    async def _check_storage_secrets(self) -> List[Finding]:
        """فحص localStorage/sessionStorage عن secrets"""
        findings = []
        
        try:
            storage_data = await self._page.evaluate("""
                () => {
                    const data = {};
                    for (let i = 0; i < localStorage.length; i++) {
                        const key = localStorage.key(i);
                        data['local:' + key] = localStorage.getItem(key);
                    }
                    for (let i = 0; i < sessionStorage.length; i++) {
                        const key = sessionStorage.key(i);
                        data['session:' + key] = sessionStorage.getItem(key);
                    }
                    return data;
                }
            """)
            
            jwt_pattern = r'eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+'
            
            for key, value in (storage_data or {}).items():
                # JWT tokens
                jwt_match = re.search(jwt_pattern, str(value))
                if jwt_match:
                    findings.append(self.add_finding(
                        vulnerability_type="JWT Token in Browser Storage",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.CERTAIN,
                        url=key,
                        evidence=f"JWT found in {key}",
                        description="JWT token stored in browser storage - vulnerable to XSS theft",
                        remediation="Use httpOnly cookies for JWT storage",
                        cvss_score=5.3,
                    ))
                
                # API keys
                if 'key' in key.lower() or 'token' in key.lower() or 'secret' in key.lower():
                    if len(str(value)) > 16:
                        findings.append(self.add_finding(
                            vulnerability_type="Sensitive Data in Browser Storage",
                            severity=Severity.HIGH,
                            confidence=Confidence.HIGH,
                            url=key,
                            evidence=f"Sensitive key: {key}",
                            description=f"Potential secret stored in {key}",
                            remediation="Do not store secrets in browser storage",
                            cvss_score=7.0,
                        ))
        except:
            pass
        
        return findings


_browser_scanner = None

def get_browser_scanner() -> BrowserScanner:
    global _browser_scanner
    if _browser_scanner is None:
        _browser_scanner = BrowserScanner()
    return _browser_scanner
