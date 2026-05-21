"""
Site Analyzer - محلل المواقع الاحترافي (Pre-Scan Phase)

الخطوات السبعة:
1. Connectivity Check - فحص الاتصال المبدئي
2. WAF/CDN Detection - كشف الحماية
3. Auth Discovery - اكتشاف المصادقة
4. Site Structure Discovery - هيكل الموقع (robots.txt, sitemap.xml)
5. Technology Fingerprinting - كشف التقنيات
6. Service Discovery - فحص المنافذ والخدمات
7. Attack Surface Analysis - تحليل سطح الهجوم
"""

import asyncio
import re
import socket
import ssl
import time
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from urllib.parse import urlparse, urljoin
from collections import defaultdict

import httpx
import logging

logger = logging.getLogger(__name__)


# ============================================================
# Data Classes
# ============================================================

@dataclass
class ConnectivityResult:
    """نتيجة فحص الاتصال"""
    url: str
    ip_address: str = ""
    status_code: int = 0
    response_time_ms: float = 0.0
    redirect_chain: List[str] = field(default_factory=list)
    final_url: str = ""
    is_reachable: bool = False
    server_header: str = ""
    content_type: str = ""
    content_length: int = 0
    ssl_info: Dict = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)


@dataclass
class WAFResult:
    """نتيجة كشف الحماية"""
    waf_detected: bool = False
    waf_name: str = ""
    waf_type: str = ""  # cloud, on-premise, custom
    confidence: float = 0.0
    evidence: List[str] = field(default_factory=list)
    bypass_difficulty: str = "unknown"  # easy, medium, hard, extreme


@dataclass
class AuthResult:
    """نتيجة اكتشاف المصادقة"""
    auth_required: bool = False
    auth_type: str = ""  # basic, bearer, session, oauth2, saml, captcha
    login_url: str = ""
    register_url: str = ""
    logout_url: str = ""
    auth_headers: Dict[str, str] = field(default_factory=dict)
    has_captcha: bool = False
    has_2fa: bool = False
    has_sso: bool = False


@dataclass
class StructureResult:
    """نتيجة هيكل الموقع"""
    robots_txt: str = ""
    sitemap_xml: str = ""
    disallowed_paths: List[str] = field(default_factory=list)
    allowed_paths: List[str] = field(default_factory=list)
    sitemap_urls: List[str] = field(default_factory=list)
    well_known_endpoints: List[str] = field(default_factory=list)
    directory_structure: List[str] = field(default_factory=list)


@dataclass
class TechnologyResult:
    """نتيجة كشف التقنيات"""
    language: str = ""
    framework: str = ""
    server: str = ""
    database: str = ""
    cms: str = ""
    libraries: List[str] = field(default_factory=list)
    versions: Dict[str, str] = field(default_factory=dict)
    confidence: float = 0.0


@dataclass
class ServiceResult:
    """نتيجة فحص الخدمات"""
    open_ports: Dict[int, str] = field(default_factory=dict)
    services: Dict[int, Dict] = field(default_factory=dict)
    total_scanned: int = 0
    scan_duration: float = 0.0


@dataclass
class AttackSurfaceResult:
    """نتيجة تحليل سطح الهجوم"""
    total_endpoints: int = 0
    total_forms: int = 0
    total_apis: int = 0
    sensitive_files: List[str] = field(default_factory=list)
    admin_panels: List[str] = field(default_factory=list)
    entry_points: List[Dict] = field(default_factory=list)
    risk_score: float = 0.0  # 0-10
    risk_level: str = "unknown"


@dataclass
class SiteAnalysisReport:
    """تقرير تحليل الموقع الكامل"""
    target: str
    analyzed_at: datetime = field(default_factory=datetime.now)
    connectivity: Optional[ConnectivityResult] = None
    waf: Optional[WAFResult] = None
    auth: Optional[AuthResult] = None
    structure: Optional[StructureResult] = None
    technology: Optional[TechnologyResult] = None
    services: Optional[ServiceResult] = None
    attack_surface: Optional[AttackSurfaceResult] = None
    summary: Dict = field(default_factory=dict)
    recommendations: List[str] = field(default_factory=list)


# ============================================================
# Site Analyzer
# ============================================================

class SiteAnalyzer:
    """
    محلل المواقع الاحترافي
    
    ينفذ 7 خطوات تحليل قبل بدء الفحص
    """
    
    # أنماط WAF
    WAF_SIGNATURES = {
        "Cloudflare": {
            "headers": ["cf-ray", "cf-cache-status", "__cfduid"],
            "cookies": ["__cfduid", "cf_clearance", "__cf_bm"],
            "response": ["cloudflare", "attention required", "cf-chl"],
            "type": "cloud"
        },
        "AWS WAF": {
            "headers": ["x-amzn-requestid", "x-amzn-errortype", "x-amz-cf-id"],
            "response": ["awswaf", "request blocked"],
            "type": "cloud"
        },
        "Akamai": {
            "headers": ["x-akamai-transformed", "x-akamai-request-id"],
            "cookies": ["ak_bmsc", "bm_sz"],
            "type": "cloud"
        },
        "Imperva/Incapsula": {
            "headers": ["x-iinfo", "x-cdn"],
            "cookies": ["incap_ses_", "visid_incap_"],
            "response": ["incapsula", "imperva"],
            "type": "cloud"
        },
        "Sucuri": {
            "headers": ["x-sucuri-id", "x-sucuri-cache"],
            "cookies": ["sucuri_cloudproxy"],
            "type": "cloud"
        },
        "ModSecurity": {
            "headers": ["mod_security", "modsecurity"],
            "response": ["modsecurity", "not acceptable"],
            "type": "on-premise"
        },
        "F5 BIG-IP": {
            "headers": ["x-cnection", "x-wa-info"],
            "cookies": ["BIGipServer", "TS"],
            "type": "on-premise"
        },
        "FortiWeb": {
            "headers": ["fortiwaf", "x-fortinet"],
            "cookies": ["FORTIWAFSID"],
            "type": "on-premise"
        },
    }
    
    # أنماط التقنيات
    TECH_PATTERNS = {
        "language": {
            "PHP": [r'\.php', r'PHPSESSID', r'X-Powered-By: PHP'],
            "Python": [r'\.py', r'python', r'Django', r'Flask'],
            "Node.js": [r'node', r'express', r'X-Powered-By: Express'],
            "Java": [r'\.jsp', r'\.do', r'JSESSIONID', r'Spring'],
            "Ruby": [r'\.rb', r'rails', r'Ruby on Rails'],
            "ASP.NET": [r'\.aspx', r'ASP\.NET', r'ViewState', r'X-AspNet-Version'],
        },
        "server": {
            "Nginx": [r'nginx', r'Server: nginx'],
            "Apache": [r'Apache', r'Server: Apache'],
            "IIS": [r'IIS', r'Microsoft-IIS'],
            "LiteSpeed": [r'LiteSpeed', r'Server: LiteSpeed'],
            "Caddy": [r'Caddy', r'Server: Caddy'],
        },
        "cms": {
            "WordPress": [r'wp-content', r'wordpress', r'wp-json'],
            "Drupal": [r'Drupal', r'drupal'],
            "Joomla": [r'Joomla', r'joomla'],
            "Magento": [r'Magento', r'mage'],
            "Shopify": [r'Shopify', r'myshopify'],
        },
        "framework": {
            "React": [r'react', r'ReactDOM', r'data-reactroot'],
            "Angular": [r'ng-version', r'angular', r'ng-app'],
            "Vue.js": [r'vue', r'data-v-', r'v-bind'],
            "jQuery": [r'jquery[.-](\d+\.\d+\.\d+)', r'jQuery v(\d+\.\d+\.\d+)'],
            "Bootstrap": [r'bootstrap[.-](\d+\.\d+\.\d+)'],
            "Laravel": [r'laravel', r'X-Powered-By: Laravel'],
            "Django": [r'django', r'csrftoken'],
            "Express": [r'express', r'X-Powered-By: Express'],
        },
    }
    
    # ملفات حساسة شائعة
    SENSITIVE_FILES = [
        "/.env", "/.git/config", "/.svn/entries", "/.DS_Store",
        "/backup.zip", "/backup.sql", "/dump.sql", "/export.sql",
        "/config.php.bak", "/wp-config.php.bak", "/web.config.bak",
        "/phpinfo.php", "/info.php", "/test.php",
        "/debug.log", "/error.log", "/access.log",
        "/composer.json", "/package.json", "/Gemfile", "/requirements.txt",
    ]
    
    # لوحات إدارة شائعة
    ADMIN_PANELS = [
        "/admin", "/administrator", "/wp-admin", "/wp-login.php",
        "/phpmyadmin", "/pma", "/mysql", "/dbadmin",
        "/manager/html", "/jenkins", "/grafana",
        "/api/admin", "/api/docs", "/swagger", "/graphql",
        "/cpanel", "/webmail", "/roundcube",
        "/django-admin", "/admin/login", "/user/login",
    ]
    
    # منافذ شائعة
    COMMON_PORTS = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
        53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
        443: "HTTPS", 993: "IMAPS", 995: "POP3S",
        3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis",
        8080: "HTTP-Alt", 8443: "HTTPS-Alt", 9200: "Elasticsearch",
        27017: "MongoDB", 11211: "Memcached",
    }
    
    def __init__(self):
        self._client = None
        logger.info("SiteAnalyzer initialized")
    
    async def _get_client(self) -> httpx.AsyncClient:
        if not self._client:
            self._client = httpx.AsyncClient(
                timeout=15, follow_redirects=True, verify=False,
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0.0.0 Safari/537.36"}
            )
        return self._client
    
    # ============================================================
    # Step 1: Connectivity Check
    # ============================================================
    
    async def check_connectivity(self, url: str) -> ConnectivityResult:
        """فحص الاتصال المبدئي"""
        print(f"  📡 Checking connectivity...")
        
        result = ConnectivityResult(url=url)
        parsed = urlparse(url)
        
        # DNS resolution
        try:
            result.ip_address = socket.gethostbyname(parsed.hostname)
        except socket.gaierror as e:
            result.errors.append(f"DNS Error: {e}")
            return result
        
        # HTTP request
        client = await self._get_client()
        start = time.time()
        
        try:
            response = await client.get(url)
            result.response_time_ms = (time.time() - start) * 1000
            result.status_code = response.status_code
            result.final_url = str(response.url)
            result.server_header = response.headers.get("server", "")
            result.content_type = response.headers.get("content-type", "")
            result.content_length = len(response.text)
            result.is_reachable = response.status_code < 500
            
            # Redirect chain
            if response.history:
                result.redirect_chain = [str(r.url) for r in response.history]
                result.redirect_chain.append(str(response.url))
            
            # SSL info
            if parsed.scheme == "https":
                result.ssl_info = self._get_ssl_info(parsed.hostname)
            
            print(f"     ✅ {result.status_code} | {result.response_time_ms:.0f}ms | IP: {result.ip_address}")
            
        except httpx.TimeoutException:
            result.errors.append("Connection timeout")
            print(f"     ❌ Timeout")
        except Exception as e:
            result.errors.append(str(e))
            print(f"     ❌ {str(e)[:50]}")
        
        return result
    
    def _get_ssl_info(self, hostname: str) -> Dict:
        """الحصول على معلومات SSL"""
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    return {
                        "issuer": dict(x[0] for x in cert.get("issuer", [])),
                        "subject": dict(x[0] for x in cert.get("subject", [])),
                        "not_before": cert.get("notBefore", ""),
                        "not_after": cert.get("notAfter", ""),
                        "version": ssock.version(),
                    }
        except:
            return {}
    
    # ============================================================
    # Step 2: WAF/CDN Detection
    # ============================================================
    
    async def detect_waf(self, response: httpx.Response = None, cookies: Dict = None) -> WAFResult:
        """كشف الحماية"""
        print(f"  🛡️  Detecting WAF/CDN...")
        
        result = WAFResult()
        
        if not response:
            return result
        
        headers = {k.lower(): v.lower() for k, v in response.headers.items()}
        response_text = response.text.lower()
        
        for waf_name, patterns in self.WAF_SIGNATURES.items():
            score = 0
            evidence = []
            
            # Check headers
            for h in patterns.get("headers", []):
                if h.lower() in headers:
                    score += 2
                    evidence.append(f"Header: {h}")
            
            # Check cookies
            for c in patterns.get("cookies", []):
                if c.lower() in response_text or any(c.lower() in k.lower() for k in (cookies or {})):
                    score += 1
                    evidence.append(f"Cookie: {c}")
            
            # Check response body
            for r in patterns.get("response", []):
                if r.lower() in response_text:
                    score += 2
                    evidence.append(f"Response: {r}")
            
            if score >= 2:
                result.waf_detected = True
                result.waf_name = waf_name
                result.waf_type = patterns.get("type", "unknown")
                result.confidence = min(1.0, score / 6)
                result.evidence = evidence
                result.bypass_difficulty = "hard" if waf_name in ["Cloudflare", "Akamai"] else "medium" if waf_name in ["AWS WAF", "Imperva/Incapsula"] else "easy"
                break
        
        if result.waf_detected:
            print(f"     ⚠️  {result.waf_name} detected (confidence: {result.confidence:.0%})")
        else:
            print(f"     ✅ No WAF detected")
        
        return result
    
    # ============================================================
    # Step 3: Auth Discovery
    # ============================================================
    
    async def discover_auth(self, response: httpx.Response) -> AuthResult:
        """اكتشاف المصادقة"""
        print(f"  🔐 Checking authentication...")
        
        result = AuthResult()
        
        if not response:
            return result
        
        status = response.status_code
        headers = {k.lower(): v for k, v in response.headers.items()}
        text = response.text.lower()
        url = str(response.url)
        
        # Check HTTP auth
        if status == 401:
            result.auth_required = True
            auth_header = response.headers.get("www-authenticate", "")
            if "basic" in auth_header.lower():
                result.auth_type = "basic"
            elif "bearer" in auth_header.lower():
                result.auth_type = "bearer"
        
        # Check for login page
        login_indicators = ["login", "sign in", "signin", "log in", "تسجيل الدخول"]
        if any(ind in text for ind in login_indicators):
            result.auth_required = True
            result.login_url = url
        
        # Check for registration
        register_indicators = ["register", "sign up", "signup", "create account", "إنشاء حساب"]
        if any(ind in text for ind in register_indicators):
            result.register_url = url
        
        # Check for CAPTCHA
        captcha_indicators = ["captcha", "recaptcha", "hcaptcha", "g-recaptcha", "cf-turnstile"]
        if any(ind in text for ind in captcha_indicators):
            result.has_captcha = True
        
        # Check for 2FA
        twofa_indicators = ["two-factor", "2fa", "authenticator", "verification code", "otp"]
        if any(ind in text for ind in twofa_indicators):
            result.has_2fa = True
        
        # Check for SSO
        sso_indicators = ["oauth", "openid", "saml", "sign in with google", "sign in with microsoft"]
        if any(ind in text for ind in sso_indicators):
            result.has_sso = True
            result.auth_type = "oauth2"
        
        if result.auth_required:
            print(f"     🔒 Auth required: {result.auth_type or 'session-based'}")
            if result.has_captcha: print(f"     🛡️  CAPTCHA detected")
            if result.has_2fa: print(f"     📱 2FA detected")
            if result.has_sso: print(f"     🔗 SSO detected")
        else:
            print(f"     ✅ No authentication required")
        
        return result
    
    # ============================================================
    # Step 4: Site Structure Discovery
    # ============================================================
    
    async def discover_structure(self, base_url: str) -> StructureResult:
        """اكتشاف هيكل الموقع"""
        print(f"  🧭 Discovering site structure...")
        
        result = StructureResult()
        client = await self._get_client()
        parsed = urlparse(base_url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        
        # robots.txt
        try:
            r = await client.get(f"{base}/robots.txt")
            if r.status_code == 200:
                result.robots_txt = r.text
                for line in r.text.split('\n'):
                    line = line.strip()
                    if line.lower().startswith('disallow:'):
                        path = line.split(':', 1)[1].strip()
                        if path:
                            result.disallowed_paths.append(path)
                    elif line.lower().startswith('allow:'):
                        path = line.split(':', 1)[1].strip()
                        if path:
                            result.allowed_paths.append(path)
                print(f"     ✅ robots.txt: {len(result.disallowed_paths)} disallowed paths")
        except:
            pass
        
        # sitemap.xml
        try:
            r = await client.get(f"{base}/sitemap.xml")
            if r.status_code == 200:
                result.sitemap_xml = r.text
                urls = re.findall(r'<loc>(.*?)</loc>', r.text)
                result.sitemap_urls = urls[:100]
                print(f"     ✅ sitemap.xml: {len(result.sitemap_urls)} URLs")
        except:
            pass
        
        # .well-known endpoints
        well_known = ["security.txt", "openid-configuration", "assetlinks.json", "apple-app-site-association"]
        for wk in well_known:
            try:
                r = await client.get(f"{base}/.well-known/{wk}")
                if r.status_code == 200:
                    result.well_known_endpoints.append(f"/.well-known/{wk}")
            except:
                pass
        
        if result.well_known_endpoints:
            print(f"     ✅ .well-known: {len(result.well_known_endpoints)} endpoints")
        
        return result
    
    # ============================================================
    # Step 5: Technology Fingerprinting
    # ============================================================
    
    async def fingerprint_technology(self, response: httpx.Response) -> TechnologyResult:
        """كشف التقنيات"""
        print(f"  🔍 Fingerprinting technology...")
        
        result = TechnologyResult()
        
        if not response:
            return result
        
        headers = {k.lower(): v for k, v in response.headers.items()}
        text = response.text[:10000]  # أول 10KB
        all_text = str(dict(response.headers)) + text
        
        # Server
        server = response.headers.get("server", "")
        for tech, patterns in self.TECH_PATTERNS["server"].items():
            if any(re.search(p, server, re.I) for p in patterns):
                result.server = tech
                break
        
        # Language
        powered = response.headers.get("x-powered-by", "")
        for tech, patterns in self.TECH_PATTERNS["language"].items():
            if any(re.search(p, powered + all_text, re.I) for p in patterns):
                result.language = tech
                break
        
        # Framework
        for tech, patterns in self.TECH_PATTERNS["framework"].items():
            for p in patterns:
                match = re.search(p, all_text, re.I)
                if match:
                    result.framework = tech
                    if match.groups():
                        result.versions[tech] = match.group(1)
                    break
            if result.framework:
                break
        
        # CMS
        for tech, patterns in self.TECH_PATTERNS["cms"].items():
            if any(re.search(p, all_text, re.I) for p in patterns):
                result.cms = tech
                break
        
        # Libraries
        lib_patterns = {
            "jQuery": r'jquery[.-]?(\d+\.\d+\.\d+)',
            "Bootstrap": r'bootstrap[.-]?(\d+\.\d+\.\d+)',
            "Font Awesome": r'font-awesome[.-]?(\d+\.\d+\.\d+)',
        }
        for lib, pattern in lib_patterns.items():
            match = re.search(pattern, all_text, re.I)
            if match:
                result.libraries.append(lib)
                result.versions[lib] = match.group(1)
        
        detected = [v for v in [result.language, result.framework, result.server, result.cms] if v]
        print(f"     ✅ {', '.join(detected) if detected else 'No specific technology detected'}")
        
        return result
    
    # ============================================================
    # Step 6: Service Discovery
    # ============================================================
    
    async def discover_services(self, hostname: str, ports: List[int] = None) -> ServiceResult:
        """فحص المنافذ والخدمات"""
        print(f"  📡 Scanning services (quick)...")
        
        result = ServiceResult()
        
        if not ports:
            ports = [80, 443, 8080, 8443, 3306, 5432, 6379, 9200, 27017]
        
        result.total_scanned = len(ports)
        start = time.time()
        
        for port in ports:
            try:
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection(hostname, port),
                    timeout=2
                )
                writer.close()
                result.open_ports[port] = self.COMMON_PORTS.get(port, "unknown")
            except:
                pass
        
        result.scan_duration = time.time() - start
        
        if result.open_ports:
            print(f"     ✅ {len(result.open_ports)} open ports: {list(result.open_ports.keys())}")
        else:
            print(f"     ℹ️  Only standard ports scanned")
        
        return result
    
    # ============================================================
    # Step 7: Attack Surface Analysis
    # ============================================================
    
    async def analyze_attack_surface(self, base_url: str, response: httpx.Response = None) -> AttackSurfaceResult:
        """تحليل سطح الهجوم"""
        print(f"  🎯 Analyzing attack surface...")
        
        result = AttackSurfaceResult()
        client = await self._get_client()
        parsed = urlparse(base_url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        
        # Check sensitive files
        sensitive_tasks = []
        for path in self.SENSITIVE_FILES:
            async def check_file(p):
                try:
                    r = await client.get(f"{base}{p}", timeout=5)
                    if r.status_code == 200:
                        return p
                except:
                    pass
                return None
            sensitive_tasks.append(check_file(path))
        
        sensitive_results = await asyncio.gather(*sensitive_tasks, return_exceptions=True)
        result.sensitive_files = [f for f in sensitive_results if f]
        
        # Check admin panels
        admin_tasks = []
        for path in self.ADMIN_PANELS:
            async def check_admin(p):
                try:
                    r = await client.get(f"{base}{p}", timeout=5)
                    if r.status_code in [200, 302, 401, 403]:
                        return {"path": p, "status": r.status_code}
                except:
                    pass
                return None
            admin_tasks.append(check_admin(path))
        
        admin_results = await asyncio.gather(*admin_tasks, return_exceptions=True)
        result.admin_panels = [a["path"] for a in admin_results if a]
        
        # Calculate risk score
        risk = 0.0
        if result.sensitive_files: risk += len(result.sensitive_files) * 1.5
        if result.admin_panels: risk += len(result.admin_panels) * 0.5
        
        result.risk_score = min(10.0, risk)
        result.risk_level = "Critical" if risk > 7 else "High" if risk > 5 else "Medium" if risk > 3 else "Low"
        
        if result.sensitive_files:
            print(f"     ⚠️  {len(result.sensitive_files)} sensitive files exposed!")
        if result.admin_panels:
            print(f"     ⚠️  {len(result.admin_panels)} admin panels found!")
        print(f"     📊 Risk Score: {result.risk_score:.1f}/10 ({result.risk_level})")
        
        return result
    
    # ============================================================
    # Full Analysis
    # ============================================================
    
    async def analyze(self, url: str, scan_ports: bool = True, check_files: bool = True) -> SiteAnalysisReport:
        """
        تحليل كامل للموقع
        
        Args:
            url: رابط الموقع
            scan_ports: فحص المنافذ
            check_files: فحص الملفات الحساسة
        
        Returns:
            تقرير تحليل كامل
        """
        print(f"\n{'='*60}")
        print(f"🔍 Site Analysis: {url}")
        print(f"{'='*60}")
        
        report = SiteAnalysisReport(target=url)
        parsed = urlparse(url)
        hostname = parsed.hostname
        
        # Step 1: Connectivity
        print(f"\n📡 Step 1/7: Connectivity Check")
        report.connectivity = await self.check_connectivity(url)
        
        if not report.connectivity.is_reachable:
            report.summary = {"error": "Site unreachable", "details": report.connectivity.errors}
            return report
        
        client = await self._get_client()
        response = await client.get(url)
        
        # Step 2: WAF
        print(f"\n🛡️  Step 2/7: WAF Detection")
        report.waf = await self.detect_waf(response)
        
        # Step 3: Auth
        print(f"\n🔐 Step 3/7: Auth Discovery")
        report.auth = await self.discover_auth(response)
        
        # Step 4: Structure
        print(f"\n🧭 Step 4/7: Site Structure")
        report.structure = await self.discover_structure(url)
        
        # Step 5: Technology
        print(f"\n🔍 Step 5/7: Technology Fingerprinting")
        report.technology = await self.fingerprint_technology(response)
        
        # Step 6: Services
        if scan_ports:
            print(f"\n📡 Step 6/7: Service Discovery")
            report.services = await self.discover_services(hostname)
        
        # Step 7: Attack Surface
        if check_files:
            print(f"\n🎯 Step 7/7: Attack Surface Analysis")
            report.attack_surface = await self.analyze_attack_surface(url, response)
        
        # Generate summary
        report.summary = self._generate_summary(report)
        report.recommendations = self._generate_recommendations(report)
        
        print(f"\n{'='*60}")
        print(f"✅ Analysis Complete!")
        self._print_summary(report)
        
        return report
    
    def _generate_summary(self, report: SiteAnalysisReport) -> Dict:
        """توليد ملخص"""
        return {
            "target": report.target,
            "reachable": report.connectivity.is_reachable if report.connectivity else False,
            "response_time_ms": report.connectivity.response_time_ms if report.connectivity else 0,
            "ip": report.connectivity.ip_address if report.connectivity else "",
            "server": report.technology.server if report.technology else "",
            "waf": report.waf.waf_name if report.waf and report.waf.waf_detected else "None",
            "auth_required": report.auth.auth_required if report.auth else False,
            "language": report.technology.language if report.technology else "",
            "framework": report.technology.framework if report.technology else "",
            "cms": report.technology.cms if report.technology else "",
            "risk_score": report.attack_surface.risk_score if report.attack_surface else 0,
            "risk_level": report.attack_surface.risk_level if report.attack_surface else "unknown",
        }
    
    def _generate_recommendations(self, report: SiteAnalysisReport) -> List[str]:
        """توليد توصيات"""
        recs = []
        
        if report.waf and report.waf.waf_detected:
            recs.append(f"WAF detected ({report.waf.waf_name}) - Use stealth scanning mode")
        
        if report.auth and report.auth.auth_required:
            recs.append("Authentication required - Use login or cookies command first")
        
        if report.attack_surface and report.attack_surface.sensitive_files:
            recs.append(f"Remove {len(report.attack_surface.sensitive_files)} exposed sensitive files")
        
        if report.attack_surface and report.attack_surface.admin_panels:
            recs.append("Restrict access to admin panels")
        
        if report.connectivity and report.connectivity.response_time_ms > 2000:
            recs.append("Slow response detected - Increase timeout settings")
        
        return recs
    
    def _print_summary(self, report: SiteAnalysisReport):
        """طباعة الملخص"""
        s = report.summary
        print(f"   Target: {s.get('target', 'N/A')}")
        print(f"   IP: {s.get('ip', 'N/A')} | Response: {s.get('response_time_ms', 0):.0f}ms")
        print(f"   Server: {s.get('server', 'Unknown')} | Language: {s.get('language', 'Unknown')}")
        print(f"   WAF: {s.get('waf', 'None')} | Auth: {'Yes' if s.get('auth_required') else 'No'}")
        print(f"   Risk: {s.get('risk_score', 0):.1f}/10 ({s.get('risk_level', 'unknown')})")
        
        if report.recommendations:
            print(f"\n   📋 Recommendations:")
            for r in report.recommendations[:5]:
                print(f"     • {r}")
    
    async def close(self):
        if self._client:
            await self._client.aclose()


# نسخة عالمية
_site_analyzer = None

def get_site_analyzer() -> SiteAnalyzer:
    global _site_analyzer
    if _site_analyzer is None:
        _site_analyzer = SiteAnalyzer()
    return _site_analyzer
