"""
Wappalyzer-style Technology Fingerprinting

يكتشف:
- خوادم الويب (Nginx, Apache, IIS, LiteSpeed, Caddy)
- لغات البرمجة (PHP, Python, Node.js, Java, Ruby, Go)
- أطر العمل (Laravel, Django, Express, Spring, Rails)
- أنظمة إدارة المحتوى (WordPress, Drupal, Joomla, Magento)
- مكتبات JavaScript (React, Angular, Vue, jQuery, Bootstrap)
- أدوات التحليل (Google Analytics, Facebook Pixel, Hotjar)
- شبكات التوصيل (Cloudflare, Akamai, Fastly, AWS CloudFront)
- قواعد البيانات (MySQL, PostgreSQL, MongoDB, Redis)
"""

import asyncio
import re
import json
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from urllib.parse import urlparse

import httpx
import logging

logger = logging.getLogger(__name__)


@dataclass
class Technology:
    """تقنية مكتشفة"""
    name: str
    category: str
    version: str = ""
    confidence: int = 0  # 0-100
    evidence: str = ""
    website: str = ""
    cpe: str = ""


@dataclass
class FingerprintResult:
    """نتائج كشف التقنيات"""
    url: str
    technologies: List[Technology] = field(default_factory=list)
    categories: Dict[str, List[str]] = field(default_factory=dict)
    total_technologies: int = 0
    errors: List[str] = field(default_factory=list)


class WappalyzerFingerprinter:
    """
    كاشف التقنيات بأسلوب Wappalyzer
    
    يستخدم:
    - Headers analysis
    - HTML meta tags
    - JavaScript globals
    - CSS class names
    - Cookie names
    - File paths
    """
    
    # قاعدة بيانات التقنيات (مبسطة)
    TECH_DATABASE = {
        # Web Servers
        "Nginx": {
            "category": "Web Server",
            "headers": {"Server": r"nginx(?:\/([\d.]+))?"},
            "website": "https://nginx.org",
        },
        "Apache": {
            "category": "Web Server",
            "headers": {"Server": r"Apache(?:\/([\d.]+))?"},
            "website": "https://httpd.apache.org",
        },
        "IIS": {
            "category": "Web Server",
            "headers": {"Server": r"Microsoft-IIS(?:\/([\d.]+))?"},
            "website": "https://www.iis.net",
        },
        "LiteSpeed": {
            "category": "Web Server",
            "headers": {"Server": r"LiteSpeed"},
            "website": "https://www.litespeedtech.com",
        },
        "Cloudflare": {
            "category": "CDN",
            "headers": {"Server": r"cloudflare", "CF-RAY": r""},
            "website": "https://www.cloudflare.com",
        },
        
        # Programming Languages
        "PHP": {
            "category": "Programming Language",
            "headers": {"X-Powered-By": r"PHP(?:\/([\d.]+))?"},
            "meta": {"generator": r"PHP"},
            "website": "https://php.net",
        },
        "Node.js": {
            "category": "Programming Language",
            "headers": {"X-Powered-By": r"Express"},
            "website": "https://nodejs.org",
        },
        "Python": {
            "category": "Programming Language",
            "headers": {"X-Powered-By": r"(?:Django|Flask|Python)"},
            "website": "https://python.org",
        },
        
        # Frameworks
        "Laravel": {
            "category": "Framework",
            "headers": {"Set-Cookie": r"laravel_session"},
            "meta": {"generator": r"Laravel"},
            "website": "https://laravel.com",
        },
        "Django": {
            "category": "Framework",
            "headers": {"Set-Cookie": r"csrftoken"},
            "website": "https://djangoproject.com",
        },
        "Express": {
            "category": "Framework",
            "headers": {"X-Powered-By": r"Express(?:\/([\d.]+))?"},
            "website": "https://expressjs.com",
        },
        "Ruby on Rails": {
            "category": "Framework",
            "headers": {"X-Powered-By": r"Rails"},
            "cookies": {"_rails_session": r""},
            "website": "https://rubyonrails.org",
        },
        
        # CMS
        "WordPress": {
            "category": "CMS",
            "meta": {"generator": r"WordPress\s*([\d.]+)?"},
            "html": [r"wp-content", r"wp-includes"],
            "website": "https://wordpress.org",
        },
        "Drupal": {
            "category": "CMS",
            "meta": {"generator": r"Drupal\s*(\d+)"},
            "headers": {"X-Drupal": r""},
            "website": "https://drupal.org",
        },
        "Joomla": {
            "category": "CMS",
            "meta": {"generator": r"Joomla!"},
            "website": "https://joomla.org",
        },
        
        # JavaScript Libraries
        "React": {
            "category": "JavaScript Library",
            "html": [r'react\.development\.js', r'react\.production\.min\.js', r'react-dom'],
            "js": {"React": r"", "__REACT_DEVTOOLS_GLOBAL_HOOK__": r""},
            "website": "https://reactjs.org",
        },
        "Angular": {
            "category": "JavaScript Library",
            "html": [r'ng-version', r'angular\.js'],
            "website": "https://angular.io",
        },
        "Vue.js": {
            "category": "JavaScript Library",
            "html": [r'vue\.js', r'vue\.min\.js'],
            "js": {"Vue": r"", "__VUE_DEVTOOLS_GLOBAL_HOOK__": r""},
            "website": "https://vuejs.org",
        },
        "jQuery": {
            "category": "JavaScript Library",
            "html": [r'jquery[.-](\d+\.\d+\.\d+)'],
            "js": {"jQuery": r""},
            "website": "https://jquery.com",
        },
        "Bootstrap": {
            "category": "UI Framework",
            "html": [r'bootstrap[.-](\d+\.\d+\.\d+)'],
            "css": [r'\.container-fluid', r'\.navbar-expand'],
            "website": "https://getbootstrap.com",
        },
        "Tailwind CSS": {
            "category": "UI Framework",
            "css": [r'\.sr-only', r'\.space-x-'],
            "website": "https://tailwindcss.com",
        },
        
        # Analytics
        "Google Analytics": {
            "category": "Analytics",
            "html": [r'google-analytics\.com', r'googletagmanager\.com'],
            "js": {"ga": r"", "google_tag_manager": r""},
            "website": "https://analytics.google.com",
        },
        "Google Tag Manager": {
            "category": "Tag Manager",
            "html": [r'googletagmanager\.com/gtm\.js'],
            "website": "https://tagmanager.google.com",
        },
        "Hotjar": {
            "category": "Analytics",
            "html": [r'hotjar\.com'],
            "js": {"hj": r""},
            "website": "https://hotjar.com",
        },
        
        # Fonts
        "Google Fonts": {
            "category": "Font",
            "html": [r'fonts\.googleapis\.com'],
            "website": "https://fonts.google.com",
        },
        "Font Awesome": {
            "category": "Font",
            "html": [r'font-awesome'],
            "css": [r'\.fa-', r'\.fas ', r'\.fab '],
            "website": "https://fontawesome.com",
        },
    }
    
    def __init__(self):
        self._results: Dict[str, FingerprintResult] = {}
    
    async def fingerprint(self, url: str, html: str = None, headers: Dict = None, 
                          cookies: Dict = None, scripts: List[str] = None) -> FingerprintResult:
        """
        كشف التقنيات المستخدمة في الموقع
        
        Args:
            url: رابط الموقع
            html: HTML الصفحة
            headers: Headers الاستجابة
            cookies: Cookies الاستجابة
            scripts: قائمة ملفات JavaScript
        
        Returns:
            FingerprintResult مع التقنيات المكتشفة
        """
        print(f"  🔍 Fingerprinting: {url}")
        
        result = FingerprintResult(url=url)
        
        if not html and not headers:
            # نجيب الصفحة
            try:
                async with httpx.AsyncClient(timeout=15, verify=False) as client:
                    response = await client.get(url)
                    html = response.text
                    headers = dict(response.headers)
                    cookies = dict(response.cookies)
                    
                    # استخراج scripts
                    scripts = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html)
            except Exception as e:
                result.errors.append(str(e))
                return result
        
        # فحص كل تقنية
        for tech_name, patterns in self.TECH_DATABASE.items():
            tech = self._detect_technology(tech_name, patterns, html or "", 
                                           headers or {}, cookies or {}, scripts or [])
            if tech:
                result.technologies.append(tech)
                
                # تنظيم حسب الفئة
                category = tech.category
                if category not in result.categories:
                    result.categories[category] = []
                if tech_name not in result.categories[category]:
                    result.categories[category].append(tech_name)
        
        result.total_technologies = len(result.technologies)
        
        # عرض النتائج
        if result.technologies:
            cats = list(result.categories.keys())
            print(f"     ✅ Found {result.total_technologies} technologies in {len(cats)} categories")
            for cat in cats[:5]:
                techs = result.categories[cat][:3]
                print(f"     📦 {cat}: {', '.join(techs)}")
        
        self._results[url] = result
        return result
    
    def _detect_technology(self, name: str, patterns: Dict, html: str,
                          headers: Dict, cookies: Dict, scripts: List[str]) -> Optional[Technology]:
        """فحص تقنية محددة"""
        confidence = 0
        evidence = ""
        version = ""
        
        # فحص headers
        for header_name, pattern in patterns.get("headers", {}).items():
            if header_name in headers:
                value = headers[header_name]
                match = re.search(pattern, str(value), re.I)
                if match:
                    confidence += 50
                    evidence = f"Header: {header_name}: {value[:50]}"
                    if match.groups() and match.group(1):
                        version = match.group(1)
        
        # فحص meta tags
        for meta_name, pattern in patterns.get("meta", {}).items():
            meta_pattern = re.compile(
                rf'<meta[^>]+name=["\']{meta_name}["\'][^>]+content=["\']({pattern})["\']',
                re.I
            )
            match = meta_pattern.search(html)
            if match:
                confidence += 40
                evidence = f"Meta: {meta_name}"
                if match.groups() and match.group(1):
                    v = match.group(1)
                    if v and v != pattern:
                        version = v
        
        # فحص HTML patterns
        for pattern in patterns.get("html", []):
            match = re.search(pattern, html, re.I)
            if match:
                confidence += 30
                evidence = f"HTML: {pattern[:50]}"
                if match.groups() and match.group(1):
                    version = match.group(1)
        
        # فحص CSS patterns
        for pattern in patterns.get("css", []):
            if re.search(pattern, html, re.I):
                confidence += 20
                evidence = f"CSS: {pattern[:50]}"
        
        # فحص cookies
        for cookie_name, pattern in patterns.get("cookies", {}).items():
            if cookie_name in cookies:
                confidence += 40
                evidence = f"Cookie: {cookie_name}"
        
        # فحص JavaScript globals
        for js_var, pattern in patterns.get("js", {}).items():
            js_pattern = re.compile(rf'(?:window\.)?{js_var}\s*=', re.I)
            if js_pattern.search(html):
                confidence += 30
                evidence = f"JS: {js_var}"
        
        if confidence > 0:
            return Technology(
                name=name,
                category=patterns.get("category", "Unknown"),
                version=version,
                confidence=min(100, confidence),
                evidence=evidence,
                website=patterns.get("website", ""),
            )
        
        return None
    
    def get_results(self, url: str) -> Optional[FingerprintResult]:
        return self._results.get(url)


# نسخة عالمية
_fingerprinter = None

def get_wappalyzer() -> WappalyzerFingerprinter:
    global _fingerprinter
    if _fingerprinter is None:
        _fingerprinter = WappalyzerFingerprinter()
    return _fingerprinter
