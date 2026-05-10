
import re
import json
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime

import logging

logger = logging.getLogger(__name__)


@dataclass
class Fingerprint:
    """بصمة تقنية"""
    name: str
    category: str  # server, framework, cms, language, database, waf
    version: Optional[str] = None
    confidence: float = 0.0
    evidence: str = ""
    detected_at: datetime = field(default_factory=datetime.now)


class FingerprintEngine:
    """
    محرك البصمات المتقدم
    
    الميزات:
    - كشف بصمات الخوادم (Apache, Nginx, IIS)
    - كشف بصمات frameworks (React, Angular, Vue, jQuery)
    - كشف بصمات CMS (WordPress, Drupal, Joomla)
    - كشف بصمات لغات البرمجة (PHP, Python, Java, Ruby)
    - كشف بصمات قواعد البيانات (MySQL, PostgreSQL, MongoDB)
    - كشف بصمات WAF (Cloudflare, AWS WAF, ModSecurity)
    - تحليل الهيدرات والكوكيز
    """
    
    # أنماط كشف الخوادم
    SERVER_PATTERNS = {
        "Apache": [r'Apache(?:/(\d+\.\d+(?:\.\d+)?))?'],
        "Nginx": [r'nginx(?:/(\d+\.\d+(?:\.\d+)?))?'],
        "IIS": [r'Microsoft-IIS(?:/(\d+\.\d+))?'],
        "Cloudflare": [r'cloudflare'],
        "AWS": [r'AmazonS3|aws|AWS'],
    }
    
    # أنماط كشف Frameworks
    FRAMEWORK_PATTERNS = {
        "React": [r'react', r'ReactDOM', r'__REACT_'],
        "Angular": [r'ng-', r'angular', r'ng-app'],
        "Vue.js": [r'vue', r'data-v-', r'Vue\.js'],
        "jQuery": [r'jquery', r'\$\(', r'jQuery'],
        "Bootstrap": [r'bootstrap', r'data-bs-'],
        "Tailwind": [r'tailwind', r'class=".*?tw-'],
        "Laravel": [r'laravel', r'csrf-token'],
        "Django": [r'csrfmiddlewaretoken', r'django'],
        "Rails": [r'rails', r'csrf-param'],
    }
    
    # أنماط كشف CMS
    CMS_PATTERNS = {
        "WordPress": [
            r'wp-content', r'wp-includes', r'wp-json', r'WordPress',
            r'generator" content="WordPress'
        ],
        "Drupal": [r'drupal', r'sites/default/files', r'Drupal.settings'],
        "Joomla": [r'joomla', r'media/system/js', r'Joomla\.'],
        "Magento": [r'magento', r'Mage\.', r'skin/frontend'],
        "Shopify": [r'shopify', r'myshopify\.com'],
    }
    
    # أنماط كشف لغات البرمجة
    LANGUAGE_PATTERNS = {
        "PHP": [r'\.php', r'PHPSESSID', r'X-Powered-By: PHP'],
        "Python": [r'\.py', r'python', r'wsgi'],
        "Java": [r'\.jsp', r'\.do', r'JSESSIONID', r'Java'],
        "Ruby": [r'\.rb', r'rails', r'ruby'],
        "Node.js": [r'node', r'express', r'x-powered-by: express'],
        "ASP.NET": [r'\.aspx', r'ASP\.NET', r'ViewState', r'__VIEWSTATE'],
    }
    
    # أنماط كشف قواعد البيانات
    DATABASE_PATTERNS = {
        "MySQL": [r'mysql', r'MySQL', r'SQL syntax.*MySQL'],
        "PostgreSQL": [r'postgresql', r'PostgreSQL', r'pg_'],
        "MongoDB": [r'mongodb', r'mongo', r'MongoDB'],
        "SQLite": [r'sqlite', r'SQLite'],
        "Oracle": [r'oracle', r'ORA-', r'Oracle'],
        "MSSQL": [r'mssql', r'SQL Server', r'MS SQL'],
    }
    
    # أنماط كشف WAF
    WAF_PATTERNS = {
        "Cloudflare": [r'cloudflare', r'__cfduid', r'cf-ray', r'cf-cache-status'],
        "AWS WAF": [r'awswaf', r'x-amzn-RequestId', r'x-amzn-ErrorType'],
        "ModSecurity": [r'ModSecurity', r'OWASP', r'Mod_Security'],
        "Imperva": [r'incapsula', r'X-Cdn', r'visid_incap'],
        "Sucuri": [r'sucuri', r'X-Sucuri', r'sucuri/cloudproxy'],
        "Akamai": [r'akamai', r'AkamaiGHost'],
    }
    
    def __init__(self):
        self._fingerprints: Dict[str, List[Fingerprint]] = {}
        
        logger.info("FingerprintEngine initialized")
    
    async def analyze_headers(self, headers: Dict[str, str]) -> List[Fingerprint]:
        """
        تحليل الهيدرات للكشف عن البصمات
        
        Args:
            headers: قاموس الهيدرات
        
        Returns:
            قائمة بالبصمات المكتشفة
        """
        fingerprints = []
        
        # خادم الويب
        server = headers.get("server", "") or headers.get("Server", "")
        if server:
            for name, patterns in self.SERVER_PATTERNS.items():
                for pattern in patterns:
                    match = re.search(pattern, server, re.I)
                    if match:
                        version = match.group(1) if match.groups() else None
                        fingerprints.append(Fingerprint(
                            name=name,
                            category="server",
                            version=version,
                            confidence=0.9,
                            evidence=server
                        ))
        
        # لغة البرمجة من X-Powered-By
        powered_by = headers.get("x-powered-by", "") or headers.get("X-Powered-By", "")
        if powered_by:
            for name, patterns in self.LANGUAGE_PATTERNS.items():
                for pattern in patterns:
                    if re.search(pattern, powered_by, re.I):
                        fingerprints.append(Fingerprint(
                            name=name,
                            category="language",
                            confidence=0.8,
                            evidence=powered_by
                        ))
        
        return fingerprints
    
    async def analyze_cookies(self, cookies: Dict[str, str]) -> List[Fingerprint]:
        """
        تحليل الكوكيز للكشف عن البصمات
        
        Args:
            cookies: قاموس الكوكيز
        
        Returns:
            قائمة بالبصمات المكتشفة
        """
        fingerprints = []
        cookie_str = str(cookies)
        
        # لغة البرمجة من أنماط الجلسات
        if "PHPSESSID" in cookie_str:
            fingerprints.append(Fingerprint(
                name="PHP",
                category="language",
                confidence=0.95,
                evidence="PHPSESSID cookie"
            ))
        
        if "JSESSIONID" in cookie_str:
            fingerprints.append(Fingerprint(
                name="Java",
                category="language",
                confidence=0.95,
                evidence="JSESSIONID cookie"
            ))
        
        if "ASP.NET_SessionId" in cookie_str or "__VIEWSTATE" in cookie_str:
            fingerprints.append(Fingerprint(
                name="ASP.NET",
                category="language",
                confidence=0.95,
                evidence="ASP.NET session cookie"
            ))
        
        # WAF من الكوكيز
        if "__cfduid" in cookie_str:
            fingerprints.append(Fingerprint(
                name="Cloudflare",
                category="waf",
                confidence=0.95,
                evidence="__cfduid cookie"
            ))
        
        if "incap_ses" in cookie_str or "visid_incap" in cookie_str:
            fingerprints.append(Fingerprint(
                name="Imperva",
                category="waf",
                confidence=0.9,
                evidence="Incapsula cookies"
            ))
        
        return fingerprints
    
    async def analyze_html(self, html: str) -> List[Fingerprint]:
        """
        تحليل محتوى HTML للكشف عن البصمات
        
        Args:
            html: محتوى HTML
        
        Returns:
            قائمة بالبصمات المكتشفة
        """
        fingerprints = []
        
        # Frameworks
        for name, patterns in self.FRAMEWORK_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, html, re.I):
                    fingerprints.append(Fingerprint(
                        name=name,
                        category="framework",
                        confidence=0.7,
                        evidence=f"Pattern '{pattern}' found"
                    ))
                    break
        
        # CMS
        for name, patterns in self.CMS_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, html, re.I):
                    fingerprints.append(Fingerprint(
                        name=name,
                        category="cms",
                        confidence=0.8,
                        evidence=f"Pattern '{pattern}' found"
                    ))
                    break
        
        # لغات البرمجة
        for name, patterns in self.LANGUAGE_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, html, re.I):
                    existing = any(f.name == name for f in fingerprints)
                    if not existing:
                        fingerprints.append(Fingerprint(
                            name=name,
                            category="language",
                            confidence=0.6,
                            evidence=f"Pattern '{pattern}' found"
                        ))
                    break
        
        return fingerprints
    
    async def analyze_url(self, url: str) -> List[Fingerprint]:
        """
        تحليل URL للكشف عن البصمات
        
        Args:
            url: الرابط
        
        Returns:
            قائمة بالبصمات المكتشفة
        """
        fingerprints = []
        url_lower = url.lower()
        
        # امتدادات الملفات
        extensions = {
            ".php": "PHP",
            ".jsp": "Java",
            ".do": "Java",
            ".aspx": "ASP.NET",
            ".py": "Python",
            ".rb": "Ruby",
        }
        
        for ext, language in extensions.items():
            if ext in url_lower:
                fingerprints.append(Fingerprint(
                    name=language,
                    category="language",
                    confidence=0.7,
                    evidence=f"URL contains {ext} extension"
                ))
        
        # مسارات CMS
        cms_paths = {
            "wp-admin": "WordPress",
            "wp-content": "WordPress",
            "sites/default": "Drupal",
            "administrator": "Joomla",
        }
        
        for path, cms in cms_paths.items():
            if f"/{path}/" in url_lower:
                fingerprints.append(Fingerprint(
                    name=cms,
                    category="cms",
                    confidence=0.85,
                    evidence=f"URL contains /{path}/ path"
                ))
        
        # API indicators
        if "/api/" in url_lower:
            fingerprints.append(Fingerprint(
                name="REST API",
                category="api",
                confidence=0.9,
                evidence="/api/ endpoint detected"
            ))
        
        if "/graphql" in url_lower:
            fingerprints.append(Fingerprint(
                name="GraphQL",
                category="api",
                confidence=0.95,
                evidence="GraphQL endpoint detected"
            ))
        
        return fingerprints
    
    async def analyze_response(self, response_text: str, status_code: int) -> List[Fingerprint]:
        """
        تحليل الاستجابة الكاملة للكشف عن البصمات
        
        Args:
            response_text: نص الاستجابة
            status_code: كود الحالة
        
        Returns:
            قائمة بالبصمات المكتشفة
        """
        fingerprints = []
        
        # قواعد البيانات من أخطاء SQL
        for name, patterns in self.DATABASE_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, response_text, re.I):
                    fingerprints.append(Fingerprint(
                        name=name,
                        category="database",
                        confidence=0.85,
                        evidence=f"SQL error pattern '{pattern}' found"
                    ))
                    break
        
        # WAF من صفحات الحظر
        if status_code in [403, 406, 503]:
            for name, patterns in self.WAF_PATTERNS.items():
                for pattern in patterns:
                    if re.search(pattern, response_text, re.I):
                        fingerprints.append(Fingerprint(
                            name=name,
                            category="waf",
                            confidence=0.9,
                            evidence=f"WAF pattern '{pattern}' found"
                        ))
                        break
        
        return fingerprints
    
    async def get_all_fingerprints(self, target_url: str) -> List[Fingerprint]:
        """
        الحصول على جميع البصمات لهدف معين
        
        Args:
            target_url: الرابط المستهدف
        
        Returns:
            قائمة بجميع البصمات
        """
        return self._fingerprints.get(target_url, [])
    
    async def add_fingerprint(self, target_url: str, fingerprint: Fingerprint):
        """
        إضافة بصمة لهدف معين
        
        Args:
            target_url: الرابط المستهدف
            fingerprint: البصمة
        """
        if target_url not in self._fingerprints:
            self._fingerprints[target_url] = []
        
        # تجنب التكرار
        existing = any(
            f.name == fingerprint.name and f.category == fingerprint.category
            for f in self._fingerprints[target_url]
        )
        
        if not existing:
            self._fingerprints[target_url].append(fingerprint)
    
    async def get_summary(self, target_url: str) -> Dict:
        """
        الحصول على ملخص البصمات لهدف معين
        
        Args:
            target_url: الرابط المستهدف
        
        Returns:
            ملخص البصمات
        """
        fingerprints = await self.get_all_fingerprints(target_url)
        
        if not fingerprints:
            return {"has_fingerprints": False}
        
        categories = {}
        for fp in fingerprints:
            if fp.category not in categories:
                categories[fp.category] = []
            categories[fp.category].append({
                "name": fp.name,
                "version": fp.version,
                "confidence": fp.confidence
            })
        
        return {
            "target_url": target_url,
            "has_fingerprints": True,
            "total_fingerprints": len(fingerprints),
            "categories": categories,
            "most_confident": max(fingerprints, key=lambda x: x.confidence).name if fingerprints else None
        }
    
    async def clear_fingerprints(self, target_url: str = None):
        """
        مسح البصمات
        
        Args:
            target_url: رابط الهدف (الكل إذا None)
        """
        if target_url:
            self._fingerprints.pop(target_url, None)
        else:
            self._fingerprints.clear()
        
        logger.info(f"Fingerprints cleared for {target_url if target_url else 'all targets'}")
    
    async def get_statistics(self) -> Dict:
        """إحصائيات المحرك"""
        total_fingerprints = sum(len(v) for v in self._fingerprints.values())
        
        return {
            "total_targets": len(self._fingerprints),
            "total_fingerprints": total_fingerprints,
            "avg_fingerprints_per_target": total_fingerprints / len(self._fingerprints) if self._fingerprints else 0,
            "categories": {
                "server": sum(1 for v in self._fingerprints.values() for f in v if f.category == "server"),
                "framework": sum(1 for v in self._fingerprints.values() for f in v if f.category == "framework"),
                "cms": sum(1 for v in self._fingerprints.values() for f in v if f.category == "cms"),
                "language": sum(1 for v in self._fingerprints.values() for f in v if f.category == "language"),
                "database": sum(1 for v in self._fingerprints.values() for f in v if f.category == "database"),
                "waf": sum(1 for v in self._fingerprints.values() for f in v if f.category == "waf"),
            }
        }

