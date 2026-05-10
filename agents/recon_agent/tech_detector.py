
import re
import json
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from collections import defaultdict

import logging

logger = logging.getLogger(__name__)


@dataclass
class Technology:
    """تقنية مكتشفة"""
    name: str
    category: str
    version: Optional[str] = None
    confidence: float = 0.0
    evidence: List[str] = field(default_factory=list)
    detected_at: datetime = field(default_factory=datetime.now)


class TechDetector:
    """
    كاشف التقنيات المتقدم
    
    الميزات:
    - كشف التقنيات الأمامية (Frontend)
    - كشف التقنيات الخلفية (Backend)
    - كشف خدمات الطرف الثالث
    - كشف أدوات التحليلات
    - كشف أطر العمل والمكتبات
    - تحليل كثافة الاستخدام
    """
    
    # تقنيات Frontend
    FRONTEND_TECHS = {
        "React": {
            "patterns": [r'react', r'ReactDOM', r'__REACT_', r'useState', r'useEffect'],
            "confidence": 0.8,
            "category": "frontend_framework"
        },
        "Angular": {
            "patterns": [r'ng-', r'angular', r'ng-app', r'ng-controller', r'AngularJS'],
            "confidence": 0.85,
            "category": "frontend_framework"
        },
        "Vue.js": {
            "patterns": [r'vue', r'data-v-', r'Vue\.js', r'v-model', r'v-for'],
            "confidence": 0.8,
            "category": "frontend_framework"
        },
        "jQuery": {
            "patterns": [r'jquery', r'\$\(', r'jQuery', r'\.jquery'],
            "confidence": 0.9,
            "category": "library"
        },
        "Bootstrap": {
            "patterns": [r'bootstrap', r'data-bs-', r'bs\.', r'\.btn-'],
            "confidence": 0.85,
            "category": "css_framework"
        },
        "Tailwind CSS": {
            "patterns": [r'tailwind', r'class=".*?tw-', r'@tailwind'],
            "confidence": 0.8,
            "category": "css_framework"
        },
        "Material UI": {
            "patterns": [r'material-ui', r'Mui', r'@material-ui'],
            "confidence": 0.75,
            "category": "ui_library"
        },
        "Next.js": {
            "patterns": [r'next', r'__NEXT_DATA__', r'next/'],
            "confidence": 0.8,
            "category": "frontend_framework"
        },
        "Nuxt.js": {
            "patterns": [r'nuxt', r'__NUXT__'],
            "confidence": 0.8,
            "category": "frontend_framework"
        },
        "Svelte": {
            "patterns": [r'svelte', r'__svelte'],
            "confidence": 0.75,
            "category": "frontend_framework"
        },
    }
    
    # تقنيات Backend
    BACKEND_TECHS = {
        "Node.js": {
            "patterns": [r'node', r'express', r'x-powered-by: express', r'connect.sid'],
            "confidence": 0.8,
            "category": "backend_runtime"
        },
        "Python": {
            "patterns": [r'python', r'django', r'flask', r'wsgi', r'fastapi'],
            "confidence": 0.7,
            "category": "backend_language"
        },
        "PHP": {
            "patterns": [r'\.php', r'PHPSESSID', r'x-powered-by: php'],
            "confidence": 0.9,
            "category": "backend_language"
        },
        "Java": {
            "patterns": [r'\.jsp', r'\.do', r'JSESSIONID', r'java', r'spring'],
            "confidence": 0.85,
            "category": "backend_language"
        },
        "Ruby": {
            "patterns": [r'\.rb', r'rails', r'ruby', r'rack'],
            "confidence": 0.75,
            "category": "backend_language"
        },
        "Go": {
            "patterns": [r'go\.', r'golang', r'goroutine'],
            "confidence": 0.7,
            "category": "backend_language"
        },
        "ASP.NET": {
            "patterns": [r'\.aspx', r'ASP\.NET', r'ViewState', r'__VIEWSTATE'],
            "confidence": 0.9,
            "category": "backend_framework"
        },
        "Django": {
            "patterns": [r'django', r'csrfmiddlewaretoken', r'Django'],
            "confidence": 0.85,
            "category": "backend_framework"
        },
        "Laravel": {
            "patterns": [r'laravel', r'csrf-token', r'Laravel'],
            "confidence": 0.85,
            "category": "backend_framework"
        },
        "Spring Boot": {
            "patterns": [r'spring', r'boot', r'X-Application-Context'],
            "confidence": 0.8,
            "category": "backend_framework"
        },
        "FastAPI": {
            "patterns": [r'fastapi', r'openapi.json', r'swagger'],
            "confidence": 0.75,
            "category": "backend_framework"
        },
    }
    
    # خدمات الطرف الثالث
    THIRD_PARTY_SERVICES = {
        "Google Analytics": {
            "patterns": [r'google-analytics\.com/analytics', r'ga\(', r'gtag'],
            "confidence": 0.95,
            "category": "analytics"
        },
        "Facebook Pixel": {
            "patterns": [r'fbq\(', r'facebook\.com/tr'],
            "confidence": 0.95,
            "category": "analytics"
        },
        "Hotjar": {
            "patterns": [r'hotjar', r'hj\.', r'_hj'],
            "confidence": 0.9,
            "category": "analytics"
        },
        "Cloudflare": {
            "patterns": [r'cloudflare', r'__cfduid', r'cf-ray'],
            "confidence": 0.95,
            "category": "cdn_waf"
        },
        "AWS CloudFront": {
            "patterns": [r'cloudfront', r'x-amz-cf-id'],
            "confidence": 0.85,
            "category": "cdn"
        },
        "Akamai": {
            "patterns": [r'akamai', r'AkamaiGHost'],
            "confidence": 0.85,
            "category": "cdn"
        },
        "Stripe": {
            "patterns": [r'stripe\.com', r'Stripe\.js', r'pk_live_'],
            "confidence": 0.9,
            "category": "payment"
        },
        "PayPal": {
            "patterns": [r'paypal', r'paypalobjects', r'paypal\.com'],
            "confidence": 0.85,
            "category": "payment"
        },
        "Intercom": {
            "patterns": [r'intercom', r'Intercom\.io'],
            "confidence": 0.9,
            "category": "chat"
        },
        "LiveChat": {
            "patterns": [r'livechat', r'livechatinc'],
            "confidence": 0.85,
            "category": "chat"
        },
        "Disqus": {
            "patterns": [r'disqus', r'disqus\.com'],
            "confidence": 0.9,
            "category": "comments"
        },
        "Typekit": {
            "patterns": [r'typekit', r'use\.typekit\.net'],
            "confidence": 0.85,
            "category": "fonts"
        },
        "Google Fonts": {
            "patterns": [r'fonts\.googleapis\.com', r'fonts\.gstatic\.com'],
            "confidence": 0.95,
            "category": "fonts"
        },
    }
    
    # خوادم الويب
    WEB_SERVERS = {
        "Nginx": {
            "patterns": [r'nginx', r'server: nginx'],
            "confidence": 0.9,
            "category": "web_server"
        },
        "Apache": {
            "patterns": [r'apache', r'server: apache'],
            "confidence": 0.9,
            "category": "web_server"
        },
        "IIS": {
            "patterns": [r'iis', r'server: microsoft-iis'],
            "confidence": 0.9,
            "category": "web_server"
        },
        "Caddy": {
            "patterns": [r'caddy', r'server: caddy'],
            "confidence": 0.8,
            "category": "web_server"
        },
    }
    
    # قواعد البيانات
    DATABASES = {
        "MySQL": {
            "patterns": [r'mysql', r'MySQL', r'SQL syntax.*MySQL', r'maria'],
            "confidence": 0.8,
            "category": "database"
        },
        "PostgreSQL": {
            "patterns": [r'postgresql', r'PostgreSQL', r'pg_', r'pgsql'],
            "confidence": 0.8,
            "category": "database"
        },
        "MongoDB": {
            "patterns": [r'mongodb', r'mongo', r'MongoDB', r'mongoose'],
            "confidence": 0.75,
            "category": "database"
        },
        "SQLite": {
            "patterns": [r'sqlite', r'SQLite', r'sqlite_'],
            "confidence": 0.7,
            "category": "database"
        },
        "Redis": {
            "patterns": [r'redis', r'Redis'],
            "confidence": 0.7,
            "category": "cache"
        },
        "Elasticsearch": {
            "patterns": [r'elasticsearch', r'elastic'],
            "confidence": 0.7,
            "category": "search"
        },
    }
    
    def __init__(self):
        self._detected_techs: Dict[str, List[Technology]] = {}
        
        logger.info("TechDetector initialized")
    
    async def detect_all(
        self,
        url: str,
        html: str,
        headers: Dict[str, str],
        cookies: Dict[str, str]
    ) -> List[Technology]:
        """
        اكتشاف جميع التقنيات من مصادر متعددة
        
        Args:
            url: الرابط المستهدف
            html: محتوى HTML
            headers: الهيدرات
            cookies: الكوكيز
        
        Returns:
            قائمة بالتقنيات المكتشفة
        """
        all_techs = []
        
        # دمج جميع المصادر
        all_techs.extend(await self._detect_from_html(html))
        all_techs.extend(await self._detect_from_headers(headers))
        all_techs.extend(await self._detect_from_cookies(cookies))
        all_techs.extend(await self._detect_from_url(url))
        
        # إزالة التكرارات
        unique_techs = {}
        for tech in all_techs:
            key = f"{tech.name}:{tech.category}"
            if key not in unique_techs or tech.confidence > unique_techs[key].confidence:
                unique_techs[key] = tech
        
        result = list(unique_techs.values())
        
        # تخزين النتائج
        self._detected_techs[url] = result
        
        return result
    
    async def _detect_from_html(self, html: str) -> List[Technology]:
        """اكتشاف التقنيات من HTML"""
        techs = []
        
        # Frontend
        for name, info in self.FRONTEND_TECHS.items():
            for pattern in info["patterns"]:
                if re.search(pattern, html, re.I):
                    techs.append(Technology(
                        name=name,
                        category=info["category"],
                        confidence=info["confidence"],
                        evidence=[f"Pattern '{pattern}' found in HTML"]
                    ))
                    break
        
        # Backend (بعضها يظهر في HTML)
        for name, info in self.BACKEND_TECHS.items():
            for pattern in info["patterns"]:
                if re.search(pattern, html, re.I):
                    techs.append(Technology(
                        name=name,
                        category=info["category"],
                        confidence=info["confidence"] * 0.7,  # ثقة أقل من headers
                        evidence=[f"Pattern '{pattern}' found in HTML"]
                    ))
                    break
        
        # خدمات الطرف الثالث
        for name, info in self.THIRD_PARTY_SERVICES.items():
            for pattern in info["patterns"]:
                if re.search(pattern, html, re.I):
                    techs.append(Technology(
                        name=name,
                        category=info["category"],
                        confidence=info["confidence"],
                        evidence=[f"Pattern '{pattern}' found in HTML"]
                    ))
                    break
        
        return techs
    
    async def _detect_from_headers(self, headers: Dict[str, str]) -> List[Technology]:
        """اكتشاف التقنيات من الهيدرات"""
        techs = []
        headers_str = str(headers).lower()
        
        # خوادم الويب
        for name, info in self.WEB_SERVERS.items():
            for pattern in info["patterns"]:
                if re.search(pattern, headers_str, re.I):
                    techs.append(Technology(
                        name=name,
                        category=info["category"],
                        confidence=info["confidence"],
                        evidence=[f"Pattern '{pattern}' found in headers"]
                    ))
                    break
        
        # Backend
        for name, info in self.BACKEND_TECHS.items():
            for pattern in info["patterns"]:
                if re.search(pattern, headers_str, re.I):
                    techs.append(Technology(
                        name=name,
                        category=info["category"],
                        confidence=info["confidence"],
                        evidence=[f"Pattern '{pattern}' found in headers"]
                    ))
                    break
        
        # خدمات الطرف الثالث
        for name, info in self.THIRD_PARTY_SERVICES.items():
            for pattern in info["patterns"]:
                if re.search(pattern, headers_str, re.I):
                    techs.append(Technology(
                        name=name,
                        category=info["category"],
                        confidence=info["confidence"] * 0.8,
                        evidence=[f"Pattern '{pattern}' found in headers"]
                    ))
                    break
        
        return techs
    
    async def _detect_from_cookies(self, cookies: Dict[str, str]) -> List[Technology]:
        """اكتشاف التقنيات من الكوكيز"""
        techs = []
        cookies_str = str(cookies).lower()
        
        # Backend من أنماط الجلسات
        session_patterns = {
            "PHP": ["phpsessid", "php"],
            "Java": ["jsessionid", "java"],
            "ASP.NET": ["asp.net_sessionid", "__viewstate"],
            "Python": ["sessionid", "csrftoken"],
            "Node.js": ["connect.sid", "token"],
        }
        
        for name, patterns in session_patterns.items():
            for pattern in patterns:
                if pattern in cookies_str:
                    techs.append(Technology(
                        name=name,
                        category="backend_language",
                        confidence=0.85,
                        evidence=[f"Cookie pattern '{pattern}' found"]
                    ))
                    break
        
        # WAF من الكوكيز
        waf_cookies = {
            "Cloudflare": ["__cfduid"],
            "Imperva": ["incap_ses", "visid_incap"],
            "Sucuri": ["sucuri"],
        }
        
        for name, patterns in waf_cookies.items():
            for pattern in patterns:
                if pattern in cookies_str:
                    techs.append(Technology(
                        name=name,
                        category="waf",
                        confidence=0.95,
                        evidence=[f"WAF cookie '{pattern}' found"]
                    ))
                    break
        
        return techs
    
    async def _detect_from_url(self, url: str) -> List[Technology]:
        """اكتشاف التقنيات من URL"""
        techs = []
        url_lower = url.lower()
        
        # امتدادات الملفات
        extension_map = {
            ".php": ("PHP", "backend_language", 0.7),
            ".jsp": ("Java", "backend_language", 0.7),
            ".do": ("Java", "backend_language", 0.6),
            ".aspx": ("ASP.NET", "backend_language", 0.7),
            ".py": ("Python", "backend_language", 0.5),
            ".rb": ("Ruby", "backend_language", 0.5),
        }
        
        for ext, (name, category, confidence) in extension_map.items():
            if ext in url_lower:
                techs.append(Technology(
                    name=name,
                    category=category,
                    confidence=confidence,
                    evidence=[f"URL contains {ext} extension"]
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
                techs.append(Technology(
                    name=cms,
                    category="cms",
                    confidence=0.85,
                    evidence=[f"URL contains /{path}/ path"]
                ))
        
        # API indicators
        if "/api/" in url_lower:
            techs.append(Technology(
                name="REST API",
                category="api",
                confidence=0.9,
                evidence=["/api/ endpoint detected"]
            ))
        
        return techs
    
    async def get_techs_for_url(self, url: str) -> List[Technology]:
        """الحصول على التقنيات المكتشفة لهدف معين"""
        return self._detected_techs.get(url, [])
    
    async def get_summary(self, url: str) -> Dict:
        """ملخص التقنيات لهدف معين"""
        techs = await self.get_techs_for_url(url)
        
        if not techs:
            return {"has_technologies": False}
        
        categories = defaultdict(list)
        for tech in techs:
            categories[tech.category].append({
                "name": tech.name,
                "confidence": tech.confidence
            })
        
        return {
            "target_url": url,
            "has_technologies": True,
            "total_technologies": len(techs),
            "categories": dict(categories),
            "most_confident": max(techs, key=lambda x: x.confidence).name if techs else None
        }
    
    async def clear_techs(self, url: str = None):
        """مسح التقنيات المكتشفة"""
        if url:
            self._detected_techs.pop(url, None)
        else:
            self._detected_techs.clear()
        
        logger.info(f"Technologies cleared for {url if url else 'all targets'}")
    
    async def get_statistics(self) -> Dict:
        """إحصائيات الكاشف"""
        total_techs = sum(len(v) for v in self._detected_techs.values())
        
        # إحصائيات حسب الفئة
        category_stats = defaultdict(int)
        for techs in self._detected_techs.values():
            for tech in techs:
                category_stats[tech.category] += 1
        
        return {
            "total_targets": len(self._detected_techs),
            "total_technologies": total_techs,
            "avg_techs_per_target": total_techs / len(self._detected_techs) if self._detected_techs else 0,
            "category_distribution": dict(category_stats),
            "available_patterns": {
                "frontend": len(self.FRONTEND_TECHS),
                "backend": len(self.BACKEND_TECHS),
                "third_party": len(self.THIRD_PARTY_SERVICES),
                "web_servers": len(self.WEB_SERVERS),
                "databases": len(self.DATABASES),
            }
        }

