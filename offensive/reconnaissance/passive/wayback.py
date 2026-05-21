"""
Wayback Machine Search - استخراج الصفحات المؤرشفة من أرشيف الإنترنت

يستخدم Wayback Machine API للبحث عن:
- كل الصفحات المؤرشفة للنطاق
- الصفحات القديمة اللي ممكن تكون محذوفة دلوقتي
- ملفات حساسة كانت موجودة في الماضي
- صفحات dev/staging منسية
- Backup files قديمة
"""

import asyncio
import re
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime

import httpx
import logging

logger = logging.getLogger(__name__)


@dataclass
class WaybackURL:
    """صفحة من أرشيف Wayback Machine"""
    url: str
    timestamp: str = ""
    status_code: str = ""
    mime_type: str = ""
    snapshot_count: int = 0


@dataclass
class WaybackResult:
    """نتائج البحث في Wayback Machine"""
    domain: str
    total_urls: int = 0
    urls: List[WaybackURL] = field(default_factory=list)
    unique_domains: List[str] = field(default_factory=list)
    subdomains: List[str] = field(default_factory=list)
    sensitive_urls: List[WaybackURL] = field(default_factory=list)
    js_files: List[str] = field(default_factory=list)
    api_endpoints: List[str] = field(default_factory=list)
    backup_files: List[str] = field(default_factory=list)
    config_files: List[str] = field(default_factory=list)
    old_pages: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)


class WaybackSearch:
    """
    البحث في أرشيف الإنترنت (Wayback Machine)
    
    archive.org بيخزن نسخ من صفحات الويب من سنة 1996
    """
    
    API_URL = "https://web.archive.org"
    
    # أنماط الملفات المهمة
    SENSITIVE_PATTERNS = [
        # Backup files
        r'\.bak$', r'\.backup$', r'\.old$', r'\.save$', r'\.tmp$',
        r'\.zip$', r'\.tar$', r'\.tar\.gz$', r'\.gz$', r'\.rar$',
        r'\.sql$', r'\.dump$', r'\.sqlite$',
        # Config files
        r'\.env$', r'\.env\.', r'config\.php$', r'wp-config\.php$',
        r'settings\.py$', r'\.htaccess$', r'\.htpasswd$',
        r'web\.config$', r'app\.config$', r'config\.yml$',
        # Git/SVN
        r'\.git/', r'\.svn/', r'\.hg/',
        # Logs
        r'\.log$', r'debug\.log$', r'error\.log$', r'access\.log$',
        # Admin panels
        r'/admin/', r'/wp-admin/', r'/administrator/',
        r'/phpmyadmin/', r'/pma/', r'/db/',
        # API endpoints
        r'/api/', r'/rest/', r'/graphql', r'/swagger',
        # Dev/Staging
        r'dev\.', r'staging\.', r'test\.', r'uat\.', r'beta\.',
        r'\.local$', r'\.dev$', r'\.test$',
    ]
    
    def __init__(self):
        self._results: Dict[str, WaybackResult] = {}
    
    async def search(self, domain: str, limit: int = 1000) -> WaybackResult:
        """
        البحث في Wayback Machine
        
        Args:
            domain: النطاق المراد البحث عنه
            limit: الحد الأقصى للنتائج
        
        Returns:
            WaybackResult مع كل الصفحات المؤرشفة
        """
        print(f"  📚 Searching Wayback Machine: {domain}")
        
        result = WaybackResult(domain=domain)
        
        try:
            # 1. جلب قائمة URLs
            urls = await self._fetch_url_list(domain)
            
            if urls:
                print(f"     📄 Fetching details for {len(urls[:limit])} URLs...")
                
                # 2. تحليل كل URL
                for entry in urls[:limit]:
                    url = entry[0] if isinstance(entry, list) else entry
                    timestamp = entry[1] if len(entry) > 1 else ""
                    
                    wayback_url = WaybackURL(
                        url=url,
                        timestamp=timestamp,
                    )
                    result.urls.append(wayback_url)
                    
                    # تصنيف URL
                    self._classify_url(wayback_url, result)
                
                result.total_urls = len(result.urls)
                result.subdomains = sorted(list(set(result.subdomains)))
                
                print(f"     ✅ Found {result.total_urls} archived URLs")
                print(f"     📋 Subdomains: {len(result.subdomains)}")
                print(f"     🔑 Sensitive URLs: {len(result.sensitive_urls)}")
                print(f"     📜 JS Files: {len(result.js_files)}")
                print(f"     🔌 APIs: {len(result.api_endpoints)}")
                print(f"     💾 Backups: {len(result.backup_files)}")
                print(f"     ⚙️  Configs: {len(result.config_files)}")
        
        except Exception as e:
            result.errors.append(str(e))
            logger.debug(f"Wayback search failed: {e}")
        
        self._results[domain] = result
        return result
    
    async def _fetch_url_list(self, domain: str) -> List[Any]:
        """جلب قائمة URLs من Wayback API"""
        urls = []
        
        try:
            async with httpx.AsyncClient(timeout=60, verify=False) as client:
                # استخدام CDX API
                cdx_url = f"{self.API_URL}/cdx/search/cdx"
                params = {
                    "url": f"*.{domain}/*",
                    "output": "json",
                    "fl": "original,timestamp,statuscode,mimetype",
                    "filter": "statuscode:200",
                    "collapse": "urlkey",
                    "limit": "10000",
                }
                
                response = await client.get(cdx_url, params=params)
                
                if response.status_code == 200:
                    data = response.json()
                    
                    # أول صف هو headers
                    if len(data) > 1:
                        urls = data[1:]  # تجاهل الـ header row
                
                # لو فشل CDX، نجرب API العادي
                if not urls:
                    api_url = f"{self.API_URL}/__wb/sparkline"
                    params = {
                        "url": f"*.{domain}",
                        "collection": "web",
                        "output": "json",
                    }
                    
                    response = await client.get(api_url, params=params)
                    
                    if response.status_code == 200:
                        data = response.json()
                        urls = data.get("urls", [])
        
        except Exception as e:
            logger.debug(f"Wayback API failed: {e}")
        
        return urls
    
    def _classify_url(self, wayback_url: WaybackURL, result: WaybackResult):
        """تصنيف URL حسب النوع"""
        url = wayback_url.url.lower()
        
        # استخراج subdomain
        subdomain_match = re.match(r'(?:https?://)?([^/]+)', url)
        if subdomain_match:
            host = subdomain_match.group(1)
            if host not in result.subdomains and host != result.domain:
                result.subdomains.append(host)
        
        # فحص الأنماط الحساسة
        is_sensitive = False
        for pattern in self.SENSITIVE_PATTERNS:
            if re.search(pattern, url):
                result.sensitive_urls.append(wayback_url)
                is_sensitive = True
                
                # تصنيف أدق
                if re.search(r'\.(?:bak|backup|old|save|tmp|zip|tar|gz|rar|sql|dump|sqlite)$', url):
                    result.backup_files.append(url)
                elif re.search(r'\.env|config\.php|wp-config|settings\.py|\.htaccess|web\.config', url):
                    result.config_files.append(url)
                elif re.search(r'\.js$', url):
                    result.js_files.append(url)
                elif re.search(r'/api/|/rest/|/graphql|/swagger', url):
                    result.api_endpoints.append(url)
                elif re.search(r'dev\.|staging\.|test\.|\.old\.', url):
                    result.old_pages.append(url)
                
                break
    
    def get_results(self, domain: str) -> Optional[WaybackResult]:
        return self._results.get(domain)


# نسخة عالمية
_wayback_search = None

def get_wayback_search() -> WaybackSearch:
    global _wayback_search
    if _wayback_search is None:
        _wayback_search = WaybackSearch()
    return _wayback_search
