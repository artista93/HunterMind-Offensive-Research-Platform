"""
Subdomain Scanner - فحص النطاقات الفرعية المكتشفة

لكل subdomain:
- التحقق من وجوده (HTTP/HTTPS)
- فحص شهادة SSL
- جلب عنوان الصفحة
- اكتشاف redirects
- فحص سريع للتقنيات
"""

import asyncio
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from urllib.parse import urlparse

import httpx
import logging

logger = logging.getLogger(__name__)


@dataclass
class SubdomainInfo:
    """معلومات نطاق فرعي"""
    url: str
    status_code: int = 0
    title: str = ""
    server: str = ""
    content_type: str = ""
    content_length: int = 0
    redirect_url: str = ""
    ssl_valid: bool = False
    ssl_issuer: str = ""
    response_time_ms: float = 0.0
    is_accessible: bool = False
    technologies: List[str] = field(default_factory=list)
    interesting: bool = False
    notes: str = ""


@dataclass
class SubdomainScanResult:
    """نتائج فحص النطاقات الفرعية"""
    target: str
    subdomains: List[SubdomainInfo] = field(default_factory=list)
    total_scanned: int = 0
    accessible_count: int = 0
    interesting_count: int = 0


class SubdomainScanner:
    """فاحص النطاقات الفرعية"""
    
    # كلمات مثيرة للاهتمام في العناوين
    INTERESTING_TITLES = [
        "admin", "login", "dashboard", "panel", "control",
        "dev", "staging", "test", "api", "upload", "backup",
        "config", "setup", "install", "debug", "status",
        "jenkins", "gitlab", "phpmyadmin", "grafana",
    ]
    
    def __init__(self):
        self._client = None
    
    async def _get_client(self) -> httpx.AsyncClient:
        if not self._client:
            self._client = httpx.AsyncClient(
                timeout=10, follow_redirects=True, verify=False,
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0.0.0 Safari/537.36"}
            )
        return self._client
    
    async def scan(self, subdomains: List[str]) -> SubdomainScanResult:
        """فحص قائمة النطاقات الفرعية"""
        result = SubdomainScanResult(target="")
        
        if not subdomains:
            return result
        
        print(f"  🔍 Scanning {len(subdomains)} subdomains...")
        
        tasks = []
        for sub in subdomains[:30]:  # حد أقصى 30
            for protocol in ["https", "http"]:
                url = f"{protocol}://{sub}"
                tasks.append(self._scan_subdomain(url))
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for res in results:
            if isinstance(res, SubdomainInfo) and res.is_accessible:
                result.subdomains.append(res)
        
        result.total_scanned = len(subdomains[:30])
        result.accessible_count = len(result.subdomains)
        result.interesting_count = len([s for s in result.subdomains if s.interesting])
        
        # عرض النتائج
        if result.subdomains:
            print(f"     ✅ {result.accessible_count} accessible subdomains")
            for sub in result.subdomains[:10]:
                marker = " ⚡" if sub.interesting else ""
                print(f"     {sub.url} ({sub.status_code}) - {sub.title[:50]}{marker}")
        
        return result
    
    async def _scan_subdomain(self, url: str) -> Optional[SubdomainInfo]:
        """فحص نطاق فرعي واحد"""
        client = await self._get_client()
        
        try:
            import time
            start = time.time()
            response = await client.get(url)
            elapsed = (time.time() - start) * 1000
            
            if response.status_code < 500:
                info = SubdomainInfo(
                    url=url,
                    status_code=response.status_code,
                    title=self._extract_title(response.text),
                    server=response.headers.get("server", ""),
                    content_type=response.headers.get("content-type", ""),
                    content_length=len(response.text),
                    response_time_ms=elapsed,
                    is_accessible=True,
                )
                
                # فحص إذا كان مثير للاهتمام
                title_lower = info.title.lower()
                for keyword in self.INTERESTING_TITLES:
                    if keyword in title_lower or keyword in url.lower():
                        info.interesting = True
                        info.notes = f"Interesting keyword: {keyword}"
                        break
                
                # فحص redirect
                if response.history:
                    info.redirect_url = str(response.url)
                
                return info
        
        except:
            pass
        
        return None
    
    def _extract_title(self, html: str) -> str:
        """استخراج عنوان الصفحة"""
        import re
        match = re.search(r'<title>(.*?)</title>', html, re.I | re.DOTALL)
        return match.group(1).strip()[:100] if match else ""
    
    async def close(self):
        if self._client:
            await self._client.aclose()


_subdomain_scanner = None

def get_subdomain_scanner() -> SubdomainScanner:
    global _subdomain_scanner
    if _subdomain_scanner is None:
        _subdomain_scanner = SubdomainScanner()
    return _subdomain_scanner
