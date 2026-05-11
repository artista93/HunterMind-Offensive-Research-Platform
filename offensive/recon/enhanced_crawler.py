import asyncio
import re
import hashlib
import time
from urllib.parse import urljoin, urlparse, urlunparse, quote
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from collections import deque
import json

from ..scanners.base_scanner import BaseScanner, ScanContext

try:
    from playwright.async_api import async_playwright, Page, Browser
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False

import logging

logger = logging.getLogger(__name__)


@dataclass
class CrawledPage:
    url: str
    title: str
    status_code: int
    content_type: str
    content_length: int
    depth: int
    discovered_at: datetime
    forms: List[Dict] = field(default_factory=list)
    links: List[str] = field(default_factory=list)
    scripts: List[str] = field(default_factory=list)
    api_endpoints: List[str] = field(default_factory=list)
    parameters: Dict[str, List[str]] = field(default_factory=dict)
    hash: str = ""


@dataclass
class CrawlResult:
    start_url: str
    start_time: datetime
    end_time: Optional[datetime] = None
    pages_crawled: List[CrawledPage] = field(default_factory=list)
    total_pages: int = 0
    total_forms: int = 0
    total_api_endpoints: int = 0
    errors: List[str] = field(default_factory=list)


class EnhancedCrawler:
    """
    الزاحف المتقدم
    
    الميزات:
    - زحف تطبيقات SPA (Single Page Applications)
    - معالجة JavaScript الديناميكي
    - استخراج النماذج والواجهات API
    - كشف نقاط النهاية المخفية
    - تحليل الروابط الداخلية والخارجية
    - دعم المصادقة (cookies, headers)
    - تقييد المعدل ومنع التكرار
    - تصدير النتائج بصيغ مختلفة
    """
    
    EXCLUDED_EXTENSIONS = {
        '.jpg', '.jpeg', '.png', '.gif', '.svg', '.ico', '.webp',
        '.mp3', '.mp4', '.avi', '.mov', '.wmv',
        '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
        '.zip', '.rar', '.7z', '.tar', '.gz',
        '.exe', '.msi', '.dmg', '.bin'
    }
    
    API_PATTERNS = [
        r'/api/',
        r'/v\d+/',
        r'/rest/',
        r'/graphql',
        r'/swagger',
        r'/openapi',
        r'/\.json$',
        r'/\.yaml$',
    ]
    
    def __init__(
        self,
        max_depth: int = 3,
        max_pages: int = 100,
        max_concurrent: int = 5,
        rate_limit: float = 1.0,
        timeout: int = 30,
        follow_external: bool = False,
        respect_robots: bool = True,
        use_browser: bool = True,
        stealth_mode: bool = True
    ):
        self._max_depth = max_depth
        self._max_pages = max_pages
        self._max_concurrent = max_concurrent
        self._rate_limit = rate_limit
        self._timeout = timeout
        self._follow_external = follow_external
        self._respect_robots = respect_robots
        self._use_browser = use_browser and PLAYWRIGHT_AVAILABLE
        self._stealth_mode = stealth_mode
        
        self._visited_urls: Set[str] = set()
        self._queue: deque = deque()
        self._semaphore = asyncio.Semaphore(max_concurrent)
        self._last_request_time = 0
        self._browser: Optional[Browser] = None
        
        self._stats = {
            "requests_made": 0,
            "pages_processed": 0,
            "forms_found": 0,
            "api_endpoints_found": 0,
            "errors": 0
        }
        
        # BaseScanner reference for HTTP requests
        self._http_scanner = None
        
        logger.info(f"EnhancedCrawler initialized (depth={max_depth}, pages={max_pages})")
    
    def _set_http_scanner(self, scanner: BaseScanner):
        """تعيين BaseScanner لإرسال الطلبات"""
        self._http_scanner = scanner
    
    async def _send_request(
        self,
        url: str,
        method: str = "GET",
        headers: Dict = None
    ) -> Optional[str]:
        """إرسال طلب HTTP باستخدام BaseScanner إذا كان متاحاً"""
        if self._http_scanner and hasattr(self._http_scanner, 'send_request'):
            return await self._http_scanner.send_request(url, method=method, headers=headers)
        
        # Fallback: استخدام httpx مباشرة (مؤقت)
        try:
            import httpx
            async with httpx.AsyncClient(timeout=self._timeout, follow_redirects=True, verify=False) as client:
                response = await client.request(method, url, headers=headers)
                return response.text
        except Exception:
            return None
    
    async def _get_browser(self):
        """الحصول على متصفح Playwright"""
        if not self._browser and self._use_browser:
            playwright = await async_playwright().start()
            if self._stealth_mode:
                self._browser = await playwright.chromium.launch(
                    headless=True,
                    args=['--disable-blink-features=AutomationControlled']
                )
            else:
                self._browser = await playwright.chromium.launch(headless=True)
        return self._browser
    
    async def crawl(self, context: ScanContext) -> CrawlResult:
        start_url = context.target.url
        result = CrawlResult(
            start_url=start_url,
            start_time=datetime.now()
        )
        
        # تعيين الـ http_scanner
        if hasattr(context, 'scanner') and context.scanner:
            self._set_http_scanner(context.scanner)
        
        self._visited_urls.clear()
        self._queue = deque()
        
        normalized = self._normalize_url(start_url)
        self._queue.append((normalized, 0))
        
        logger.info(f"Starting crawl of {start_url} (max_depth={self._max_depth}, max_pages={self._max_pages})")
        
        tasks = []
        while self._queue and len(result.pages_crawled) < self._max_pages:
            batch = []
            while self._queue and len(batch) < self._max_concurrent:
                url, depth = self._queue.popleft()
                if url not in self._visited_urls:
                    batch.append((url, depth))
                    self._visited_urls.add(url)
            
            if batch:
                async def process_item(item):
                    async with self._semaphore:
                        return await self._process_page(item[0], item[1], context)
                
                results = await asyncio.gather(*[process_item(item) for item in batch], return_exceptions=True)
                
                for res in results:
                    if isinstance(res, Exception):
                        result.errors.append(str(res))
                        self._stats["errors"] += 1
                    elif res:
                        page, new_links = res
                        result.pages_crawled.append(page)
                        self._stats["pages_processed"] += 1
                        
                        for link in new_links:
                            if link not in self._visited_urls and len(self._queue) < self._max_pages * 2:
                                self._queue.append((link, page.depth + 1))
        
        result.end_time = datetime.now()
        result.total_pages = len(result.pages_crawled)
        result.total_forms = self._stats["forms_found"]
        result.total_api_endpoints = self._stats["api_endpoints_found"]
        
        logger.info(f"Crawl completed: {result.total_pages} pages, {result.total_forms} forms, {result.total_api_endpoints} APIs")
        
        return result
    
    async def _process_page(
        self,
        url: str,
        depth: int,
        context: ScanContext
    ) -> Tuple[Optional[CrawledPage], List[str]]:
        await self._apply_rate_limit()
        
        page_data = None
        new_links = []
        
        if self._use_browser and depth < 2:
            page_data = await self._crawl_with_browser(url, depth, context)
        else:
            page_data = await self._crawl_with_http(url, depth, context)
        
        if not page_data:
            return None, []
        
        for link in page_data.links:
            absolute_url = urljoin(url, link)
            normalized = self._normalize_url(absolute_url)
            
            if self._should_follow(normalized, depth):
                new_links.append(normalized)
        
        self._stats["forms_found"] += len(page_data.forms)
        self._stats["api_endpoints_found"] += len(page_data.api_endpoints)
        
        return page_data, new_links
    
    async def _crawl_with_http(
        self,
        url: str,
        depth: int,
        context: ScanContext
    ) -> Optional[CrawledPage]:
        try:
            content = await self._send_request(url, method="GET", headers=context.target.headers)
            
            if not content:
                return None
            
            status_code = 200
            content_type = "text/html"
            content_length = len(content)
            
            title = self._extract_title(content)
            forms = self._extract_forms(content, url)
            links = self._extract_links(content, url)
            scripts = self._extract_scripts(content, url)
            api_endpoints = self._extract_api_endpoints(content, url)
            parameters = self._extract_parameters(content, url)
            
            content_hash = hashlib.md5(content.encode()).hexdigest()
            
            return CrawledPage(
                url=url,
                title=title,
                status_code=status_code,
                content_type=content_type,
                content_length=content_length,
                depth=depth,
                discovered_at=datetime.now(),
                forms=forms,
                links=links[:100],
                scripts=scripts[:50],
                api_endpoints=api_endpoints,
                parameters=parameters,
                hash=content_hash
            )
            
        except Exception as e:
            logger.debug(f"Error crawling {url}: {e}")
            return None
    
    async def _crawl_with_browser(
        self,
        url: str,
        depth: int,
        context: ScanContext
    ) -> Optional[CrawledPage]:
        browser = await self._get_browser()
        if not browser:
            return await self._crawl_with_http(url, depth, context)
        
        page = None
        try:
            page = await browser.new_page()
            
            if context.target.cookies:
                await page.context.add_cookies([
                    {"name": k, "value": v, "url": url}
                    for k, v in context.target.cookies.items()
                ])
            
            await page.goto(url, wait_until="networkidle", timeout=self._timeout * 1000)
            await page.wait_for_load_state("networkidle")
            
            content = await page.content()
            title = await page.title()
            
            links = await page.eval_on_selector_all(
                'a[href]',
                'elements => elements.map(el => el.href)'
            )
            
            forms = await self._extract_forms_with_playwright(page, url)
            api_endpoints = await self._capture_network_requests(page, url)
            
            scripts = await page.eval_on_selector_all(
                'script[src]',
                'elements => elements.map(el => el.src)'
            )
            
            status_code = 200
            content_type = "text/html"
            content_length = len(content)
            parameters = self._extract_parameters(content, url)
            
            content_hash = hashlib.md5(content.encode()).hexdigest()
            
            return CrawledPage(
                url=url,
                title=title,
                status_code=status_code,
                content_type=content_type,
                content_length=content_length,
                depth=depth,
                discovered_at=datetime.now(),
                forms=forms,
                links=list(links)[:100] if links else [],
                scripts=list(scripts)[:50] if scripts else [],
                api_endpoints=api_endpoints,
                parameters=parameters,
                hash=content_hash
            )
            
        except Exception as e:
            logger.debug(f"Browser crawling error for {url}: {e}")
            return None
            
        finally:
            if page:
                await page.close()
    
    async def _capture_network_requests(self, page: Page, base_url: str) -> List[str]:
        api_endpoints = []
        
        def on_request(request):
            url = request.url
            if self._is_api_endpoint(url):
                api_endpoints.append(url)
        
        page.on("request", on_request)
        await asyncio.sleep(1)
        page.remove_listener("request", on_request)
        
        return list(set(api_endpoints))[:50]
    
    async def _extract_forms_with_playwright(self, page: Page, base_url: str) -> List[Dict]:
        forms = []
        
        form_elements = await page.query_selector_all('form')
        
        for form in form_elements:
            action = await form.get_attribute('action') or ''
            method = await form.get_attribute('method') or 'GET'
            
            inputs = []
            input_elements = await form.query_selector_all('input, textarea, select')
            
            for inp in input_elements:
                name = await inp.get_attribute('name')
                if name:
                    input_type = await inp.get_attribute('type') or 'text'
                    inputs.append({
                        "name": name,
                        "type": input_type,
                        "value": await inp.get_attribute('value') or ''
                    })
            
            forms.append({
                "action": urljoin(base_url, action),
                "method": method.upper(),
                "inputs": inputs,
                "has_csrf": any("csrf" in inp["name"].lower() or "token" in inp["name"].lower() for inp in inputs)
            })
        
        return forms
    
    def _extract_title(self, html: str) -> str:
        match = re.search(r'<title>(.*?)</title>', html, re.I | re.DOTALL)
        return match.group(1).strip() if match else ""
    
    def _extract_forms(self, html: str, base_url: str) -> List[Dict]:
        forms = []
        
        form_pattern = re.compile(r'<form[^>]*>(.*?)</form>', re.I | re.DOTALL)
        
        for form_match in form_pattern.finditer(html):
            form_html = form_match.group(0)
            
            action_match = re.search(r'action=["\']?([^"\'\\s>]+)', form_html, re.I)
            action = action_match.group(1) if action_match else base_url
            
            method_match = re.search(r'method=["\']?([^"\'\\s>]+)', form_html, re.I)
            method = method_match.group(1).upper() if method_match else "GET"
            
            inputs = []
            input_pattern = re.compile(r'<input[^>]*name=["\']?([^"\'\\s>]+)[^>]*>', re.I)
            for input_match in input_pattern.finditer(form_html):
                name = input_match.group(1)
                inputs.append({"name": name, "type": "text"})
            
            forms.append({
                "action": urljoin(base_url, action),
                "method": method,
                "inputs": inputs,
                "has_csrf": any("csrf" in inp["name"].lower() or "token" in inp["name"].lower() for inp in inputs)
            })
        
        return forms
    
    def _extract_links(self, html: str, base_url: str) -> List[str]:
        links = set()
        
        link_pattern = re.compile(r'<a[^>]*href=["\']([^"\'#]+)["\']', re.I)
        
        for match in link_pattern.finditer(html):
            link = match.group(1).strip()
            if link and not link.startswith('#') and not link.startswith('javascript:'):
                absolute_url = urljoin(base_url, link)
                links.add(absolute_url)
        
        return list(links)
    
    def _extract_scripts(self, html: str, base_url: str) -> List[str]:
        scripts = set()
        
        script_pattern = re.compile(r'<script[^>]*src=["\']([^"\'#]+)["\']', re.I)
        
        for match in script_pattern.finditer(html):
            src = match.group(1).strip()
            absolute_url = urljoin(base_url, src)
            scripts.add(absolute_url)
        
        return list(scripts)
    
    def _extract_api_endpoints(self, html: str, base_url: str) -> List[str]:
        endpoints = set()
        
        for pattern in self.API_PATTERNS:
            api_pattern = re.compile(f'{pattern}[^"\'\\s<>]*', re.I)
            for match in api_pattern.finditer(html):
                endpoint = match.group(0)
                if endpoint.startswith('/'):
                    absolute_url = urljoin(base_url, endpoint)
                    endpoints.add(absolute_url)
        
        return list(endpoints)[:50]
    
    def _extract_parameters(self, html: str, url: str) -> Dict[str, List[str]]:
        parameters = {}
        
        parsed = urlparse(url)
        if parsed.query:
            import urllib.parse
            query_params = urllib.parse.parse_qs(parsed.query)
            for key, values in query_params.items():
                parameters[key] = values
        
        input_pattern = re.compile(r'<input[^>]*name=["\']([^"\'\\s>]+)', re.I)
        for match in input_pattern.finditer(html):
            name = match.group(1)
            if name not in parameters:
                parameters[name] = []
        
        return parameters
    
    def _is_api_endpoint(self, url: str) -> bool:
        url_lower = url.lower()
        for pattern in self.API_PATTERNS:
            if pattern.lower() in url_lower:
                return True
        return False
    
    def _should_follow(self, url: str, current_depth: int) -> bool:
        if current_depth >= self._max_depth:
            return False
        
        parsed = urlparse(url)
        
        path = parsed.path.lower()
        for ext in self.EXCLUDED_EXTENSIONS:
            if path.endswith(ext):
                return False
        
        if parsed.fragment:
            return False
        
        return True
    
    def _normalize_url(self, url: str) -> str:
        parsed = urlparse(url)
        
        normalized = parsed._replace(fragment="")
        
        path = normalized.path
        if not path:
            path = "/"
        normalized = normalized._replace(path=path)
        
        if (normalized.scheme == "http" and normalized.port == 80) or \
           (normalized.scheme == "https" and normalized.port == 443):
            normalized = normalized._replace(netloc=normalized.hostname)
        
        return urlunparse(normalized)
    
    async def _apply_rate_limit(self):
        if self._rate_limit <= 0:
            return
        
        now = time.time()
        elapsed = now - self._last_request_time
        min_interval = 1.0 / self._rate_limit
        
        if elapsed < min_interval:
            await asyncio.sleep(min_interval - elapsed)
        
        self._last_request_time = time.time()
        self._stats["requests_made"] += 1
    
    async def get_statistics(self) -> Dict:
        return {
            "total_requests": self._stats["requests_made"],
            "pages_processed": self._stats["pages_processed"],
            "forms_found": self._stats["forms_found"],
            "api_endpoints_found": self._stats["api_endpoints_found"],
            "errors": self._stats["errors"],
            "max_depth": self._max_depth,
            "max_pages": self._max_pages,
            "use_browser": self._use_browser,
            "playwright_available": PLAYWRIGHT_AVAILABLE
        }
    
    async def close(self):
        if self._browser:
            await self._browser.close()
            self._browser = None
        
        logger.info("EnhancedCrawler closed")


async def get_enhanced_crawler() -> EnhancedCrawler:
    return EnhancedCrawler()
