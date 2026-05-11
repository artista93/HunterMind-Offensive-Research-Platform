import re
import json
import asyncio
from collections import defaultdict
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from urllib.parse import urljoin, urlparse

import logging

logger = logging.getLogger(__name__)


@dataclass
class DiscoveredEndpoint:
    path: str
    method: str
    full_url: str
    source: str
    status_code: Optional[int] = None
    content_type: Optional[str] = None
    parameters: List[str] = field(default_factory=list)
    discovered_at: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)


class EndpointDiscovery:
    """
    اكتشاف نقاط النهاية المتقدم
    
    الميزات:
    - اكتشاف من sitemap.xml
    - اكتشاف من robots.txt
    - اكتشاف من ملفات JavaScript
    - اكتشاف من HTML
    - كشف عناوين شائعة (wordlist)
    - تحليل الأنماط
    - اكتشاف إصدارات API
    """
    
    COMMON_ENDPOINTS = [
        "/api", "/api/v1", "/api/v2", "/api/v3",
        "/rest", "/rest/v1", "/graphql", "/gql",
        "/swagger", "/swagger.json", "/swagger.yaml",
        "/openapi", "/openapi.json", "/openapi.yaml",
        "/docs", "/documentation", "/redoc",
        "/admin", "/administrator", "/adminpanel", "/cp",
        "/wp-admin", "/wp-login", "/administrator/index.php",
        "/login", "/logout", "/signin", "/signout",
        "/register", "/signup", "/auth", "/oauth",
        "/user", "/users", "/profile", "/account",
        "/settings", "/preferences", "/dashboard",
        "/robots.txt", "/sitemap.xml", "/sitemap.gz",
        "/.env", "/.git/config", "/.htaccess",
        "/phpinfo.php", "/info.php", "/server-status",
        "/_debug", "/debug", "/test",
        "/wp-json", "/wp-content", "/wp-includes",
        "/xmlrpc.php", "/wp-config.php",
        "/_ignition", "/vendor", "/storage",
        "/admin/login", "/static", "/media",
        "/assets", "/rails/info",
    ]
    
    API_PATTERNS = [
        r'["\'](/api/[a-zA-Z0-9_\-/]+)["\']',
        r'["\'](/v\d+/[a-zA-Z0-9_\-/]+)["\']',
        r'["\'](/rest/[a-zA-Z0-9_\-/]+)["\']',
        r'["\'](/graphql)["\']',
        r'["\'](/gql)["\']',
        r'fetch\(["\']([^"\']+)["\']',
        r'\.get\(["\']([^"\']+)["\']',
        r'\.post\(["\']([^"\']+)["\']',
        r'axios\.(get|post|put|delete)\(["\']([^"\']+)["\']',
    ]
    
    def __init__(self, http_client=None):
        self._http_client = http_client
        self._discovered_endpoints: Dict[str, List[DiscoveredEndpoint]] = {}
        self._common_endpoints = self.COMMON_ENDPOINTS.copy()
        
        logger.info("EndpointDiscovery initialized")
    
    def set_http_client(self, client):
        """تعيين عميل HTTP"""
        self._http_client = client
    
    async def _send_request(self, url: str, follow_redirects: bool = False) -> tuple:
        """إرسال طلب HTTP"""
        if self._http_client and hasattr(self._http_client, 'send_request'):
            response = await self._http_client.send_request(url, method="GET")
            return response, 200 if response else 404, {}
        
        try:
            import httpx
            async with httpx.AsyncClient(timeout=10.0, follow_redirects=follow_redirects) as client:
                response = await client.get(url)
                return response.text, response.status_code, dict(response.headers)
        except Exception as e:
            logger.debug(f"Request error: {e}")
            return None, 0, {}
    
    async def discover_all(
        self,
        base_url: str,
        html: str = None,
        js_contents: List[Tuple[str, str]] = None,
        send_requests: bool = True,
        timeout: float = 5.0
    ) -> List[DiscoveredEndpoint]:
        all_endpoints = []
        seen_paths = set()
        
        sitemap_endpoints = await self._discover_from_sitemap(base_url, send_requests, timeout)
        for ep in sitemap_endpoints:
            if ep.path not in seen_paths:
                all_endpoints.append(ep)
                seen_paths.add(ep.path)
        
        robots_endpoints = await self._discover_from_robots(base_url, send_requests, timeout)
        for ep in robots_endpoints:
            if ep.path not in seen_paths:
                all_endpoints.append(ep)
                seen_paths.add(ep.path)
        
        if html:
            html_endpoints = await self._discover_from_html(html, base_url)
            for ep in html_endpoints:
                if ep.path not in seen_paths:
                    all_endpoints.append(ep)
                    seen_paths.add(ep.path)
        
        if js_contents:
            for js_url, js_content in js_contents:
                js_endpoints = await self._discover_from_js(js_content, js_url, base_url)
                for ep in js_endpoints:
                    if ep.path not in seen_paths:
                        all_endpoints.append(ep)
                        seen_paths.add(ep.path)
        
        common_endpoints = await self._discover_common_endpoints(base_url, send_requests, timeout)
        for ep in common_endpoints:
            if ep.path not in seen_paths:
                all_endpoints.append(ep)
                seen_paths.add(ep.path)
        
        self._discovered_endpoints[base_url] = all_endpoints
        
        logger.info(f"Discovered {len(all_endpoints)} endpoints for {base_url}")
        return all_endpoints
    
    async def _discover_from_sitemap(
        self,
        base_url: str,
        send_requests: bool,
        timeout: float
    ) -> List[DiscoveredEndpoint]:
        endpoints = []
        sitemap_url = urljoin(base_url, "/sitemap.xml")
        
        try:
            body, status_code, headers = await self._send_request(sitemap_url)
            
            if status_code == 200 and body:
                urls = re.findall(r'<loc>(.*?)</loc>', body, re.I)
                for url in urls:
                    parsed = urlparse(url)
                    path = parsed.path
                    if path and path != "/":
                        endpoint = DiscoveredEndpoint(
                            path=path,
                            method="GET",
                            full_url=url,
                            source="sitemap",
                            status_code=200 if send_requests else None
                        )
                        endpoints.append(endpoint)
        except Exception as e:
            logger.debug(f"Failed to fetch sitemap: {e}")
        
        return endpoints
    
    async def _discover_from_robots(
        self,
        base_url: str,
        send_requests: bool,
        timeout: float
    ) -> List[DiscoveredEndpoint]:
        endpoints = []
        robots_url = urljoin(base_url, "/robots.txt")
        
        try:
            body, status_code, headers = await self._send_request(robots_url)
            
            if status_code == 200 and body:
                for line in body.split('\n'):
                    line = line.strip()
                    if line.lower().startswith('disallow:'):
                        path = line[9:].strip()
                        if path and path != "/":
                            full_url = urljoin(base_url, path)
                            endpoint = DiscoveredEndpoint(
                                path=path,
                                method="GET",
                                full_url=full_url,
                                source="robots.txt",
                                status_code=200 if send_requests else None
                            )
                            endpoints.append(endpoint)
                    elif line.lower().startswith('allow:'):
                        path = line[6:].strip()
                        if path and path != "/":
                            full_url = urljoin(base_url, path)
                            endpoint = DiscoveredEndpoint(
                                path=path,
                                method="GET",
                                full_url=full_url,
                                source="robots.txt",
                                status_code=200 if send_requests else None
                            )
                            endpoints.append(endpoint)
        except Exception as e:
            logger.debug(f"Failed to fetch robots.txt: {e}")
        
        return endpoints
    
    async def _discover_from_html(
        self,
        html: str,
        base_url: str
    ) -> List[DiscoveredEndpoint]:
        endpoints = set()
        
        link_pattern = re.compile(r'<a[^>]+href=["\']([^"\']+)["\']', re.I)
        for match in link_pattern.finditer(html):
            url = match.group(1)
            if url and not url.startswith('#') and not url.startswith('javascript:'):
                parsed = urlparse(url)
                path = parsed.path
                if path and path != "/":
                    full_url = urljoin(base_url, url)
                    endpoints.add((path, full_url))
        
        form_pattern = re.compile(r'<form[^>]+action=["\']([^"\']+)["\']', re.I)
        for match in form_pattern.finditer(html):
            action = match.group(1)
            if action:
                parsed = urlparse(action)
                path = parsed.path
                if path:
                    full_url = urljoin(base_url, action)
                    endpoints.add((path, full_url))
        
        return [
            DiscoveredEndpoint(
                path=path,
                method="GET",
                full_url=full_url,
                source="html"
            )
            for path, full_url in endpoints
        ]
    
    async def _discover_from_js(
        self,
        js_content: str,
        js_url: str,
        base_url: str
    ) -> List[DiscoveredEndpoint]:
        endpoints = []
        seen = set()
        
        for pattern in self.API_PATTERNS:
            matches = re.finditer(pattern, js_content, re.I)
            for match in matches:
                url = None
                for group in match.groups():
                    if group and not group.startswith('http') and not group.startswith('//'):
                        url = group
                        break
                
                if url and url not in seen:
                    seen.add(url)
                    if url.startswith('/'):
                        full_url = urljoin(base_url, url)
                    else:
                        full_url = urljoin(js_url, url)
                    
                    parsed = urlparse(full_url)
                    endpoint = DiscoveredEndpoint(
                        path=parsed.path,
                        method="GET",
                        full_url=full_url,
                        source=f"js:{js_url}"
                    )
                    endpoints.append(endpoint)
        
        return endpoints
    
    async def _discover_common_endpoints(
        self,
        base_url: str,
        send_requests: bool,
        timeout: float
    ) -> List[DiscoveredEndpoint]:
        endpoints = []
        
        async def check_endpoint(endpoint_path: str) -> Optional[DiscoveredEndpoint]:
            full_url = urljoin(base_url, endpoint_path)
            try:
                body, status_code, headers = await self._send_request(full_url)
                if status_code and status_code < 400:
                    return DiscoveredEndpoint(
                        path=endpoint_path,
                        method="GET",
                        full_url=full_url,
                        source="common",
                        status_code=status_code,
                        content_type=headers.get("content-type", "")
                    )
            except Exception:
                pass
            return None
        
        tasks = [check_endpoint(path) for path in self._common_endpoints[:100]]
        results = await asyncio.gather(*tasks)
        
        for result in results:
            if result:
                endpoints.append(result)
        
        return endpoints
    
    async def discover_by_bruteforce(
        self,
        base_url: str,
        wordlist: List[str],
        extensions: List[str] = None,
        max_concurrent: int = 10,
        timeout: float = 5.0
    ) -> List[DiscoveredEndpoint]:
        endpoints = []
        semaphore = asyncio.Semaphore(max_concurrent)
        
        async def check_path(path: str) -> Optional[DiscoveredEndpoint]:
            async with semaphore:
                full_url = urljoin(base_url, path)
                try:
                    body, status_code, headers = await self._send_request(full_url)
                    if status_code and status_code < 400:
                        return DiscoveredEndpoint(
                            path=path,
                            method="GET",
                            full_url=full_url,
                            source="bruteforce",
                            status_code=status_code,
                            content_type=headers.get("content-type", "")
                        )
                except Exception:
                    pass
                return None
        
        paths_to_check = []
        paths_to_check.extend(wordlist)
        
        if extensions:
            for word in wordlist:
                for ext in extensions:
                    paths_to_check.append(f"{word}{ext}")
        
        tasks = [check_path(path) for path in paths_to_check[:500]]
        results = await asyncio.gather(*tasks)
        
        for result in results:
            if result:
                endpoints.append(result)
        
        logger.info(f"Discovered {len(endpoints)} endpoints via bruteforce for {base_url}")
        return endpoints
    
    async def get_endpoints_for_url(self, url: str) -> List[DiscoveredEndpoint]:
        return self._discovered_endpoints.get(url, [])
    
    async def get_api_endpoints(self, url: str) -> List[DiscoveredEndpoint]:
        endpoints = await self.get_endpoints_for_url(url)
        return [ep for ep in endpoints if "/api/" in ep.path or "graphql" in ep.path]
    
    async def get_admin_endpoints(self, url: str) -> List[DiscoveredEndpoint]:
        endpoints = await self.get_endpoints_for_url(url)
        admin_patterns = ["admin", "wp-admin", "administrator", "cp", "dashboard", "control"]
        return [
            ep for ep in endpoints
            if any(pattern in ep.path.lower() for pattern in admin_patterns)
        ]
    
    async def get_statistics(self) -> Dict:
        total_endpoints = sum(len(v) for v in self._discovered_endpoints.values())
        
        source_stats = defaultdict(int)
        for endpoints in self._discovered_endpoints.values():
            for ep in endpoints:
                source_stats[ep.source] += 1
        
        return {
            "total_targets": len(self._discovered_endpoints),
            "total_endpoints": total_endpoints,
            "avg_endpoints_per_target": total_endpoints / len(self._discovered_endpoints) if self._discovered_endpoints else 0,
            "source_distribution": dict(source_stats),
            "common_endpoints_count": len(self._common_endpoints)
        }
    
    async def add_common_endpoint(self, endpoint: str):
        if endpoint not in self._common_endpoints:
            self._common_endpoints.append(endpoint)
    
    async def clear_endpoints(self, url: str = None):
        if url:
            self._discovered_endpoints.pop(url, None)
        else:
            self._discovered_endpoints.clear()
        
        logger.info(f"Endpoints cleared for {url if url else 'all targets'}")
    
    async def close(self):
        """إغلاق الموارد"""
        self._http_client = None
        logger.info("EndpointDiscovery closed")
