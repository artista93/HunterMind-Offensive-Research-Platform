"""
JS API Discovery - استخراج API endpoints من ملفات JavaScript
"""

import re
from typing import List, Dict, Set
from urllib.parse import urljoin, urlparse

import httpx
import logging

logger = logging.getLogger(__name__)


class JSAPIDiscovery:
    """
    مستخرج API endpoints من JavaScript
    
    يستخرج:
    - API endpoints (/api/*, /rest/*, /graphql)
    - URLs كاملة من fetch/axios/xhr calls
    - WebSocket endpoints
    - GraphQL endpoints
    """
    
    API_PATTERNS = [
        r'(?:fetch|axios|http)\(["\']([^"\']+(?:/api/[^"\']+))["\']',
        r'(?:fetch|axios|http)\(["\']([^"\']+(?:/rest/[^"\']+))["\']',
        r'(?:fetch|axios|http)\(["\']([^"\']+(?:/graphql)[^"\']*)["\']',
        r'["\']((?:https?:)?//[^"\']+(?:/api/[^"\']+))["\']',
        r'["\'](/api/v?\d?/[\w/-]+)["\']',
        r'["\'](/rest/[\w/-]+)["\']',
        r'["\'](/graphql)["\']',
        r'(?:WebSocket|ws)\(["\']([^"\']+)["\']',
        r'(?:baseURL|apiUrl|API_URL|apiEndpoint)\s*[:=]\s*["\']([^"\']+)["\']',
    ]
    
    def __init__(self):
        self._found_endpoints: Set[str] = set()
        logger.info("JSAPIDiscovery initialized")
    
    async def analyze_page(self, html: str, base_url: str) -> Dict:
        """تحليل صفحة HTML واستخراج JS files ثم API endpoints"""
        result = {
            "js_files": [],
            "api_endpoints": [],
            "graphql_queries": []
        }
        
        js_files = self._extract_js_files(html, base_url)
        result["js_files"] = js_files
        
        async with httpx.AsyncClient(timeout=15, verify=False) as client:
            for js_url in js_files[:20]:
                try:
                    response = await client.get(js_url)
                    if response.status_code == 200:
                        endpoints = self._extract_endpoints(response.text, base_url)
                        result["api_endpoints"].extend(endpoints)
                except Exception as e:
                    logger.debug(f"Failed to fetch {js_url}: {e}")
        
        result["api_endpoints"] = list(set(result["api_endpoints"]))
        logger.info(f"JS Analysis: {len(js_files)} files, {len(result['api_endpoints'])} API endpoints")
        
        return result
    
    def _extract_js_files(self, html: str, base_url: str) -> List[str]:
        """استخراج روابط ملفات JavaScript من HTML"""
        js_files = []
        script_pattern = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.IGNORECASE)
        for match in script_pattern.finditer(html):
            src = match.group(1)
            full_url = urljoin(base_url, src)
            if urlparse(full_url).netloc == urlparse(base_url).netloc:
                js_files.append(full_url)
        return list(set(js_files))
    
    def _extract_endpoints(self, content: str, base_url: str) -> List[str]:
        """استخراج API endpoints من محتوى JS"""
        endpoints = []
        for pattern in self.API_PATTERNS:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                if isinstance(match, tuple):
                    match = match[0]
                url = match.strip()
                if not url:
                    continue
                if url.startswith('/'):
                    parsed = urlparse(base_url)
                    url = f"{parsed.scheme}://{parsed.netloc}{url}"
                if url not in self._found_endpoints:
                    self._found_endpoints.add(url)
                    endpoints.append(url)
        return endpoints
    
    def get_discovered_endpoints(self) -> List[str]:
        return list(self._found_endpoints)


_js_discovery = None

def get_js_api_discovery() -> JSAPIDiscovery:
    global _js_discovery
    if _js_discovery is None:
        _js_discovery = JSAPIDiscovery()
    return _js_discovery
