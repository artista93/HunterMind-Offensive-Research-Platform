
import re
import json
import asyncio
from urllib.parse import urljoin, urlparse, parse_qs
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime

try:
    import httpx
    HTTPX_AVAILABLE = True
except ImportError:
    HTTPX_AVAILABLE = False
    import aiohttp

import logging

logger = logging.getLogger(__name__)


@dataclass
class APIEndpoint:
    """نقطة نهاية API"""
    path: str
    method: str  # GET, POST, PUT, DELETE, PATCH, etc.
    full_url: str
    parameters: List[str] = field(default_factory=list)
    headers: Dict[str, str] = field(default_factory=dict)
    body_schema: Optional[Dict] = None
    response_schema: Optional[Dict] = None
    auth_required: bool = False
    discovered_from: str = ""  # html, js, swagger, network
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class APICollection:
    """مجموعة واجهات API"""
    base_url: str
    collected_at: datetime
    endpoints: List[APIEndpoint] = field(default_factory=list)
    total_endpoints: int = 0
    methods_stats: Dict[str, int] = field(default_factory=dict)
    auth_required_count: int = 0
    sources: Dict[str, int] = field(default_factory=dict)


class APICollector:
    """
    جامع واجهات API المتقدم
    
    الميزات:
    - جمع واجهات API من HTML (links, forms)
    - جمع واجهات API من JavaScript
    - جمع واجهات API من Swagger/OpenAPI
    - جمع واجهات API من طلبات الشبكة
    - تحليل نقاط النهاية RESTful
    - كشف معاملات API
    - تصدير المجموعة بصيغ متعددة
    """
    
    # أنماط كشف API endpoints
    API_PATTERNS = {
        # REST patterns
        'rest': [
            r'/api/[a-zA-Z0-9_\-/]+',
            r'/v[0-9]+/[a-zA-Z0-9_\-/]+',
            r'/rest/[a-zA-Z0-9_\-/]+',
            r'/service/[a-zA-Z0-9_\-/]+',
        ],
        # GraphQL
        'graphql': [
            r'/graphql',
            r'/gql',
            r'/query',
        ],
        # RPC
        'rpc': [
            r'/rpc/[a-zA-Z0-9_\-]+',
            r'/jsonrpc',
            r'/xmlrpc',
        ],
        # Common API paths
        'common': [
            r'/users?',
            r'/posts?',
            r'/comments?',
            r'/products?',
            r'/orders?',
            r'/auth',
            r'/login',
            r'/logout',
            r'/register',
            r'/profile',
            r'/settings',
            r'/admin',
            r'/health',
            r'/status',
            r'/metrics',
            r'/swagger',
            r'/docs',
            r'/redoc',
        ],
    }
    
    # HTTP methods
    HTTP_METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS']
    
    def __init__(self):
        self._session = None
        self._collected_endpoints: Set[str] = set()
        self._base_urls: Set[str] = set()
        
        logger.info("APICollector initialized")
    
    async def _get_session(self):
        """الحصول على جلسة HTTP"""
        if not self._session:
            if HTTPX_AVAILABLE:
                self._session = httpx.AsyncClient(timeout=30.0, follow_redirects=True)
            else:
                self._session = aiohttp.ClientSession()
        return self._session
    
    async def collect_from_html(self, html: str, base_url: str) -> List[APIEndpoint]:
        """
        جمع واجهات API من HTML
        
        Args:
            html: محتوى HTML
            base_url: الرابط الأساسي
        
        Returns:
            قائمة بواجهات API المكتشفة
        """
        endpoints = []
        
        # البحث في الروابط
        link_pattern = re.compile(r'<a[^>]+href=["\']([^"\']+)["\']', re.I)
        for match in link_pattern.finditer(html):
            url = match.group(1)
            full_url = urljoin(base_url, url)
            if self._is_api_endpoint(full_url):
                endpoint = APIEndpoint(
                    path=url,
                    method="GET",
                    full_url=full_url,
                    discovered_from="html_link"
                )
                if full_url not in self._collected_endpoints:
                    endpoints.append(endpoint)
                    self._collected_endpoints.add(full_url)
        
        # البحث في النماذج
        form_pattern = re.compile(r'<form[^>]+action=["\']([^"\']+)["\']', re.I)
        for match in form_pattern.finditer(html):
            action = match.group(1)
            full_url = urljoin(base_url, action)
            if self._is_api_endpoint(full_url):
                endpoint = APIEndpoint(
                    path=action,
                    method="POST",  # النماذج عادة POST
                    full_url=full_url,
                    discovered_from="html_form"
                )
                if full_url not in self._collected_endpoints:
                    endpoints.append(endpoint)
                    self._collected_endpoints.add(full_url)
        
        return endpoints
    
    async def collect_from_js(self, js_content: str, source_url: str, base_url: str) -> List[APIEndpoint]:
        """
        جمع واجهات API من JavaScript
        
        Args:
            js_content: محتوى JavaScript
            source_url: رابط الملف المصدر
            base_url: الرابط الأساسي للتحويل
        
        Returns:
            قائمة بواجهات API المكتشفة
        """
        endpoints = []
        
        # Fetch API
        fetch_pattern = re.compile(r'fetch\(["\']([^"\']+)["\']', re.I)
        for match in fetch_pattern.finditer(js_content):
            url = match.group(1)
            full_url = urljoin(base_url, url)
            if self._is_api_endpoint(full_url):
                endpoint = APIEndpoint(
                    path=url,
                    method="GET",
                    full_url=full_url,
                    discovered_from=f"js_fetch:{source_url}"
                )
                if full_url not in self._collected_endpoints:
                    endpoints.append(endpoint)
                    self._collected_endpoints.add(full_url)
        
        # XMLHttpRequest
        xhr_pattern = re.compile(r'\.open\(["\'](GET|POST|PUT|DELETE|PATCH)["\'],\s*["\']([^"\']+)["\']', re.I)
        for match in xhr_pattern.finditer(js_content):
            method, url = match.groups()
            full_url = urljoin(base_url, url)
            if self._is_api_endpoint(full_url):
                endpoint = APIEndpoint(
                    path=url,
                    method=method.upper(),
                    full_url=full_url,
                    discovered_from=f"js_xhr:{source_url}"
                )
                if full_url not in self._collected_endpoints:
                    endpoints.append(endpoint)
                    self._collected_endpoints.add(full_url)
        
        # Axios
        axios_pattern = re.compile(r'axios\.(get|post|put|delete|patch)\(["\']([^"\']+)["\']', re.I)
        for match in axios_pattern.finditer(js_content):
            method, url = match.groups()
            full_url = urljoin(base_url, url)
            if self._is_api_endpoint(full_url):
                endpoint = APIEndpoint(
                    path=url,
                    method=method.upper(),
                    full_url=full_url,
                    discovered_from=f"js_axios:{source_url}"
                )
                if full_url not in self._collected_endpoints:
                    endpoints.append(endpoint)
                    self._collected_endpoints.add(full_url)
        
        # jQuery AJAX
        jq_pattern = re.compile(r'\$\.(get|post|ajax)\(["\']([^"\']+)["\']', re.I)
        for match in jq_pattern.finditer(js_content):
            method, url = match.groups()
            full_url = urljoin(base_url, url)
            if self._is_api_endpoint(full_url):
                endpoint = APIEndpoint(
                    path=url,
                    method=method.upper(),
                    full_url=full_url,
                    discovered_from=f"js_jquery:{source_url}"
                )
                if full_url not in self._collected_endpoints:
                    endpoints.append(endpoint)
                    self._collected_endpoints.add(full_url)
        
        # روابط مباشرة في الكود
        url_pattern = re.compile(r'["\'](/api/[a-zA-Z0-9_\-/]+)["\']', re.I)
        for match in url_pattern.finditer(js_content):
            url = match.group(1)
            full_url = urljoin(base_url, url)
            if self._is_api_endpoint(full_url):
                endpoint = APIEndpoint(
                    path=url,
                    method="GET",
                    full_url=full_url,
                    discovered_from=f"js_url:{source_url}"
                )
                if full_url not in self._collected_endpoints:
                    endpoints.append(endpoint)
                    self._collected_endpoints.add(full_url)
        
        return endpoints
    
    async def collect_from_swagger(self, swagger_url: str) -> Optional[List[APIEndpoint]]:
        """
        جمع واجهات API من Swagger/OpenAPI
        
        Args:
            swagger_url: رابط ملف Swagger (JSON أو YAML)
        
        Returns:
            قائمة بواجهات API المكتشفة
        """
        session = await self._get_session()
        
        try:
            if HTTPX_AVAILABLE:
                response = await session.get(swagger_url)
                if response.status_code != 200:
                    return None
                content = response.text
            else:
                async with session.get(swagger_url) as resp:
                    if resp.status != 200:
                        return None
                    content = await resp.text()
            
            # محاولة تحليل JSON
            try:
                spec = json.loads(content)
            except json.JSONDecodeError:
                # قد يكون YAML
                try:
                    import yaml
                    spec = yaml.safe_load(content)
                except ImportError:
                    logger.warning("YAML support not available")
                    return None
            
            endpoints = []
            base_path = spec.get('basePath', '')
            
            # OpenAPI 3.0
            if 'paths' in spec:
                for path, methods in spec['paths'].items():
                    for method, details in methods.items():
                        if method.lower() in ['get', 'post', 'put', 'delete', 'patch']:
                            full_path = base_path + path
                            full_url = urljoin(swagger_url, full_path)
                            
                            endpoint = APIEndpoint(
                                path=full_path,
                                method=method.upper(),
                                full_url=full_url,
                                discovered_from=f"swagger:{swagger_url}",
                                metadata={
                                    'summary': details.get('summary', ''),
                                    'description': details.get('description', ''),
                                    'parameters': details.get('parameters', [])
                                }
                            )
                            
                            # استخراج المعاملات
                            if 'parameters' in details:
                                endpoint.parameters = [p.get('name', '') for p in details['parameters']]
                            
                            # كشف المصادقة
                            if 'security' in details or spec.get('security'):
                                endpoint.auth_required = True
                            
                            if full_url not in self._collected_endpoints:
                                endpoints.append(endpoint)
                                self._collected_endpoints.add(full_url)
            
            return endpoints
            
        except Exception as e:
            logger.debug(f"Error parsing Swagger from {swagger_url}: {e}")
            return None
    
    async def collect_from_network(self, requests: List[Dict]) -> List[APIEndpoint]:
        """
        جمع واجهات API من طلبات الشبكة
        
        Args:
            requests: قائمة طلبات الشبكة (URL, method, headers)
        
        Returns:
            قائمة بواجهات API المكتشفة
        """
        endpoints = []
        
        for req in requests:
            url = req.get('url', '')
            method = req.get('method', 'GET')
            headers = req.get('headers', {})
            
            if self._is_api_endpoint(url):
                endpoint = APIEndpoint(
                    path=urlparse(url).path,
                    method=method.upper(),
                    full_url=url,
                    headers=headers,
                    discovered_from="network_traffic"
                )
                
                # استخراج المعاملات من URL
                parsed = urlparse(url)
                if parsed.query:
                    params = parse_qs(parsed.query)
                    endpoint.parameters = list(params.keys())
                
                if url not in self._collected_endpoints:
                    endpoints.append(endpoint)
                    self._collected_endpoints.add(url)
        
        return endpoints
    
    def _is_api_endpoint(self, url: str) -> bool:
        """التحقق مما إذا كان الرابط يمثل API endpoint"""
        url_lower = url.lower()
        
        for category, patterns in self.API_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, url_lower):
                    return True
        
        return False
    
    def merge_collections(self, collections: List[APICollection]) -> APICollection:
        """
        دمج مجموعات متعددة من واجهات API
        
        Args:
            collections: قائمة المجموعات
        
        Returns:
            مجموعة مدمجة
        """
        if not collections:
            return APICollection(base_url="", collected_at=datetime.now())
        
        merged = APICollection(
            base_url=collections[0].base_url,
            collected_at=datetime.now()
        )
        
        seen_urls = set()
        
        for collection in collections:
            for endpoint in collection.endpoints:
                if endpoint.full_url not in seen_urls:
                    merged.endpoints.append(endpoint)
                    seen_urls.add(endpoint.full_url)
                    
                    # تحديث الإحصائيات
                    merged.methods_stats[endpoint.method] = merged.methods_stats.get(endpoint.method, 0) + 1
                    if endpoint.auth_required:
                        merged.auth_required_count += 1
                    merged.sources[endpoint.discovered_from] = merged.sources.get(endpoint.discovered_from, 0) + 1
        
        merged.total_endpoints = len(merged.endpoints)
        
        return merged
    
    async def test_endpoint(self, endpoint: APIEndpoint, auth_token: str = None) -> Dict:
        """
        اختبار نقطة نهاية API (فحص بسيط)
        
        Args:
            endpoint: نقطة النهاية
            auth_token: توكن المصادقة (اختياري)
        
        Returns:
            نتيجة الاختبار
        """
        session = await self._get_session()
        
        headers = {}
        if auth_token:
            headers['Authorization'] = f'Bearer {auth_token}'
        
        result = {
            "endpoint": endpoint.full_url,
            "method": endpoint.method,
            "status_code": None,
            "accessible": False,
            "response_time": None,
            "error": None
        }
        
        import time
        start_time = time.time()
        
        try:
            if endpoint.method == "GET":
                if HTTPX_AVAILABLE:
                    response = await session.get(endpoint.full_url, headers=headers)
                else:
                    async with session.get(endpoint.full_url, headers=headers) as resp:
                        response = resp
            elif endpoint.method == "POST":
                if HTTPX_AVAILABLE:
                    response = await session.post(endpoint.full_url, headers=headers)
                else:
                    async with session.post(endpoint.full_url, headers=headers) as resp:
                        response = resp
            else:
                return result
            
            result["status_code"] = response.status_code
            result["accessible"] = response.status_code < 400
            result["response_time"] = time.time() - start_time
            
        except Exception as e:
            result["error"] = str(e)
        
        return result
    
    async def export_to_json(self, collection: APICollection, filepath: str):
        """
        تصدير مجموعة واجهات API إلى ملف JSON
        
        Args:
            collection: مجموعة واجهات API
            filepath: مسار الملف
        """
        export_data = {
            "base_url": collection.base_url,
            "collected_at": collection.collected_at.isoformat(),
            "total_endpoints": collection.total_endpoints,
            "methods_stats": collection.methods_stats,
            "auth_required_count": collection.auth_required_count,
            "sources": collection.sources,
            "endpoints": [
                {
                    "path": e.path,
                    "method": e.method,
                    "full_url": e.full_url,
                    "parameters": e.parameters,
                    "auth_required": e.auth_required,
                    "discovered_from": e.discovered_from,
                    "metadata": e.metadata
                }
                for e in collection.endpoints
            ]
        }
        
        with open(filepath, 'w') as f:
            json.dump(export_data, f, indent=2)
        
        logger.info(f"Exported {collection.total_endpoints} endpoints to {filepath}")
    
    async def get_statistics(self) -> Dict:
        """إحصائيات الجامع"""
        return {
            "collected_endpoints": len(self._collected_endpoints),
            "base_urls": len(self._base_urls),
            "api_patterns": {
                category: len(patterns) for category, patterns in self.API_PATTERNS.items()
            },
            "supported_methods": self.HTTP_METHODS
        }
    
    async def close(self):
        """إغلاق الجلسة"""
        if self._session:
            if HTTPX_AVAILABLE:
                await self._session.aclose()
            else:
                await self._session.close()
            self._session = None


# نسخة عالمية
async def get_api_collector() -> APICollector:
    """الحصول على نسخة من جامع واجهات API"""
    return APICollector()

