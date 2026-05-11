import re
import json
import asyncio
from urllib.parse import urljoin, urlparse
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime

import logging

logger = logging.getLogger(__name__)


@dataclass
class JSEndpoint:
    url: str
    method: str
    found_in: str
    line_number: Optional[int] = None
    parameters: List[str] = field(default_factory=list)
    headers: Dict[str, str] = field(default_factory=dict)


@dataclass
class JSSensitiveInfo:
    type: str
    value: str
    found_in: str
    line_number: Optional[int] = None
    context: str = ""


@dataclass
class JSAnalysisResult:
    source_url: str
    analyzed_at: datetime
    endpoints: List[JSEndpoint] = field(default_factory=list)
    sensitive_info: List[JSSensitiveInfo] = field(default_factory=list)
    libraries: List[str] = field(default_factory=list)
    version_info: Dict[str, str] = field(default_factory=dict)
    comments: List[str] = field(default_factory=list)
    suspicious_patterns: List[str] = field(default_factory=list)


class JSProcessor:
    """
    معالج ملفات JavaScript المتقدم
    
    الميزات:
    - كشف واجهات API في كود JS
    - اكتشاف المعلومات الحساسة (API keys, tokens, passwords)
    - تحليل المكتبات والإصدارات
    - اكتشاف نقاط النهاية المخفية
    - تحليل كود مدمج (inline JS)
    - كشف أنماط خطيرة (eval, document.write, innerHTML)
    - دعم تحميل ملفات JS عن بُعد
    """
    
    SENSITIVE_PATTERNS = {
        "api_key": [
            r'api[_-]?key["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{16,})["\']',
            r'apikey["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{16,})["\']',
            r'key["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{16,})["\']',
        ],
        "access_token": [
            r'access[_]?token["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-\.]{20,})["\']',
            r'token["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-\.]{20,})["\']',
            r'bearer["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-\.]{20,})["\']',
        ],
        "jwt_token": [
            r'eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+',
        ],
        "password": [
            r'password["\']?\s*[:=]\s*["\']([^"\']{4,})["\']',
            r'pwd["\']?\s*[:=]\s*["\']([^"\']{4,})["\']',
            r'pass["\']?\s*[:=]\s*["\']([^"\']{4,})["\']',
        ],
        "endpoint": [
            r'https?://[a-zA-Z0-9\-\.]+/[a-zA-Z0-9\-/]+',
            r'/[a-z]{2,}/[a-z]{2,}/[a-z]{2,}\.json',
        ],
        "email": [
            r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
        ],
        "internal_ip": [
            r'(?:10|172\.(?:1[6-9]|2[0-9]|3[01])|192\.168)\.\d{1,3}\.\d{1,3}',
            r'127\.0\.0\.1',
            r'localhost',
        ],
    }
    
    API_PATTERNS = [
        r'fetch\(["\']([^"\']+)["\']',
        r'\.open\(["\'](GET|POST|PUT|DELETE|PATCH)["\'],\s*["\']([^"\']+)["\']',
        r'axios\.(get|post|put|delete|patch)\(["\']([^"\']+)["\']',
        r'\$\.(get|post|ajax)\(["\']([^"\']+)["\']',
        r'\$\.(get|post)\(["\']([^"\']+)["\']',
        r'\$http\.(get|post|put|delete)\(["\']([^"\']+)["\']',
        r'req\.(get|post|put|delete)\(["\']([^"\']+)["\']',
        r'["\'](/api/[^"\']+)["\']',
        r"['`](/api/[^'`]+)['`]",
    ]
    
    LIBRARY_PATTERNS = {
        "jQuery": r'jQuery\s*v?(\d+\.\d+\.\d+)',
        "React": r'React\s*v?(\d+\.\d+\.\d+)',
        "Angular": r'AngularJS\s*v?(\d+\.\d+\.\d+)',
        "Vue": r'Vue\.js\s+v?(\d+\.\d+\.\d+)',
        "Bootstrap": r'Bootstrap\s+v?(\d+\.\d+\.\d+)',
        "Axios": r'axios\s*v?(\d+\.\d+\.\d+)',
        "Lodash": r'lodash\s*v?(\d+\.\d+\.\d+)',
        "Moment": r'moment\.js\s+v?(\d+\.\d+\.\d+)',
    }
    
    DANGEROUS_PATTERNS = [
        r'eval\([^)]+\)',
        r'document\.write\([^)]+\)',
        r'innerHTML\s*=\s*[^;]+',
        r'outerHTML\s*=\s*[^;]+',
        r'setTimeout\([^,]+,\s*\d+\)',
        r'setInterval\([^,]+,\s*\d+\)',
        r'Function\([^)]+\)',
        r'new\s+Function\([^)]+\)',
    ]
    
    def __init__(self, http_client=None):
        self._http_client = http_client
        self._processed_urls: Set[str] = set()
        
        logger.info("JSProcessor initialized")
    
    def _set_http_client(self, client):
        """تعيين عميل HTTP"""
        self._http_client = client
    
    async def _fetch_url(self, url: str) -> Optional[str]:
        """جلب محتوى URL باستخدام العميل المتاح"""
        if self._http_client and hasattr(self._http_client, 'send_request'):
            return await self._http_client.send_request(url, method="GET")
        
        # Fallback المؤقت
        try:
            import httpx
            async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
                response = await client.get(url)
                return response.text
        except Exception:
            return None
    
    async def process_url(self, js_url: str, base_url: str = None) -> Optional[JSAnalysisResult]:
        if js_url in self._processed_urls:
            return None
        
        self._processed_urls.add(js_url)
        
        content = await self._fetch_url(js_url)
        
        if not content:
            return None
        
        return await self.process_content(content, js_url, base_url)
    
    async def process_content(
        self,
        content: str,
        source: str,
        base_url: str = None
    ) -> JSAnalysisResult:
        result = JSAnalysisResult(
            source_url=source,
            analyzed_at=datetime.now()
        )
        
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            for info_type, patterns in self.SENSITIVE_PATTERNS.items():
                for pattern in patterns:
                    matches = re.findall(pattern, line, re.IGNORECASE)
                    for match in matches:
                        if match and not match.startswith('{{') and len(match) > 4:
                            result.sensitive_info.append(JSSensitiveInfo(
                                type=info_type,
                                value=match[:100],
                                found_in=source,
                                line_number=line_num,
                                context=line[:200].strip()
                            ))
        
        for pattern in self.API_PATTERNS:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                groups = match.groups()
                
                if len(groups) == 2:
                    method, url = groups
                    method = method.upper()
                elif len(groups) == 1:
                    method = "GET"
                    url = groups[0]
                else:
                    continue
                
                if base_url and not url.startswith('http'):
                    full_url = urljoin(base_url, url)
                else:
                    full_url = url
                
                parameters = self._extract_url_parameters(url)
                
                result.endpoints.append(JSEndpoint(
                    url=full_url,
                    method=method,
                    found_in=source,
                    parameters=parameters
                ))
        
        for lib_name, pattern in self.LIBRARY_PATTERNS.items():
            match = re.search(pattern, content, re.IGNORECASE)
            if match:
                version = match.group(1) if match.groups() else "unknown"
                result.libraries.append(lib_name)
                result.version_info[lib_name] = version
        
        comment_patterns = [
            r'//(.+)$',
            r'/\*(.+?)\*/',
        ]
        for pattern in comment_patterns:
            matches = re.findall(pattern, content, re.DOTALL)
            for match in matches:
                comment = match.strip()[:200]
                if comment and len(comment) > 10:
                    result.comments.append(comment)
        
        for pattern in self.DANGEROUS_PATTERNS:
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                result.suspicious_patterns.append(pattern)
        
        result.endpoints = list({(e.url, e.method): e for e in result.endpoints}.values())
        result.sensitive_info = list({(i.type, i.value): i for i in result.sensitive_info}.values())
        result.comments = list(set(result.comments))[:50]
        
        logger.info(f"JS analysis complete: {len(result.endpoints)} endpoints, {len(result.sensitive_info)} sensitive items")
        
        return result
    
    def _extract_url_parameters(self, url: str) -> List[str]:
        parameters = []
        
        param_pattern = r'[?&]([^=]+)='
        matches = re.findall(param_pattern, url)
        parameters.extend(matches)
        
        rest_params = re.findall(r'/:([a-zA-Z_][a-zA-Z0-9_]*)', url)
        parameters.extend(rest_params)
        
        return list(set(parameters))
    
    async def process_inline_js(self, html: str, base_url: str) -> List[JSAnalysisResult]:
        results = []
        
        inline_pattern = re.compile(r'<script[^>]*>(.*?)</script>', re.I | re.DOTALL)
        
        for i, match in enumerate(inline_pattern.finditer(html)):
            js_content = match.group(1).strip()
            if js_content and len(js_content) > 20:
                result = await self.process_content(
                    js_content,
                    f"{base_url}:inline_{i}",
                    base_url
                )
                results.append(result)
        
        src_pattern = re.compile(r'<script[^>]*src=["\']([^"\']+)["\']', re.I)
        
        for match in src_pattern.finditer(html):
            js_url = match.group(1)
            full_url = urljoin(base_url, js_url)
            result = await self.process_url(full_url, base_url)
            if result:
                results.append(result)
        
        return results
    
    async def find_all_js_files(self, html: str, base_url: str) -> List[str]:
        js_files = set()
        
        patterns = [
            r'<script[^>]*src=["\']([^"\']+\.js[^"\']*)["\']',
            r'<link[^>]*href=["\']([^"\']+\.js[^"\']*)["\'][^>]*>',
            r'import\(["\']([^"\']+\.js)["\']',
            r'require\(["\']([^"\']+\.js)["\']',
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, html, re.I)
            for match in matches:
                full_url = urljoin(base_url, match)
                js_files.add(full_url)
        
        return list(js_files)
    
    async def scan_for_secrets(self, content: str, source: str) -> List[JSSensitiveInfo]:
        secrets = []
        
        for info_type, patterns in self.SENSITIVE_PATTERNS.items():
            for pattern in patterns:
                matches = re.finditer(pattern, content, re.IGNORECASE)
                for match in matches:
                    value = match.group(1) if match.groups() else match.group(0)
                    if value and len(value) > 4:
                        secrets.append(JSSensitiveInfo(
                            type=info_type,
                            value=value[:100],
                            found_in=source,
                            context=match.group(0)[:200]
                        ))
        
        return secrets
    
    async def get_statistics(self) -> Dict:
        return {
            "processed_urls": len(self._processed_urls),
            "sensitive_patterns": sum(len(p) for p in self.SENSITIVE_PATTERNS.values()),
            "api_patterns": len(self.API_PATTERNS),
            "library_patterns": len(self.LIBRARY_PATTERNS),
        }
    
    async def close(self):
        self._http_client = None
        logger.info("JSProcessor closed")
