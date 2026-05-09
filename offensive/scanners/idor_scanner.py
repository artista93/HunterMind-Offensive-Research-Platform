
import asyncio
import re
import json
from typing import Dict, List, Optional, Any, Set, Tuple
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from dataclasses import dataclass
from collections import defaultdict

from .base_scanner import BaseScanner, ScanContext, Finding, Severity, Confidence

try:
    import httpx
    HTTPX_AVAILABLE = True
except ImportError:
    HTTPX_AVAILABLE = False
    import aiohttp

import logging

logger = logging.getLogger(__name__)


@dataclass
class IDORPattern:
    """نمط IDOR"""
    name: str
    pattern: str  # regex pattern
    id_type: str  # numeric, uuid, hash, sequential
    examples: List[str]
    risk_level: str  # high, medium, low


class IDORScanner(BaseScanner):
    """
    فاحص ثغرات Insecure Direct Object References (IDOR)
    
    الميزات:
    - كشف المعرفات القابلة للتخمين (numeric, UUID, hash)
    - اختبار الوصول الأفقي (horizontal privilege escalation)
    - اختبار الوصول العمودي (vertical privilege escalation)
    - تحليل الأنماط في URLs والـ API endpoints
    - اختبار التكرار (+1, -1, increment)
    - استخراج المعرفات من الردود
    """
    
    # أنماط المعرفات
    ID_PATTERNS = {
        "numeric": re.compile(r'\b([0-9]{1,10})\b'),
        "uuid": re.compile(r'\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b', re.I),
        "hash_md5": re.compile(r'\b[0-9a-f]{32}\b', re.I),
        "hash_sha1": re.compile(r'\b[0-9a-f]{40}\b', re.I),
        "base64": re.compile(r'\b[A-Za-z0-9+/]{4,}={0,2}\b'),
        "sequential": re.compile(r'\b(?:user|id|item|post|product)[_-]?([0-9]+)\b', re.I),
    }
    
    # نقاط نهاية شائعة لـ IDOR
    COMMON_ENDPOINTS = [
        "/user/", "/users/", "/profile/", "/account/",
        "/order/", "/orders/", "/invoice/", "/payment/",
        "/document/", "/file/", "/download/", "/attachment/",
        "/api/user/", "/api/users/", "/api/profile/",
        "/api/order/", "/api/orders/", "/api/invoice/",
    ]
    
    def __init__(
        self,
        rate_limit: float = 2.0,
        timeout: int = 30,
        max_retries: int = 2,
        test_increment: bool = True,
        test_decrement: bool = True,
        extract_ids_from_responses: bool = True
    ):
        super().__init__(
            name="IDORScanner",
            rate_limit=rate_limit,
            timeout=timeout,
            max_retries=max_retries
        )
        self._test_increment = test_increment
        self._test_decrement = test_decrement
        self._extract_ids_from_responses = extract_ids_from_responses
        self._session = None
        self._tested_endpoints: Set[str] = set()
        self._discovered_ids: Dict[str, Set[str]] = defaultdict(set)
    
    async def _get_session(self):
        """الحصول على جلسة HTTP"""
        if not self._session:
            if HTTPX_AVAILABLE:
                self._session = httpx.AsyncClient(
                    timeout=self.timeout,
                    follow_redirects=True,
                    verify=False
                )
            else:
                self._session = aiohttp.ClientSession()
        return self._session
    
    async def can_scan(self, context: ScanContext) -> bool:
        """التحقق من وجود endpoints قابلة للاختبار"""
        url = context.target.url
        parsed = urlparse(url)
        path = parsed.path
        
        # التحقق من وجود نقاط نهاية معروفة
        for endpoint in self.COMMON_ENDPOINTS:
            if endpoint in path:
                return True
        
        # التحقق من وجود معاملات رقمية
        params = parse_qs(parsed.query)
        for value in params.values():
            if value and value[0].isdigit():
                return True
        
        return False
    
    async def scan(self, context: ScanContext) -> List[Finding]:
        """تنفيذ فحص IDOR"""
        findings = []
        url = context.target.url
        session = await self._get_session()
        
        # 1. تحليل URL الحالي
        url_findings = await self._analyze_url(context, url)
        findings.extend(url_findings)
        
        # 2. اكتشاف المعرفات من الردود
        if self._extract_ids_from_responses:
            extracted_findings = await self._extract_and_test_ids(context, url)
            findings.extend(extracted_findings)
        
        # 3. اختبار نقاط النهاية الشائعة
        endpoint_findings = await self._test_common_endpoints(context)
        findings.extend(endpoint_findings)
        
        # 4. اختبار التكرار (Incremental IDs)
        if self._test_increment or self._test_decrement:
            incremental_findings = await self._test_incremental_ids(context)
            findings.extend(incremental_findings)
        
        return findings
    
    async def _analyze_url(self, context: ScanContext, url: str) -> List[Finding]:
        """تحليل URL لاكتشاف المعرفات القابلة للتخمين"""
        findings = []
        parsed = urlparse(url)
        
        # فحص المعاملات
        params = parse_qs(parsed.query)
        for param_name, param_values in params.items():
            for value in param_values:
                # التحقق من أنماط المعرفات
                for id_type, pattern in self.ID_PATTERNS.items():
                    match = pattern.search(value)
                    if match:
                        # اختبار ما إذا كان يمكن تغيير المعرف
                        modified_finding = await self._test_id_modification(
                            context, param_name, value, match.group(), id_type
                        )
                        if modified_finding:
                            findings.append(modified_finding)
        
        # فحص مسار URL
        path_parts = parsed.path.split('/')
        for i, part in enumerate(path_parts):
            for id_type, pattern in self.ID_PATTERNS.items():
                match = pattern.search(part)
                if match:
                    # بناء URL معدل
                    modified_parts = path_parts.copy()
                    original_id = match.group()
                    
                    # اختبار زيادة المعرف
                    if self._test_increment and original_id.isdigit():
                        new_id = str(int(original_id) + 1)
                        modified_parts[i] = part.replace(original_id, new_id)
                        test_url = urlunparse(parsed._replace(path='/'.join(modified_parts)))
                        
                        finding = await self._check_unauthorized_access(context, test_url, param_name, original_id, new_id)
                        if finding:
                            findings.append(finding)
                    
                    # اختبار نقصان المعرف
                    if self._test_decrement and original_id.isdigit() and int(original_id) > 1:
                        new_id = str(int(original_id) - 1)
                        modified_parts[i] = part.replace(original_id, new_id)
                        test_url = urlunparse(parsed._replace(path='/'.join(modified_parts)))
                        
                        finding = await self._check_unauthorized_access(context, test_url, param_name, original_id, new_id)
                        if finding:
                            findings.append(finding)
        
        return findings
    
    async def _test_id_modification(
        self,
        context: ScanContext,
        param_name: str,
        original_value: str,
        extracted_id: str,
        id_type: str
    ) -> Optional[Finding]:
        """اختبار تعديل المعرف"""
        if not extracted_id.isdigit():
            return None
        
        # اختبار زيادة المعرف
        if self._test_increment:
            new_id = str(int(extracted_id) + 1)
            modified_value = original_value.replace(extracted_id, new_id)
            
            # بناء URL معدل
            parsed = urlparse(context.target.url)
            params = parse_qs(parsed.query)
            
            if param_name in params:
                params[param_name] = [modified_value]
                new_query = urlencode(params, doseq=True)
                test_url = urlunparse(parsed._replace(query=new_query))
                
                finding = await self._check_unauthorized_access(
                    context, test_url, param_name, extracted_id, new_id
                )
                if finding:
                    return finding
        
        # اختبار نقصان المعرف
        if self._test_decrement and int(extracted_id) > 1:
            new_id = str(int(extracted_id) - 1)
            modified_value = original_value.replace(extracted_id, new_id)
            
            parsed = urlparse(context.target.url)
            params = parse_qs(parsed.query)
            
            if param_name in params:
                params[param_name] = [modified_value]
                new_query = urlencode(params, doseq=True)
                test_url = urlunparse(parsed._replace(query=new_query))
                
                finding = await self._check_unauthorized_access(
                    context, test_url, param_name, extracted_id, new_id
                )
                if finding:
                    return finding
        
        return None
    
    async def _check_unauthorized_access(
        self,
        context: ScanContext,
        test_url: str,
        param_name: str,
        original_id: str,
        modified_id: str
    ) -> Optional[Finding]:
        """التحقق من الوصول غير المصرح به"""
        session = await self._get_session()
        
        try:
            # إرسال الطلب مع المعرف المعدل
            if HTTPX_AVAILABLE:
                response = await session.get(test_url, headers=context.target.headers)
                status_code = response.status_code
                body = response.text
            else:
                async with session.get(test_url, headers=context.target.headers) as resp:
                    status_code = resp.status
                    body = await resp.text()
            
            # التحقق من الوصول الناجح (200 OK) مع بيانات مختلفة
            if status_code == 200:
                # التحقق من وجود بيانات للمستخدم الآخر
                # نبحث عن تغيير في المحتوى
                original_response = await self._get_original_response(context)
                
                if original_response and body != original_response:
                    # قد يكون هناك IDOR
                    confidence = Confidence.HIGH if "user" in body.lower() or "profile" in body.lower() else Confidence.MEDIUM
                    
                    finding = self.add_finding(
                        vulnerability_type="Insecure Direct Object Reference (IDOR)",
                        severity=Severity.HIGH,
                        confidence=confidence,
                        url=test_url,
                        parameter=param_name,
                        payload=f"ID modified from {original_id} to {modified_id}",
                        evidence=f"Successfully accessed resource with modified ID {modified_id}. Status: {status_code}",
                        description=f"IDOR vulnerability discovered in {param_name} parameter. Able to access other user's data by changing the ID from {original_id} to {modified_id}.",
                        remediation="Implement proper access control checks for each resource. Use indirect references (mapping) instead of direct IDs. Verify user authorization for every request.",
                        cvss_score=6.5,
                        metadata={
                            "original_id": original_id,
                            "modified_id": modified_id,
                            "parameter": param_name
                        }
                    )
                    return finding
            
        except Exception as e:
            logger.debug(f"Error checking unauthorized access: {e}")
        
        return None
    
    async def _get_original_response(self, context: ScanContext) -> Optional[str]:
        """الحصول على الرد الأصلي للمقارنة"""
        session = await self._get_session()
        
        try:
            if HTTPX_AVAILABLE:
                response = await session.get(context.target.url, headers=context.target.headers)
                return response.text
            else:
                async with session.get(context.target.url, headers=context.target.headers) as resp:
                    return await resp.text()
        except:
            return None
    
    async def _extract_and_test_ids(self, context: ScanContext, url: str) -> List[Finding]:
        """استخراج المعرفات من الردود واختبارها"""
        findings = []
        session = await self._get_session()
        
        # الحصول على الرد الأولي
        try:
            if HTTPX_AVAILABLE:
                response = await session.get(url, headers=context.target.headers)
                body = response.text
            else:
                async with session.get(url, headers=context.target.headers) as resp:
                    body = await resp.text()
            
            # استخراج المعرفات من الرد
            for id_type, pattern in self.ID_PATTERNS.items():
                matches = pattern.findall(body)
                for match in matches:
                    if match not in self._discovered_ids[id_type]:
                        self._discovered_ids[id_type].add(match)
                        
                        # اختبار المعرف المستخرج
                        if match.isdigit() and len(match) >= 3:
                            # اختبار زيادة
                            if self._test_increment:
                                new_id = str(int(match) + 1)
                                # البحث عن endpoint يحتوي على هذا المعرف
                                test_url = self._replace_id_in_url(url, match, new_id)
                                if test_url:
                                    finding = await self._check_unauthorized_access(
                                        context, test_url, "extracted_id", match, new_id
                                    )
                                    if finding:
                                        findings.append(finding)
            
        except Exception as e:
            logger.debug(f"Error extracting IDs: {e}")
        
        return findings
    
    async def _test_common_endpoints(self, context: ScanContext) -> List[Finding]:
        """اختبار نقاط النهاية الشائعة لـ IDOR"""
        findings = []
        base_url = context.target.url.rstrip('/')
        
        for endpoint in self.COMMON_ENDPOINTS:
            # اختبار مع معرفات رقمية شائعة
            test_ids = [1, 2, 3, 100, 1000]
            
            for test_id in test_ids:
                test_url = f"{base_url}{endpoint}{test_id}"
                
                # التحقق من الوصول
                session = await self._get_session()
                try:
                    if HTTPX_AVAILABLE:
                        response = await session.get(test_url, headers=context.target.headers)
                        status_code = response.status_code
                        body = response.text
                    else:
                        async with session.get(test_url, headers=context.target.headers) as resp:
                            status_code = resp.status
                            body = await resp.text()
                    
                    # إذا كان الوصول ناجحاً، قد يكون هناك IDOR
                    if status_code == 200 and len(body) > 100:
                        # تحقق مما إذا كان الرد يحتوي على بيانات مستخدم
                        if "user" in body.lower() or "email" in body.lower() or "profile" in body.lower():
                            finding = self.add_finding(
                                vulnerability_type="Insecure Direct Object Reference (IDOR)",
                                severity=Severity.MEDIUM,
                                confidence=Confidence.TENTATIVE,
                                url=test_url,
                                description=f"Potential IDOR at {endpoint} with ID {test_id}",
                                remediation="Implement proper access control checks.",
                                cvss_score=5.3,
                                metadata={"endpoint": endpoint, "tested_id": test_id}
                            )
                            findings.append(finding)
                            
                except Exception as e:
                    logger.debug(f"Error testing endpoint {endpoint}: {e}")
        
        return findings
    
    async def _test_incremental_ids(self, context: ScanContext) -> List[Finding]:
        """اختبار المعرفات التزايدية"""
        findings = []
        base_url = context.target.url
        
        # استخراج المعرفات من URL الحالي
        parsed = urlparse(base_url)
        path = parsed.path
        
        # البحث عن أرقام في المسار
        import re
        numbers = re.findall(r'\b\d{3,}\b', path)
        
        for num in numbers:
            num_int = int(num)
            
            # اختبار المعرف التالي
            if self._test_increment:
                next_id = str(num_int + 1)
                test_url = base_url.replace(num, next_id)
                
                if test_url != base_url:
                    finding = await self._check_unauthorized_access(
                        context, test_url, "path_id", num, next_id
                    )
                    if finding:
                        findings.append(finding)
            
            # اختبار المعرف السابق
            if self._test_decrement and num_int > 1:
                prev_id = str(num_int - 1)
                test_url = base_url.replace(num, prev_id)
                
                if test_url != base_url:
                    finding = await self._check_unauthorized_access(
                        context, test_url, "path_id", num, prev_id
                    )
                    if finding:
                        findings.append(finding)
        
        return findings
    
    def _replace_id_in_url(self, url: str, old_id: str, new_id: str) -> Optional[str]:
        """استبدال معرف في URL"""
        if old_id in url:
            return url.replace(old_id, new_id)
        return None
    
    async def close(self):
        """إغلاق الجلسة"""
        if self._session:
            if HTTPX_AVAILABLE:
                await self._session.aclose()
            else:
                await self._session.close()
            self._session = None

