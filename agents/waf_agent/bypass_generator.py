
import random
import string
import urllib.parse
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum

import logging

logger = logging.getLogger(__name__)


class BypassTechnique(Enum):
    """تقنيات التجاوز"""
    CASE_SWAPPING = "case_swapping"
    URL_ENCODING = "url_encoding"
    DOUBLE_ENCODING = "double_encoding"
    UNICODE_ENCODING = "unicode_encoding"
    HEX_ENCODING = "hex_encoding"
    COMMENT_INSERTION = "comment_insertion"
    WHITESPACE_VARIATION = "whitespace_variation"
    LINE_BREAKING = "line_breaking"
    NULL_BYTE_INJECTION = "null_byte_injection"
    PARAMETER_POLLUTION = "parameter_pollution"
    HTTP_VERB_TAMPERING = "http_verb_tampering"
    PAYLOAD_SPLITTING = "payload_splitting"
    CHUNKED_TRANSFER = "chunked_transfer"
    UNICODE_NORMALIZATION = "unicode_normalization"
    TAB_INJECTION = "tab_injection"
    NEWLINE_INJECTION = "newline_injection"


@dataclass
class BypassResult:
    """نتيجة تجاوز"""
    original_payload: str
    modified_payload: str
    technique: BypassTechnique
    success: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)


class BypassGenerator:
    """
    مولد تقنيات تجاوز WAF المتقدم
    
    الميزات:
    - توليد حمولات متجاوزة بـ 15 تقنية
    - تكامل مع كاشف WAF
    - حمولات مخصصة حسب نوع WAF
    - تجاوز متعدد المستويات
    """
    
    # تقنيات تجاوز خريطة حروف خاصة
    CHAR_MAPPINGS = {
        "<": ["%3c", "\\x3c", "&lt;", "&#60;", "\\u003c", "<", "<"],
        ">": ["%3e", "\\x3e", "&gt;", "&#62;", "\\u003e", ">"],
        "'": ["%27", "\\'", "''", "‘", "’", "`", "&apos;"],
        '"': ["%22", '\\"', '""', "“", "”", "&quot;"],
        "/": ["%2f", "\\x2f", "&#47;", "\\/"],
        "\\": ["%5c", "&#92;", "\\\\"],
        "(": ["%28", "\\x28", "&#40;", "\\("],
        ")": ["%29", "\\x29", "&#41;", "\\)"],
        "=": ["%3d", "\\x3d", "&#61;", "LIKE", "REGEXP", "RLIKE", "!=", ">", "<"],
        " ": ["%20", "+", "/**/", "--%0a", "\t", "\n", "\r", "\x0b", "\x0c"]
    }
    
    # حمولات تجاوز حسب نوع WAF
    WAF_SPECIFIC_BYPASS = {
        "Cloudflare": [
            "case_swapping",
            "double_encoding",
            "chunked_transfer"
        ],
        "AWS WAF": [
            "url_encoding",
            "unicode_normalization",
            "payload_splitting"
        ],
        "ModSecurity": [
            "comment_insertion",
            "whitespace_variation",
            "line_breaking"
        ],
        "Imperva": [
            "parameter_pollution",
            "http_verb_tampering",
            "null_byte_injection"
        ],
        "Sucuri": [
            "tab_injection",
            "newline_injection",
            "chunked_transfer"
        ]
    }
    
    def __init__(self):
        self._generated_bypasses: Dict[str, List[BypassResult]] = {}
        
        logger.info("BypassGenerator initialized")
    
    async def generate_bypass(
        self,
        payload: str,
        technique: BypassTechnique,
        waf_type: str = None
    ) -> BypassResult:
        """
        توليد حمولة متجاوزة بتقنية محددة
        
        Args:
            payload: الحمولة الأصلية
            technique: تقنية التجاوز
            waf_type: نوع WAF (للتوليد المخصص)
        
        Returns:
            نتيجة التجاوز
        """
        modified = payload
        
        if technique == BypassTechnique.CASE_SWAPPING:
            modified = await self._case_swap(payload)
        
        elif technique == BypassTechnique.URL_ENCODING:
            modified = urllib.parse.quote(payload)
        
        elif technique == BypassTechnique.DOUBLE_ENCODING:
            modified = urllib.parse.quote(urllib.parse.quote(payload))
        
        elif technique == BypassTechnique.UNICODE_ENCODING:
            modified = await self._unicode_encode(payload)
        
        elif technique == BypassTechnique.HEX_ENCODING:
            modified = payload.encode().hex()
        
        elif technique == BypassTechnique.COMMENT_INSERTION:
            modified = await self._insert_comments(payload)
        
        elif technique == BypassTechnique.WHITESPACE_VARIATION:
            modified = await self._vary_whitespace(payload)
        
        elif technique == BypassTechnique.LINE_BREAKING:
            modified = await self._insert_line_breaks(payload)
        
        elif technique == BypassTechnique.NULL_BYTE_INJECTION:
            modified = payload.replace(" ", "%00")
        
        elif technique == BypassTechnique.PARAMETER_POLLUTION:
            modified = f"{payload}&{payload}"
        
        elif technique == BypassTechnique.HTTP_VERB_TAMPERING:
            modified = payload  # يتم تطبيقها على مستوى الطلب
        
        elif technique == BypassTechnique.PAYLOAD_SPLITTING:
            modified = await self._split_payload(payload)
        
        elif technique == BypassTechnique.CHUNKED_TRANSFER:
            modified = await self._chunked_encode(payload)
        
        elif technique == BypassTechnique.UNICODE_NORMALIZATION:
            modified = await self._unicode_normalize(payload)
        
        elif technique == BypassTechnique.TAB_INJECTION:
            modified = payload.replace(" ", "\t")
        
        elif technique == BypassTechnique.NEWLINE_INJECTION:
            modified = payload.replace(" ", "%0a")
        
        result = BypassResult(
            original_payload=payload,
            modified_payload=modified,
            technique=technique
        )
        
        # تخزين النتيجة
        key = f"{payload}_{technique.value}"
        if key not in self._generated_bypasses:
            self._generated_bypasses[key] = []
        self._generated_bypasses[key].append(result)
        
        return result
    
    async def generate_all_bypasses(
        self,
        payload: str,
        waf_type: str = None
    ) -> List[BypassResult]:
        """
        توليد جميع تقنيات التجاوز الممكنة
        
        Args:
            payload: الحمولة الأصلية
            waf_type: نوع WAF (للتوليد المخصص)
        
        Returns:
            قائمة بنتائج التجاوز
        """
        results = []
        
        # اختيار التقنيات المناسبة
        if waf_type and waf_type in self.WAF_SPECIFIC_BYPASS:
            techniques = self.WAF_SPECIFIC_BYPASS[waf_type]
        else:
            techniques = [t.value for t in BypassTechnique]
        
        for technique_name in techniques:
            try:
                technique = BypassTechnique(technique_name)
                result = await self.generate_bypass(payload, technique, waf_type)
                results.append(result)
            except ValueError:
                continue
        
        return results
    
    async def _case_swap(self, payload: str) -> str:
        """تغيير حالة الأحرف"""
        return ''.join(
            c.upper() if random.random() > 0.5 else c.lower()
            for c in payload
        )
    
    async def _unicode_encode(self, payload: str) -> str:
        """ترميز يونيكود"""
        return ''.join(f'\\u{ord(c):04x}' for c in payload)
    
    async def _insert_comments(self, payload: str) -> str:
        """إدراج تعليقات"""
        comments = ["/*", "*/", "--", "#", "/*!*/", "/*50000*/"]
        
        # إدراج تعليق عشوائي
        comment = random.choice(comments)
        insert_pos = random.randint(0, len(payload) - 1)
        
        return payload[:insert_pos] + comment + payload[insert_pos:]
    
    async def _vary_whitespace(self, payload: str) -> str:
        """تنويع المسافات"""
        whitespace_vars = ["%20", "+", "/**/", "--%0a", "\t", "%09", "%0a", "%0d"]
        
        result = []
        for char in payload:
            if char == " " and random.random() > 0.5:
                result.append(random.choice(whitespace_vars))
            else:
                result.append(char)
        
        return ''.join(result)
    
    async def _insert_line_breaks(self, payload: str) -> str:
        """إدراج كسرات الأسطر"""
        line_breaks = ["%0a", "%0d", "\\n", "\\r", "\n", "\r"]
        
        result = []
        for char in payload:
            result.append(char)
            if random.random() > 0.7 and char.isalnum():
                result.append(random.choice(line_breaks))
        
        return ''.join(result)
    
    async def _split_payload(self, payload: str) -> str:
        """تقسيم الحمولة"""
        if len(payload) < 10:
            return payload
        
        mid = len(payload) // 2
        split_char = random.choice(["%00", "%0a", "/**/", "--", "/*!*/"])
        
        return payload[:mid] + split_char + payload[mid:]
    
    async def _chunked_encode(self, payload: str) -> str:
        """ترميز مجزأ (Chunked transfer)"""
        result = []
        for i, c in enumerate(payload):
            if i % 2 == 0:
                result.append(urllib.parse.quote(c))
            else:
                result.append(c)
        
        return ''.join(result)
    
    async def _unicode_normalize(self, payload: str) -> str:
        """تطبيع يونيكود"""
        # استبدال أحرف معينة بنماذج يونيكود مشابهة
        unicode_mappings = {
            'a': ['а', 'ḁ', 'ȁ', 'ɐ'],
            'e': ['е', 'ė', 'ȅ', 'ɘ'],
            'o': ['о', 'ő', 'ȍ', 'ɵ'],
            'c': ['с', 'ċ', 'ȼ', 'ɔ'],
            'p': ['р', 'ṗ', 'ȕ', 'ƥ'],
        }
        
        result = []
        for c in payload:
            if c in unicode_mappings and random.random() > 0.5:
                result.append(random.choice(unicode_mappings[c]))
            else:
                result.append(c)
        
        return ''.join(result)
    
    async def get_bypasses_for_payload(self, payload: str) -> List[BypassResult]:
        """الحصول على حمولات متجاوزة لحمولة معينة"""
        results = []
        for key, bypasses in self._generated_bypasses.items():
            if key.startswith(payload):
                results.extend(bypasses)
        return results
    
    async def get_statistics(self) -> Dict:
        """إحصائيات المولد"""
        total_bypasses = sum(len(v) for v in self._generated_bypasses.values())
        
        return {
            "total_generated": total_bypasses,
            "unique_payloads": len(self._generated_bypasses),
            "techniques_available": len(BypassTechnique),
            "waf_specific_bypasses": len(self.WAF_SPECIFIC_BYPASS),
            "char_mappings": len(self.CHAR_MAPPINGS)
        }
    
    async def clear_bypasses(self):
        """مسح الحمولات المتجاوزة"""
        self._generated_bypasses.clear()
        logger.info("Bypass generator cleared")

