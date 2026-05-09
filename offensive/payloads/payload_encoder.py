
import base64
import urllib.parse
import html
import re
import json
import zlib
import gzip
import hashlib
import codecs
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass
from enum import Enum

from .payload_generator import Payload, PayloadType, EncodingType, get_payload_generator

import logging

logger = logging.getLogger(__name__)


class EncodingStrategy(Enum):
    """استراتيجيات الترميز"""
    SINGLE = "single"          # ترميز واحد
    MULTI = "multi"            # ترميز متعدد
    CHAINED = "chained"        # ترميز متسلسل
    RANDOM = "random"          # ترميز عشوائي
    ADAPTIVE = "adaptive"      # ترميز متكيف حسب السياق


@dataclass
class EncodedPayload:
    """حمولة مشفرة"""
    original: Payload
    encoded: str
    encoding_strategy: EncodingStrategy
    encoding_chain: List[str]  # قائمة الترميزات المستخدمة
    success_probability: float  # احتمالية النجاح
    size_ratio: float  # نسبة الحجم إلى الأصلي


class PayloadEncoder:
    """
    مشفر الحمولات المتقدم
    
    الميزات:
    - 15+ طريقة ترميز مختلفة
    - ترميز متعدد ومتسلسل
    - ترميز متكيف حسب السياق
    - دعم ترميزات WAF bypass
    - تقييم احتمالية النجاح
    - توليد ترميزات عشوائية
    """
    
    # طرق الترميز المتاحة
    AVAILABLE_ENCODINGS = {
        "url": lambda x: urllib.parse.quote(x),
        "url_full": lambda x: urllib.parse.quote(x, safe=''),
        "double_url": lambda x: urllib.parse.quote(urllib.parse.quote(x)),
        "triple_url": lambda x: urllib.parse.quote(urllib.parse.quote(urllib.parse.quote(x))),
        "html_entity": lambda x: html.escape(x),
        "html_hex": lambda x: ''.join(f'&#x{ord(c):02x};' for c in x),
        "html_dec": lambda x: ''.join(f'&#{ord(c)};' for c in x),
        "base64": lambda x: base64.b64encode(x.encode()).decode(),
        "base64_url": lambda x: base64.urlsafe_b64encode(x.encode()).decode().rstrip('='),
        "hex": lambda x: x.encode().hex(),
        "unicode_escape": lambda x: x.encode('unicode_escape').decode(),
        "utf_16_le": lambda x: x.encode('utf-16-le').hex(),
        "utf_16_be": lambda x: x.encode('utf-16-be').hex(),
        "utf_32": lambda x: x.encode('utf-32').hex(),
        "gzip": lambda x: base64.b64encode(gzip.compress(x.encode())).decode(),
        "zlib": lambda x: base64.b64encode(zlib.compress(x.encode())).decode(),
        "rot13": lambda x: codecs.encode(x, 'rot_13'),
        "rot47": lambda x: self._rot47(x),
        "reverse": lambda x: x[::-1],
        "binary": lambda x: ' '.join(format(ord(c), '08b') for c in x),
    }
    
    # سلاسل ترميز محسنة للتجاوز
    BYPASS_CHAINS = [
        ["url", "html_entity"],
        ["url", "double_url"],
        ["hex", "url"],
        ["base64", "url"],
        ["unicode_escape", "url"],
        ["html_hex", "url"],
        ["double_url", "html_entity"],
        ["base64", "html_entity"],
    ]
    
    def __init__(self):
        self._encoded_cache: Dict[str, List[EncodedPayload]] = {}
        
        logger.info("PayloadEncoder initialized")
    
    def encode_payload(
        self,
        payload: Payload,
        encoding_name: str,
        strategy: EncodingStrategy = EncodingStrategy.SINGLE
    ) -> Optional[EncodedPayload]:
        """
        ترميز حمولة بطريقة محددة
        
        Args:
            payload: الحمولة الأصلية
            encoding_name: اسم طريقة الترميز
            strategy: استراتيجية الترميز
        
        Returns:
            الحمولة المشفرة أو None إذا فشل
        """
        if encoding_name not in self.AVAILABLE_ENCODINGS:
            logger.warning(f"Unknown encoding: {encoding_name}")
            return None
        
        encoder = self.AVAILABLE_ENCODINGS[encoding_name]
        
        try:
            encoded = encoder(payload.payload)
            
            # حساب احتمالية النجاح وحجم النسخة المشفرة
            success_prob = self._calculate_success_probability(encoded, encoding_name)
            size_ratio = len(encoded) / max(len(payload.payload), 1)
            
            return EncodedPayload(
                original=payload,
                encoded=encoded,
                encoding_strategy=strategy,
                encoding_chain=[encoding_name],
                success_probability=success_prob,
                size_ratio=size_ratio
            )
            
        except Exception as e:
            logger.debug(f"Encoding failed for {encoding_name}: {e}")
            return None
    
    def encode_multi(
        self,
        payload: Payload,
        encodings: List[str],
        strategy: EncodingStrategy = EncodingStrategy.CHAINED
    ) -> Optional[EncodedPayload]:
        """
        ترميز حمولة بطرق متعددة (متسلسل)
        
        Args:
            payload: الحمولة الأصلية
            encodings: قائمة طرق الترميز بالتسلسل
            strategy: استراتيجية الترميز
        
        Returns:
            الحمولة المشفرة
        """
        current = payload.payload
        
        for encoding_name in encodings:
            if encoding_name not in self.AVAILABLE_ENCODINGS:
                logger.warning(f"Unknown encoding: {encoding_name}")
                return None
            
            encoder = self.AVAILABLE_ENCODINGS[encoding_name]
            try:
                current = encoder(current)
            except Exception as e:
                logger.debug(f"Encoding failed at {encoding_name}: {e}")
                return None
        
        # حساب احتمالية النجاح ونسبة الحجم
        success_prob = self._calculate_chained_success_probability(encodings)
        size_ratio = len(current) / max(len(payload.payload), 1)
        
        return EncodedPayload(
            original=payload,
            encoded=current,
            encoding_strategy=strategy,
            encoding_chain=encodings,
            success_probability=success_prob,
            size_ratio=size_ratio
        )
    
    def encode_all(
        self,
        payload: Payload,
        max_encodings: int = 5
    ) -> List[EncodedPayload]:
        """
        ترميز حمولة بجميع الطرق المتاحة
        
        Args:
            payload: الحمولة الأصلية
            max_encodings: الحد الأقصى لعدد الترميزات
        
        Returns:
            قائمة بالحمولات المشفرة
        """
        encoded_payloads = []
        
        # ترميز فردي
        for enc_name in list(self.AVAILABLE_ENCODINGS.keys())[:max_encodings]:
            encoded = self.encode_payload(payload, enc_name, EncodingStrategy.SINGLE)
            if encoded:
                encoded_payloads.append(encoded)
        
        # سلاسل ترميز مسبقة للـ bypass
        for chain in self.BYPASS_CHAINS[:max_encodings // 2]:
            if len(chain) <= max_encodings:
                encoded = self.encode_multi(payload, chain, EncodingStrategy.CHAINED)
                if encoded:
                    encoded_payloads.append(encoded)
        
        # ترميز عشوائي
        random_encodings = self._generate_random_chain(random.randint(2, min(max_encodings, 4)))
        encoded = self.encode_multi(payload, random_encodings, EncodingStrategy.RANDOM)
        if encoded:
            encoded_payloads.append(encoded)
        
        # ترتيب حسب احتمالية النجاح
        encoded_payloads.sort(key=lambda x: x.success_probability, reverse=True)
        
        # تخزين في الذاكرة المؤقتة
        self._encoded_cache[payload.id] = encoded_payloads
        
        return encoded_payloads
    
    def encode_adaptive(
        self,
        payload: Payload,
        context: Dict[str, Any]
    ) -> List[EncodedPayload]:
        """
        ترميز متكيف حسب السياق
        
        Args:
            payload: الحمولة الأصلية
            context: سياق الهدف (نوع WAF، مستوى الحماية، إلخ)
        
        Returns:
            قائمة بالحمولات المشفرة المناسبة للسياق
        """
        recommended_encodings = []
        
        # إذا كان هناك WAF معروف
        waf_type = context.get("waf_type", "").lower()
        
        if "cloudflare" in waf_type:
            # Cloudflare WAF - استخدام ترميزات متعددة
            recommended_encodings = [
                ["html_entity", "url"],
                ["double_url"],
                ["unicode_escape", "url"],
            ]
        elif "aws" in waf_type or "waf" in waf_type:
            # AWS WAF - تجنب الأنماط الشائعة
            recommended_encodings = [
                ["hex", "url"],
                ["base64", "url"],
                ["html_hex"],
            ]
        elif "modsecurity" in waf_type:
            # ModSecurity - استخدام ترميزات متعددة
            recommended_encodings = [
                ["unicode_escape"],
                ["double_url"],
                ["url", "html_entity"],
            ]
        else:
            # WAF غير معروف - اختبار جميع الخيارات الجيدة
            recommended_encodings = [
                ["url"],
                ["double_url"],
                ["html_entity", "url"],
                ["base64", "url"],
            ]
        
        encoded_payloads = []
        
        for chain in recommended_encodings[:5]:
            encoded = self.encode_multi(payload, chain, EncodingStrategy.ADAPTIVE)
            if encoded:
                encoded_payloads.append(encoded)
        
        # إضافة ترميزات عشوائية إضافية
        random_encodings = self._generate_random_chain(2)
        encoded = self.encode_multi(payload, random_encodings, EncodingStrategy.RANDOM)
        if encoded:
            encoded_payloads.append(encoded)
        
        # ترتيب حسب احتمالية النجاح
        encoded_payloads.sort(key=lambda x: x.success_probability, reverse=True)
        
        return encoded_payloads
    
    def _calculate_success_probability(self, encoded: str, encoding_name: str) -> float:
        """
        حساب احتمالية نجاح الترميز في تجاوز الحماية
        """
        probability = 0.5  # قيمة افتراضية
        
        # الترميزات الأساسية
        if encoding_name == "url":
            probability = 0.4
        elif encoding_name == "double_url":
            probability = 0.6
        elif encoding_name == "html_entity":
            probability = 0.55
        elif encoding_name == "base64":
            probability = 0.65
        elif encoding_name == "hex":
            probability = 0.6
        elif encoding_name == "unicode_escape":
            probability = 0.7
        elif encoding_name == "gzip":
            probability = 0.75
        elif encoding_name == "zlib":
            probability = 0.7
        
        # تعديل حسب طول الترميز
        if len(encoded) > 500:  # طويل جداً قد يرفض
            probability -= 0.1
        
        # تعديل حسب وجود أحرف خاصة
        special_chars = ['%', '&', '#', '=', '?']
        for char in special_chars:
            if char in encoded:
                probability += 0.05
        
        return max(0.1, min(0.95, probability))
    
    def _calculate_chained_success_probability(self, encoding_chain: List[str]) -> float:
        """
        حساب احتمالية نجاح سلسلة ترميزات
        """
        probability = 1.0
        
        for enc in encoding_chain:
            prob = self._calculate_success_probability("", enc)  # قيمة تقريبية
            probability *= prob
        
        # مكافأة للسلاسل الطويلة (تجاوز أفضل)
        if len(encoding_chain) >= 3:
            probability *= 1.1
        if len(encoding_chain) >= 4:
            probability *= 1.05
        
        return min(0.95, probability)
    
    def _generate_random_chain(self, length: int) -> List[str]:
        """
        توليد سلسلة ترميز عشوائية
        """
        available = list(self.AVAILABLE_ENCODINGS.keys())
        return random.sample(available, min(length, len(available)))
    
    def _rot47(self, text: str) -> str:
        """ROT47 encoding for ASCII 33-126"""
        result = []
        for char in text:
            if 33 <= ord(char) <= 126:
                result.append(chr(33 + ((ord(char) - 33 + 47) % 94)))
            else:
                result.append(char)
        return ''.join(result)
    
    def decode_payload(self, encoded: str, encoding_chain: List[str]) -> Optional[str]:
        """
        فك ترميز حمولة
        
        Args:
            encoded: الحمولة المشفرة
            encoding_chain: سلسلة الترميزات المستخدمة (بترتيب عكسي)
        
        Returns:
            الحمولة الأصلية أو None
        """
        current = encoded
        
        # فك الترميز بترتيب عكسي
        for encoding_name in reversed(encoding_chain):
            if encoding_name not in self.AVAILABLE_ENCODINGS:
                return None
            
            decoder = self._get_decoder(encoding_name)
            if not decoder:
                return None
            
            try:
                current = decoder(current)
            except Exception as e:
                logger.debug(f"Decoding failed at {encoding_name}: {e}")
                return None
        
        return current
    
    def _get_decoder(self, encoding_name: str):
        """الحصول على دالة فك الترميز"""
        decoders = {
            "url": urllib.parse.unquote,
            "double_url": lambda x: urllib.parse.unquote(urllib.parse.unquote(x)),
            "html_entity": html.unescape,
            "base64": lambda x: base64.b64decode(x).decode(),
            "hex": lambda x: bytes.fromhex(x).decode(),
            "gzip": lambda x: gzip.decompress(base64.b64decode(x)).decode(),
            "zlib": lambda x: zlib.decompress(base64.b64decode(x)).decode(),
            "rot13": lambda x: codecs.decode(x, 'rot_13'),
            "reverse": lambda x: x[::-1],
        }
        return decoders.get(encoding_name)
    
    def get_best_encodings(
        self,
        payload: Payload,
        limit: int = 10
    ) -> List[EncodedPayload]:
        """
        الحصول على أفضل ترميزات لحمولة معينة
        """
        if payload.id not in self._encoded_cache:
            self.encode_all(payload)
        
        encoded_payloads = self._encoded_cache.get(payload.id, [])
        encoded_payloads.sort(key=lambda x: x.success_probability, reverse=True)
        
        return encoded_payloads[:limit]
    
    def get_statistics(self) -> Dict:
        """إحصائيات نظام الترميز"""
        stats = {
            "available_encodings": len(self.AVAILABLE_ENCODINGS),
            "bypass_chains": len(self.BYPASS_CHAINS),
            "cached_payloads": len(self._encoded_cache),
            "total_encoded_versions": sum(len(v) for v in self._encoded_cache.values()),
            "encodings": list(self.AVAILABLE_ENCODINGS.keys())
        }
        
        return stats


# نسخة عالمية
_default_encoder = None


def get_payload_encoder() -> PayloadEncoder:
    """الحصول على نسخة عالمية من مشفر الحمولات"""
    global _default_encoder
    if _default_encoder is None:
        _default_encoder = PayloadEncoder()
    return _default_encoder

