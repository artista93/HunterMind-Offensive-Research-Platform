
import base64
import random
import string
import zlib
import gzip
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum

import logging

logger = logging.getLogger(__name__)


class ObfuscationMethod(Enum):
    """طرق الإبهام"""
    BASE64 = "base64"
    HEX = "hex"
    REVERSE = "reverse"
    ROT13 = "rot13"
    ROT47 = "rot47"
    GZIP = "gzip"
    ZLIB = "zlib"
    XOR = "xor"
    CUSTOM_ENCODING = "custom_encoding"
    MULTI_LAYER = "multi_layer"
    JS_UNICODE = "js_unicode"
    HTML_ENTITY = "html_entity"
    STRING_SPLIT = "string_split"
    CHAR_CODE = "char_code"
    EVAL_WRAPPER = "eval_wrapper"


@dataclass
class ObfuscatedPayload:
    """حمولة مبهمة"""
    original: str
    obfuscated: str
    method: ObfuscationMethod
    layers: int = 1
    success_rate: float = 0.5
    metadata: Dict[str, Any] = field(default_factory=dict)


class PayloadObfuscator:
    """
    مبهم الحمولات المتقدم
    
    الميزات:
    - 13 طريقة إبهام مختلفة
    - إبهام متعدد الطبقات
    - إبهام عشوائي
    - فك الإبهام
    - تقييم فعالية الإبهام
    """
    
    def __init__(self):
        self._obfuscated_payloads: Dict[str, List[ObfuscatedPayload]] = {}
        
        logger.info("PayloadObfuscator initialized")
    
    async def obfuscate(
        self,
        payload: str,
        method: ObfuscationMethod,
        layers: int = 1,
        key: int = None
    ) -> ObfuscatedPayload:
        """
        إبهام حمولة بطريقة محددة
        
        Args:
            payload: الحمولة الأصلية
            method: طريقة الإبهام
            layers: عدد طبقات الإبهام
            key: مفتاح (لـ XOR)
        
        Returns:
            حمولة مبهمة
        """
        result = payload
        
        for _ in range(layers):
            if method == ObfuscationMethod.BASE64:
                result = base64.b64encode(result.encode()).decode()
            
            elif method == ObfuscationMethod.HEX:
                result = result.encode().hex()
            
            elif method == ObfuscationMethod.REVERSE:
                result = result[::-1]
            
            elif method == ObfuscationMethod.ROT13:
                result = self._rot13(result)
            
            elif method == ObfuscationMethod.ROT47:
                result = self._rot47(result)
            
            elif method == ObfuscationMethod.GZIP:
                compressed = gzip.compress(result.encode())
                result = base64.b64encode(compressed).decode()
            
            elif method == ObfuscationMethod.ZLIB:
                compressed = zlib.compress(result.encode())
                result = base64.b64encode(compressed).decode()
            
            elif method == ObfuscationMethod.XOR:
                if key is None:
                    key = random.randint(1, 255)
                result = self._xor_encrypt(result, key)
            
            elif method == ObfuscationMethod.CUSTOM_ENCODING:
                result = self._custom_encode(result)
            
            elif method == ObfuscationMethod.JS_UNICODE:
                result = self._js_unicode_encode(result)
            
            elif method == ObfuscationMethod.HTML_ENTITY:
                result = self._html_entity_encode(result)
            
            elif method == ObfuscationMethod.STRING_SPLIT:
                result = self._string_split_encode(result)
            
            elif method == ObfuscationMethod.CHAR_CODE:
                result = self._char_code_encode(result)
            
            elif method == ObfuscationMethod.MULTI_LAYER:
                # اختيار عشوائي لطبقات متعددة
                result = await self._multi_layer_obfuscate(result)
        
        obfuscated = ObfuscatedPayload(
            original=payload,
            obfuscated=result,
            method=method,
            layers=layers
        )
        
        # تخزين النتيجة
        key = f"{payload}_{method.value}"
        if key not in self._obfuscated_payloads:
            self._obfuscated_payloads[key] = []
        self._obfuscated_payloads[key].append(obfuscated)
        
        return obfuscated
    
    async def obfuscate_all(
        self,
        payload: str,
        max_methods: int = 10
    ) -> List[ObfuscatedPayload]:
        """
        إبهام الحمولة بجميع الطرق
        
        Args:
            payload: الحمولة الأصلية
            max_methods: الحد الأقصى لعدد الطرق
        
        Returns:
            قائمة بالحمولات المبهمة
        """
        results = []
        
        for method in list(ObfuscationMethod)[:max_methods]:
            obfuscated = await self.obfuscate(payload, method)
            results.append(obfuscated)
        
        return results
    
    async def deobfuscate(
        self,
        obfuscated: str,
        method: ObfuscationMethod,
        key: int = None
    ) -> Optional[str]:
        """
        فك إبهام حمولة
        
        Args:
            obfuscated: الحمولة المبهمة
            method: طريقة الإبهام
            key: مفتاح (لـ XOR)
        
        Returns:
            الحمولة الأصلية أو None
        """
        result = obfuscated
        
        try:
            if method == ObfuscationMethod.BASE64:
                result = base64.b64decode(result).decode()
            
            elif method == ObfuscationMethod.HEX:
                result = bytes.fromhex(result).decode()
            
            elif method == ObfuscationMethod.REVERSE:
                result = result[::-1]
            
            elif method == ObfuscationMethod.ROT13:
                result = self._rot13(result)
            
            elif method == ObfuscationMethod.ROT47:
                result = self._rot47(result)
            
            elif method == ObfuscationMethod.GZIP:
                decoded = base64.b64decode(result)
                result = gzip.decompress(decoded).decode()
            
            elif method == ObfuscationMethod.ZLIB:
                decoded = base64.b64decode(result)
                result = zlib.decompress(decoded).decode()
            
            elif method == ObfuscationMethod.XOR and key:
                result = self._xor_decrypt(result, key)
            
            elif method == ObfuscationMethod.CUSTOM_ENCODING:
                result = self._custom_decode(result)
            
            elif method == ObfuscationMethod.JS_UNICODE:
                result = self._js_unicode_decode(result)
            
            elif method == ObfuscationMethod.HTML_ENTITY:
                result = self._html_entity_decode(result)
            
            elif method == ObfuscationMethod.STRING_SPLIT:
                result = self._string_split_decode(result)
            
            elif method == ObfuscationMethod.CHAR_CODE:
                result = self._char_code_decode(result)
            
            return result
            
        except Exception as e:
            logger.debug(f"Deobfuscation failed: {e}")
            return None
    
    async def _multi_layer_obfuscate(self, payload: str) -> str:
        """إبهام متعدد الطبقات"""
        methods = list(ObfuscationMethod)
        methods.remove(ObfuscationMethod.MULTI_LAYER)
        
        result = payload
        num_layers = random.randint(2, 5)
        
        for _ in range(num_layers):
            method = random.choice(methods)
            obfuscated = await self.obfuscate(result, method)
            result = obfuscated.obfuscated
        
        return result
    
    def _rot13(self, text: str) -> str:
        """ترميز ROT13"""
        result = []
        for c in text:
            if 'a' <= c <= 'z':
                result.append(chr((ord(c) - ord('a') + 13) % 26 + ord('a')))
            elif 'A' <= c <= 'Z':
                result.append(chr((ord(c) - ord('A') + 13) % 26 + ord('A')))
            else:
                result.append(c)
        return ''.join(result)
    
    def _rot47(self, text: str) -> str:
        """ترميز ROT47"""
        result = []
        for c in text:
            if 33 <= ord(c) <= 126:
                result.append(chr(33 + ((ord(c) - 33 + 47) % 94)))
            else:
                result.append(c)
        return ''.join(result)
    
    def _xor_encrypt(self, data: str, key: int) -> str:
        """تشفير XOR"""
        return ''.join(chr(ord(c) ^ key) for c in data)
    
    def _xor_decrypt(self, data: str, key: int) -> str:
        """فك تشفير XOR"""
        return self._xor_encrypt(data, key)
    
    def _custom_encode(self, data: str) -> str:
        """ترميز مخصص (استبدال أحرف)"""
        mapping = {
            'a': '@', 'e': '3', 'i': '1', 'o': '0', 's': '$',
            'A': '@', 'E': '3', 'I': '1', 'O': '0', 'S': '$'
        }
        return ''.join(mapping.get(c, c) for c in data)
    
    def _custom_decode(self, data: str) -> str:
        """فك ترميز مخصص"""
        mapping = {
            '@': 'a', '3': 'e', '1': 'i', '0': 'o', '$': 's'
        }
        return ''.join(mapping.get(c, c) for c in data)
    
    def _js_unicode_encode(self, data: str) -> str:
        """ترميز يونيكود لـ JavaScript"""
        return ''.join(f'\\u{ord(c):04x}' for c in data)
    
    def _js_unicode_decode(self, data: str) -> str:
        """فك ترميز يونيكود JavaScript"""
        result = []
        i = 0
        while i < len(data):
            if data[i:i+2] == '\\u' and i + 6 <= len(data):
                code = int(data[i+2:i+6], 16)
                result.append(chr(code))
                i += 6
            else:
                result.append(data[i])
                i += 1
        return ''.join(result)
    
    def _html_entity_encode(self, data: str) -> str:
        """ترميز كيانات HTML"""
        return ''.join(f'&#{ord(c)};' for c in data)
    
    def _html_entity_decode(self, data: str) -> str:
        """فك ترميز كيانات HTML"""
        import html
        return html.unescape(data)
    
    def _string_split_encode(self, data: str) -> str:
        """تقسيم السلسلة"""
        return '+'.join(f"'{c}'" for c in data)
    
    def _string_split_decode(self, data: str) -> str:
        """فك تقسيم السلسلة"""
        # إزالة علامات الاقتباس والفواصل
        parts = data.replace("'", "").split('+')
        return ''.join(parts)
    
    def _char_code_encode(self, data: str) -> str:
        """ترميز باستخدام رموز الأحرف"""
        codes = [str(ord(c)) for c in data]
        return f"String.fromCharCode({','.join(codes)})"
    
    def _char_code_decode(self, data: str) -> str:
        """فك ترميز رموز الأحرف"""
        # استخراج الأرقام بين الأقواس
        import re
        match = re.search(r'fromCharCode\(([^)]+)\)', data)
        if match:
            codes = match.group(1).split(',')
            return ''.join(chr(int(c)) for c in codes)
        return data
    
    async def get_obfuscated_for_payload(self, payload: str) -> List[ObfuscatedPayload]:
        """الحصول على الحمولات المبهمة لحمولة معينة"""
        results = []
        for key, obfuscateds in self._obfuscated_payloads.items():
            if key.startswith(payload):
                results.extend(obfuscateds)
        return results
    
    async def get_statistics(self) -> Dict:
        """إحصائيات المبهم"""
        total_obfuscated = sum(len(v) for v in self._obfuscated_payloads.values())
        
        return {
            "total_obfuscated": total_obfuscated,
            "unique_payloads": len(self._obfuscated_payloads),
            "methods_available": len(ObfuscationMethod),
            "methods": [m.value for m in ObfuscationMethod]
        }
    
    async def clear_obfuscated(self):
        """مسح الحمولات المبهمة"""
        self._obfuscated_payloads.clear()
        logger.info("Obfuscated payloads cleared")

