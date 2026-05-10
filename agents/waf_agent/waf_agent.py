
import asyncio
import re
from typing import Dict, List, Optional, Any, Set, Tuple
from datetime import datetime

from ..base.base_agent import BaseAgent, AgentPriority, AgentMessage
from ..base.agent_state import AgentStateEnum
from ...offensive.scanners.base_scanner import ScanContext, ScanTarget

import logging

logger = logging.getLogger(__name__)


class WAFAgent(BaseAgent):
    """
    وكيل تجاوز WAF المتقدم
    
    الميزات:
    - كشف وجود WAF ونوعه
    - توليد حمولات متجاوزة
    - اختبار تقنيات التجاوز المختلفة
    - تعلم من الاستجابات
    - تكامل مع مولد الحمولات
    """
    
    # أنماط كشف WAF
    WAF_PATTERNS = {
        "Cloudflare": {
            "headers": [r'cf-ray', r'__cfduid', r'cf-cache-status'],
            "cookies": [r'__cfduid'],
            "response": [r'Cloudflare', r'cdn-cgi']
        },
        "AWS WAF": {
            "headers": [r'x-amzn-RequestId', r'x-amzn-ErrorType'],
            "response": [r'AWS WAF', r'awswaf']
        },
        "ModSecurity": {
            "headers": [r'ModSecurity', r'OWASP'],
            "response": [r'ModSecurity', r'Request rejected']
        },
        "Imperva": {
            "cookies": [r'incap_ses', r'visid_incap'],
            "headers": [r'X-Cdn', r'X-Iinfo'],
            "response": [r'Incapsula', r'Imperva']
        },
        "Sucuri": {
            "headers": [r'X-Sucuri', r'x-sucuri-id'],
            "cookies": [r'sucuri'],
            "response": [r'Sucuri', r'CloudProxy']
        },
        "Akamai": {
            "headers": [r'AkamaiGHost', r'X-Akamai'],
            "response": [r'Akamai', r'EdgeControl']
        }
    }
    
    # تقنيات التجاوز
    BYPASS_TECHNIQUES = [
        "case_swapping",
        "url_encoding",
        "double_encoding",
        "comment_insertion",
        "whitespace_variation",
        "line_breaking",
        "null_byte_injection",
        "parameter_pollution",
        "http_verb_tampering",
        "payload_splitting"
    ]
    
    def __init__(
        self,
        name: str = "WAFAgent",
        priority: AgentPriority = AgentPriority.NORMAL,
        rate_limit: float = 1.0,
        timeout: int = 30
    ):
        super().__init__(name, priority)
        
        self._rate_limit = rate_limit
        self._timeout = timeout
        
        # حالة الوكيل
        self._detected_waf: Dict[str, Any] = {}
        self._bypass_attempts: List[Dict] = []
        self._active_tests: Set[str] = set()
        self._successful_bypasses: List[Dict] = []
        
        logger.info(f"WAFAgent initialized: {name}")
    
    async def _on_initialize(self):
        """تهيئة الوكيل"""
        logger.info("Initializing WAFAgent components...")
    
    async def _on_start(self):
        """بدء تشغيل الوكيل"""
        logger.info("WAFAgent started")
    
    async def _on_stop(self):
        """إيقاف تشغيل الوكيل"""
        self._active_tests.clear()
        logger.info("WAFAgent stopped")
    
    async def _handle_message(self, message: AgentMessage) -> Optional[AgentMessage]:
        """
        معالجة الرسائل الواردة
        
        أنواع الرسائل المدعومة:
        - detect_waf: كشف WAF
        - test_bypass: اختبار تقنية تجاوز
        - get_status: الحصول على حالة WAF
        """
        if message.type == "detect_waf":
            result = await self.detect_waf(message.content)
            return AgentMessage(
                id="",
                sender=self.name,
                receiver=message.sender,
                type="waf_detected",
                content=result
            )
        
        elif message.type == "test_bypass":
            result = await self.test_bypass_technique(message.content)
            return AgentMessage(
                id="",
                sender=self.name,
                receiver=message.sender,
                type="bypass_result",
                content=result
            )
        
        elif message.type == "get_status":
            status = await self.get_waf_status()
            return AgentMessage(
                id="",
                sender=self.name,
                receiver=message.sender,
                type="waf_status",
                content=status
            )
        
        return await super()._handle_message(message)
    
    async def detect_waf(self, target_url: str) -> Dict[str, Any]:
        """
        كشف وجود WAF ونوعه
        
        Args:
            target_url: الرابط المستهدف
        
        Returns:
            معلومات عن WAF
        """
        import httpx
        
        result = {
            "has_waf": False,
            "waf_type": None,
            "confidence": 0.0,
            "evidence": [],
            "tested_at": datetime.now().isoformat()
        }
        
        test_id = f"waf_detect_{datetime.now().timestamp()}"
        self._active_tests.add(test_id)
        
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                # إرسال طلب عادي
                response = await client.get(target_url)
                
                # تحليل الهيدرات
                headers = dict(response.headers)
                cookies = dict(response.cookies)
                response_text = response.text
                
                # فحص كل WAF
                for waf_name, patterns in self.WAF_PATTERNS.items():
                    confidence = 0.0
                    evidence = []
                    
                    # فحص الهيدرات
                    for pattern in patterns.get("headers", []):
                        for header, value in headers.items():
                            if re.search(pattern, header, re.I) or re.search(pattern, value, re.I):
                                confidence += 0.3
                                evidence.append(f"Header pattern: {pattern}")
                    
                    # فحص الكوكيز
                    for pattern in patterns.get("cookies", []):
                        for cookie in cookies:
                            if re.search(pattern, cookie, re.I):
                                confidence += 0.3
                                evidence.append(f"Cookie pattern: {pattern}")
                    
                    # فحص الاستجابة
                    for pattern in patterns.get("response", []):
                        if re.search(pattern, response_text, re.I):
                            confidence += 0.2
                            evidence.append(f"Response pattern: {pattern}")
                    
                    if confidence >= 0.5:
                        result["has_waf"] = True
                        result["waf_type"] = waf_name
                        result["confidence"] = min(confidence, 1.0)
                        result["evidence"] = evidence
                        break
            
            # تخزين نتيجة الكشف
            self._detected_waf = result
            
            logger.info(f"WAF detection completed: {result['waf_type'] if result['has_waf'] else 'No WAF detected'}")
            
        except Exception as e:
            logger.error(f"WAF detection failed: {e}")
            result["error"] = str(e)
        
        finally:
            self._active_tests.discard(test_id)
        
        return result
    
    async def test_bypass_technique(
        self,
        data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        اختبار تقنية تجاوز WAF
        
        Args:
            data: معلومات الاختبار (url, payload, technique, parameters)
        
        Returns:
            نتيجة الاختبار
        """
        url = data.get("url")
        original_payload = data.get("payload")
        technique = data.get("technique")
        parameters = data.get("parameters", {})
        
        result = {
            "technique": technique,
            "success": False,
            "original_payload": original_payload,
            "modified_payload": None,
            "status_code": None,
            "blocked": True,
            "execution_time": 0.0,
            "tested_at": datetime.now().isoformat()
        }
        
        import time
        import httpx
        
        start_time = time.time()
        test_id = f"bypass_{technique}_{datetime.now().timestamp()}"
        self._active_tests.add(test_id)
        
        try:
            # تطبيق تقنية التجاوز
            modified_payload = await self._apply_bypass_technique(original_payload, technique)
            result["modified_payload"] = modified_payload
            
            # بناء الطلب
            test_url = self._build_test_url(url, parameters, modified_payload)
            
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                response = await client.get(test_url)
                result["status_code"] = response.status_code
                
                # التحقق من النجاح (لم يتم الحظر)
                if response.status_code not in [403, 406, 429, 503]:
                    result["success"] = True
                    result["blocked"] = False
                    
                    # تسجيل النجاح
                    self._successful_bypasses.append({
                        "technique": technique,
                        "payload": modified_payload,
                        "url": url,
                        "timestamp": datetime.now().isoformat()
                    })
                    
                    logger.info(f"Bypass successful: {technique}")
                else:
                    result["blocked"] = True
            
            result["execution_time"] = time.time() - start_time
            
            # تسجيل المحاولة
            self._bypass_attempts.append(result)
            
        except Exception as e:
            logger.error(f"Bypass test failed: {e}")
            result["error"] = str(e)
        
        finally:
            self._active_tests.discard(test_id)
        
        return result
    
    async def _apply_bypass_technique(self, payload: str, technique: str) -> str:
        """
        تطبيق تقنية تجاوز على الحمولة
        
        Args:
            payload: الحمولة الأصلية
            technique: التقنية
        
        Returns:
            الحمولة المعدلة
        """
        import urllib.parse
        
        if technique == "case_swapping":
            # تغيير حالة الأحرف
            return ''.join(
                c.upper() if i % 2 == 0 else c.lower()
                for i, c in enumerate(payload)
            )
        
        elif technique == "url_encoding":
            # ترميز URL
            return urllib.parse.quote(payload)
        
        elif technique == "double_encoding":
            # ترميز مزدوج
            return urllib.parse.quote(urllib.parse.quote(payload))
        
        elif technique == "comment_insertion":
            # إضافة تعليقات
            return payload.replace(" ", "/**/").replace("=", "/*=*/")
        
        elif technique == "whitespace_variation":
            # تنويع المسافات
            whitespace_vars = ["%09", "%0a", "%0d", "%20", "+", "/**/"]
            return payload.replace(" ", random.choice(whitespace_vars))
        
        elif technique == "line_breaking":
            # كسر الأسطر
            return payload.replace(" ", "%0a").replace("=", "%0a=%0a")
        
        elif technique == "null_byte_injection":
            # حقن null byte
            return payload.replace(" ", "%00")
        
        elif technique == "parameter_pollution":
            # تلوث المعاملات
            return f"{payload}&{payload}"
        
        elif technique == "http_verb_tampering":
            # العبث بطريقة HTTP (تطبق في الطلب)
            return payload
        
        elif technique == "payload_splitting":
            # تقسيم الحمولة
            mid = len(payload) // 2
            return payload[:mid] + "%00" + payload[mid:]
        
        return payload
    
    def _build_test_url(self, base_url: str, parameters: Dict, payload: str) -> str:
        """بناء رابط الاختبار"""
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
        
        parsed = urlparse(base_url)
        params = parse_qs(parsed.query)
        
        # إدراج الحمولة في المعامل الأول
        if parameters:
            first_param = list(parameters.keys())[0] if parameters else "q"
            params[first_param] = [payload]
        
        new_query = urlencode(params, doseq=True)
        return urlunparse(parsed._replace(query=new_query))
    
    async def get_waf_status(self) -> Dict[str, Any]:
        """الحصول على حالة WAF"""
        return {
            "detected": self._detected_waf,
            "bypass_attempts": len(self._bypass_attempts),
            "successful_bypasses": len(self._successful_bypasses),
            "success_rate": len(self._successful_bypasses) / len(self._bypass_attempts) if self._bypass_attempts else 0,
            "active_tests": len(self._active_tests),
            "techniques_tested": list(set(a["technique"] for a in self._bypass_attempts)),
            "successful_techniques": list(set(a["technique"] for a in self._successful_bypasses))
        }
    
    async def get_bypass_history(self) -> List[Dict]:
        """الحصول على تاريخ محاولات التجاوز"""
        return self._bypass_attempts
    
    async def get_successful_bypasses(self) -> List[Dict]:
        """الحصول على التجاوزات الناجحة"""
        return self._successful_bypasses
    
    async def get_statistics(self) -> Dict:
        """إحصائيات الوكيل"""
        base_stats = await super().get_statistics()
        
        return {
            **base_stats,
            "waf_specific": await self.get_waf_status()
        }

