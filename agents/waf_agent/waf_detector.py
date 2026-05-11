import re
import asyncio
import time
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime

import logging

logger = logging.getLogger(__name__)


@dataclass
class WAFDetection:
    waf_name: str
    confidence: float
    evidence: List[str]
    detected_at: datetime = field(default_factory=datetime.now)
    version: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


class WAFDetector:
    """
    كاشف WAF المتقدم
    
    الميزات:
    - كشف 15+ نظام WAF
    - تحليل الهيدرات والكوكيز
    - تحليل صفحات الحظر
    - كشف الإصدارات
    - اختبار الاستجابة للتأخير
    """
    
    WAF_PATTERNS = {
        "Cloudflare": {
            "headers": [
                r'cf-ray', r'__cfduid', r'cf-cache-status', r'cf-request-id',
                r'cf-worker', r'CF-RAY', r'CF-Cache-Status'
            ],
            "cookies": [r'__cfduid', r'__cf_bm'],
            "response": [
                r'Cloudflare', r'cdn-cgi', r'Attention Required!', 
                r'DDoS protection', r'Checking your browser'
            ],
            "status_codes": [403, 503]
        },
        "AWS WAF": {
            "headers": [
                r'x-amzn-RequestId', r'x-amzn-ErrorType', r'x-amzn-Remapped-',
                r'AWSALB', r'AWSALBCORS'
            ],
            "cookies": [],
            "response": [r'AWS WAF', r'awswaf', r'Request blocked'],
            "status_codes": [403]
        },
        "ModSecurity": {
            "headers": [r'ModSecurity', r'OWASP', r'X-Mod-Security'],
            "cookies": [],
            "response": [
                r'ModSecurity', r'Request rejected', r'Not Acceptable',
                r'Your request was blocked', r'Possible attack detected'
            ],
            "status_codes": [403, 406]
        },
        "Imperva (Incapsula)": {
            "headers": [r'X-Cdn', r'X-Iinfo', r'Incapsula', r'X-Forwarded-For'],
            "cookies": [r'incap_ses', r'visid_incap', r'___utm'],
            "response": [r'Incapsula', r'Imperva', r'Request rejected'],
            "status_codes": [403]
        },
        "Sucuri": {
            "headers": [r'X-Sucuri', r'x-sucuri-id', r'X-Sucuri-Cloud'],
            "cookies": [r'sucuri', r'cloudproxy'],
            "response": [r'Sucuri', r'CloudProxy', r'Access Denied'],
            "status_codes": [403]
        },
        "Akamai": {
            "headers": [r'AkamaiGHost', r'X-Akamai', r'X-Akamai-Transformed'],
            "cookies": [r'_abck', r'bm_sz', r'ak_bmsc'],
            "response": [r'Akamai', r'EdgeControl', r'Reference ID'],
            "status_codes": [403]
        },
        "F5 BIG-IP ASM": {
            "headers": [r'X-WA-Info', r'X-F5-ASM', r'BigIP'],
            "cookies": [r'TS', r'BIGipServer'],
            "response": [r'F5', r'ASM', r'The requested URL was rejected'],
            "status_codes": [403]
        },
        "Barracuda WAF": {
            "headers": [r'Barracuda', r'x-barracuda'],
            "cookies": [r'barracuda'],
            "response": [r'Barracuda', r'Barracuda WAF'],
            "status_codes": [403]
        },
        "Fortinet FortiWeb": {
            "headers": [r'FortiWeb', r'X-FW'],
            "cookies": [r'fortiweb'],
            "response": [r'FortiWeb', r'Fortinet'],
            "status_codes": [403]
        },
        "Radware AppWall": {
            "headers": [r'X-SL-CompState', r'Radware'],
            "cookies": [],
            "response": [r'AppWall', r'Radware', r'Request Rejected'],
            "status_codes": [403]
        },
        "Citrix NetScaler": {
            "headers": [r'NS-CACHE', r'Citrix'],
            "cookies": [r'NSC_'],
            "response": [r'NetScaler', r'Citrix'],
            "status_codes": [403]
        },
        "Microsoft Azure WAF": {
            "headers": [r'x-azure-ref', r'x-azure', r'x-ms-request-id'],
            "cookies": [],
            "response": [r'Azure', r'Microsoft Azure'],
            "status_codes": [403]
        },
        "Google Cloud Armor": {
            "headers": [r'X-GCP', r'Google'],
            "cookies": [],
            "response": [r'Google Cloud', r'Cloud Armor'],
            "status_codes": [403]
        },
        "Wordfence": {
            "headers": [],
            "cookies": [r'wfvt_', r'wordfence'],
            "response": [r'Wordfence', r'Your access to this site has been limited'],
            "status_codes": [403, 503]
        },
        "Comodo WAF": {
            "headers": [r'Comodo', r'CWAF'],
            "cookies": [r'comodo'],
            "response": [r'Comodo', r'CWAF', r'Access Denied'],
            "status_codes": [403]
        },
        "SiteGround": {
            "headers": [r'SG-'],
            "cookies": [r'wpSGCacheBypass'],
            "response": [r'SiteGround', r'SG Optimizer'],
            "status_codes": [403]
        }
    }
    
    def __init__(self, http_client=None):
        self._http_client = http_client
        self._detections: Dict[str, WAFDetection] = {}
        
        logger.info("WAFDetector initialized")
    
    def set_http_client(self, client):
        """تعيين عميل HTTP"""
        self._http_client = client
    
    async def _send_request(self, url: str, timeout: float = 30.0) -> tuple:
        """إرسال طلب HTTP"""
        if self._http_client and hasattr(self._http_client, 'send_request'):
            start = time.time()
            response = await self._http_client.send_request(url, method="GET")
            elapsed = time.time() - start
            return response, elapsed, 200 if response else 404
        
        try:
            import httpx
            start = time.time()
            async with httpx.AsyncClient(timeout=timeout) as client:
                response = await client.get(url)
            elapsed = time.time() - start
            return response.text, elapsed, response.status_code
        except Exception as e:
            logger.debug(f"Request error: {e}")
            return None, 0, 0
    
    async def detect(
        self,
        headers: Dict[str, str],
        cookies: Dict[str, str],
        response_text: str,
        status_code: int,
        target_url: str
    ) -> Optional[WAFDetection]:
        detections = []
        
        for waf_name, patterns in self.WAF_PATTERNS.items():
            confidence = 0.0
            evidence = []
            
            if status_code in patterns.get("status_codes", []):
                confidence += 0.3
                evidence.append(f"Status code {status_code}")
            
            for pattern in patterns.get("headers", []):
                for header, value in headers.items():
                    if re.search(pattern, header, re.I) or re.search(pattern, value, re.I):
                        confidence += 0.25
                        evidence.append(f"Header pattern: {pattern}")
                        break
            
            for pattern in patterns.get("cookies", []):
                for cookie in cookies:
                    if re.search(pattern, cookie, re.I):
                        confidence += 0.25
                        evidence.append(f"Cookie pattern: {pattern}")
                        break
            
            for pattern in patterns.get("response", []):
                if re.search(pattern, response_text, re.I):
                    confidence += 0.2
                    evidence.append(f"Response pattern: {pattern}")
                    break
            
            if confidence >= 0.5:
                detection = WAFDetection(
                    waf_name=waf_name,
                    confidence=min(confidence, 1.0),
                    evidence=evidence
                )
                detections.append(detection)
        
        if detections:
            best = max(detections, key=lambda x: x.confidence)
            self._detections[target_url] = best
            logger.info(f"WAF detected: {best.waf_name} (confidence={best.confidence:.1%})")
            return best
        
        return None
    
    async def detect_by_challenge(self, response_text: str) -> Optional[str]:
        challenge_patterns = {
            "Cloudflare": [
                r'Checking if the site connection is secure',
                r"Please stand by, while we are checking your browser",
                r'__cf_chl',
                r'cf-chl-widget'
            ],
            "Akamai": [
                r'akamai',
                r'EdgeControl',
                r'Checking your browser before accessing'
            ],
            "Imperva": [
                r'Incapsula',
                r'Please complete this security check',
                r'/_Incapsula_Resource'
            ]
        }
        
        for waf_name, patterns in challenge_patterns.items():
            for pattern in patterns:
                if re.search(pattern, response_text, re.I):
                    logger.info(f"WAF challenge page detected: {waf_name}")
                    return waf_name
        
        return None
    
    async def test_delay(self, url: str, timeout: float = 5.0) -> float:
        response, elapsed, status = await self._send_request(url, timeout)
        
        if elapsed > 1.0:
            logger.debug(f"Response delay detected: {elapsed:.2f}s (possible WAF)")
        
        return elapsed
    
    async def test_waf_blocking(
        self,
        url: str,
        test_payload: str = "<script>alert('test')</script>"
    ) -> Dict[str, Any]:
        """
        اختبار قدرة WAF على حظر حمولة ضارة
        
        Args:
            url: الرابط للاختبار
            test_payload: حمولة للاختبار
        
        Returns:
            نتيجة الاختبار
        """
        # بناء URL مع الحمولة
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
        
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        # إضافة الحمولة إلى معامل
        params['q'] = [test_payload]
        new_query = urlencode(params, doseq=True)
        test_url = urlunparse(parsed._replace(query=new_query))
        
        response, elapsed, status = await self._send_request(test_url)
        
        result = {
            "url": test_url,
            "payload": test_payload,
            "status_code": status,
            "blocked": status in [403, 406, 429, 503],
            "response_time": elapsed
        }
        
        return result
    
    async def get_detection(self, target_url: str) -> Optional[WAFDetection]:
        return self._detections.get(target_url)
    
    async def get_all_detections(self) -> List[Dict]:
        return [
            {
                "url": url,
                "waf_name": d.waf_name,
                "confidence": d.confidence,
                "evidence": d.evidence,
                "detected_at": d.detected_at.isoformat()
            }
            for url, d in self._detections.items()
        ]
    
    async def get_statistics(self) -> Dict:
        waf_counts = {}
        for detection in self._detections.values():
            waf_counts[detection.waf_name] = waf_counts.get(detection.waf_name, 0) + 1
        
        return {
            "total_targets": len(self._detections),
            "waf_distribution": waf_counts,
            "supported_wafs": len(self.WAF_PATTERNS)
        }
    
    async def clear_detections(self, target_url: str = None):
        if target_url:
            self._detections.pop(target_url, None)
        else:
            self._detections.clear()
        
        logger.info(f"WAF detections cleared for {target_url if target_url else 'all targets'}")
    
    async def close(self):
        """إغلاق الموارد"""
        self._http_client = None
        logger.info("WAFDetector closed")
