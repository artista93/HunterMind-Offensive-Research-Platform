
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime

import logging

logger = logging.getLogger(__name__)


@dataclass
class WAFInfo:
    """معلومات WAF"""
    name: str
    type: str  # cloudflare, aws, modsecurity, etc.
    detected_at: datetime
    confidence: float = 0.8
    bypass_techniques: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AuthInfo:
    """معلومات المصادقة"""
    type: str  # basic, bearer, jwt, session
    required: bool
    endpoints: List[str] = field(default_factory=list)
    weaknesses: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class RateLimitInfo:
    """معلومات تحديد المعدل"""
    enabled: bool
    limit: Optional[int] = None
    window_seconds: Optional[int] = None
    endpoints: List[str] = field(default_factory=list)


class DefenseModel:
    """
    نموذج الدفاع المتقدم
    
    الميزات:
    - تخزين معلومات WAF
    - تخزين معلومات المصادقة
    - تخزين معلومات تحديد المعدل
    - تحليل نقاط الضعف في الدفاعات
    """
    
    def __init__(self):
        self._waf: Optional[WAFInfo] = None
        self._auth: Optional[AuthInfo] = None
        self._rate_limit: Optional[RateLimitInfo] = None
        self._headers: Dict[str, str] = {}
        self._cookies: Dict[str, str] = {}
        self._metadata: Dict[str, Any] = {}
        
        self.created_at = datetime.now()
        self.updated_at = datetime.now()
        
        logger.info("DefenseModel initialized")
    
    async def set_waf(
        self,
        name: str,
        waf_type: str,
        confidence: float = 0.8,
        bypass_techniques: List[str] = None,
        metadata: Dict = None
    ):
        """تعيين معلومات WAF"""
        self._waf = WAFInfo(
            name=name,
            type=waf_type,
            detected_at=datetime.now(),
            confidence=confidence,
            bypass_techniques=bypass_techniques or [],
            metadata=metadata or {}
        )
        self.updated_at = datetime.now()
        
        logger.info(f"WAF set: {name} ({waf_type})")
    
    async def set_auth(
        self,
        auth_type: str,
        required: bool = True,
        endpoints: List[str] = None,
        weaknesses: List[str] = None,
        metadata: Dict = None
    ):
        """تعيين معلومات المصادقة"""
        self._auth = AuthInfo(
            type=auth_type,
            required=required,
            endpoints=endpoints or [],
            weaknesses=weaknesses or [],
            metadata=metadata or {}
        )
        self.updated_at = datetime.now()
        
        logger.info(f"Auth set: {auth_type} (required={required})")
    
    async def set_rate_limit(
        self,
        enabled: bool,
        limit: int = None,
        window_seconds: int = None,
        endpoints: List[str] = None
    ):
        """تعيين معلومات تحديد المعدل"""
        self._rate_limit = RateLimitInfo(
            enabled=enabled,
            limit=limit,
            window_seconds=window_seconds,
            endpoints=endpoints or []
        )
        self.updated_at = datetime.now()
        
        logger.info(f"Rate limit set: enabled={enabled}")
    
    async def add_header(self, name: str, value: str):
        """إضافة هيدر"""
        self._headers[name] = value
        self.updated_at = datetime.now()
    
    async def add_cookie(self, name: str, value: str):
        """إضافة كوكي"""
        self._cookies[name] = value
        self.updated_at = datetime.now()
    
    async def has_waf(self) -> bool:
        """هل يوجد WAF؟"""
        return self._waf is not None
    
    async def get_waf(self) -> Optional[WAFInfo]:
        """الحصول على معلومات WAF"""
        return self._waf
    
    async def get_auth(self) -> Optional[AuthInfo]:
        """الحصول على معلومات المصادقة"""
        return self._auth
    
    async def get_rate_limit(self) -> Optional[RateLimitInfo]:
        """الحصول على معلومات تحديد المعدل"""
        return self._rate_limit
    
    async def get_headers(self) -> Dict[str, str]:
        """الحصول على جميع الهيدرات"""
        return self._headers
    
    async def get_cookies(self) -> Dict[str, str]:
        """الحصول على جميع الكوكيز"""
        return self._cookies
    
    async def get_bypass_recommendations(self) -> List[str]:
        """الحصول على توصيات لتجاوز الدفاعات"""
        recommendations = []
        
        if self._waf:
            recommendations.append(f"WAF detected: {self._waf.name}")
            recommendations.append("Try encoding techniques: URL, double URL, Unicode")
            recommendations.append("Use case swapping and comment insertion")
            if self._waf.bypass_techniques:
                recommendations.extend(self._waf.bypass_techniques)
        
        if self._auth and self._auth.required:
            recommendations.append(f"Authentication required: {self._auth.type}")
            if "weak_password" in self._auth.weaknesses:
                recommendations.append("Try weak password attacks")
            if "no_mfa" in self._auth.weaknesses:
                recommendations.append("MFA not detected - brute force possible")
        
        if self._rate_limit and self._rate_limit.enabled:
            recommendations.append(f"Rate limiting detected: {self._rate_limit.limit} requests per {self._rate_limit.window_seconds}s")
            recommendations.append("Use distributed attacks or slow down request rate")
        
        return recommendations
    
    async def get_defense_score(self) -> float:
        """
        حساب درجة قوة الدفاع
        
        Returns:
            درجة الدفاع (0-100، كلما زادت كلما كان الدفاع أقوى)
        """
        score = 0.0
        
        # WAF
        if self._waf:
            score += self._waf.confidence * 30
        
        # المصادقة
        if self._auth:
            if self._auth.required:
                score += 20
            if "no_mfa" not in self._auth.weaknesses:
                score += 10
        
        # تحديد المعدل
        if self._rate_limit and self._rate_limit.enabled:
            score += 15
        
        # الهيدرات الأمنية
        security_headers = ["X-Frame-Options", "X-Content-Type-Options", "Content-Security-Policy"]
        for header in security_headers:
            if header in self._headers:
                score += 5
        
        return min(score, 100.0)
    
    async def get_summary(self) -> Dict:
        """ملخص الدفاعات"""
        return {
            "has_waf": self._waf is not None,
            "waf_name": self._waf.name if self._waf else None,
            "waf_confidence": self._waf.confidence if self._waf else 0,
            "auth_required": self._auth.required if self._auth else False,
            "auth_type": self._auth.type if self._auth else None,
            "rate_limiting_enabled": self._rate_limit.enabled if self._rate_limit else False,
            "security_headers_count": sum(1 for h in self._headers if h in ["X-Frame-Options", "X-Content-Type-Options", "Content-Security-Policy"]),
            "defense_score": await self.get_defense_score(),
            "bypass_recommendations": await self.get_bypass_recommendations()
        }
    
    async def export(self) -> Dict:
        """تصدير النموذج إلى قاموس"""
        return {
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "waf": {
                "name": self._waf.name,
                "type": self._waf.type,
                "detected_at": self._waf.detected_at.isoformat(),
                "confidence": self._waf.confidence,
                "bypass_techniques": self._waf.bypass_techniques,
                "metadata": self._waf.metadata
            } if self._waf else None,
            "auth": {
                "type": self._auth.type,
                "required": self._auth.required,
                "endpoints": self._auth.endpoints,
                "weaknesses": self._auth.weaknesses,
                "metadata": self._auth.metadata
            } if self._auth else None,
            "rate_limit": {
                "enabled": self._rate_limit.enabled,
                "limit": self._rate_limit.limit,
                "window_seconds": self._rate_limit.window_seconds,
                "endpoints": self._rate_limit.endpoints
            } if self._rate_limit else None,
            "headers": self._headers,
            "cookies": self._cookies,
            "metadata": self._metadata
        }

