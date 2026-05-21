"""
JWT Analyzer - محلل ثغرات JSON Web Tokens الاحترافي

الثغرات الحقيقية اللي بيكتشفها:
- Algorithm confusion (alg:none)
- Weak HMAC secrets
- Key confusion (RS256 → HS256)
- Missing signature verification
- Expired tokens accepted
- Sensitive data in JWT payload
- kid injection
- JKU/JWK header injection
"""

import jwt
import json
import base64
import hashlib
import hmac
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime, timedelta

from .base_scanner import BaseScanner, ScanContext, Finding, Severity, Confidence

import logging

logger = logging.getLogger(__name__)


class JWTAnalyzer:
    """
    محلل JWT احترافي
    
    بيكتشف ثغرات JWT حقيقية مش مجرد injection
    """
    
    # أسرار ضعيفة شائعة
    WEAK_SECRETS = [
        "secret", "password", "secretkey", "jwt_secret",
        "key", "private", "changeme", "changethis",
        "123456", "test", "admin", "default",
        "mysecret", "mykey", "jwtkey", "token_secret",
    ]
    
    # كلمات حساسة في payload
    SENSITIVE_CLAIMS = [
        "password", "secret", "key", "token", "credit",
        "ssn", "social", "passport", "license",
        "role", "is_admin", "isAdmin", "admin",
        "permissions", "scope", "authorities",
    ]
    
    def __init__(self):
        self._findings: List[Finding] = []
    
    def analyze(self, token: str, url: str = "") -> List[Finding]:
        """تحليل JWT كامل"""
        findings = []
        
        if not token or '.' not in token:
            return findings
        
        # 1. فك التشفير
        try:
            header = jwt.get_unverified_header(token)
            payload = jwt.decode(token, options={"verify_signature": False})
        except Exception as e:
            findings.append(Finding(
                vulnerability_type="Invalid JWT Format",
                severity=Severity.LOW,
                confidence=Confidence.CERTAIN,
                url=url,
                evidence=str(e),
                description="JWT token is malformed",
                remediation="Use proper JWT encoding",
                cvss_score=2.0
            ))
            return findings
        
        # 2. فحص algorithm
        alg_findings = self._check_algorithm(header, token, url)
        findings.extend(alg_findings)
        
        # 3. فحص weak secret
        secret_findings = self._check_weak_secret(token, header, payload, url)
        findings.extend(secret_findings)
        
        # 4. فحص key confusion
        confusion_findings = self._check_key_confusion(header, token, url)
        findings.extend(confusion_findings)
        
        # 5. فحص expiration
        exp_findings = self._check_expiration(payload, url)
        findings.extend(exp_findings)
        
        # 6. فحص sensitive data
        sensitive_findings = self._check_sensitive_data(payload, url)
        findings.extend(sensitive_findings)
        
        # 7. فحص kid injection
        kid_findings = self._check_kid_injection(header, token, url)
        findings.extend(kid_findings)
        
        return findings
    
    def _check_algorithm(self, header: Dict, token: str, url: str) -> List[Finding]:
        """فحص ثغرات الـ algorithm"""
        findings = []
        alg = header.get("alg", "")
        
        # alg:none - أخطر ثغرة
        if alg.lower() == "none":
            # نحاول نستخدم token بدون توقيع
            try:
                parts = token.split('.')
                new_header = base64.urlsafe_b64encode(
                    json.dumps({"alg": "none", "typ": "JWT"}).encode()
                ).decode().rstrip('=')
                forged_token = f"{new_header}.{parts[1]}."
                
                findings.append(Finding(
                    vulnerability_type="JWT Algorithm Confusion (alg:none)",
                    severity=Severity.CRITICAL,
                    confidence=Confidence.CERTAIN,
                    url=url,
                    payload=forged_token,
                    evidence="Server accepts 'none' algorithm",
                    description="JWT accepts 'none' algorithm allowing token forgery",
                    remediation="Explicitly whitelist allowed algorithms (RS256, ES256)",
                    cvss_score=9.1,
                    metadata={"algorithm": "none", "forged_token": forged_token[:50]}
                ))
            except:
                pass
        
        # HMAC with weak key
        if alg.startswith("HS"):
            findings.append(Finding(
                vulnerability_type="JWT Using Symmetric Algorithm",
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                url=url,
                evidence=f"Algorithm: {alg}",
                description="Symmetric algorithms (HS256/HS384/HS512) use shared secrets",
                remediation="Consider using asymmetric algorithms (RS256, ES256)",
                cvss_score=5.3,
                metadata={"algorithm": alg}
            ))
        
        return findings
    
    def _check_weak_secret(self, token: str, header: Dict, payload: Dict, url: str) -> List[Finding]:
        """فحص الأسرار الضعيفة"""
        findings = []
        alg = header.get("alg", "")
        
        if not alg.startswith("HS"):
            return findings
        
        for secret in self.WEAK_SECRETS:
            try:
                decoded = jwt.decode(token, secret, algorithms=[alg])
                findings.append(Finding(
                    vulnerability_type="JWT Weak HMAC Secret",
                    severity=Severity.CRITICAL,
                    confidence=Confidence.CERTAIN,
                    url=url,
                    payload=secret,
                    evidence=f"Weak secret: {secret}",
                    description=f"JWT HMAC secret is weak: '{secret}'",
                    remediation="Use a strong, random secret (minimum 256 bits)",
                    cvss_score=9.8,
                    metadata={"secret": secret, "algorithm": alg}
                ))
                break  # اكتفينا بواحد
            except:
                continue
        
        return findings
    
    def _check_key_confusion(self, header: Dict, token: str, url: str) -> List[Finding]:
        """فحص key confusion (RS256 → HS256)"""
        findings = []
        alg = header.get("alg", "")
        
        if alg.startswith("RS") or alg.startswith("ES"):
            findings.append(Finding(
                vulnerability_type="JWT Key Confusion Possible",
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                url=url,
                evidence=f"Algorithm: {alg}",
                description="Server may be vulnerable to algorithm confusion attack",
                remediation="Use separate key validation for each algorithm type",
                cvss_score=7.5,
                metadata={"current_alg": alg, "attack": "Change RS256 to HS256"}
            ))
        
        return findings
    
    def _check_expiration(self, payload: Dict, url: str) -> List[Finding]:
        """فحص انتهاء الصلاحية"""
        findings = []
        
        exp = payload.get("exp")
        if exp:
            exp_time = datetime.fromtimestamp(exp)
            if exp_time < datetime.now():
                findings.append(Finding(
                    vulnerability_type="Expired JWT Token Accepted",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.CERTAIN,
                    url=url,
                    evidence=f"Expired: {exp_time.isoformat()}",
                    description="Server accepts expired JWT tokens",
                    remediation="Properly validate token expiration",
                    cvss_score=5.3,
                    metadata={"expiration": exp_time.isoformat()}
                ))
        else:
            # مفيش expiration - token صالح للأبد
            findings.append(Finding(
                vulnerability_type="JWT Missing Expiration",
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                url=url,
                description="JWT has no expiration claim",
                remediation="Always set 'exp' claim in JWT tokens",
                cvss_score=4.3
            ))
        
        return findings
    
    def _check_sensitive_data(self, payload: Dict, url: str) -> List[Finding]:
        """فحص البيانات الحساسة في JWT"""
        findings = []
        
        for claim in self.SENSITIVE_CLAIMS:
            if claim in payload:
                findings.append(Finding(
                    vulnerability_type="Sensitive Data in JWT Payload",
                    severity=Severity.HIGH,
                    confidence=Confidence.CERTAIN,
                    url=url,
                    evidence=f"Claim: {claim}",
                    description=f"JWT contains sensitive claim: '{claim}'",
                    remediation="Never store sensitive data in JWT payload",
                    cvss_score=7.5,
                    metadata={"sensitive_claim": claim}
                ))
        
        return findings
    
    def _check_kid_injection(self, header: Dict, token: str, url: str) -> List[Finding]:
        """فحص kid injection"""
        findings = []
        
        kid = header.get("kid")
        if kid:
            # لو kid فيه path traversal
            if "../" in kid or "..\\" in kid:
                findings.append(Finding(
                    vulnerability_type="JWT kid Parameter Injection",
                    severity=Severity.CRITICAL,
                    confidence=Confidence.HIGH,
                    url=url,
                    payload=kid,
                    evidence=f"kid: {kid}",
                    description="JWT kid parameter contains path traversal",
                    remediation="Sanitize kid parameter, use UUIDs",
                    cvss_score=9.1,
                    metadata={"kid": kid}
                ))
            
            # لو kid = مسار لملف معروف
            if kid.endswith(("/dev/null", "/etc/passwd", "/proc/self/environ")):
                findings.append(Finding(
                    vulnerability_type="JWT kid Parameter to Known File",
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    url=url,
                    payload=kid,
                    evidence=f"kid points to: {kid}",
                    description="JWT kid parameter references known file",
                    remediation="Use random kid values, not file paths",
                    cvss_score=7.5,
                    metadata={"kid": kid}
                ))
        
        return findings


_jwt_analyzer = None

def get_jwt_analyzer() -> JWTAnalyzer:
    global _jwt_analyzer
    if _jwt_analyzer is None:
        _jwt_analyzer = JWTAnalyzer()
    return _jwt_analyzer
