"""
Secrets Scanner - كاشف الأسرار والمفاتيح في الكود المصدري

بيكتشف:
- API Keys (AWS, Google, Stripe, GitHub, etc.)
- Private Keys (SSH, PGP)
- Database URLs
- OAuth tokens
- Webhook URLs
- Internal endpoints
"""

import re
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field

import logging

logger = logging.getLogger(__name__)


@dataclass
class Secret:
    """سر مكتشف"""
    type: str
    value: str
    source: str
    line_number: int = 0
    confidence: float = 0.0
    masked_value: str = ""
    
    def __post_init__(self):
        if len(self.value) > 10:
            self.masked_value = self.value[:5] + "..." + self.value[-5:]
        else:
            self.masked_value = "***"


class SecretsScanner:
    """
    كاشف الأسرار الاحترافي
    
    يفحص JavaScript, HTML, JSON, YAML عن:
    - API Keys
    - Access Tokens
    - Private Keys
    - Database URLs
    - Internal URLs
    """
    
    # أنماط الكشف - كل نمط له درجة ثقة
    PATTERNS = {
        "AWS Access Key": {
            "pattern": r'(?:AKIA|ASIA)[A-Z0-9]{16}',
            "confidence": 0.9,
            "severity": "critical"
        },
        "AWS Secret Key": {
            "pattern": r'(?:"|\'|`)?[A-Za-z0-9/+=]{40}(?:"|\'|`)?',
            "confidence": 0.5,  # أقل لأن ممكن يكون حاجة تانية
            "severity": "critical"
        },
        "Google API Key": {
            "pattern": r'AIza[0-9A-Za-z\-_]{35}',
            "confidence": 0.95,
            "severity": "high"
        },
        "GitHub Token": {
            "pattern": r'(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}',
            "confidence": 0.95,
            "severity": "critical"
        },
        "Stripe Secret Key": {
            "pattern": r'sk_live_[0-9a-zA-Z]{24,}',
            "confidence": 0.95,
            "severity": "critical"
        },
        "Stripe Publishable Key": {
            "pattern": r'pk_live_[0-9a-zA-Z]{24,}',
            "confidence": 0.9,
            "severity": "medium"
        },
        "Slack Token": {
            "pattern": r'xox[baprs]-[0-9a-zA-Z\-]{10,}',
            "confidence": 0.9,
            "severity": "high"
        },
        "Generic API Key": {
            "pattern": r'(?:api[_-]?key|apikey)["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{16,})["\']',
            "confidence": 0.8,
            "severity": "high"
        },
        "JWT Token": {
            "pattern": r'eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+',
            "confidence": 0.95,
            "severity": "medium"
        },
        "Private Key (PEM)": {
            "pattern": r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----',
            "confidence": 1.0,
            "severity": "critical"
        },
        "SSH Private Key": {
            "pattern": r'-----BEGIN OPENSSH PRIVATE KEY-----',
            "confidence": 1.0,
            "severity": "critical"
        },
        "Database URL": {
            "pattern": r'(?:mysql|postgres|postgresql|mongodb|redis|sqlite)://[^/\s]+:[^/\s]+@[^/\s]+',
            "confidence": 0.9,
            "severity": "high"
        },
        "Bearer Token": {
            "pattern": r'[Bb]earer\s+([A-Za-z0-9\-\._~\+\/]+=*)',
            "confidence": 0.85,
            "severity": "high"
        },
        "Internal URL": {
            "pattern": r'https?://(?:10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.|127\.0\.0\.1|localhost)[^\s"\']*',
            "confidence": 0.8,
            "severity": "medium"
        },
        "Webhook URL": {
            "pattern": r'https://hooks\.(?:slack|discord|teams)\.com/[^\s"\']+',
            "confidence": 0.9,
            "severity": "medium"
        },
    }
    
    def __init__(self):
        self._found_secrets: List[Secret] = []
    
    def scan(self, content: str, source: str = "unknown") -> List[Secret]:
        """فحص المحتوى عن أسرار"""
        secrets = []
        
        if not content:
            return secrets
        
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            for secret_type, config in self.PATTERNS.items():
                matches = re.finditer(config["pattern"], line)
                for match in matches:
                    value = match.group(0)
                    
                    # تجاهل false positives الشائعة
                    if self._is_false_positive(value, secret_type):
                        continue
                    
                    secret = Secret(
                        type=secret_type,
                        value=value,
                        source=source,
                        line_number=line_num,
                        confidence=config["confidence"],
                    )
                    secrets.append(secret)
                    self._found_secrets.append(secret)
        
        return secrets
    
    def _is_false_positive(self, value: str, secret_type: str) -> bool:
        """فحص إذا كانت القيمة false positive"""
        # تجاهل القيم الواضحة إنها مش أسرار
        false_indicators = [
            "example", "test", "placeholder", "xxx", "TODO",
            "your-", "my-", "sample", "demo", "replace",
            "YOUR_API_KEY", "API_KEY_HERE", "<your",
        ]
        
        value_lower = value.lower()
        
        for indicator in false_indicators:
            if indicator in value_lower:
                return True
        
        # لو القيمة قصيرة جداً
        if len(value) < 8 and secret_type not in ["Generic API Key"]:
            return True
        
        return False
    
    def scan_js_files(self, js_content: str, js_url: str = "") -> List[Secret]:
        """فحص ملفات JavaScript"""
        return self.scan(js_content, f"JS: {js_url}")
    
    def scan_html(self, html: str, page_url: str = "") -> List[Secret]:
        """فحص HTML"""
        secrets = []
        
        # فحص الـ HTML نفسه
        secrets.extend(self.scan(html, f"HTML: {page_url}"))
        
        # استخراج inline JavaScript
        script_pattern = re.compile(r'<script[^>]*>(.*?)</script>', re.DOTALL | re.IGNORECASE)
        for match in script_pattern.finditer(html):
            js_content = match.group(1)
            if js_content.strip():
                secrets.extend(self.scan(js_content, f"Inline JS: {page_url}"))
        
        # استخراج meta tags
        meta_pattern = re.compile(r'<meta[^>]+content=["\']([^"\']+)["\']', re.IGNORECASE)
        for match in meta_pattern.finditer(html):
            content = match.group(1)
            secrets.extend(self.scan(content, f"Meta: {page_url}"))
        
        return secrets
    
    def get_summary(self) -> Dict:
        """ملخص الأسرار المكتشفة"""
        by_type = {}
        by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        
        for secret in self._found_secrets:
            by_type[secret.type] = by_type.get(secret.type, 0) + 1
            
            # استخراج severity من الـ patterns
            for st, config in self.PATTERNS.items():
                if st == secret.type:
                    by_severity[config["severity"]] += 1
                    break
        
        return {
            "total_secrets": len(self._found_secrets),
            "by_type": by_type,
            "by_severity": by_severity,
            "secrets": [
                {"type": s.type, "source": s.source, "masked": s.masked_value, "confidence": s.confidence}
                for s in self._found_secrets[:20]
            ]
        }
    
    def clear(self):
        self._found_secrets.clear()


_secrets_scanner = None

def get_secrets_scanner() -> SecretsScanner:
    global _secrets_scanner
    if _secrets_scanner is None:
        _secrets_scanner = SecretsScanner()
    return _secrets_scanner
