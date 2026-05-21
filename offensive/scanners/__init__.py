# offensive/scanners/__init__.py

"""
Scanners Module - فاحصات الثغرات
"""

from .base_scanner import BaseScanner, ScanContext, ScanTarget, Finding, Severity, Confidence, ScannerSeverity, ScannerConfidence
from .xss_scanner import XSSScanner, XSSPayload
from .sqli_scanner import SQLiScanner, SQLiPayload
from .idor_scanner import IDORScanner, IDORPattern
from .csrf_scanner import CSRFScanner, CSRFTokenInfo
from .ssrf_scanner import SSRFScanner, SSRFTest
from .rce_scanner import RCEScanner, RCEPayload
from .auth_scanner import AuthScanner, TokenInfo
from .graphql_scanner import GraphQLScanner, GraphQLQuery
from .api_scanner import APIScanner, APITest

# أدوات متقدمة
from .jwt_analyzer import JWTAnalyzer, get_jwt_analyzer
from .context_aware_scanner import ContextAwareScanner, VerifiedFinding, get_context_aware_scanner
from .ai_scanner import AIScanner, AIPayloadSelector, get_ai_payload_selector
from .browser_scanner import BrowserScanner, get_browser_scanner

# المحولات
from .adapters import (
    ScannerAdapter,
    PayloadAdapter,
    ConfigLoader,
    quick_convert,
    batch_convert,
)

# مدير الحمولات
from .payload_integration import (
    PayloadManager,
    PayloadTestResult,
    PayloadEvolutionStrategy,
    get_payload_manager,
)

__all__ = [
    # Base
    'BaseScanner',
    'ScanContext',
    'ScanTarget',
    'Finding',
    'Severity',
    'Confidence',
    'ScannerSeverity',
    'ScannerConfidence',
    
    # Scanners
    'XSSScanner',
    'XSSPayload',
    'SQLiScanner',
    'SQLiPayload',
    'IDORScanner',
    'IDORPattern',
    'CSRFScanner',
    'CSRFTokenInfo',
    'SSRFScanner',
    'SSRFTest',
    'RCEScanner',
    'RCEPayload',
    'AuthScanner',
    'TokenInfo',
    'GraphQLScanner',
    'GraphQLQuery',
    'APIScanner',
    'APITest',
    
    # Advanced Scanners
    'JWTAnalyzer',
    'get_jwt_analyzer',
    'ContextAwareScanner',
    'VerifiedFinding',
    'get_context_aware_scanner',
    'AIScanner',
    'AIPayloadSelector',
    'get_ai_payload_selector',
    'BrowserScanner',
    'get_browser_scanner',
    
    # Adapters
    'ScannerAdapter',
    'PayloadAdapter',
    'ConfigLoader',
    'quick_convert',
    'batch_convert',
    
    # Payload Manager
    'PayloadManager',
    'PayloadTestResult',
    'PayloadEvolutionStrategy',
    'get_payload_manager',
]
