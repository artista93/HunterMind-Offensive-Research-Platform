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
