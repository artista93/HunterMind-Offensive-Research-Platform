"""
Datasets Module - مجلد البيانات والمجموعات التعليمية
"""

from . import attack_payloads
from . import exploit_chains
from . import telemetry_data
from . import testing
from . import training
from . import vulnerable_apps
from . import waf_patterns

# attack_payloads
from .attack_payloads import (
    RCE_PAYLOADS, SQLI_PAYLOADS, XSS_PAYLOADS,
    get_payloads, ALL_PAYLOADS,
)

# exploit_chains
from .exploit_chains import (
    CHAINS_DATA, get_chains, get_chain_by_name, get_chains_by_complexity,
)

# vulnerable_apps
from .vulnerable_apps import (
    APPS_DATA, get_applications, get_app_by_name,
    get_apps_by_vulnerability, get_app_url, get_app_credentials,
)

# waf_patterns
from .waf_patterns import (
    WAF_DATA, get_wafs, get_waf_names, get_waf_patterns,
    detect_waf_by_header, detect_waf_by_cookie, detect_waf_by_response,
)

__all__ = [
    'attack_payloads', 'exploit_chains', 'telemetry_data',
    'testing', 'training', 'vulnerable_apps', 'waf_patterns',
    # Payloads
    'RCE_PAYLOADS', 'SQLI_PAYLOADS', 'XSS_PAYLOADS',
    'get_payloads', 'ALL_PAYLOADS',
    # Chains
    'CHAINS_DATA', 'get_chains', 'get_chain_by_name', 'get_chains_by_complexity',
    # Apps
    'APPS_DATA', 'get_applications', 'get_app_by_name',
    'get_apps_by_vulnerability', 'get_app_url', 'get_app_credentials',
    # WAF
    'WAF_DATA', 'get_wafs', 'get_waf_names', 'get_waf_patterns',
    'detect_waf_by_header', 'detect_waf_by_cookie', 'detect_waf_by_response',
]
