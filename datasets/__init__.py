# datasets/__init__.py

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

# استيراد من attack_payloads
from .attack_payloads import (
    RCE_PAYLOADS,
    SQLI_PAYLOADS,
    XSS_PAYLOADS,
    get_payloads,
    ALL_PAYLOADS,
)

# استيراد من exploit_chains
from .exploit_chains import (
    CHAINS_DATA,
    get_chains,
    get_chain_by_name,
    get_chains_by_complexity,
)

# استيراد من vulnerable_apps
from .vulnerable_apps import (
    APPS_DATA,
    get_applications,
    get_app_by_name,
    get_apps_by_vulnerability,
    get_app_url,
    get_app_credentials,
)

# استيراد من waf_patterns
from .waf_patterns import (
    WAF_DATA,
    get_wafs,
    get_waf_names,
    get_waf_patterns,
    detect_waf_by_header,
    detect_waf_by_cookie,
    detect_waf_by_response,
)

__all__ = [
    'attack_payloads',
    'exploit_chains',
    'telemetry_data',
    'testing',
    'training',
    'vulnerable_apps',
    'waf_patterns',
    # attack_payloads
    'RCE_PAYLOADS',
    'SQLI_PAYLOADS',
    'XSS_PAYLOADS',
    'get_payloads',
    'ALL_PAYLOADS',
    # exploit_chains
    'CHAINS_DATA',
    'get_chains',
    'get_chain_by_name',
    'get_chains_by_complexity',
    # vulnerable_apps
    'APPS_DATA',
    'get_applications',
    'get_app_by_name',
    'get_apps_by_vulnerability',
    'get_app_url',
    'get_app_credentials',
    # waf_patterns
    'WAF_DATA',
    'get_wafs',
    'get_waf_names',
    'get_waf_patterns',
    'detect_waf_by_header',
    'detect_waf_by_cookie',
    'detect_waf_by_response',
]
