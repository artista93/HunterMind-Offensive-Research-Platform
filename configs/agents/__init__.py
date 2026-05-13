# configs/agents/__init__.py

"""
Agent Configurations Module - وحدة تكوينات الوكلاء
"""

import yaml
from pathlib import Path
from typing import Dict, Any

# تحميل ملف YAML
_CONFIG_PATH = Path(__file__).parent / "default.yaml"

with open(_CONFIG_PATH, 'r', encoding='utf-8') as _f:
    _RAW_CONFIG: Dict[str, Any] = yaml.safe_load(_f)

# التكوين العام
COMMON_CONFIG: Dict[str, Any] = _RAW_CONFIG.get("common", {})

# تكوينات الوكلاء الفردية
CRAWLER_AGENT_CONFIG: Dict[str, Any] = _RAW_CONFIG.get("crawler_agent", {})
RECON_AGENT_CONFIG: Dict[str, Any] = _RAW_CONFIG.get("recon_agent", {})
XSS_AGENT_CONFIG: Dict[str, Any] = _RAW_CONFIG.get("xss_agent", {})
SQLI_AGENT_CONFIG: Dict[str, Any] = _RAW_CONFIG.get("sqli_agent", {})
IDOR_AGENT_CONFIG: Dict[str, Any] = _RAW_CONFIG.get("idor_agent", {})
WAF_AGENT_CONFIG: Dict[str, Any] = _RAW_CONFIG.get("waf_agent", {})
AUTH_AGENT_CONFIG: Dict[str, Any] = _RAW_CONFIG.get("auth_agent", {})
EXPLOITATION_AGENT_CONFIG: Dict[str, Any] = _RAW_CONFIG.get("exploitation_agent", {})
LEARNING_AGENT_CONFIG: Dict[str, Any] = _RAW_CONFIG.get("learning_agent", {})
REASONING_AGENT_CONFIG: Dict[str, Any] = _RAW_CONFIG.get("reasoning_agent", {})
PLANNING_AGENT_CONFIG: Dict[str, Any] = _RAW_CONFIG.get("planning_agent", {})

# التكوين الكامل
AGENTS_CONFIG: Dict[str, Any] = _RAW_CONFIG

__all__ = [
    'COMMON_CONFIG',
    'CRAWLER_AGENT_CONFIG',
    'RECON_AGENT_CONFIG',
    'XSS_AGENT_CONFIG',
    'SQLI_AGENT_CONFIG',
    'IDOR_AGENT_CONFIG',
    'WAF_AGENT_CONFIG',
    'AUTH_AGENT_CONFIG',
    'EXPLOITATION_AGENT_CONFIG',
    'LEARNING_AGENT_CONFIG',
    'REASONING_AGENT_CONFIG',
    'PLANNING_AGENT_CONFIG',
    'AGENTS_CONFIG',
]
