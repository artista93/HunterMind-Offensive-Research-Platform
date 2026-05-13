import yaml
from pathlib import Path
from typing import Dict, Any

_CONFIG_PATH = Path(__file__).parent / "default.yaml"

with open(_CONFIG_PATH, 'r', encoding='utf-8') as _f:
    _RAW_CONFIG: Dict[str, Any] = yaml.safe_load(_f)

BROWSER_CONFIG: Dict[str, Any] = _RAW_CONFIG.get("browser", {})
NETWORKING_CONFIG: Dict[str, Any] = _RAW_CONFIG.get("networking", {})
PROXY_CONFIG: Dict[str, Any] = NETWORKING_CONFIG.get("proxy", {})
AUTH_CONFIG: Dict[str, Any] = _RAW_CONFIG.get("auth", {})
RUNTIME_CONFIG: Dict[str, Any] = _RAW_CONFIG.get("runtime", {})
INFRASTRUCTURE_CONFIG: Dict[str, Any] = _RAW_CONFIG

__all__ = [
    'BROWSER_CONFIG',
    'NETWORKING_CONFIG',
    'PROXY_CONFIG',
    'AUTH_CONFIG',
    'RUNTIME_CONFIG',
    'INFRASTRUCTURE_CONFIG',
]
