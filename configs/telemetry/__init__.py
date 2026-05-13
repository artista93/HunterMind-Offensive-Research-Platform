import yaml
from pathlib import Path
from typing import Dict, Any

_CONFIG_PATH = Path(__file__).parent / "default.yaml"

with open(_CONFIG_PATH, 'r', encoding='utf-8') as _f:
    _RAW_CONFIG: Dict[str, Any] = yaml.safe_load(_f)

METRICS_CONFIG: Dict[str, Any] = _RAW_CONFIG.get("metrics", {})
TRACING_CONFIG: Dict[str, Any] = _RAW_CONFIG.get("tracing", {})
ANALYTICS_CONFIG: Dict[str, Any] = _RAW_CONFIG.get("analytics", {})
LOGGING_CONFIG: Dict[str, Any] = _RAW_CONFIG.get("logging", {})
TELEMETRY_CONFIG: Dict[str, Any] = _RAW_CONFIG

__all__ = [
    'METRICS_CONFIG',
    'TRACING_CONFIG',
    'ANALYTICS_CONFIG',
    'LOGGING_CONFIG',
    'TELEMETRY_CONFIG',
]
