import yaml
from pathlib import Path
from typing import Dict, Any

_CONFIG_PATH = Path(__file__).parent / "default.yaml"

with open(_CONFIG_PATH, 'r', encoding='utf-8') as _f:
    _RAW_CONFIG: Dict[str, Any] = yaml.safe_load(_f)

EXPERIMENTATION_CONFIG: Dict[str, Any] = _RAW_CONFIG.get("experimentation", {})
BENCHMARKING_CONFIG: Dict[str, Any] = _RAW_CONFIG.get("benchmarking", {})
PATTERN_DISCOVERY_CONFIG: Dict[str, Any] = _RAW_CONFIG.get("pattern_discovery", {})
VISUALIZATION_CONFIG: Dict[str, Any] = _RAW_CONFIG.get("visualization", {})
RESEARCH_CONFIG: Dict[str, Any] = _RAW_CONFIG

__all__ = [
    'EXPERIMENTATION_CONFIG',
    'BENCHMARKING_CONFIG',
    'PATTERN_DISCOVERY_CONFIG',
    'VISUALIZATION_CONFIG',
    'RESEARCH_CONFIG',
]
