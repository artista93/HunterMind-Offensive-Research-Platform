import yaml
from pathlib import Path
from typing import Dict, Any

_CONFIG_PATH = Path(__file__).parent / "default.yaml"

with open(_CONFIG_PATH, 'r', encoding='utf-8') as _f:
    _RAW_CONFIG: Dict[str, Any] = yaml.safe_load(_f)

DOCKER_CONFIG: Dict[str, Any] = _RAW_CONFIG.get("docker", {})
ISOLATION_CONFIG: Dict[str, Any] = _RAW_CONFIG.get("isolation", {})
TARGET_EMULATOR_CONFIG: Dict[str, Any] = _RAW_CONFIG.get("target_emulator", {})
LAB_ENVIRONMENT_CONFIG: Dict[str, Any] = _RAW_CONFIG.get("lab_environment", {})
SANDBOX_CONFIG: Dict[str, Any] = _RAW_CONFIG

__all__ = [
    'DOCKER_CONFIG',
    'ISOLATION_CONFIG',
    'TARGET_EMULATOR_CONFIG',
    'LAB_ENVIRONMENT_CONFIG',
    'SANDBOX_CONFIG',
]
