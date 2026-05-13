# configs/cognition/__init__.py

"""
Cognition Configurations Module - وحدة تكوينات نظام المعرفة والتفكير
"""

import yaml
from pathlib import Path
from typing import Dict, Any

# تحميل ملف YAML
_CONFIG_PATH = Path(__file__).parent / "default.yaml"

with open(_CONFIG_PATH, 'r', encoding='utf-8') as _f:
    _RAW_CONFIG: Dict[str, Any] = yaml.safe_load(_f)

# تكوينات العقل (Brain)
BRAIN_CONFIG: Dict[str, Any] = _RAW_CONFIG.get("brain", {})

# تكوينات الذاكرة (Memory)
MEMORY_CONFIG: Dict[str, Any] = _RAW_CONFIG.get("memory", {})
EPISODIC_MEMORY_CONFIG: Dict[str, Any] = MEMORY_CONFIG.get("episodic", {})
SEMANTIC_MEMORY_CONFIG: Dict[str, Any] = MEMORY_CONFIG.get("semantic", {})
WORKING_MEMORY_CONFIG: Dict[str, Any] = MEMORY_CONFIG.get("working", {})
PROCEDURAL_MEMORY_CONFIG: Dict[str, Any] = MEMORY_CONFIG.get("procedural", {})

# تكوينات المعرفة (Knowledge)
KNOWLEDGE_CONFIG: Dict[str, Any] = _RAW_CONFIG.get("knowledge", {})

# تكوينات التفكير (Reasoning)
REASONING_CONFIG: Dict[str, Any] = _RAW_CONFIG.get("reasoning", {})

# تكوينات التخطيط (Planning)
PLANNING_CONFIG: Dict[str, Any] = _RAW_CONFIG.get("planning", {})

# تكوينات التأمل (Reflection)
REFLECTION_CONFIG: Dict[str, Any] = _RAW_CONFIG.get("reflection", {})

# تكوينات التحسين الذاتي (Self Improvement)
SELF_IMPROVEMENT_CONFIG: Dict[str, Any] = _RAW_CONFIG.get("self_improvement", {})

# التكوين الكامل
COGNITION_CONFIG: Dict[str, Any] = _RAW_CONFIG

__all__ = [
    'BRAIN_CONFIG',
    'MEMORY_CONFIG',
    'EPISODIC_MEMORY_CONFIG',
    'SEMANTIC_MEMORY_CONFIG',
    'WORKING_MEMORY_CONFIG',
    'PROCEDURAL_MEMORY_CONFIG',
    'KNOWLEDGE_CONFIG',
    'REASONING_CONFIG',
    'PLANNING_CONFIG',
    'REFLECTION_CONFIG',
    'SELF_IMPROVEMENT_CONFIG',
    'COGNITION_CONFIG',
]
