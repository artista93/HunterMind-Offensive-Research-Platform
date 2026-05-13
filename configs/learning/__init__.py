# configs/learning/__init__.py

"""
Learning Configurations Module - وحدة تكوينات التعلم
"""

import yaml
from pathlib import Path
from typing import Dict, Any

# تحميل ملف YAML
_CONFIG_PATH = Path(__file__).parent / "default.yaml"

with open(_CONFIG_PATH, 'r', encoding='utf-8') as _f:
    _RAW_CONFIG: Dict[str, Any] = yaml.safe_load(_f)

# تكوينات التعلم الفوقي (Meta Learning)
META_LEARNING_CONFIG: Dict[str, Any] = _RAW_CONFIG.get("meta_learning", {})

# تكوينات التعلم المعزز (Reinforcement Learning)
REINFORCEMENT_CONFIG: Dict[str, Any] = _RAW_CONFIG.get("reinforcement", {})
DQN_CONFIG: Dict[str, Any] = REINFORCEMENT_CONFIG.get("dqn", {})
PPO_CONFIG: Dict[str, Any] = REINFORCEMENT_CONFIG.get("ppo", {})
ACTOR_CRITIC_CONFIG: Dict[str, Any] = REINFORCEMENT_CONFIG.get("actor_critic", {})

# تكوينات تعلم التسلسلات (Sequence Learning)
SEQUENCE_LEARNING_CONFIG: Dict[str, Any] = _RAW_CONFIG.get("sequence_learning", {})

# تكوينات التعلم عبر الإنترنت (Online Learning)
ONLINE_LEARNING_CONFIG: Dict[str, Any] = _RAW_CONFIG.get("online_learning", {})

# التكوين الكامل
LEARNING_CONFIG: Dict[str, Any] = _RAW_CONFIG

__all__ = [
    'META_LEARNING_CONFIG',
    'REINFORCEMENT_CONFIG',
    'DQN_CONFIG',
    'PPO_CONFIG',
    'ACTOR_CRITIC_CONFIG',
    'SEQUENCE_LEARNING_CONFIG',
    'ONLINE_LEARNING_CONFIG',
    'LEARNING_CONFIG',
]
