# configs/__init__.py

"""
Configs Module - مجلد الإعدادات والتكوين الرئيسي
"""

from . import agents
from . import cognition
from . import infrastructure
from . import learning
from . import offensive
from . import research
from . import sandbox
from . import telemetry

# استيراد التكوينات من المجلدات الفرعية
from .agents import AGENTS_CONFIG
from .cognition import COGNITION_CONFIG
from .infrastructure import INFRASTRUCTURE_CONFIG
from .learning import LEARNING_CONFIG
from .offensive import OFFENSIVE_CONFIG
from .research import RESEARCH_CONFIG
from .sandbox import SANDBOX_CONFIG
from .telemetry import TELEMETRY_CONFIG

__all__ = [
    'agents',
    'cognition',
    'infrastructure',
    'learning',
    'offensive',
    'research',
    'sandbox',
    'telemetry',
    'AGENTS_CONFIG',
    'COGNITION_CONFIG',
    'INFRASTRUCTURE_CONFIG',
    'LEARNING_CONFIG',
    'OFFENSIVE_CONFIG',
    'RESEARCH_CONFIG',
    'SANDBOX_CONFIG',
    'TELEMETRY_CONFIG',
]
