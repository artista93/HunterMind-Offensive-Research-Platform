"""
IDOR Agent Module - وكيل هجمات IDOR المتقدم
"""

from .idor_agent import IDORAgent, get_idor_agent
from .access_pattern_learner import AccessPatternLearner, AccessEvent, AccessPattern
from .object_mapper import ObjectMapper, ObjectMapping
from .privilege_analyzer import PrivilegeAnalyzer, UserPrivilege, PrivilegeEscalationPath, PrivilegeLevel

__all__ = [
    'IDORAgent',
    'get_idor_agent',
    'AccessPatternLearner',
    'AccessEvent',
    'AccessPattern',
    'ObjectMapper',
    'ObjectMapping',
    'PrivilegeAnalyzer',
    'UserPrivilege',
    'PrivilegeEscalationPath',
    'PrivilegeLevel',
]
