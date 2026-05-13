"""
WAF Agent Module - وكلاء كشف وتجاوز جدران الحماية
"""

from .waf_agent import WAFAgent, get_waf_agent
from .waf_detector import WAFDetector, WAFDetection
from .adaptive_evasion import AdaptiveEvasion, EvasionState, EvasionAttempt, TechniqueStats
from .bypass_generator import BypassGenerator, BypassTechnique, BypassResult
from .payload_obfuscator import PayloadObfuscator, ObfuscationMethod, ObfuscatedPayload
from .response_classifier import ResponseClassifier, BlockReason, BlockSeverity, WAFResponse

__all__ = [
    'WAFAgent',
    'get_waf_agent',
    'WAFDetector',
    'WAFDetection',
    'AdaptiveEvasion',
    'EvasionState',
    'EvasionAttempt',
    'TechniqueStats',
    'BypassGenerator',
    'BypassTechnique',
    'BypassResult',
    'PayloadObfuscator',
    'ObfuscationMethod',
    'ObfuscatedPayload',
    'ResponseClassifier',
    'BlockReason',
    'BlockSeverity',
    'WAFResponse',
]
