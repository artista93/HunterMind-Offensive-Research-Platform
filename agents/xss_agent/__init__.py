"""
XSS Agent Module - وكيل هجمات XSS المتقدم
"""

from .xss_agent import XSSAgent, get_xss_agent
from .xss_validator import XSSValidator, ValidationResult, ValidationDetails
from .context_analyzer import ContextAnalyzer, ExecutionContext, ContextAnalysisResult
from .sink_detector import SinkDetector, SinkType, DetectedSink

__all__ = [
    'XSSAgent',
    'get_xss_agent',
    'XSSValidator',
    'ValidationResult',
    'ValidationDetails',
    'ContextAnalyzer',
    'ExecutionContext',
    'ContextAnalysisResult',
    'SinkDetector',
    'SinkType',
    'DetectedSink',
]
