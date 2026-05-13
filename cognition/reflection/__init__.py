"""
Reflection Module - نظام التأمل والتحسين الذاتي المتقدم
"""

from .reflection_engine import ReflectionEngine, ReflectionInsight, ReflectionSession
from .behavior_evaluator import BehaviorEvaluator, AgentBehavior, BehaviorMetric, BehaviorStatus
from .failure_analysis import FailureAnalysis, FailureRecord, FailurePattern
from .strategy_reflection import StrategyReflection, StrategyEvaluation
from .success_analysis import SuccessAnalysis, SuccessRecord, SuccessPattern

__all__ = [
    'ReflectionEngine',
    'ReflectionInsight',
    'ReflectionSession',
    'BehaviorEvaluator',
    'AgentBehavior',
    'BehaviorMetric',
    'BehaviorStatus',
    'FailureAnalysis',
    'FailureRecord',
    'FailurePattern',
    'StrategyReflection',
    'StrategyEvaluation',
    'SuccessAnalysis',
    'SuccessRecord',
    'SuccessPattern',
]
