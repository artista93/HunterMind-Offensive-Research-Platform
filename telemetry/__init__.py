# telemetry/__init__.py

"""
Telemetry Module - طبقة المراقبة والقياس
"""

from . import metrics
from . import tracing
from . import analytics
from . import logging

# استيراد من metrics
from .metrics import (
    MetricsEngine, Metric, MetricType,
    SystemMetrics, SystemRecord,
    AttackMetrics, AttackRecord,
    LearningMetrics, LearningRecord,
    get_metrics_engine, get_system_metrics,
    get_attack_metrics, get_learning_metrics,
)

# استيراد من tracing
from .tracing import (
    ExecutionTracer, Trace, Span,
    DecisionTracer, DecisionTrace, DecisionNode,
    LearningTracer, LearningTrace, LearningEvent,
    AttackTracer, AttackTrace, AttackStep,
    get_execution_tracer, get_decision_tracer,
    get_learning_tracer, get_attack_tracer,
)

# استيراد من analytics
from .analytics import (
    PerformanceAnalytics, PerformanceReport,
    StrategyAnalytics, StrategyPerformance,
    TrendAnalysis, TrendResult,
    VulnerabilityAnalytics, VulnerabilityPattern,
    get_performance_analytics, get_strategy_analytics,
    get_trend_analysis, get_vulnerability_analytics,
)

# استيراد من logging
from .logging import (
    AuditLogger, AuditAction, AuditSeverity,
    DebugLogger, EventLogger, Event, EventType,
    StructuredLogger, LogLevel,
    get_audit_logger, get_debug_logger,
    get_event_logger, get_structured_logger,
)

__all__ = [
    'metrics',
    'tracing',
    'analytics',
    'logging',
    # metrics
    'MetricsEngine', 'Metric', 'MetricType',
    'SystemMetrics', 'SystemRecord',
    'AttackMetrics', 'AttackRecord',
    'LearningMetrics', 'LearningRecord',
    'get_metrics_engine', 'get_system_metrics',
    'get_attack_metrics', 'get_learning_metrics',
    # tracing
    'ExecutionTracer', 'Trace', 'Span',
    'DecisionTracer', 'DecisionTrace', 'DecisionNode',
    'LearningTracer', 'LearningTrace', 'LearningEvent',
    'AttackTracer', 'AttackTrace', 'AttackStep',
    'get_execution_tracer', 'get_decision_tracer',
    'get_learning_tracer', 'get_attack_tracer',
    # analytics
    'PerformanceAnalytics', 'PerformanceReport',
    'StrategyAnalytics', 'StrategyPerformance',
    'TrendAnalysis', 'TrendResult',
    'VulnerabilityAnalytics', 'VulnerabilityPattern',
    'get_performance_analytics', 'get_strategy_analytics',
    'get_trend_analysis', 'get_vulnerability_analytics',
    # logging
    'AuditLogger', 'AuditAction', 'AuditSeverity',
    'DebugLogger', 'EventLogger', 'Event', 'EventType',
    'StructuredLogger', 'LogLevel',
    'get_audit_logger', 'get_debug_logger',
    'get_event_logger', 'get_structured_logger',
]
