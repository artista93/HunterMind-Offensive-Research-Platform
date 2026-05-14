# schemas/__init__.py

"""
Schemas Module - عقود البيانات الموحدة للمنصة
"""

from .vulnerability import (
    Vulnerability, VulnerabilityType, Severity, VerificationStatus, 
    ExploitationStatus, VulnerabilityEvidence, HttpRequest, HttpResponse,
    VulnerabilitySummary, generate_vulnerability_id
)

from .attack_chain import (
    AttackChain, AttackStep, ChainType, ChainStepStatus, Prerequisite, 
    StepOutcome, AttackChainTemplate, COMMON_ATTACK_CHAINS, generate_chain_id
)

from .world_state import (
    WorldState, ScanPhase, TargetStatus, WAFType, AuthLevel, StealthLevel,
    DiscoveredEndpoint, DiscoveredTechnology, ScanStatistics, create_initial_state
)

from .decision import (
    Decision, DecisionType, DecisionSource, DecisionPriority, DecisionStatus,
    ExecutionStrategy, DecisionConfidence, DecisionImpact, DecisionContext,
    DecisionProposal, FusedDecision, CommonDecisions, generate_decision_id
)

from .agent_message import (
    AgentMessage, MessageType, MessagePriority, MessageStatus,
    MessageHeader, MessagePayload,
    ScanCommandPayload, ExploitCommandPayload, VulnerabilityDataPayload,
    AttackChainDataPayload, WorldStateDataPayload, StatusResponsePayload,
    create_message, create_response, serialize_message, deserialize_message
)

from .telemetry import (
    TelemetryData, MetricType, EventSeverity, TraceSpanType,
    MetricPoint, Event, Trace, TraceSpan, PerformanceMetrics,
    ScanMetrics, LearningMetrics,
    create_counter_metric, create_gauge_metric, create_timer_metric,
    create_event, start_trace, start_span
)

from .payload import (
    Payload, PayloadType, PayloadContext, PayloadStatus, BypassLevel,
    PayloadVariation, PayloadLibrary, PayloadExecution,
    create_xss_payload, create_sqli_payload, create_idor_payload,
    XSS_PAYLOADS, SQLI_PAYLOADS, IDOR_PAYLOADS
)

__all__ = [
    # vulnerability
    'Vulnerability', 'VulnerabilityType', 'Severity', 'VerificationStatus',
    'ExploitationStatus', 'VulnerabilityEvidence', 'HttpRequest', 'HttpResponse',
    'VulnerabilitySummary', 'generate_vulnerability_id',
    # attack_chain
    'AttackChain', 'AttackStep', 'ChainType', 'ChainStepStatus', 'Prerequisite',
    'StepOutcome', 'AttackChainTemplate', 'COMMON_ATTACK_CHAINS', 'generate_chain_id',
    # world_state
    'WorldState', 'ScanPhase', 'TargetStatus', 'WAFType', 'AuthLevel', 'StealthLevel',
    'DiscoveredEndpoint', 'DiscoveredTechnology', 'ScanStatistics', 'create_initial_state',
    # decision
    'Decision', 'DecisionType', 'DecisionSource', 'DecisionPriority', 'DecisionStatus',
    'ExecutionStrategy', 'DecisionConfidence', 'DecisionImpact', 'DecisionContext',
    'DecisionProposal', 'FusedDecision', 'CommonDecisions', 'generate_decision_id',
    # agent_message
    'AgentMessage', 'MessageType', 'MessagePriority', 'MessageStatus',
    'MessageHeader', 'MessagePayload', 'ScanCommandPayload', 'ExploitCommandPayload',
    'VulnerabilityDataPayload', 'AttackChainDataPayload', 'WorldStateDataPayload',
    'StatusResponsePayload', 'create_message', 'create_response', 'serialize_message',
    'deserialize_message',
    # telemetry
    'TelemetryData', 'MetricType', 'EventSeverity', 'TraceSpanType',
    'MetricPoint', 'Event', 'Trace', 'TraceSpan', 'PerformanceMetrics',
    'ScanMetrics', 'LearningMetrics', 'create_counter_metric', 'create_gauge_metric',
    'create_timer_metric', 'create_event', 'start_trace', 'start_span',
    # payload
    'Payload', 'PayloadType', 'PayloadContext', 'PayloadStatus', 'BypassLevel',
    'PayloadVariation', 'PayloadLibrary', 'PayloadExecution',
    'create_xss_payload', 'create_sqli_payload', 'create_idor_payload',
    'XSS_PAYLOADS', 'SQLI_PAYLOADS', 'IDOR_PAYLOADS',
]
