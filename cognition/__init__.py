"""
Cognition Layer - طبقة المعرفة والتفكير
"""

from .brain import (
    CognitiveCore, CognitiveState, get_cognitive_core,
    AttentionManager, BrainLoop, ContextIntegrator,
    DecisionEngine, DecisionFusion, PolicyRouter, RLPolicy
)
from .knowledge import (
    KnowledgeGraph, KGNode, KGEdge,
    AttackGraph, AttackPath,
    AttackSurfaceModel, EntryPoint, AttackVector,
    DefenseModel, WAFInfo, AuthInfo, RateLimitInfo,
    TargetModel, ServiceInfo, TechnologyInfo, EndpointInfo
)
from .memory import (
    EpisodicMemory, Episode,
    SemanticMemory, Concept,
    WorkingMemory, WorkingMemoryItem,
    ProceduralMemory, Procedure,
    VectorMemory, VectorItem,
    AttackMemory, AttackRecord, AttackPattern,
    MemoryConsolidation, ConsolidationStats,
    MemoryRetriever, MemoryQuery, MemoryResult
)
from .reasoning import (
    AttackReasoner, AttackChain, AttackStep,
    AttackPathReasoner, AttackNode, AttackPath,
    CausalReasoner, CausalLink, CausalChain,
    ChainReasoner, ChainEvent, LogicChain,
    GraphReasoner, GraphNode, GraphEdge, GraphPattern,
    MultiStepReasoner, ReasoningStep, ReasoningChain, ReasoningStepType,
    SymbolicReasoner, Fact, Rule,
    UncertaintyReasoner, UncertainFact, Belief
)
from .planning import (
    ExecutionPlanner, ExecutionPlan, ExecutionStep, ExecutionStatus,
    StrategicPlanner, StrategicPlan, StrategicObjective, StrategicGoal,
    TacticalPlanner, TacticalPlan, TacticalAction,
    WorldState, WorldAttribute,
    GoalManager, Goal, SubGoal, GoalStatus, GoalPriority,
    RiskEngine, RiskAssessment, RiskFactor, RiskLevel,
    PlannerMemory, PlanRecord,
    AdaptiveStrategy, StrategyRule, AdaptationEvent
)
from .reflection import (
    ReflectionEngine, ReflectionInsight, ReflectionSession,
    BehaviorEvaluator, AgentBehavior, BehaviorMetric, BehaviorStatus,
    FailureAnalysis, FailureRecord, FailurePattern,
    StrategyReflection, StrategyEvaluation,
    SuccessAnalysis, SuccessRecord, SuccessPattern
)
from .self_improvement import (
    ArchitectureAdapter, ArchitectureConfig,
    AutonomousTuner, Parameter, TuningResult,
    ExplorationController, ExplorationState,
    PolicyOptimizer, PolicyRule, OptimizationResult,
    RewardShaper, RewardRule, ShapingFunction,
    StrategyEvolver, StrategyGene, StrategyChromosome
)

__all__ = [
    # Brain
    'CognitiveCore',
    'CognitiveState',
    'get_cognitive_core',
    'AttentionManager',
    'BrainLoop',
    'ContextIntegrator',
    'DecisionEngine',
    'DecisionFusion',
    'PolicyRouter',
    'RLPolicy',
    
    # Knowledge
    'KnowledgeGraph',
    'KGNode',
    'KGEdge',
    'AttackGraph',
    'AttackPath',
    'AttackSurfaceModel',
    'EntryPoint',
    'AttackVector',
    'DefenseModel',
    'WAFInfo',
    'AuthInfo',
    'RateLimitInfo',
    'TargetModel',
    'ServiceInfo',
    'TechnologyInfo',
    'EndpointInfo',
    
    # Memory
    'EpisodicMemory',
    'Episode',
    'SemanticMemory',
    'Concept',
    'WorkingMemory',
    'WorkingMemoryItem',
    'ProceduralMemory',
    'Procedure',
    'VectorMemory',
    'VectorItem',
    'AttackMemory',
    'AttackRecord',
    'AttackPattern',
    'MemoryConsolidation',
    'ConsolidationStats',
    'MemoryRetriever',
    'MemoryQuery',
    'MemoryResult',
    
    # Reasoning
    'AttackReasoner',
    'AttackChain',
    'AttackStep',
    'AttackPathReasoner',
    'AttackNode',
    'AttackPath',
    'CausalReasoner',
    'CausalLink',
    'CausalChain',
    'ChainReasoner',
    'ChainEvent',
    'LogicChain',
    'GraphReasoner',
    'GraphNode',
    'GraphEdge',
    'GraphPattern',
    'MultiStepReasoner',
    'ReasoningStep',
    'ReasoningChain',
    'ReasoningStepType',
    'SymbolicReasoner',
    'Fact',
    'Rule',
    'UncertaintyReasoner',
    'UncertainFact',
    'Belief',
    
    # Planning
    'ExecutionPlanner',
    'ExecutionPlan',
    'ExecutionStep',
    'ExecutionStatus',
    'StrategicPlanner',
    'StrategicPlan',
    'StrategicObjective',
    'StrategicGoal',
    'TacticalPlanner',
    'TacticalPlan',
    'TacticalAction',
    'WorldState',
    'WorldAttribute',
    'GoalManager',
    'Goal',
    'SubGoal',
    'GoalStatus',
    'GoalPriority',
    'RiskEngine',
    'RiskAssessment',
    'RiskFactor',
    'RiskLevel',
    'PlannerMemory',
    'PlanRecord',
    'AdaptiveStrategy',
    'StrategyRule',
    'AdaptationEvent',
    
    # Reflection
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
    
    # Self Improvement
    'ArchitectureAdapter',
    'ArchitectureConfig',
    'AutonomousTuner',
    'Parameter',
    'TuningResult',
    'ExplorationController',
    'ExplorationState',
    'PolicyOptimizer',
    'PolicyRule',
    'OptimizationResult',
    'RewardShaper',
    'RewardRule',
    'ShapingFunction',
    'StrategyEvolver',
    'StrategyGene',
    'StrategyChromosome',
]
