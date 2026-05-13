# learning/__init__.py

"""
Learning Module - طبقة التعلم المتقدم
"""

from . import meta_learning
from . import reinforcement
from . import sequence_learning
from . import online_learning

# استيراد من meta_learning
from .meta_learning import (
    AdaptiveLearning, LearningParameters,
    ContextVectorizer, ContextFeature,
    MetaLearner, LearningStrategy,
    PatternMemory, Pattern, PatternMatch,
    StrategyOptimizer, StrategyParameter, StrategyProfile,
    TransferLearning, KnowledgeTransfer,
)

# استيراد من reinforcement
from .reinforcement import (
    ActorCriticAgent, ActorCriticMemory,
    DQNAgent, Transition,
    PPOAgent, PPOMemory,
    ReplayBuffer, Experience,
    RewardModel, RewardPrediction,
    RLEnvironment, StepResult,
)

# استيراد من sequence_learning
from .sequence_learning import (
    AttackSequenceModel, AttackStep, AttackSequence,
    BehaviorPredictor, BehaviorEvent, BehaviorPrediction,
    SequenceLearner, Sequence,
    TemporalMemory, TemporalRecord,
)

# استيراد من online_learning
from .online_learning import (
    ContinualLearner, KnowledgeChunk,
    FailureAnalyzer, FailureIncident,
    IncrementalTrainer, TrainingBatch,
    ModelUpdater, ModelVersion,
    OnlineAdapter, AdaptationRule,
)

__all__ = [
    'meta_learning',
    'reinforcement',
    'sequence_learning',
    'online_learning',
    # meta_learning
    'AdaptiveLearning', 'LearningParameters',
    'ContextVectorizer', 'ContextFeature',
    'MetaLearner', 'LearningStrategy',
    'PatternMemory', 'Pattern', 'PatternMatch',
    'StrategyOptimizer', 'StrategyParameter', 'StrategyProfile',
    'TransferLearning', 'KnowledgeTransfer',
    # reinforcement
    'ActorCriticAgent', 'ActorCriticMemory',
    'DQNAgent', 'Transition',
    'PPOAgent', 'PPOMemory',
    'ReplayBuffer', 'Experience',
    'RewardModel', 'RewardPrediction',
    'RLEnvironment', 'StepResult',
    # sequence_learning
    'AttackSequenceModel', 'AttackStep', 'AttackSequence',
    'BehaviorPredictor', 'BehaviorEvent', 'BehaviorPrediction',
    'SequenceLearner', 'Sequence',
    'TemporalMemory', 'TemporalRecord',
    # online_learning
    'ContinualLearner', 'KnowledgeChunk',
    'FailureAnalyzer', 'FailureIncident',
    'IncrementalTrainer', 'TrainingBatch',
    'ModelUpdater', 'ModelVersion',
    'OnlineAdapter', 'AdaptationRule',
]
