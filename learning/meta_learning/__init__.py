# learning/meta_learning/__init__.py

"""
Meta Learning Module - التعلم الفوقي المتقدم
"""

from .adaptive_learning import AdaptiveLearning, LearningParameters
from .context_vectorizer import ContextVectorizer, ContextFeature
from .meta_learner import MetaLearner, LearningStrategy
from .pattern_memory import PatternMemory, Pattern, PatternMatch
from .strategy_optimizer import StrategyOptimizer, StrategyParameter, StrategyProfile
from .transfer_learning import TransferLearning, KnowledgeTransfer

__all__ = [
    'AdaptiveLearning',
    'LearningParameters',
    'ContextVectorizer',
    'ContextFeature',
    'MetaLearner',
    'LearningStrategy',
    'PatternMemory',
    'Pattern',
    'PatternMatch',
    'StrategyOptimizer',
    'StrategyParameter',
    'StrategyProfile',
    'TransferLearning',
    'KnowledgeTransfer',
]
