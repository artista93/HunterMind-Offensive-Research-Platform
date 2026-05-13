# learning/online_learning/__init__.py

"""
Online Learning Module - التعلم عبر الإنترنت والتكيف الفوري
"""

from .continual_learning import ContinualLearner, KnowledgeChunk
from .failure_analyzer import FailureAnalyzer, FailureIncident
from .incremental_training import IncrementalTrainer, TrainingBatch
from .model_updater import ModelUpdater, ModelVersion
from .online_adaptation import OnlineAdapter, AdaptationRule

__all__ = [
    'ContinualLearner',
    'KnowledgeChunk',
    'FailureAnalyzer',
    'FailureIncident',
    'IncrementalTrainer',
    'TrainingBatch',
    'ModelUpdater',
    'ModelVersion',
    'OnlineAdapter',
    'AdaptationRule',
]
