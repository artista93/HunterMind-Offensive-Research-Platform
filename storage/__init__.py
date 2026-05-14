# storage/__init__.py

"""
Storage Module - طبقة التخزين المتكاملة
"""

from .base_storage import BaseStorage, StorageType, StorageStatus, StorageStats, get_default_storage

from . import sqlite
from . import vector_db
from . import graph_db
from . import object_storage
from . import checkpoints

# استيراد من sqlite
from .sqlite import (
    PersistenceManager, PersistedState, get_persistence_manager,
    LearningDatabase, RLTransition, Episode, Experience, get_learning_database,
)

# استيراد من vector_db
from .vector_db import (
    VectorStore, VectorDocument, SearchResult, HNSWIndex, get_vector_store,
)

# استيراد من graph_db
from .graph_db import (
    GraphStore, GraphNode, GraphEdge, GraphPath, EdgeType, get_graph_store,
)

# استيراد من object_storage
from .object_storage import (
    ObjectStore, StoredObject, ObjectChunk, StorageBackend, get_object_store,
)

# استيراد من checkpoints
from .checkpoints import (
    CheckpointManager, Checkpoint, CheckpointStatus, CheckpointStrategy,
    CheckpointComponent, get_checkpoint_manager,
)

__all__ = [
    'BaseStorage',
    'StorageType',
    'StorageStatus',
    'StorageStats',
    'get_default_storage',
    'sqlite',
    'vector_db',
    'graph_db',
    'object_storage',
    'checkpoints',
    # sqlite
    'PersistenceManager', 'PersistedState', 'get_persistence_manager',
    'LearningDatabase', 'RLTransition', 'Episode', 'Experience', 'get_learning_database',
    # vector_db
    'VectorStore', 'VectorDocument', 'SearchResult', 'HNSWIndex', 'get_vector_store',
    # graph_db
    'GraphStore', 'GraphNode', 'GraphEdge', 'GraphPath', 'EdgeType', 'get_graph_store',
    # object_storage
    'ObjectStore', 'StoredObject', 'ObjectChunk', 'StorageBackend', 'get_object_store',
    # checkpoints
    'CheckpointManager', 'Checkpoint', 'CheckpointStatus', 'CheckpointStrategy',
    'CheckpointComponent', 'get_checkpoint_manager',
]
