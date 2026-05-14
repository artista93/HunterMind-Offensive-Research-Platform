# storage/object_storage/__init__.py

"""
Object Storage Module - تخزين الكائنات والملفات
"""

from .object_store import ObjectStore, StoredObject, ObjectChunk, StorageBackend, get_object_store

__all__ = [
    'ObjectStore',
    'StoredObject',
    'ObjectChunk',
    'StorageBackend',
    'get_object_store',
]
