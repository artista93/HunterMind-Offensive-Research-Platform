"""
SQLi Agent Module - وكيل هجمات SQL Injection المتقدم
"""

from .sqli_agent import SQLiAgent, get_sqli_agent
from .dbms_fingerprinter import DBMSFingerprinter, DBMS, DBMSFingerprint
from .query_mutator import QueryMutator, MutationTechnique, MutatedQuery

__all__ = [
    'SQLiAgent',
    'get_sqli_agent',
    'DBMSFingerprinter',
    'DBMS',
    'DBMSFingerprint',
    'QueryMutator',
    'MutationTechnique',
    'MutatedQuery',
]
