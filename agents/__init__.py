"""
Agents Layer - جميع وكلاء المنصة
"""

from .base import (
    BaseAgent, AgentState, AgentPriority, AgentMessage,
    AgentRegistry, AgentType, get_agent_registry,
    AgentMemory, MemoryType, MemoryImportance,
    AgentStateEnum, AgentStateManager
)

from .auth_agent import AuthAgent, get_auth_agent, RegistrationAgent, RegistrationResult, get_registration_agent
from .waf_agent import WAFAgent, get_waf_agent, WAFDetector, AdaptiveEvasion
from .xss_agent import XSSAgent, get_xss_agent, XSSValidator, ContextAnalyzer, SinkDetector
from .sqli_agent import SQLiAgent, get_sqli_agent, DBMSFingerprinter, DBMS, QueryMutator, MutationTechnique
from .idor_agent import IDORAgent, get_idor_agent, AccessPatternLearner, ObjectMapper, PrivilegeAnalyzer
from .exploitation_agent import ExploitationAgent, get_exploitation_agent, ChainExecutor, ExploitSelector, PrivilegeEscalation, SessionAbuse
from .learning_agent import LearningAgent, get_learning_agent, ExperienceManager, OnlineTrainer, RewardEngine
from .reasoning_agent import ReasoningAgent, get_reasoning_agent, ObjectiveSolver, ObjectiveType
from .planning_agent import PlanningAgent, get_planning_agent, AttackPlan, PlanStep, PlanStatus, AdaptivePlanner
from .crawler_agent import CrawlerAgent, get_crawler_agent, LinkGraphBuilder, Link, PageNode, LinkType
from .recon_agent import ReconAgent, get_recon_agent, EndpointDiscovery, FingerprintEngine, SurfaceMapper, TechDetector

__all__ = [
    # Base
    'BaseAgent',
    'AgentState',
    'AgentPriority',
    'AgentMessage',
    'AgentRegistry',
    'AgentType',
    'get_agent_registry',
    'AgentMemory',
    'MemoryType',
    'MemoryImportance',
    'AgentStateEnum',
    'AgentStateManager',
    
    # Auth
    'AuthAgent',
    'get_auth_agent',
    'RegistrationAgent',
    'RegistrationResult',
    'get_registration_agent',
    
    # WAF
    'WAFAgent',
    'get_waf_agent',
    'WAFDetector',
    'AdaptiveEvasion',
    
    # XSS
    'XSSAgent',
    'get_xss_agent',
    'XSSValidator',
    'ContextAnalyzer',
    'SinkDetector',
    
    # SQLi
    'SQLiAgent',
    'get_sqli_agent',
    'DBMSFingerprinter',
    'DBMS',
    'QueryMutator',
    'MutationTechnique',
    
    # IDOR
    'IDORAgent',
    'get_idor_agent',
    'AccessPatternLearner',
    'ObjectMapper',
    'PrivilegeAnalyzer',
    
    # Exploitation
    'ExploitationAgent',
    'get_exploitation_agent',
    'ChainExecutor',
    'ExploitSelector',
    'PrivilegeEscalation',
    'SessionAbuse',
    
    # Learning
    'LearningAgent',
    'get_learning_agent',
    'ExperienceManager',
    'OnlineTrainer',
    'RewardEngine',
    
    # Reasoning
    'ReasoningAgent',
    'get_reasoning_agent',
    'ObjectiveSolver',
    'ObjectiveType',
    
    # Planning
    'PlanningAgent',
    'get_planning_agent',
    'AttackPlan',
    'PlanStep',
    'PlanStatus',
    'AdaptivePlanner',
    
    # Crawler
    'CrawlerAgent',
    'get_crawler_agent',
    'LinkGraphBuilder',
    'Link',
    'PageNode',
    'LinkType',
    
    # Recon
    'ReconAgent',
    'get_recon_agent',
    'EndpointDiscovery',
    'FingerprintEngine',
    'SurfaceMapper',
    'TechDetector',
]
