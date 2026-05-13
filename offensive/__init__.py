# offensive/__init__.py

"""
Offensive Module - طبقة الهجوم (Scanners, Payloads, Recon, Exploitation, Pipelines)
"""

from . import scanners
from . import payloads
from . import recon
from . import exploitation
from . import pipelines

# استيراد من scanners
from .scanners import (
    BaseScanner, ScanContext, ScanTarget, Finding, Severity, Confidence,
    XSSScanner, SQLiScanner, IDORScanner, CSRFScanner, SSRFScanner,
    RCEScanner, AuthScanner, GraphQLScanner, APIScanner,
)

# استيراد من payloads
from .payloads import (
    PayloadGenerator, Payload, PayloadType, EncodingType,
    PayloadMutator, PayloadEncoder, PayloadRanker, PayloadLibrary,
    PayloadEvolver, ContextPayloadBuilder,
)

# استيراد من recon
from .recon import (
    EnhancedCrawler, CrawledPage, CrawlResult,
    JSProcessor, JSAnalysisResult,
    APICollector, APIEndpoint,
    FormExtractor, ExtractedForm,
    AttackSurfaceMapper, AttackSurface,
)

# استيراد من exploitation
from .exploitation import (
    ExploitOrchestrator, ExploitTarget, ExploitResult, ExploitStatus,
    ExploitChains, ExploitChain,
    ExploitMemory, StoredExploit,
    AdaptiveExploitation,
    PostExploitation, SystemInfo, ExfiltratedData,
)

# استيراد من pipelines
from .pipelines import (
    ReconPipeline, ReconPipelineResult,
    XSSPipeline, XSSPipelineResult,
    SQLiPipeline, SQLiPipelineResult,
    IDORPipeline, IDORPipelineResult,
    APIPipeline, APIPipelineResult,
    AuthPipeline, AuthPipelineResult,
    AttackChainPipeline, AttackChainPipelineResult,
)

__all__ = [
    'scanners',
    'payloads',
    'recon',
    'exploitation',
    'pipelines',
    # scanners
    'BaseScanner', 'ScanContext', 'ScanTarget', 'Finding', 'Severity', 'Confidence',
    'XSSScanner', 'SQLiScanner', 'IDORScanner', 'CSRFScanner', 'SSRFScanner',
    'RCEScanner', 'AuthScanner', 'GraphQLScanner', 'APIScanner',
    # payloads
    'PayloadGenerator', 'Payload', 'PayloadType', 'EncodingType',
    'PayloadMutator', 'PayloadEncoder', 'PayloadRanker', 'PayloadLibrary',
    'PayloadEvolver', 'ContextPayloadBuilder',
    # recon
    'EnhancedCrawler', 'CrawledPage', 'CrawlResult',
    'JSProcessor', 'JSAnalysisResult',
    'APICollector', 'APIEndpoint',
    'FormExtractor', 'ExtractedForm',
    'AttackSurfaceMapper', 'AttackSurface',
    # exploitation
    'ExploitOrchestrator', 'ExploitTarget', 'ExploitResult', 'ExploitStatus',
    'ExploitChains', 'ExploitChain',
    'ExploitMemory', 'StoredExploit',
    'AdaptiveExploitation',
    'PostExploitation', 'SystemInfo', 'ExfiltratedData',
    # pipelines
    'ReconPipeline', 'ReconPipelineResult',
    'XSSPipeline', 'XSSPipelineResult',
    'SQLiPipeline', 'SQLiPipelineResult',
    'IDORPipeline', 'IDORPipelineResult',
    'APIPipeline', 'APIPipelineResult',
    'AuthPipeline', 'AuthPipelineResult',
    'AttackChainPipeline', 'AttackChainPipelineResult',
]
