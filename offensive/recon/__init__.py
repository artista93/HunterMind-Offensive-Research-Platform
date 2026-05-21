"""
Recon Module - أدوات الاستطلاع وجمع المعلومات
"""
from .enhanced_crawler import EnhancedCrawler, CrawledPage, CrawlResult
from .js_processor import JSProcessor, JSAnalysisResult, JSEndpoint, JSSensitiveInfo
from .api_collector import APICollector, APIEndpoint, APICollection
from .form_extractor import FormExtractor, ExtractedForm, FormField, FormAnalysisResult
from .attack_surface_mapper import AttackSurfaceMapper, AttackSurface, Technology, EntryPoint
from .js_api_discovery import JSAPIDiscovery, get_js_api_discovery
from .site_analyzer import (
    SiteAnalyzer, SiteAnalysisReport,
    ConnectivityResult, WAFResult, AuthResult,
    StructureResult, TechnologyResult, ServiceResult, AttackSurfaceResult,
    get_site_analyzer
)
from .secrets_scanner import SecretsScanner, Secret, get_secrets_scanner

__all__ = [
    'EnhancedCrawler', 'CrawledPage', 'CrawlResult',
    'JSProcessor', 'JSAnalysisResult', 'JSEndpoint', 'JSSensitiveInfo',
    'APICollector', 'APIEndpoint', 'APICollection',
    'FormExtractor', 'ExtractedForm', 'FormField', 'FormAnalysisResult',
    'AttackSurfaceMapper', 'AttackSurface', 'Technology', 'EntryPoint',
    'JSAPIDiscovery', 'get_js_api_discovery',
    'SiteAnalyzer', 'SiteAnalysisReport',
    'ConnectivityResult', 'WAFResult', 'AuthResult',
    'StructureResult', 'TechnologyResult', 'ServiceResult', 'AttackSurfaceResult',
    'get_site_analyzer',
    'SecretsScanner', 'Secret', 'get_secrets_scanner',
]
