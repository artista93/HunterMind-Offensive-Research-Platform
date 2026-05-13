import yaml
from pathlib import Path
from typing import Dict, Any

_CONFIG_PATH = Path(__file__).parent / "default.yaml"

with open(_CONFIG_PATH, 'r', encoding='utf-8') as _f:
    _RAW_CONFIG: Dict[str, Any] = yaml.safe_load(_f)

SCANNERS_CONFIG: Dict[str, Any] = _RAW_CONFIG.get("scanners", {})
XSS_SCANNER_CONFIG: Dict[str, Any] = SCANNERS_CONFIG.get("xss", {})
SQLI_SCANNER_CONFIG: Dict[str, Any] = SCANNERS_CONFIG.get("sqli", {})
IDOR_SCANNER_CONFIG: Dict[str, Any] = SCANNERS_CONFIG.get("idor", {})
PAYLOADS_CONFIG: Dict[str, Any] = _RAW_CONFIG.get("payloads", {})
GENERATOR_CONFIG: Dict[str, Any] = PAYLOADS_CONFIG.get("generator", {})
MUTATOR_CONFIG: Dict[str, Any] = PAYLOADS_CONFIG.get("mutator", {})
RANKER_CONFIG: Dict[str, Any] = PAYLOADS_CONFIG.get("ranker", {})
RECON_CONFIG: Dict[str, Any] = _RAW_CONFIG.get("recon", {})
CRAWLER_RECON_CONFIG: Dict[str, Any] = RECON_CONFIG.get("crawler", {})
JS_PROCESSOR_CONFIG: Dict[str, Any] = RECON_CONFIG.get("js_processor", {})
EXPLOITATION_CONFIG: Dict[str, Any] = _RAW_CONFIG.get("exploitation", {})
ORCHESTRATOR_CONFIG: Dict[str, Any] = EXPLOITATION_CONFIG.get("orchestrator", {})
CHAINS_CONFIG: Dict[str, Any] = EXPLOITATION_CONFIG.get("chains", {})
PIPELINES_CONFIG: Dict[str, Any] = _RAW_CONFIG.get("pipelines", {})
XSS_PIPELINE_CONFIG: Dict[str, Any] = PIPELINES_CONFIG.get("xss", {})
SQLI_PIPELINE_CONFIG: Dict[str, Any] = PIPELINES_CONFIG.get("sqli", {})
IDOR_PIPELINE_CONFIG: Dict[str, Any] = PIPELINES_CONFIG.get("idor", {})
OFFENSIVE_CONFIG: Dict[str, Any] = _RAW_CONFIG

__all__ = [
    'SCANNERS_CONFIG', 'XSS_SCANNER_CONFIG', 'SQLI_SCANNER_CONFIG', 'IDOR_SCANNER_CONFIG',
    'PAYLOADS_CONFIG', 'GENERATOR_CONFIG', 'MUTATOR_CONFIG', 'RANKER_CONFIG',
    'RECON_CONFIG', 'CRAWLER_RECON_CONFIG', 'JS_PROCESSOR_CONFIG',
    'EXPLOITATION_CONFIG', 'ORCHESTRATOR_CONFIG', 'CHAINS_CONFIG',
    'PIPELINES_CONFIG', 'XSS_PIPELINE_CONFIG', 'SQLI_PIPELINE_CONFIG', 'IDOR_PIPELINE_CONFIG',
    'OFFENSIVE_CONFIG',
]
