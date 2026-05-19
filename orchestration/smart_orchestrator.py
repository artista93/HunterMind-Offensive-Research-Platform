"""
Smart Orchestrator - يدمج جميع أدوات recon/ بشكل احترافي
"""

import asyncio
from typing import Dict, List, Optional, Any, Set
from datetime import datetime
from urllib.parse import urlparse, urljoin, parse_qs

import httpx

from orchestration.orchestrator import Orchestrator
from offensive.scanners.base_scanner import ScanContext, ScanTarget
from offensive.recon.enhanced_crawler import EnhancedCrawler
from offensive.recon.js_processor import JSProcessor, JSAnalysisResult
from offensive.recon.api_collector import APICollector, APIEndpoint
from offensive.recon.form_extractor import FormExtractor, ExtractedForm
from offensive.recon.attack_surface_mapper import AttackSurfaceMapper

import logging

logger = logging.getLogger(__name__)


class SmartOrchestrator(Orchestrator):
    """منسق ذكي - يستخدم جميع أدوات recon/"""
    
    def __init__(self):
        super().__init__()
        
        # أدوات recon الحقيقية
        self._crawler = EnhancedCrawler(max_depth=3, max_pages=100)
        self._js_processor = JSProcessor()
        self._api_collector = APICollector()
        self._form_extractor = FormExtractor()
        self._surface_mapper = AttackSurfaceMapper()
        
        # نتائج التحليل
        self._forms: List[ExtractedForm] = []
        self._api_endpoints: List[APIEndpoint] = []
        self._js_results: List[JSAnalysisResult] = []
        self._sensitive_info: List[Dict] = []
        self._technologies: List[str] = []
        
        logger.info("SmartOrchestrator initialized with all recon tools")
    
    async def smart_scan(self, url: str, depth: int = 2, max_pages: int = 10) -> Dict:
        """فحص ذكي كامل باستخدام جميع أدوات recon"""
        scan_id = f"smart_{len(self._scans)+1:03d}"
        start_time = datetime.now()
        
        print(f"\n🧠 Smart Scan: {url}")
        print(f"{'='*60}")
        
        await self._init_world_state(url)
        
        # ===== 1: الزحف باستخدام EnhancedCrawler =====
        print(f"\n🕷️  Phase 1: Crawling with EnhancedCrawler...")
        crawl_result = await self._crawler.crawl(
            ScanContext(target=ScanTarget(url=url, force_scan=True))
        )
        
        pages = [p.url for p in crawl_result.pages_crawled]
        if url not in pages:
            pages.insert(0, url)
        
        print(f"   ✅ Pages: {len(pages)} | Forms: {crawl_result.total_forms} | APIs: {crawl_result.total_api_endpoints}")
        
        if not pages:
            return {"error": "No pages found", "vulnerabilities": []}
        
        # ===== 2: تحليل JavaScript =====
        print(f"\n📜 Phase 2: JavaScript Analysis...")
        
        all_js_files = set()
        for page in crawl_result.pages_crawled[:5]:
            for script in page.scripts:
                all_js_files.add(script)
        
        for js_url in list(all_js_files)[:10]:
            result = await self._js_processor.process_url(js_url, url)
            if result:
                self._js_results.append(result)
                self._api_endpoints.extend(
                    APIEndpoint(path=e.url, method=e.method, full_url=e.url,
                               parameters=e.parameters, discovered_from=f"js:{js_url}")
                    for e in result.endpoints
                )
                self._sensitive_info.extend(
                    {"type": s.type, "value": s.value[:50], "source": js_url}
                    for s in result.sensitive_info
                )
        
        print(f"   ✅ JS Files: {len(all_js_files)} | Endpoints: {len(self._api_endpoints)} | Secrets: {len(self._sensitive_info)}")
        
        # ===== 3: استخراج Forms =====
        print(f"\n📝 Phase 3: Form Extraction...")
        
        for page in crawl_result.pages_crawled[:5]:
            try:
                async with httpx.AsyncClient(timeout=15, verify=False) as client:
                    response = await client.get(page.url)
                    if response.status_code == 200:
                        form_result = await self._form_extractor.extract_from_html(response.text, page.url)
                        self._forms.extend(form_result.forms)
            except Exception as e:
                logger.debug(f"Form extraction failed for {page.url}: {e}")
        
        # تحليل أماني للنماذج
        form_vulns = []
        for form in self._forms:
            if form.method == 'POST' and not form.has_csrf_token:
                form_vulns.append({
                    "type": "Missing CSRF Protection",
                    "url": form.action_url,
                    "severity": "MEDIUM",
                    "details": f"Form at {form.action_url} has no CSRF token"
                })
        
        print(f"   ✅ Forms: {len(self._forms)} | Form Issues: {len(form_vulns)}")
        
        # ===== 4: بناء Targets للفحص =====
        print(f"\n🎯 Phase 4: Building Scan Targets...")
        
        targets = self._build_targets(pages, url)
        print(f"   ✅ Targets: {len(targets)}")
        
        # ===== 5: فحص موجه =====
        print(f"\n⚡ Phase 5: Scanning {len(targets)} Targets...")
        
        all_vulnerabilities = []
        
        for i, target in enumerate(targets[:15], 1):
            params = target.get('params', {})
            print(f"   [{i}/{min(len(targets), 15)}] {target['url'][:70]} - {list(params.keys())[:3] if params else 'no params'}")
            
            scan_target = ScanTarget(
                url=target['url'], method=target['method'],
                params=params, data=target.get('data', {}),
                force_scan=True
            )
            
            vulns = await self._scan_target(ScanContext(target=scan_target), target)
            all_vulnerabilities.extend(vulns)
        
        # ===== 6: ملخص =====
        duration = (datetime.now() - start_time).total_seconds()
        
        # إضافة form vulns
        all_vulnerabilities.extend(form_vulns)
        
        # إضافة sensitive info findings
        for info in self._sensitive_info[:5]:
            all_vulnerabilities.append({
                "type": "Sensitive Information in JS",
                "severity": "MEDIUM",
                "url": info["source"],
                "details": f"Found {info['type']}: {info['value']}"
            })
        
        result = {
            "scan_id": scan_id, "target": url,
            "pages_found": len(pages),
            "js_files_analyzed": len(all_js_files),
            "forms_found": len(self._forms),
            "api_endpoints_found": len(self._api_endpoints),
            "sensitive_info_found": len(self._sensitive_info),
            "targets_scanned": len(targets[:15]),
            "vulnerabilities_count": len(all_vulnerabilities),
            "vulnerabilities": all_vulnerabilities[:20],
            "duration_seconds": duration,
        }
        
        print(f"\n{'='*60}")
        print(f"✅ Scan Complete!")
        print(f"   Pages: {len(pages)} | JS: {len(all_js_files)} | Forms: {len(self._forms)}")
        print(f"   APIs: {len(self._api_endpoints)} | Secrets: {len(self._sensitive_info)}")
        print(f"   Vulnerabilities: {len(all_vulnerabilities)} | Duration: {duration:.1f}s")
        
        return result
    
    def _build_targets(self, pages: List[str], base_url: str) -> List[Dict]:
        """بناء أهداف الفحص من الصفحات والـ forms"""
        targets = []
        seen = set()
        
        # الصفحات الرئيسية
        for page_url in pages[:5]:
            key = f"GET:{page_url}"
            if key not in seen:
                seen.add(key)
                targets.append({'url': page_url, 'method': 'GET', 'params': {}, 'data': {}, 'type': 'page'})
        
        # من الـ forms
        for form in self._forms[:10]:
            params = {f.name: 'test' for f in form.fields if f.name}
            key = f"{form.method}:{form.action_url}"
            if key not in seen and params:
                seen.add(key)
                targets.append({
                    'url': form.action_url, 'method': form.method,
                    'params': params,
                    'data': params if form.method == 'POST' else {},
                    'type': 'form'
                })
        
        # من الـ API endpoints
        for api in self._api_endpoints[:5]:
            key = f"{api.method}:{api.full_url}"
            if key not in seen:
                seen.add(key)
                targets.append({
                    'url': api.full_url, 'method': api.method,
                    'params': {p: 'test' for p in api.parameters} if api.parameters else {},
                    'data': {}, 'type': 'api'
                })
        
        return targets
    
    async def _scan_target(self, context: ScanContext, target_info: Dict) -> List[Dict]:
        """فحص target واحد"""
        vulns = []
        
        # اختيار scanners المناسبة
        has_params = bool(target_info.get('params'))
        is_form = target_info.get('type') == 'form'
        target_type = target_info.get('type', 'page')
        
        scanners_to_run = []
        
        if has_params:
            scanners_to_run.extend([
                ("xss", "offensive.scanners.xss_scanner", "XSSScanner"),
                ("sqli", "offensive.scanners.sqli_scanner", "SQLiScanner"),
                ("idor", "offensive.scanners.idor_scanner", "IDORScanner"),
            ])
        
        if is_form:
            scanners_to_run.append(("csrf", "offensive.scanners.csrf_scanner", "CSRFScanner"))
        
        if target_type == "page":
            scanners_to_run.append(("auth", "offensive.scanners.auth_scanner", "AuthScanner"))
        
        for key, module_path, class_name in scanners_to_run:
            try:
                import importlib
                from offensive.scanners.adapters import ScannerAdapter
                
                module = importlib.import_module(module_path)
                scanner_class = getattr(module, class_name)
                scanner = scanner_class(timeout=15, max_retries=1)
                
                findings = await scanner.execute_scan(context)
                
                if findings:
                    converted = ScannerAdapter.batch_convert(findings, scanner_name=key)
                    for v in converted:
                        vulns.append(v.to_dict())
                
                await scanner.close()
            except Exception as e:
                logger.debug(f"Scanner {key} failed: {e}")
        
        return vulns


_smart_orchestrator = None

async def get_smart_orchestrator() -> SmartOrchestrator:
    global _smart_orchestrator
    if _smart_orchestrator is None:
        _smart_orchestrator = SmartOrchestrator()
        await _smart_orchestrator.start()
    return _smart_orchestrator
