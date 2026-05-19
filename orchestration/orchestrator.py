import asyncio
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

from orchestration.messaging.event_bus import EventBus, Event, EventType
from orchestration.world_state_manager import WorldStateManager, get_world_state_manager
from schemas.world_state import ScanPhase, TargetStatus

import logging

logger = logging.getLogger(__name__)


class OrchestratorState(Enum):
    INITIALIZING = "initializing"
    RUNNING = "running"
    PAUSED = "paused"
    STOPPING = "stopping"
    STOPPED = "stopped"
    ERROR = "error"


@dataclass
class WorkflowStep:
    id: str
    name: str
    action: str
    depends_on: List[str]
    status: str = "pending"
    result: Any = None
    error: Optional[str] = None


class Orchestrator:
    """المنسق الرئيسي المتقدم - يدير جميع مكونات المنصة"""
    
    ALL_SCANNERS = [
        ("xss", "XSSScanner"),
        ("sqli", "SQLiScanner"),
        ("idor", "IDORScanner"),
        ("rce", "RCEScanner"),
        ("ssrf", "SSRFScanner"),
        ("csrf", "CSRFScanner"),
        ("auth", "AuthScanner"),
        ("graphql", "GraphQLScanner"),
        ("api", "APIScanner"),
    ]
    
    def __init__(self):
        self.state = OrchestratorState.INITIALIZING
        self.components: Dict[str, Any] = {}
        self.workflows: Dict[str, List[WorkflowStep]] = {}
        self.active_workflows: Set[str] = set()
        self._lock = asyncio.Lock()
        
        self._event_bus: Optional[EventBus] = None
        
        self._scans: List[Dict] = []
        self._vulnerabilities: List[Dict] = []
        self._registered_accounts: List[Dict] = []
        
        self._scanner_stats: Dict[str, Dict] = {}
        self._payload_manager = None
        
        # WorldState Manager (جديد)
        self._world_state_manager: Optional[WorldStateManager] = None
        
        logger.info("Orchestrator initialized")
    
    async def _ensure_event_bus(self):
        if self._event_bus is None:
            from orchestration.messaging.event_bus import get_event_bus
            self._event_bus = await get_event_bus()
    
    async def _ensure_payload_manager(self):
        if self._payload_manager is None:
            from offensive.scanners.payload_integration import get_payload_manager
            self._payload_manager = get_payload_manager()
    
    async def _ensure_world_state_manager(self):
        """تأكد من وجود WorldStateManager (جديد)"""
        if self._world_state_manager is None:
            self._world_state_manager = get_world_state_manager()
    
    async def _publish_event(self, event_type: EventType, source: str, data: Any):
        await self._ensure_event_bus()
        event = Event(type=event_type, source=source, data=data)
        await self._event_bus.publish(event)
    
    async def register_component(self, name: str, component: Any):
        async with self._lock:
            self.components[name] = component
            await self._publish_event(EventType.COMPONENT_LOAD, "orchestrator", {"component_name": name})
            logger.info(f"Component registered: {name}")
    
    async def start(self):
        self.state = OrchestratorState.RUNNING
        await self._ensure_payload_manager()
        await self._ensure_world_state_manager()
        await self._publish_event(EventType.SYSTEM_START, "orchestrator", {"state": self.state.value})
        logger.info("Orchestrator started")
    
    async def stop(self):
        self.state = OrchestratorState.STOPPING
        for workflow_id in self.active_workflows:
            await self.cancel_workflow(workflow_id)
        self.state = OrchestratorState.STOPPED
        await self._publish_event(EventType.SYSTEM_STOP, "orchestrator", {"state": self.state.value})
        logger.info("Orchestrator stopped")
    
    async def create_workflow(self, name: str, steps: List[WorkflowStep]) -> str:
        import uuid
        workflow_id = str(uuid.uuid4())[:8]
        self.workflows[workflow_id] = steps
        return workflow_id
    
    async def execute_workflow(self, workflow_id: str) -> Dict[str, Any]:
        if workflow_id not in self.workflows:
            raise ValueError(f"Workflow {workflow_id} not found")
        
        self.active_workflows.add(workflow_id)
        steps = self.workflows[workflow_id]
        results = {}
        
        for step in steps:
            deps_met = all(
                step.depends_on[i] in results or step.depends_on[i] in [s.id for s in steps]
                for i in range(len(step.depends_on))
            )
            if not deps_met:
                step.status = "skipped"
                continue
            try:
                step.status = "running"
                result = await self._execute_step(step)
                step.result = result
                step.status = "completed"
                results[step.id] = result
            except Exception as e:
                step.status = "failed"
                step.error = str(e)
                logger.error(f"Step {step.name} failed: {e}")
                break
        
        self.active_workflows.discard(workflow_id)
        return results
    
    # ==================== دوال الفحص الأساسية ====================
    
    async def execute_full_scan(self, url: str, depth: int = 3, max_pages: int = 50) -> Dict:
        """فحص شامل للموقع"""
        logger.info(f"Starting full scan on {url}")
        
        await self._ensure_payload_manager()
        await self._ensure_world_state_manager()
        
        scan_id = f"scan_{len(self._scans)+1:03d}"
        await self._publish_event(EventType.SCAN_STARTED, "orchestrator", {"scan_id": scan_id, "target": url})
        
        # تهيئة WorldState
        await self._init_world_state(url)
        
        # ===== المرحلة 1: RECONNAISSANCE =====
        await self._world_state_manager.transition_phase(ScanPhase.RECONNAISSANCE)
        await self._publish_event(EventType.TASK_START, "orchestrator", {"phase": "reconnaissance", "url": url})
        
        crawl_result = await self._execute_crawl(url, depth, max_pages)
        
        if not crawl_result.get("pages"):
            await self._world_state_manager.transition_phase(ScanPhase.ERROR)
            await self._publish_event(EventType.TASK_FAIL, "orchestrator", {"scan_id": scan_id, "error": "No pages discovered"})
            return {
                "scan_id": scan_id, "pages_scanned": 0, "total_vulnerabilities": 0,
                "vulnerabilities": [], "scanner_stats": {}, "payload_stats": {},
                "world_state": await self._world_state_manager.get_summary(),
                "error": "No pages discovered"
            }
        
        # ===== المرحلة 2: SCANNING =====
        await self._world_state_manager.transition_phase(ScanPhase.SCANNING)
        await self._publish_event(EventType.TASK_START, "orchestrator", {"phase": "scanning", "pages": len(crawl_result["pages"])})
        
        pages = crawl_result["pages"]
        all_vulnerabilities = []
        all_findings_raw = []
        
        for i, page_url in enumerate(pages[:max_pages], 1):
            logger.info(f"Scanning [{i}/{min(len(pages), max_pages)}]: {page_url[:80]}")
            await self._publish_event(EventType.SCAN_PAGE_COMPLETE, "orchestrator", {
                "page_index": i, "total_pages": min(len(pages), max_pages), "url": page_url
            })
            
            page_result = await self._scan_page_full(page_url)
            all_vulnerabilities.extend(page_result["vulnerabilities"])
            all_findings_raw.extend(page_result["findings"])
        
        # ===== المرحلة 3: ANALYSIS =====
        await self._world_state_manager.transition_phase(ScanPhase.ANALYSIS)
        
        attack_chains = await self._build_attack_chains(all_vulnerabilities)
        evolved_count = 0
        if self._payload_manager:
            evolved_count = self._payload_manager.auto_evolve_low_performers()
        
        # ===== المرحلة 4: COMPLETED =====
        await self._world_state_manager.transition_phase(ScanPhase.COMPLETED)
        
        scan_result = {
            "id": scan_id, "target": url,
            "pages_scanned": len(pages[:max_pages]),
            "total_pages_found": crawl_result.get("total_pages", 0),
            "total_forms": crawl_result.get("total_forms", 0),
            "total_apis": crawl_result.get("total_apis", 0),
            "vulnerabilities_count": len(all_vulnerabilities),
            "vulnerabilities": [v.to_dict() for v in all_vulnerabilities[:20]],
            "attack_chains": len(attack_chains),
            "payloads_evolved": evolved_count,
            "scanner_stats": self._scanner_stats,
            "payload_stats": self._payload_manager.get_statistics() if self._payload_manager else {},
            "world_state": await self._world_state_manager.get_summary(),
            "date": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        self._scans.append(scan_result)
        
        for vuln in all_vulnerabilities:
            self._vulnerabilities.append({
                "id": vuln.id, "type": vuln.type.value,
                "severity": vuln.severity.name, "url": vuln.url,
                "parameter": vuln.parameter or "N/A",
                "payload": vuln.payload or "N/A",
                "confidence": vuln.confidence, "discovered_by": vuln.discovered_by
            })
        
        await self._publish_event(EventType.SCAN_COMPLETED, "orchestrator", {
            "scan_id": scan_id, "target": url,
            "vulnerabilities_count": len(all_vulnerabilities),
            "world_state": await self._world_state_manager.get_summary()
        })
        
        return {
            "scan_id": scan_id,
            "pages_scanned": scan_result["pages_scanned"],
            "total_vulnerabilities": len(all_vulnerabilities),
            "vulnerabilities": [v.to_dict() for v in all_vulnerabilities[:10]],
            "scanner_stats": self._scanner_stats,
            "payload_stats": self._payload_manager.get_statistics() if self._payload_manager else {},
            "world_state": await self._world_state_manager.get_summary(),
            "attack_chains": len(attack_chains),
            "payloads_evolved": evolved_count
        }
    
    async def _scan_page_full(self, url: str) -> Dict:
        """فحص صفحة واحدة باستخدام جميع الـ scanners"""
        vulnerabilities = []
        findings_raw = []
        
        try:
            from offensive.scanners.base_scanner import ScanContext, ScanTarget
            from offensive.scanners.adapters import ScannerAdapter, ConfigLoader
            from offensive.scanners.payload_integration import PayloadTestResult
            
            context = ScanContext(target=ScanTarget(url=url, force_scan=True))
            
            scanner_classes = {
                "xss": ("offensive.scanners.xss_scanner", "XSSScanner"),
                "sqli": ("offensive.scanners.sqli_scanner", "SQLiScanner"),
                "idor": ("offensive.scanners.idor_scanner", "IDORScanner"),
                "rce": ("offensive.scanners.rce_scanner", "RCEScanner"),
                "ssrf": ("offensive.scanners.ssrf_scanner", "SSRFScanner"),
                "csrf": ("offensive.scanners.csrf_scanner", "CSRFScanner"),
                "auth": ("offensive.scanners.auth_scanner", "AuthScanner"),
                "graphql": ("offensive.scanners.graphql_scanner", "GraphQLScanner"),
                "api": ("offensive.scanners.api_scanner", "APIScanner"),
            }
            
            for scanner_key, (module_path, class_name) in scanner_classes.items():
                if not ConfigLoader.is_scanner_enabled(scanner_key):
                    continue
                
                try:
                    config = ConfigLoader.load_scanner_config(scanner_key)
                    
                    import importlib
                    module = importlib.import_module(module_path)
                    scanner_class = getattr(module, class_name)
                    
                    scanner_kwargs = {}
                    if "rate_limit" in config:
                        scanner_kwargs["rate_limit"] = config["rate_limit"]
                    if "timeout" in config:
                        scanner_kwargs["timeout"] = config["timeout"]
                    
                    scanner = scanner_class(**scanner_kwargs)
                    
                    # ربط الـ scanner بـ WorldStateManager (جديد)
                    if self._world_state_manager:
                        scanner.set_world_state_manager(self._world_state_manager)
                    
                    findings = await scanner.execute_scan(context)
                    
                    if findings:
                        vulns = ScannerAdapter.batch_convert(findings, scanner_name=scanner_key)
                        vulnerabilities.extend(vulns)
                        findings_raw.extend(findings)
                        
                        # إضافة الثغرات لـ WorldState (جديد)
                        if self._world_state_manager:
                            for vuln in vulns:
                                await self._world_state_manager.add_vulnerability(vuln)
                        
                        # تسجيل نتائج الحمولات
                        if self._payload_manager:
                            for finding in findings:
                                if finding.payload:
                                    try:
                                        from schemas.payload import PayloadType
                                        payload_type_map = {
                                            "xss": PayloadType.XSS, "sqli": PayloadType.SQLI,
                                            "idor": PayloadType.IDOR, "ssrf": PayloadType.SSRF,
                                            "rce": PayloadType.RCE,
                                        }
                                        payload_type = payload_type_map.get(scanner_key, PayloadType.CUSTOM)
                                        
                                        import uuid
                                        from schemas.payload import Payload, PayloadContext
                                        test_payload = Payload(
                                            id=f"PLS-{uuid.uuid4().hex[:8].upper()}",
                                            content=finding.payload,
                                            payload_type=payload_type,
                                            context=PayloadContext.URL,
                                            name=f"{scanner_key}_{finding.vulnerability_type[:30]}",
                                            tags=[scanner_key]
                                        )
                                        
                                        result = PayloadTestResult(
                                            payload=test_payload,
                                            target_url=finding.url,
                                            target_parameter=finding.parameter or "unknown",
                                            success=True,
                                            response_time_ms=0.0,
                                            evidence=finding.evidence
                                        )
                                        self._payload_manager.record_test_result(result)
                                    except Exception as e:
                                        logger.debug(f"Failed to record payload: {e}")
                        
                        self._scanner_stats[scanner_key] = {
                            "findings_count": len(findings),
                            "vulnerabilities_count": len(vulns),
                            "last_scan_url": url[:80], "enabled": True
                        }
                        
                        for vuln in vulns:
                            await self._publish_event(EventType.VULNERABILITY_FOUND, scanner_key, vuln.to_dict())
                    else:
                        self._scanner_stats[scanner_key] = {
                            "findings_count": 0, "vulnerabilities_count": 0,
                            "last_scan_url": url[:80], "enabled": True
                        }
                    
                    await scanner.close()
                    
                except Exception as e:
                    logger.error(f"Scanner {scanner_key} failed on {url}: {e}")
                    self._scanner_stats[scanner_key] = {
                        "findings_count": 0, "vulnerabilities_count": 0,
                        "error": str(e), "enabled": True
                    }
            
        except Exception as e:
            logger.error(f"Page scan error for {url}: {e}")
        
        return {"vulnerabilities": vulnerabilities, "findings": findings_raw, "url": url}
    
    # ==================== دوال الزحف ====================
    
    async def _execute_crawl(self, url: str, depth: int, max_pages: int) -> Dict:
        try:
            from offensive.recon.enhanced_crawler import EnhancedCrawler
            from offensive.scanners.base_scanner import ScanContext, ScanTarget
            
            try:
                from configs.offensive import CRAWLER_RECON_CONFIG
                crawl_depth = CRAWLER_RECON_CONFIG.get("max_depth", depth)
                crawl_pages = CRAWLER_RECON_CONFIG.get("max_pages", max_pages)
            except ImportError:
                crawl_depth = depth
                crawl_pages = max_pages
            
            crawler = EnhancedCrawler(max_depth=crawl_depth, max_pages=crawl_pages)
            context = ScanContext(target=ScanTarget(url=url, force_scan=True))
            result = await crawler.crawl(context)
            
            pages = [page.url for page in result.pages_crawled]
            if url not in pages:
                pages.insert(0, url)
            
            # إضافة كل الـ URLs لـ WorldState (جديد)
            if self._world_state_manager:
                for page_url in pages:
                    await self._world_state_manager.add_endpoint(url=page_url)
                    if hasattr(self._world_state_manager.state, 'add_pending_url'):
                        self._world_state_manager.state.add_pending_url(page_url)
            
            return {
                "pages": pages,
                "total_pages": len(pages),
                "total_forms": result.total_forms if hasattr(result, 'total_forms') else 0,
                "total_apis": result.total_api_endpoints if hasattr(result, 'total_api_endpoints') else 0
            }
        except Exception as e:
            logger.error(f"Crawl failed: {e}")
            return {"pages": [url], "total_pages": 1, "error": str(e)}
    
    async def execute_crawl(self, url: str, depth: int = 3, max_pages: int = 100) -> Dict:
        await self._ensure_world_state_manager()
        await self._init_world_state(url)
        
        await self._publish_event(EventType.TASK_START, "orchestrator", {"target": url, "type": "crawl"})
        result = await self._execute_crawl(url, depth, max_pages)
        await self._publish_event(EventType.TASK_COMPLETE, "orchestrator", {"target": url, "pages_found": result.get("total_pages", 0)})
        
        return {
            "total_pages": result.get("total_pages", 0),
            "total_forms": result.get("total_forms", 0),
            "total_apis": result.get("total_apis", 0),
            "pages": result.get("pages", [])[:20],
            "world_state": await self._world_state_manager.get_summary() if self._world_state_manager else {}
        }
    
    # ==================== دوال WorldState ====================
    
    async def _init_world_state(self, url: str):
        """تهيئة WorldState للفحص (مُحسَّنة)"""
        await self._ensure_world_state_manager()
        if self._world_state_manager:
            await self._world_state_manager.initialize(url)
            logger.info(f"WorldState initialized for {url}")
    
    async def get_world_state(self) -> Dict:
        """الحصول على WorldState الحالي"""
        await self._ensure_world_state_manager()
        if self._world_state_manager:
            return await self._world_state_manager.to_dict()
        return {"error": "WorldState not initialized"}
    
    async def get_world_state_summary(self) -> Dict:
        """ملخص WorldState"""
        await self._ensure_world_state_manager()
        if self._world_state_manager:
            return await self._world_state_manager.get_summary()
        return {"phase": "not_initialized"}
    
    async def get_world_state_statistics(self) -> Dict:
        """إحصائيات WorldState"""
        await self._ensure_world_state_manager()
        if self._world_state_manager:
            return await self._world_state_manager.get_statistics()
        return {"error": "WorldState not initialized"}
    
    async def get_phase_history(self) -> List[Dict]:
        """تاريخ انتقالات المراحل"""
        await self._ensure_world_state_manager()
        if self._world_state_manager:
            return await self._world_state_manager.get_phase_history()
        return []
    
    # ==================== دوال AttackChain ====================
    
    async def _build_attack_chains(self, vulnerabilities: List) -> List:
        chains = []
        try:
            from schemas.attack_chain import COMMON_ATTACK_CHAINS
            target = self._world_state_manager.state.target_url if self._world_state_manager and self._world_state_manager.state else ""
            for template in COMMON_ATTACK_CHAINS:
                chain = template.create_chain(target=target, vulnerabilities=vulnerabilities)
                if chain:
                    chains.append(chain)
        except ImportError:
            pass
        return chains
    
    # ==================== دوال Payload Management ====================
    
    async def get_payload_statistics(self) -> Dict:
        await self._ensure_payload_manager()
        if self._payload_manager:
            return self._payload_manager.get_statistics()
        return {"error": "PayloadManager not initialized"}
    
    async def get_best_payloads(self, scanner_type: str, limit: int = 5) -> List[Dict]:
        await self._ensure_payload_manager()
        if self._payload_manager:
            return [p.to_dict() for p in self._payload_manager.get_best_payloads(scanner_type, limit)]
        return []
    
    async def evolve_payloads(self, scanner_type: str = None) -> Dict:
        await self._ensure_payload_manager()
        if self._payload_manager:
            if scanner_type:
                return {"scanner_type": scanner_type, "evolved_count": len(self._payload_manager.evolve_payloads(scanner_type))}
            else:
                return {"evolved_count": self._payload_manager.auto_evolve_low_performers()}
        return {"error": "PayloadManager not initialized"}
    
    async def get_payloads_needing_evolution(self) -> List[Dict]:
        await self._ensure_payload_manager()
        if self._payload_manager:
            return [p.to_dict() for p in self._payload_manager.get_payloads_needing_evolution()]
        return []
    
    # ==================== دوال المصادقة ====================
    
    async def register_account(self, url: str, username: str = None, password: str = None) -> Dict:
        logger.info(f"Registering account on {url}")
        await self._publish_event(EventType.DATA_RECEIVED, "orchestrator", {"action": "register", "url": url})
        try:
            from agents.auth_agent.registration_agent import get_registration_agent
            agent = await get_registration_agent()
            await agent.initialize()
            await agent.start()
            result = await agent.register(url, username=username, password=password)
            await agent.stop()
            if result.success:
                self._registered_accounts.append({"username": result.username, "password": result.password, "email": result.email, "url": url, "created_at": datetime.now().isoformat()})
                await self._publish_event(EventType.DATA_SENT, "orchestrator", {"action": "register_success", "username": result.username})
                return {"success": True, "username": result.username, "password": result.password, "email": result.email, "message": result.message}
            else:
                await self._publish_event(EventType.TASK_FAIL, "orchestrator", {"action": "register", "error": result.message})
                return {"success": False, "message": result.message}
        except Exception as e:
            logger.error(f"Registration failed: {e}")
            return {"success": False, "message": str(e)}
    
    async def login(self, username: str, password: str) -> Dict:
        await self._publish_event(EventType.DATA_RECEIVED, "orchestrator", {"action": "login", "username": username})
        return {"success": True, "message": "Session saved"}
    
    async def full_automation(self, register_url: str, target_url: str) -> Dict:
        reg_result = await self.register_account(register_url)
        if not reg_result.get("success"):
            return {"success": False, "message": reg_result.get("message")}
        scan_result = await self.execute_full_scan(target_url)
        return {
            "success": True, "username": reg_result.get("username"),
            "password": reg_result.get("password"),
            "total_vulnerabilities": scan_result.get("total_vulnerabilities", 0),
            "scan_id": scan_result.get("scan_id"),
            "scanner_stats": scan_result.get("scanner_stats", {}),
            "payload_stats": scan_result.get("payload_stats", {}),
            "world_state": scan_result.get("world_state", {})
        }
    
    # ==================== دوال إدارة الحالة ====================
    
    async def get_status(self) -> Dict:
        await self._ensure_world_state_manager()
        return {
            "state": self.state.value,
            "components": len(self.components),
            "active_workflows": len(self.active_workflows),
            "total_scans": len(self._scans),
            "total_vulnerabilities": len(self._vulnerabilities),
            "total_accounts": len(self._registered_accounts),
            "scanner_stats": self._scanner_stats,
            "payload_stats": self._payload_manager.get_statistics() if self._payload_manager else {},
            "world_state": await self._world_state_manager.get_summary() if self._world_state_manager else {}
        }
    
    async def list_scans(self) -> List[Dict]:
        return self._scans
    
    async def list_vulnerabilities(self) -> List[Dict]:
        return self._vulnerabilities
    
    async def list_registered_accounts(self) -> List[Dict]:
        return self._registered_accounts
    
    async def list_agents(self) -> List[str]:
        return list(self.components.keys())
    
    async def get_scan_details(self, scan_id: str) -> Optional[Dict]:
        for scan in self._scans:
            if scan.get("id") == scan_id:
                return scan
        return None
    
    async def get_vulnerability_details(self, vuln_id: str) -> Optional[Dict]:
        for vuln in self._vulnerabilities:
            if vuln.get("id") == vuln_id:
                return vuln
        return None
    
    async def get_scanner_statistics(self) -> Dict:
        return self._scanner_stats
    
    async def cancel_workflow(self, workflow_id: str) -> bool:
        if workflow_id in self.active_workflows:
            self.active_workflows.discard(workflow_id)
            return True
        return False
    
    async def _execute_step(self, step: WorkflowStep) -> Any:
        if step.action == "scan":
            return await self.execute_full_scan(step.result or "https://example.com")
        elif step.action == "crawl":
            return await self.execute_crawl(step.result or "https://example.com")
        elif step.action == "register":
            return await self.register_account(step.result or "https://example.com")
        elif step.action == "analyze":
            return {"analyzed": True, "findings": []}
        elif step.action == "exploit":
            return {"exploited": True, "success": False}
        else:
            return {"executed": True}


_default_orchestrator = None

async def get_orchestrator() -> Orchestrator:
    global _default_orchestrator
    if _default_orchestrator is None:
        _default_orchestrator = Orchestrator()
        await _default_orchestrator.start()
    return _default_orchestrator
