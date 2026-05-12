import asyncio
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

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
    """
    المنسق الرئيسي المتقدم - يدير جميع مكونات المنصة
    """
    
    def __init__(self):
        self.state = OrchestratorState.INITIALIZING
        self.components: Dict[str, Any] = {}
        self.workflows: Dict[str, List[WorkflowStep]] = {}
        self.active_workflows: Set[str] = set()
        self._lock = asyncio.Lock()
        
        # تخزين النتائج
        self._scans: List[Dict] = []
        self._vulnerabilities: List[Dict] = []
        self._registered_accounts: List[Dict] = []
        
        logger.info("Orchestrator initialized")
    
    async def register_component(self, name: str, component: Any):
        async with self._lock:
            self.components[name] = component
            logger.info(f"Component registered: {name}")
    
    async def start(self):
        self.state = OrchestratorState.RUNNING
        logger.info("Orchestrator started")
    
    async def stop(self):
        self.state = OrchestratorState.STOPPING
        for workflow_id in self.active_workflows:
            await self.cancel_workflow(workflow_id)
        self.state = OrchestratorState.STOPPED
        logger.info("Orchestrator stopped")
    
    async def create_workflow(self, name: str, steps: List[WorkflowStep]) -> str:
        import uuid
        workflow_id = str(uuid.uuid4())[:8]
        self.workflows[workflow_id] = steps
        logger.info(f"Workflow created: {name} ({workflow_id})")
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
                logger.debug(f"Step {step.name} completed")
            except Exception as e:
                step.status = "failed"
                step.error = str(e)
                logger.error(f"Step {step.name} failed: {e}")
                break
        
        self.active_workflows.discard(workflow_id)
        return results
    
    # ==================== الدوال الجديدة المطلوبة ====================
    
    async def execute_full_scan(self, url: str, depth: int = 3, max_pages: int = 50) -> Dict:
        """
        فحص شامل للموقع (زحف + فحص جميع الصفحات)
        
        Args:
            url: رابط الموقع
            depth: عمق الزحف
            max_pages: الحد الأقصى للصفحات
        
        Returns:
            نتائج الفحص
        """
        logger.info(f"Starting full scan on {url} (depth={depth}, max_pages={max_pages})")
        
        # ========== 1. الزحف ==========
        crawl_result = await self._execute_crawl(url, depth, max_pages)
        
        if not crawl_result.get("pages"):
            return {
                "pages_scanned": 0,
                "total_findings": 0,
                "findings": [],
                "error": "No pages discovered"
            }
        
        pages = crawl_result["pages"]
        all_findings = []
        
        # ========== 2. فحص كل صفحة ==========
        for i, page_url in enumerate(pages[:max_pages], 1):
            logger.info(f"Scanning [{i}/{min(len(pages), max_pages)}]: {page_url[:80]}")
            
            page_findings = await self._scan_page(page_url)
            all_findings.extend(page_findings)
        
        # ========== 3. حفظ النتائج ==========
        scan_id = f"scan_{len(self._scans)+1:03d}"
        scan_result = {
            "id": scan_id,
            "target": url,
            "pages_scanned": len(pages[:max_pages]),
            "findings_count": len(all_findings),
            "findings": all_findings,
            "date": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        self._scans.append(scan_result)
        
        for f in all_findings:
            self._vulnerabilities.append({
                "id": f"vuln_{len(self._vulnerabilities)+1:03d}",
                "type": f.get("type", "Unknown"),
                "severity": f.get("severity", "info"),
                "url": f.get("url", ""),
                "parameter": f.get("parameter", "N/A"),
                "payload": f.get("payload", "N/A")
            })
        
        return {
            "pages_scanned": scan_result["pages_scanned"],
            "total_findings": len(all_findings),
            "findings": all_findings[:10],
            "scan_id": scan_id
        }
    
    async def _execute_crawl(self, url: str, depth: int, max_pages: int) -> Dict:
        """تنفيذ الزحف الفعلي"""
        try:
            from offensive.recon.enhanced_crawler import EnhancedCrawler
            from offensive.scanners.base_scanner import ScanContext, ScanTarget
            
            crawler = EnhancedCrawler(max_depth=depth, max_pages=max_pages)
            context = ScanContext(target=ScanTarget(url=url))
            result = await crawler.crawl(context)
            
            pages = [page.url for page in result.pages_crawled]
            if url not in pages:
                pages.insert(0, url)
            
            return {
                "pages": pages,
                "total_pages": len(pages),
                "total_forms": result.total_forms,
                "total_apis": result.total_api_endpoints
            }
        except Exception as e:
            logger.error(f"Crawl failed: {e}")
            return {"pages": [url], "total_pages": 1, "error": str(e)}
    
    async def _scan_page(self, url: str) -> List[Dict]:
        """فحص صفحة واحدة باستخدام جميع الفاحصات"""
        findings = []
        
        try:
            from offensive.scanners.xss_scanner import XSSScanner
            from offensive.scanners.sqli_scanner import SQLiScanner
            from offensive.scanners.idor_scanner import IDORScanner
            from offensive.scanners.base_scanner import ScanContext, ScanTarget
            
            context = ScanContext(target=ScanTarget(url=url))
            
            # فحص XSS
            try:
                scanner = XSSScanner()
                xss_findings = await scanner.execute_scan(context)
                for f in xss_findings:
                    findings.append({
                        "type": f.vulnerability_type,
                        "severity": f.severity.value,
                        "url": f.url,
                        "parameter": f.parameter,
                        "payload": f.payload
                    })
            except Exception as e:
                logger.debug(f"XSS scan error on {url}: {e}")
            
            # فحص SQLi
            try:
                scanner = SQLiScanner()
                sqli_findings = await scanner.execute_scan(context)
                for f in sqli_findings:
                    findings.append({
                        "type": f.vulnerability_type,
                        "severity": f.severity.value,
                        "url": f.url,
                        "parameter": f.parameter,
                        "payload": f.payload
                    })
            except Exception as e:
                logger.debug(f"SQLi scan error on {url}: {e}")
            
            # فحص IDOR
            try:
                scanner = IDORScanner()
                idor_findings = await scanner.execute_scan(context)
                for f in idor_findings:
                    findings.append({
                        "type": f.vulnerability_type,
                        "severity": f.severity.value,
                        "url": f.url,
                        "parameter": f.parameter,
                        "payload": f.payload
                    })
            except Exception as e:
                logger.debug(f"IDOR scan error on {url}: {e}")
            
        except Exception as e:
            logger.error(f"Page scan error: {e}")
        
        return findings
    
    async def execute_crawl(self, url: str, depth: int = 3, max_pages: int = 100) -> Dict:
        """زحف الموقع فقط"""
        result = await self._execute_crawl(url, depth, max_pages)
        return {
            "total_pages": result.get("total_pages", 0),
            "total_forms": result.get("total_forms", 0),
            "total_apis": result.get("total_apis", 0),
            "pages": result.get("pages", [])[:20]
        }
    
    async def register_account(self, url: str, username: str = None, password: str = None) -> Dict:
        """تسجيل حساب جديد"""
        try:
            from agents.auth_agent.registration_agent import get_registration_agent
            
            agent = await get_registration_agent()
            await agent.initialize()
            await agent.start()
            
            result = await agent.register(url, username=username, password=password)
            
            await agent.stop()
            
            if result.success:
                self._registered_accounts.append({
                    "username": result.username,
                    "password": result.password,
                    "email": result.email,
                    "url": url,
                    "created_at": datetime.now().isoformat()
                })
                return {
                    "success": True,
                    "username": result.username,
                    "password": result.password,
                    "email": result.email,
                    "message": result.message
                }
            else:
                return {"success": False, "message": result.message}
                
        except Exception as e:
            logger.error(f"Registration failed: {e}")
            return {"success": False, "message": str(e)}
    
    async def login(self, username: str, password: str) -> Dict:
        """تسجيل الدخول (محاكاة - لتطوير لاحق)"""
        # يتم تطوير هذه الدالة لاحقاً
        return {"success": True, "message": "Session saved"}
    
    async def full_automation(self, register_url: str, target_url: str) -> Dict:
        """أتمتة كاملة: تسجيل → فحص"""
        # تسجيل حساب
        reg_result = await self.register_account(register_url)
        
        if not reg_result.get("success"):
            return {"success": False, "message": reg_result.get("message")}
        
        # فحص الموقع
        scan_result = await self.execute_full_scan(target_url)
        
        return {
            "success": True,
            "username": reg_result.get("username"),
            "password": reg_result.get("password"),
            "total_findings": scan_result.get("total_findings", 0),
            "scan_id": scan_result.get("scan_id")
        }
    
    async def get_status(self) -> Dict:
        return {
            "state": self.state.value,
            "components": len(self.components),
            "components_list": list(self.components.keys()),
            "active_workflows": len(self.active_workflows),
            "total_workflows": len(self.workflows),
            "total_scans": len(self._scans),
            "total_vulnerabilities": len(self._vulnerabilities),
            "total_accounts": len(self._registered_accounts)
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
    
    async def cancel_workflow(self, workflow_id: str) -> bool:
        if workflow_id in self.active_workflows:
            self.active_workflows.discard(workflow_id)
            logger.info(f"Workflow {workflow_id} cancelled")
            return True
        return False
    
    async def _execute_step(self, step: WorkflowStep) -> Any:
        """تنفيذ خطوة واحدة (محاكاة)"""
        if step.action == "scan":
            return {"scanned": True, "results": []}
        elif step.action == "analyze":
            return {"analyzed": True, "findings": []}
        elif step.action == "exploit":
            return {"exploited": True, "success": False}
        else:
            return {"executed": True}


_default_orchestrator = None


async def get_orchestrator() -> Orchestrator:
    """الحصول على نسخة عالمية من المنسق"""
    global _default_orchestrator
    if _default_orchestrator is None:
        _default_orchestrator = Orchestrator()
        await _default_orchestrator.start()
    return _default_orchestrator
