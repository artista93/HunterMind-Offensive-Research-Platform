"""
Scan Tester Pro - الإصدار الاحترافي المتكامل
يشمل جميع قدرات HunterMind في لوحة تحكم واحدة
"""

from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect, BackgroundTasks
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from typing import Dict, List, Optional, Any
from datetime import datetime
import asyncio
import uuid
import json
import os
import psutil
from enum import Enum

import sys
sys.path.insert(0, '/workspaces/HunterMind-Offensive-Research-Platform')

# استيراد جميع مكونات المشروع
from orchestration.orchestrator import get_orchestrator
from offensive.scanners.base_scanner import ScanContext, ScanTarget, Severity, Confidence, Finding
from offensive.scanners.xss_scanner import XSSScanner
from offensive.scanners.sqli_scanner import SQLiScanner
from offensive.scanners.idor_scanner import IDORScanner
from offensive.scanners.rce_scanner import RCEScanner
from offensive.scanners.csrf_scanner import CSRFScanner
from offensive.scanners.ssrf_scanner import SSRFScanner
from offensive.scanners.auth_scanner import AuthScanner
from offensive.scanners.api_scanner import APIScanner
from offensive.scanners.graphql_scanner import GraphQLScanner
from offensive.recon.enhanced_crawler import EnhancedCrawler
from offensive.recon.js_processor import JSProcessor
from offensive.recon.api_collector import APICollector
from offensive.recon.form_extractor import FormExtractor
from offensive.recon.attack_surface_mapper import AttackSurfaceMapper
from offensive.payloads.payload_generator import get_payload_generator
from offensive.payloads.payload_mutator import get_payload_mutator
from offensive.payloads.payload_encoder import get_payload_encoder
from offensive.payloads.payload_ranker import get_payload_ranker
from offensive.payloads.payload_library import get_payload_library
from offensive.payloads.payload_evolver import get_payload_evolver
from offensive.payloads.context_payload_builder import get_context_payload_builder
from offensive.exploitation.exploit_orchestrator import get_exploit_orchestrator
from offensive.exploitation.exploit_chains import get_exploit_chains
from offensive.exploitation.exploit_memory import get_exploit_memory
from offensive.exploitation.adaptive_exploitation import get_adaptive_exploitation
from offensive.exploitation.post_exploitation import get_post_exploitation
from offensive.pipelines.recon_pipeline import get_recon_pipeline
from offensive.pipelines.xss_pipeline import get_xss_pipeline
from offensive.pipelines.sqli_pipeline import get_sqli_pipeline
from offensive.pipelines.idor_pipeline import get_idor_pipeline
from offensive.pipelines.api_pipeline import get_api_pipeline
from offensive.pipelines.auth_pipeline import get_auth_pipeline
from offensive.pipelines.attack_chain_pipeline import get_attack_chain_pipeline
from cognition.reasoning.attack_reasoner import get_attack_reasoner, ReasoningContext, AttackPhase, AttackStrategy
from cognition.reflection.reflection_engine import get_reflection_engine
from telemetry.metrics.metrics_engine import get_metrics_engine
from telemetry.logging.structured_logger import get_structured_logger
from storage.sqlite.persistence import get_persistence_manager
from storage.vector_db.vector_store import get_vector_store
from storage.graph_db.graph_store import get_graph_store

import logging
logger = logging.getLogger(__name__)

app = FastAPI(title="HunterMind Scan Tester Pro", version="3.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

templates = Jinja2Templates(directory="interfaces/dashboard/templates")
os.makedirs("interfaces/dashboard/templates", exist_ok=True)
os.makedirs("scan_reports", exist_ok=True)

# تخزين جلسات الفحص
scan_sessions = {}
active_scans = set()
websocket_connections = set()


class ScanSession:
    """جلسة فحص متكاملة"""
    def __init__(self, session_id: str, target_url: str, config: Dict):
        self.id = session_id
        self.target_url = target_url
        self.config = config
        self.status = "pending"
        self.start_time = datetime.now()
        self.end_time = None
        self.progress = 0
        self.current_phase = "initializing"
        self.results = {
            "recon": {},
            "scanners": {},
            "payloads": {},
            "exploitation": {},
            "cognition": {},
            "telemetry": {},
            "summary": {}
        }
        self.error = None


class ScanPhase(Enum):
    INIT = "initialization"
    RECON = "reconnaissance"
    SCAN = "scanning"
    PAYLOAD = "payload_generation"
    EXPLOIT = "exploitation"
    COGNITION = "cognitive_analysis"
    REPORT = "reporting"
    COMPLETE = "complete"


async def run_full_assessment(session_id: str, target_url: str, config: Dict):
    """تنفيذ تقييم كامل بجميع قدرات المشروع"""
    session = scan_sessions.get(session_id)
    if not session:
        return
    
    session.status = "running"
    active_scans.add(session_id)
    
    try:
        # إرسال تحديث WebSocket
        await broadcast_status(session_id, "started", 0, ScanPhase.INIT.value)
        
        # ============================================================
        # المرحلة 1: الاستطلاع المتقدم (Advanced Reconnaissance)
        # ============================================================
        session.current_phase = ScanPhase.RECON.value
        session.progress = 10
        await broadcast_status(session_id, "phase_change", 10, ScanPhase.RECON.value)
        
        recon_results = {}
        
        # 1.1 الزحف المتقدم
        if config.get("recon_crawl", True):
            crawler = EnhancedCrawler(
                max_depth=config.get("depth", 3),
                max_pages=config.get("max_pages", 100),
                use_browser=config.get("use_browser", True),
                stealth_mode=config.get("stealth_mode", True)
            )
            context = ScanContext(target=ScanTarget(url=target_url))
            crawl_result = await crawler.crawl(context)
            recon_results["crawler"] = {
                "pages_found": len(crawl_result.pages_crawled),
                "forms_found": crawl_result.total_forms,
                "api_endpoints": crawl_result.total_api_endpoints,
                "pages": [{"url": p.url, "title": p.title, "depth": p.depth} for p in crawl_result.pages_crawled[:30]]
            }
        
        # 1.2 تحليل JavaScript
        if config.get("recon_js", True):
            js_processor = JSProcessor()
            js_files = await js_processor.find_all_js_files("", target_url)
            js_results = []
            for js_url in js_files[:20]:
                analysis = await js_processor.process_url(js_url, target_url)
                if analysis:
                    js_results.append({
                        "url": js_url,
                        "endpoints": len(analysis.endpoints),
                        "sensitive_info": len(analysis.sensitive_info)
                    })
            recon_results["javascript"] = js_results
        
        # 1.3 جمع واجهات API
        if config.get("recon_api", True):
            api_collector = APICollector()
            api_endpoints = []
            for page in recon_results.get("crawler", {}).get("pages", [])[:20]:
                endpoints = await api_collector.collect_from_html("", page["url"])
                api_endpoints.extend(endpoints)
            recon_results["api_endpoints"] = [
                {"path": e.path, "method": e.method, "full_url": e.full_url}
                for e in api_endpoints[:50]
            ]
        
        # 1.4 استخراج النماذج
        if config.get("recon_forms", True):
            form_extractor = FormExtractor()
            forms_results = []
            for page in recon_results.get("crawler", {}).get("pages", [])[:30]:
                forms = await form_extractor.extract_from_html("", page["url"])
                forms_results.extend(forms.forms)
            recon_results["forms"] = [
                {"action": f.action_url, "method": f.method, "fields_count": len(f.fields), "has_csrf": f.has_csrf_token}
                for f in forms_results[:30]
            ]
        
        # 1.5 تحليل سطح الهجوم
        if config.get("recon_surface", True):
            surface_mapper = AttackSurfaceMapper()
            surface = await surface_mapper.map_attack_surface(target_url, config.get("depth", 3), config.get("max_pages", 100))
            recon_results["attack_surface"] = {
                "total_entry_points": surface.total_entry_points,
                "technologies": [{"name": t.name, "confidence": t.confidence} for t in surface.technologies[:10]],
                "risk_levels": surface.summary.get("risk_levels", {})
            }
        
        session.results["recon"] = recon_results
        session.progress = 30
        await broadcast_status(session_id, "recon_complete", 30, ScanPhase.SCAN.value)
        
        # ============================================================
        # المرحلة 2: الفحص الشامل (Comprehensive Scanning)
        # ============================================================
        session.current_phase = ScanPhase.SCAN.value
        session.progress = 35
        await broadcast_status(session_id, "phase_change", 35, ScanPhase.SCAN.value)
        
        scanner_results = {}
        all_findings = []
        
        scanners_config = [
            ("XSS Scanner", "xss", XSSScanner(), config.get("scan_xss", True)),
            ("SQL Injection Scanner", "sqli", SQLiScanner(), config.get("scan_sqli", True)),
            ("IDOR Scanner", "idor", IDORScanner(), config.get("scan_idor", True)),
            ("RCE Scanner", "rce", RCEScanner(), config.get("scan_rce", True)),
            ("CSRF Scanner", "csrf", CSRFScanner(), config.get("scan_csrf", True)),
            ("SSRF Scanner", "ssrf", SSRFScanner(), config.get("scan_ssrf", True)),
            ("Auth Scanner", "auth", AuthScanner(), config.get("scan_auth", True)),
            ("API Scanner", "api", APIScanner(), config.get("scan_api", True)),
            ("GraphQL Scanner", "graphql", GraphQLScanner(), config.get("scan_graphql", True)),
        ]
        
        for idx, (name, key, scanner, enabled) in enumerate(scanners_config):
            if not enabled:
                continue
            
            await broadcast_status(session_id, "scanning", 35 + (idx * 5), f"scanning_{key}")
            
            try:
                context = ScanContext(target=ScanTarget(url=target_url))
                findings = await scanner.execute_scan(context)
                
                scanner_results[key] = {
                    "name": name,
                    "findings_count": len(findings),
                    "findings": [
                        {
                            "id": f.id if hasattr(f, 'id') else str(i),
                            "type": f.vulnerability_type,
                            "severity": f.severity.value,
                            "confidence": f.confidence.value,
                            "url": f.url,
                            "parameter": f.parameter,
                            "payload": f.payload[:200] if f.payload else None,
                            "evidence": f.evidence[:200] if f.evidence else None,
                            "description": f.description,
                            "remediation": f.remediation,
                            "cvss_score": f.cvss_score
                        }
                        for i, f in enumerate(findings[:20])
                    ]
                }
                
                for f in findings:
                    all_findings.append({
                        "type": f.vulnerability_type,
                        "severity": f.severity.value,
                        "confidence": f.confidence.value,
                        "url": f.url,
                        "parameter": f.parameter,
                        "payload": f.payload,
                        "scanner": name,
                        "cvss_score": f.cvss_score
                    })
                    
            except Exception as e:
                scanner_results[key] = {"name": name, "error": str(e)}
        
        session.results["scanners"] = scanner_results
        session.results["scanners"]["all_findings"] = all_findings
        session.results["scanners"]["total_findings"] = len(all_findings)
        session.progress = 60
        await broadcast_status(session_id, "scan_complete", 60, ScanPhase.PAYLOAD.value)
        
        # ============================================================
        # المرحلة 3: توليد وتحسين الحمولات (Payload Generation & Evolution)
        # ============================================================
        session.current_phase = ScanPhase.PAYLOAD.value
        session.progress = 65
        await broadcast_status(session_id, "phase_change", 65, ScanPhase.PAYLOAD.value)
        
        payload_results = {}
        
        if config.get("payload_generation", True):
            # 3.1 مولد الحمولات
            payload_gen = get_payload_generator()
            xss_payloads = payload_gen.generate_xss_payloads(max_payloads=50)
            sqli_payloads = payload_gen.generate_sqli_payloads(max_payloads=50)
            rce_payloads = payload_gen.generate_rce_payloads(max_payloads=50)
            
            payload_results["generator"] = {
                "xss_count": len(xss_payloads),
                "sqli_count": len(sqli_payloads),
                "rce_count": len(rce_payloads),
                "sample_xss": [p.payload[:100] for p in xss_payloads[:5]],
                "sample_sqli": [p.payload[:100] for p in sqli_payloads[:5]]
            }
            
            # 3.2 محول الحمولات
            if config.get("payload_mutation", True):
                mutator = get_payload_mutator()
                if xss_payloads:
                    mutated = mutator.mutate_payload(xss_payloads[0])
                    payload_results["mutator"] = {
                        "mutations_count": len(mutated),
                        "sample_mutation": mutated[0].mutated.payload[:100] if mutated else None
                    }
            
            # 3.3 مشفر الحمولات
            if config.get("payload_encoding", True):
                encoder = get_payload_encoder()
                payload_results["encoder"] = {
                    "available_encodings": list(encoder.AVAILABLE_ENCODINGS.keys())[:10],
                    "bypass_chains": len(encoder.BYPASS_CHAINS)
                }
            
            # 3.4 مكتبة الحمولات
            if config.get("payload_library", True):
                library = await get_payload_library()
                lib_stats = await library.get_statistics()
                payload_results["library"] = lib_stats
        
        session.results["payloads"] = payload_results
        session.progress = 75
        await broadcast_status(session_id, "payload_complete", 75, ScanPhase.EXPLOIT.value)
        
        # ============================================================
        # المرحلة 4: الاستغلال المتقدم (Advanced Exploitation)
        # ============================================================
        session.current_phase = ScanPhase.EXPLOIT.value
        session.progress = 80
        await broadcast_status(session_id, "phase_change", 80, ScanPhase.EXPLOIT.value)
        
        exploit_results = {}
        
        if config.get("auto_exploit", True) and all_findings:
            # 4.1 منسق الاستغلال
            exploit_orch = get_exploit_orchestrator()
            exploit_results["orchestrator"] = {"status": "ready", "targets": len(all_findings)}
            
            # 4.2 سلاسل الهجوم
            if config.get("attack_chains", True):
                chains = get_exploit_chains()
                chain_suggestions = await chains.suggest_chains(
                    [Finding(**{k:v for k,v in f.items() if k in ['type','url','parameter']}) 
                     for f in all_findings[:5]]
                )
                exploit_results["attack_chains"] = chain_suggestions
            
            # 4.3 ذاكرة الاستغلال
            if config.get("exploit_memory", True):
                memory = get_exploit_memory()
                mem_stats = memory.get_statistics()
                exploit_results["exploit_memory"] = mem_stats
            
            # 4.4 الاستغلال التكيفي
            if config.get("adaptive_exploit", True):
                adaptive = get_adaptive_exploitation()
                adaptive_stats = adaptive.get_strategy_performance()
                exploit_results["adaptive"] = adaptive_stats
            
            # 4.5 ما بعد الاستغلال
            if config.get("post_exploit", True):
                post = get_post_exploitation()
                post_stats = post.get_statistics()
                exploit_results["post_exploitation"] = post_stats
        
        session.results["exploitation"] = exploit_results
        session.progress = 85
        await broadcast_status(session_id, "exploit_complete", 85, ScanPhase.COGNITION.value)
        
        # ============================================================
        # المرحلة 5: التحليل المعرفي (Cognitive Analysis)
        # ============================================================
        session.current_phase = ScanPhase.COGNITION.value
        session.progress = 88
        await broadcast_status(session_id, "phase_change", 88, ScanPhase.COGNITION.value)
        
        cognition_results = {}
        
        if config.get("cognitive_analysis", True) and all_findings:
            # 5.1 محلل الهجمات
            reasoner = await get_attack_reasoner()
            context = ReasoningContext(
                target_url=target_url,
                findings=all_findings,
                target_info=recon_results.get("crawler", {}),
                available_tools=list(scanner_results.keys()),
                phase=AttackPhase.VULNERABILITY_ANALYSIS
            )
            recommendations = await reasoner.analyze_findings(context)
            
            cognition_results["attack_reasoner"] = {
                "recommendations_count": len(recommendations),
                "recommendations": [
                    {
                        "action": r.action,
                        "reason": r.reason,
                        "priority": r.priority,
                        "confidence": r.confidence,
                        "phase": r.phase.value if hasattr(r.phase, 'value') else str(r.phase)
                    }
                    for r in recommendations[:15]
                ],
                "best_recommendation": {
                    "action": (await reasoner.get_best_recommendation()).action,
                    "confidence": (await reasoner.get_best_recommendation()).confidence
                } if await reasoner.get_best_recommendation() else None
            }
            
            # 5.2 محرك التأمل
            if config.get("reflection", True):
                reflection = await get_reflection_engine()
                reflections = await reflection.analyze_scan_results({
                    "findings": all_findings,
                    "pages_scanned": recon_results.get("crawler", {}).get("pages_found", 0)
                })
                cognition_results["reflection"] = {
                    "insights": [r.insight for r in reflections[:5]],
                    "recommendations": [r.recommendations for r in reflections[:3]]
                }
        
        session.results["cognition"] = cognition_results
        session.progress = 95
        await broadcast_status(session_id, "cognition_complete", 95, ScanPhase.REPORT.value)
        
        # ============================================================
        # المرحلة 6: التقارير والمقاييس (Reporting & Telemetry)
        # ============================================================
        session.current_phase = ScanPhase.REPORT.value
        session.progress = 98
        await broadcast_status(session_id, "phase_change", 98, ScanPhase.REPORT.value)
        
        telemetry_results = {}
        
        # 6.1 مقاييس النظام
        if config.get("telemetry", True):
            metrics = await get_metrics_engine()
            metrics_summary = await metrics.get_summary()
            telemetry_results["metrics"] = metrics_summary
        
        # 6.2 التخزين
        if config.get("storage", True):
            try:
                storage = await get_persistence_manager()
                storage_stats = await storage.get_stats()
                telemetry_results["storage"] = {
                    "total_items": storage_stats.total_items,
                    "total_size_bytes": storage_stats.total_size_bytes,
                    "status": storage_stats.status.value
                }
            except:
                pass
        
        session.results["telemetry"] = telemetry_results
        
        # ============================================================
        # المرحلة 7: الملخص النهائي (Final Summary)
        # ============================================================
        critical_count = sum(1 for f in all_findings if f.get("severity") == "critical")
        high_count = sum(1 for f in all_findings if f.get("severity") == "high")
        medium_count = sum(1 for f in all_findings if f.get("severity") == "medium")
        low_count = sum(1 for f in all_findings if f.get("severity") == "low")
        
        risk_score = (critical_count * 10 + high_count * 7 + medium_count * 4 + low_count * 2) / max(1, len(all_findings))
        
        session.results["summary"] = {
            "total_findings": len(all_findings),
            "critical": critical_count,
            "high": high_count,
            "medium": medium_count,
            "low": low_count,
            "risk_score": round(risk_score, 2),
            "risk_level": "Critical" if risk_score > 7 else "High" if risk_score > 5 else "Medium" if risk_score > 3 else "Low",
            "pages_analyzed": recon_results.get("crawler", {}).get("pages_found", 0),
            "scanners_used": len([s for s in scanners_config if s[3]]),
            "payloads_generated": payload_results.get("generator", {}).get("xss_count", 0) + 
                                  payload_results.get("generator", {}).get("sqli_count", 0) +
                                  payload_results.get("generator", {}).get("rce_count", 0),
            "recommendations_count": cognition_results.get("attack_reasoner", {}).get("recommendations_count", 0),
            "scan_duration": (datetime.now() - session.start_time).total_seconds(),
            "capabilities_used": [
                cap for cap, enabled in config.items() if enabled and cap not in ['target_url', 'depth', 'max_pages']
            ][:20]
        }
        
        session.status = "completed"
        session.progress = 100
        session.current_phase = ScanPhase.COMPLETE.value
        await broadcast_status(session_id, "completed", 100, ScanPhase.COMPLETE.value)
        
        # حفظ التقرير
        report_path = f"scan_reports/report_{session_id}.json"
        with open(report_path, "w") as f:
            json.dump({
                "session_id": session.id,
                "target_url": session.target_url,
                "start_time": session.start_time.isoformat(),
                "end_time": datetime.now().isoformat(),
                "results": session.results
            }, f, indent=2, default=str)
        
    except Exception as e:
        session.status = "failed"
        session.error = str(e)
        logger.error(f"Scan failed: {e}")
        await broadcast_status(session_id, "failed", session.progress, session.current_phase, str(e))
    
    finally:
        session.end_time = datetime.now()
        active_scans.discard(session_id)


async def broadcast_status(session_id: str, event: str, progress: int, phase: str = None, error: str = None):
    """بث حالة الفحص عبر WebSocket"""
    message = {
        "session_id": session_id,
        "event": event,
        "progress": progress,
        "phase": phase,
        "timestamp": datetime.now().isoformat()
    }
    if error:
        message["error"] = error
    
    for ws in websocket_connections:
        try:
            await ws.send_json(message)
        except:
            pass


@app.websocket("/ws/scan/{session_id}")
async def websocket_endpoint(websocket: WebSocket, session_id: str):
    await websocket.accept()
    websocket_connections.add(websocket)
    try:
        while True:
            await websocket.receive_text()
    except:
        websocket_connections.discard(websocket)


@app.get("/", response_class=HTMLResponse)
async def scan_tester(request: Request):
    return templates.TemplateResponse("scan_tester_pro.html", {
        "request": request,
        "active_scans": len(active_scans)
    })


@app.post("/api/scan/start")
async def start_scan(
    target_url: str,
    depth: int = 3,
    max_pages: int = 100,
    use_browser: bool = True,
    stealth_mode: bool = True,
    # Recon
    recon_crawl: bool = True,
    recon_js: bool = True,
    recon_api: bool = True,
    recon_forms: bool = True,
    recon_surface: bool = True,
    # Scanners
    scan_xss: bool = True,
    scan_sqli: bool = True,
    scan_idor: bool = True,
    scan_rce: bool = True,
    scan_csrf: bool = True,
    scan_ssrf: bool = True,
    scan_auth: bool = True,
    scan_api: bool = True,
    scan_graphql: bool = True,
    # Payloads
    payload_generation: bool = True,
    payload_mutation: bool = True,
    payload_encoding: bool = True,
    payload_library: bool = True,
    # Exploitation
    auto_exploit: bool = True,
    attack_chains: bool = True,
    exploit_memory: bool = True,
    adaptive_exploit: bool = True,
    post_exploit: bool = True,
    # Cognition
    cognitive_analysis: bool = True,
    reflection: bool = True,
    # Telemetry
    telemetry: bool = True,
    storage: bool = True,
    background_tasks: BackgroundTasks
):
    session_id = str(uuid.uuid4())[:8]
    
    config = {
        "depth": depth,
        "max_pages": max_pages,
        "use_browser": use_browser,
        "stealth_mode": stealth_mode,
        "recon_crawl": recon_crawl,
        "recon_js": recon_js,
        "recon_api": recon_api,
        "recon_forms": recon_forms,
        "recon_surface": recon_surface,
        "scan_xss": scan_xss,
        "scan_sqli": scan_sqli,
        "scan_idor": scan_idor,
        "scan_rce": scan_rce,
        "scan_csrf": scan_csrf,
        "scan_ssrf": scan_ssrf,
        "scan_auth": scan_auth,
        "scan_api": scan_api,
        "scan_graphql": scan_graphql,
        "payload_generation": payload_generation,
        "payload_mutation": payload_mutation,
        "payload_encoding": payload_encoding,
        "payload_library": payload_library,
        "auto_exploit": auto_exploit,
        "attack_chains": attack_chains,
        "exploit_memory": exploit_memory,
        "adaptive_exploit": adaptive_exploit,
        "post_exploit": post_exploit,
        "cognitive_analysis": cognitive_analysis,
        "reflection": reflection,
        "telemetry": telemetry,
        "storage": storage
    }
    
    session = ScanSession(session_id, target_url, config)
    scan_sessions[session_id] = session
    
    background_tasks.add_task(run_full_assessment, session_id, target_url, config)
    
    return {"session_id": session_id, "status": "started"}


@app.get("/api/scan/status/{session_id}")
async def get_scan_status(session_id: str):
    session = scan_sessions.get(session_id)
    if not session:
        return {"error": "Session not found"}
    
    return {
        "id": session.id,
        "target_url": session.target_url,
        "status": session.status,
        "progress": session.progress,
        "current_phase": session.current_phase,
        "start_time": session.start_time.isoformat(),
        "end_time": session.end_time.isoformat() if session.end_time else None,
        "results": session.results,
        "error": session.error
    }


@app.get("/api/scan/report/{session_id}")
async def download_report(session_id: str):
    report_path = f"scan_reports/report_{session_id}.json"
    if os.path.exists(report_path):
        return FileResponse(report_path, media_type='application/json', filename=f"huntermind_report_{session_id}.json")
    return {"error": "Report not found"}


@app.get("/api/capabilities")
async def get_capabilities():
    return {
        "version": "3.0.0",
        "reconnaissance": [
            {"name": "Web Crawler", "description": "زحف الموقع واكتشاف الصفحات", "enabled": True},
            {"name": "JavaScript Analyzer", "description": "تحليل JS واستخراج endpoints", "enabled": True},
            {"name": "API Collector", "description": "جمع واجهات API", "enabled": True},
            {"name": "Form Extractor", "description": "استخراج وتحليل النماذج", "enabled": True},
            {"name": "Attack Surface Mapper", "description": "رسم سطح الهجوم", "enabled": True}
        ],
        "scanners": [
            {"name": "XSS Scanner", "description": "كشف ثغرات XSS", "enabled": True},
            {"name": "SQL Injection Scanner", "description": "كشف ثغرات SQLi", "enabled": True},
            {"name": "IDOR Scanner", "description": "كشف ثغرات IDOR", "enabled": True},
            {"name": "RCE Scanner", "description": "كشف ثغرات RCE", "enabled": True},
            {"name": "CSRF Scanner", "description": "كشف ثغرات CSRF", "enabled": True},
            {"name": "SSRF Scanner", "description": "كشف ثغرات SSRF", "enabled": True},
            {"name": "Auth Scanner", "description": "اختبار المصادقة", "enabled": True},
            {"name": "API Scanner", "description": "فحص أمان APIs", "enabled": True},
            {"name": "GraphQL Scanner", "description": "فحص أمان GraphQL", "enabled": True}
        ],
        "payloads": [
            {"name": "Payload Generator", "description": "توليد حمولات", "enabled": True},
            {"name": "Payload Mutator", "description": "تحوير الحمولات", "enabled": True},
            {"name": "Payload Encoder", "description": "ترميز الحمولات", "enabled": True},
            {"name": "Payload Library", "description": "مكتبة الحمولات", "enabled": True},
            {"name": "Payload Evolver", "description": "تطور الحمولات", "enabled": True}
        ],
        "exploitation": [
            {"name": "Auto Exploitation", "description": "استغلال تلقائي", "enabled": True},
            {"name": "Attack Chains", "description": "سلاسل الهجوم", "enabled": True},
            {"name": "Exploit Memory", "description": "ذاكرة الاستغلال", "enabled": True},
            {"name": "Adaptive Exploitation", "description": "استغلال تكيفي", "enabled": True},
            {"name": "Post Exploitation", "description": "ما بعد الاستغلال", "enabled": True}
        ],
        "cognition": [
            {"name": "Attack Reasoner", "description": "تحليل وتوصيات", "enabled": True},
            {"name": "Reflection Engine", "description": "تحليل النتائج", "enabled": True}
        ],
        "total_capabilities": 28
    }


# قالب HTML احترافي
html_template = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>HunterMind Pro - Ultimate Security Scanner</title>
    <script src="https://cdn.jsdelivr.net/npm/echarts@5.4.3/dist/echarts.min.js"></script>
    <style>
        :root {
            --primary: #6366f1;
            --primary-dark: #4f46e5;
            --success: #10b981;
            --warning: #f59e0b;
            --danger: #ef4444;
            --info: #3b82f6;
            --dark: #1e293b;
            --bg-dark: #0f172a;
            --bg-card: rgba(30, 41, 59, 0.95);
        }
        
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: var(--bg-dark);
            color: #fff;
            min-height: 100vh;
        }
        
        .sidebar {
            position: fixed;
            left: 0;
            top: 0;
            width: 280px;
            height: 100vh;
            background: linear-gradient(180deg, #1e293b 0%, #0f172a 100%);
            border-right: 1px solid rgba(255,255,255,0.1);
            z-index: 100;
            overflow-y: auto;
        }
        
        .logo { padding: 24px; text-align: center; border-bottom: 1px solid rgba(255,255,255,0.1); }
        .logo span { font-size: 1.5rem; font-weight: bold; background: linear-gradient(135deg, #667eea, #764ba2); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
        
        .nav-menu { padding: 16px; }
        .nav-item {
            display: flex;
            align-items: center;
            padding: 12px 16px;
            margin-bottom: 8px;
            border-radius: 12px;
            color: rgba(255,255,255,0.7);
            cursor: pointer;
            transition: all 0.3s;
        }
        .nav-item:hover, .nav-item.active { background: rgba(99,102,241,0.2); color: #fff; }
        .nav-item i { margin-right: 12px; font-size: 1.2rem; }
        
        .main-content { margin-left: 280px; padding: 24px; }
        
        .top-bar {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 24px;
            padding: 16px 24px;
            background: var(--bg-card);
            border-radius: 16px;
            backdrop-filter: blur(10px);
        }
        
        .stats-grid { display: grid; grid-template-columns: repeat(5, 1fr); gap: 16px; margin-bottom: 24px; }
        .stat-card {
            background: var(--bg-card);
            border-radius: 16px;
            padding: 16px;
            text-align: center;
            border: 1px solid rgba(255,255,255,0.1);
            transition: all 0.3s;
        }
        .stat-card:hover { transform: translateY(-3px); border-color: var(--primary); }
        .stat-value { font-size: 1.8rem; font-weight: bold; color: var(--primary); }
        .stat-label { font-size: 0.75rem; color: rgba(255,255,255,0.7); margin-top: 8px; }
        
        .progress-section {
            background: var(--bg-card);
            border-radius: 16px;
            padding: 20px;
            margin-bottom: 24px;
            border: 1px solid rgba(255,255,255,0.1);
        }
        .progress-bar {
            height: 8px;
            background: rgba(255,255,255,0.1);
            border-radius: 4px;
            overflow: hidden;
        }
        .progress-fill {
            height: 100%;
            background: linear-gradient(90deg, var(--primary), var(--primary-dark));
            width: 0%;
            transition: width 0.3s;
        }
        .phase-text { margin-top: 12px; font-size: 0.85rem; color: rgba(255,255,255,0.6); }
        
        .card {
            background: var(--bg-card);
            border-radius: 16px;
            padding: 20px;
            margin-bottom: 24px;
            border: 1px solid rgba(255,255,255,0.1);
        }
        .card-title {
            font-size: 1.1rem;
            margin-bottom: 16px;
            color: var(--primary);
            border-left: 3px solid var(--primary);
            padding-left: 12px;
        }
        
        .finding-item {
            background: rgba(0,0,0,0.2);
            border-radius: 12px;
            padding: 12px;
            margin-bottom: 12px;
            border-left: 3px solid;
        }
        .severity { display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 0.7rem; font-weight: 600; }
        .severity-critical { background: #ef4444; }
        .severity-high { background: #f59e0b; }
        .severity-medium { background: #eab308; color: #333; }
        .severity-low { background: #10b981; }
        
        .checkbox-group { display: flex; flex-wrap: wrap; gap: 12px; margin-bottom: 16px; }
        .checkbox-item { display: flex; align-items: center; gap: 8px; font-size: 0.85rem; }
        
        button {
            background: linear-gradient(135deg, var(--primary), var(--primary-dark));
            border: none;
            padding: 14px 24px;
            border-radius: 12px;
            color: white;
            font-weight: 600;
            cursor: pointer;
            width: 100%;
            transition: all 0.3s;
        }
        button:hover { transform: translateY(-2px); box-shadow: 0 10px 20px -5px rgba(99,102,241,0.4); }
        button:disabled { opacity: 0.5; cursor: not-allowed; }
        
        input, select {
            width: 100%;
            padding: 10px;
            background: rgba(0,0,0,0.3);
            border: 1px solid rgba(255,255,255,0.2);
            border-radius: 10px;
            color: white;
            margin-bottom: 16px;
        }
        
        .badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.7rem;
            font-weight: 600;
        }
        .badge-running { background: #f59e0b; }
        .badge-completed { background: #10b981; }
        
        @media (max-width: 768px) {
            .sidebar { transform: translateX(-100%); transition: transform 0.3s; }
            .sidebar.open { transform: translateX(0); }
            .main-content { margin-left: 0; }
            .stats-grid { grid-template-columns: repeat(2, 1fr); }
        }
    </style>
</head>
<body>
    <div class="sidebar" id="sidebar">
        <div class="logo"><span>🦅 HunterMind Pro</span></div>
        <nav class="nav-menu">
            <div class="nav-item active"><i>🎯</i> Dashboard</div>
            <div class="nav-item"><i>🔍</i> Scans</div>
            <div class="nav-item"><i>📊</i> Reports</div>
            <div class="nav-item"><i>⚙️</i> Settings</div>
        </nav>
    </div>
    
    <div class="main-content">
        <div class="top-bar">
            <div><strong>Ultimate Security Scanner</strong><br><small>All capabilities activated</small></div>
            <div style="display: flex; gap: 16px; align-items: center;">
                <span id="wsStatus" style="width: 10px; height: 10px; border-radius: 50%; display: inline-block;"></span>
                <span>🟢 System Ready</span>
                <span onclick="toggleSidebar()" style="cursor: pointer;">☰</span>
            </div>
        </div>
        
        <div class="stats-grid">
            <div class="stat-card"><div class="stat-value" id="totalScans">0</div><div class="stat-label">Total Scans</div></div>
            <div class="stat-card"><div class="stat-value" id="activeScans">0</div><div class="stat-label">Active Scans</div></div>
            <div class="stat-card"><div class="stat-value" id="capabilitiesCount">28</div><div class="stat-label">Capabilities</div></div>
            <div class="stat-card"><div class="stat-value" id="findingsTotal">0</div><div class="stat-label">Findings</div></div>
            <div class="stat-card"><div class="stat-value" id="riskScore">0</div><div class="stat-label">Risk Score</div></div>
        </div>
        
        <div class="progress-section" id="progressSection" style="display: none;">
            <div class="progress-bar"><div class="progress-fill" id="progressFill"></div></div>
            <div class="phase-text" id="phaseText">Initializing...</div>
        </div>
        
        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 24px;">
            <div class="card">
                <div class="card-title">🎯 Target Configuration</div>
                <input type="text" id="targetUrl" placeholder="https://example.com" value="http://localhost:8080">
                <input type="number" id="depth" placeholder="Crawl Depth" value="3" min="1" max="5">
                <input type="number" id="maxPages" placeholder="Max Pages" value="100" min="10" max="500">
                
                <div class="card-title" style="margin-top: 16px;">🔧 Scanner Selection</div>
                <div class="checkbox-group">
                    <label class="checkbox-item"><input type="checkbox" id="scanXSS" checked> XSS</label>
                    <label class="checkbox-item"><input type="checkbox" id="scanSQLi" checked> SQLi</label>
                    <label class="checkbox-item"><input type="checkbox" id="scanIDOR" checked> IDOR</label>
                    <label class="checkbox-item"><input type="checkbox" id="scanRCE" checked> RCE</label>
                    <label class="checkbox-item"><input type="checkbox" id="scanCSRF" checked> CSRF</label>
                    <label class="checkbox-item"><input type="checkbox" id="scanSSRF" checked> SSRF</label>
                    <label class="checkbox-item"><input type="checkbox" id="scanAuth" checked> Auth</label>
                    <label class="checkbox-item"><input type="checkbox" id="scanAPI" checked> API</label>
                    <label class="checkbox-item"><input type="checkbox" id="scanGraphQL" checked> GraphQL</label>
                </div>
                
                <div class="card-title">🧠 Advanced Options</div>
                <div class="checkbox-group">
                    <label class="checkbox-item"><input type="checkbox" id="payloadGen" checked> Payload Generation</label>
                    <label class="checkbox-item"><input type="checkbox" id="autoExploit" checked> Auto Exploitation</label>
                    <label class="checkbox-item"><input type="checkbox" id="attackChains" checked> Attack Chains</label>
                    <label class="checkbox-item"><input type="checkbox" id="cognitiveAnalysis" checked> Cognitive Analysis</label>
                    <label class="checkbox-item"><input type="checkbox" id="stealthMode" checked> Stealth Mode</label>
                </div>
                
                <button id="startBtn" onclick="startScan()">🚀 Start Comprehensive Assessment</button>
            </div>
            
            <div class="card">
                <div class="card-title">📊 Live Results</div>
                <div id="resultsArea" style="max-height: 500px; overflow-y: auto;">
                    <div style="text-align: center; padding: 40px; color: rgba(255,255,255,0.5);">
                        Enter a URL and click Start Assessment
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <script>
        let currentSessionId = null;
        let statusInterval = null;
        let ws = null;
        
        function connectWebSocket(sessionId) {
            const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
            ws = new WebSocket(`${protocol}//${location.host}/ws/scan/${sessionId}`);
            ws.onmessage = (e) => {
                const data = JSON.parse(e.data);
                document.getElementById('progressFill').style.width = data.progress + '%';
                document.getElementById('phaseText').innerHTML = `<strong>Phase:</strong> ${data.phase} | <strong>Progress:</strong> ${data.progress}%`;
                if (data.event === 'completed') {
                    clearInterval(statusInterval);
                    document.getElementById('startBtn').disabled = false;
                    document.getElementById('startBtn').textContent = '🚀 Start Comprehensive Assessment';
                }
            };
        }
        
        async function startScan() {
            const targetUrl = document.getElementById('targetUrl').value;
            if (!targetUrl) { alert('Enter target URL'); return; }
            
            const params = new URLSearchParams();
            params.append('target_url', targetUrl);
            params.append('depth', document.getElementById('depth').value);
            params.append('max_pages', document.getElementById('maxPages').value);
            params.append('scan_xss', document.getElementById('scanXSS').checked);
            params.append('scan_sqli', document.getElementById('scanSQLi').checked);
            params.append('scan_idor', document.getElementById('scanIDOR').checked);
            params.append('scan_rce', document.getElementById('scanRCE').checked);
            params.append('scan_csrf', document.getElementById('scanCSRF').checked);
            params.append('scan_ssrf', document.getElementById('scanSSRF').checked);
            params.append('scan_auth', document.getElementById('scanAuth').checked);
            params.append('scan_api', document.getElementById('scanAPI').checked);
            params.append('scan_graphql', document.getElementById('scanGraphQL').checked);
            params.append('payload_generation', document.getElementById('payloadGen').checked);
            params.append('auto_exploit', document.getElementById('autoExploit').checked);
            params.append('attack_chains', document.getElementById('attackChains').checked);
            params.append('cognitive_analysis', document.getElementById('cognitiveAnalysis').checked);
            params.append('stealth_mode', document.getElementById('stealthMode').checked);
            
            document.getElementById('startBtn').disabled = true;
            document.getElementById('startBtn').textContent = '🔄 Scanning...';
            document.getElementById('progressSection').style.display = 'block';
            document.getElementById('resultsArea').innerHTML = '<div style="text-align: center; padding: 20px;"><div class="progress-bar"><div class="progress-fill" style="width: 0%;"></div></div><p>Initializing scan...</p></div>';
            
            try {
                const response = await fetch(`/api/scan/start?${params}`, { method: 'POST' });
                const data = await response.json();
                currentSessionId = data.session_id;
                connectWebSocket(currentSessionId);
                if (statusInterval) clearInterval(statusInterval);
                statusInterval = setInterval(checkStatus, 2000);
            } catch(e) { alert('Error: ' + e); document.getElementById('startBtn').disabled = false; }
        }
        
        async function checkStatus() {
            if (!currentSessionId) return;
            try {
                const response = await fetch(`/api/scan/status/${currentSessionId}`);
                const data = await response.json();
                if (data.status === 'completed' || data.status === 'failed') {
                    clearInterval(statusInterval);
                    document.getElementById('startBtn').disabled = false;
                    document.getElementById('startBtn').textContent = '🚀 Start Comprehensive Assessment';
                    displayResults(data);
                    document.getElementById('progressFill').style.width = '100%';
                    document.getElementById('phaseText').innerHTML = '✅ Scan completed!';
                }
            } catch(e) { console.error(e); }
        }
        
        function displayResults(data) {
            const results = data.results;
            const summary = results.summary || {};
            const findings = results.scanners?.all_findings || [];
            
            document.getElementById('findingsTotal').textContent = summary.total_findings || 0;
            document.getElementById('riskScore').textContent = summary.risk_score || 0;
            
            let html = `
                <div style="margin-bottom: 16px;">
                    <span class="badge badge-completed">COMPLETED</span>
                    <span style="float: right;">Duration: ${Math.floor(summary.scan_duration || 0)}s</span>
                </div>
                <div style="background: rgba(0,0,0,0.2); border-radius: 12px; padding: 12px; margin-bottom: 16px;">
                    <strong>Risk Level:</strong> 
                    <span style="color: ${summary.risk_level === 'Critical' ? '#ef4444' : summary.risk_level === 'High' ? '#f59e0b' : '#10b981'}">
                        ${summary.risk_level || 'Unknown'}
                    </span>
                    <br>
                    <strong>Risk Score:</strong> ${summary.risk_score || 0}/10
                </div>
                
                <div style="display: grid; grid-template-columns: repeat(4, 1fr); gap: 8px; margin-bottom: 16px;">
                    <div style="text-align: center;"><span style="color: #ef4444; font-size: 1.5rem; font-weight: bold;">${summary.critical || 0}</span><br>Critical</div>
                    <div style="text-align: center;"><span style="color: #f59e0b; font-size: 1.5rem; font-weight: bold;">${summary.high || 0}</span><br>High</div>
                    <div style="text-align: center;"><span style="color: #eab308; font-size: 1.5rem; font-weight: bold;">${summary.medium || 0}</span><br>Medium</div>
                    <div style="text-align: center;"><span style="color: #10b981; font-size: 1.5rem; font-weight: bold;">${summary.low || 0}</span><br>Low</div>
                </div>
            `;
            
            if (findings.length > 0) {
                html += `<div class="card-title">⚠️ Vulnerabilities Found (${findings.length})</div>`;
                findings.slice(0, 10).forEach(f => {
                    html += `
                        <div class="finding-item" style="border-left-color: ${f.severity === 'critical' ? '#ef4444' : f.severity === 'high' ? '#f59e0b' : '#eab308'}">
                            <span class="severity severity-${f.severity}">${f.severity.toUpperCase()}</span>
                            <strong>${f.type}</strong><br>
                            <small>📍 ${f.url}</small><br>
                            <small>🎯 ${f.parameter ? `Parameter: ${f.parameter}` : 'No parameter'}</small>
                        </div>
                    `;
                });
                if (findings.length > 10) html += `<div style="text-align: center; margin-top: 8px;">... and ${findings.length - 10} more findings</div>`;
            } else {
                html += `<div style="background: rgba(16,185,129,0.1); border-radius: 12px; padding: 20px; text-align: center;">✅ No vulnerabilities found</div>`;
            }
            
            if (results.cognition?.attack_reasoner?.recommendations?.length > 0) {
                html += `<div class="card-title" style="margin-top: 16px;">💡 Recommendations</div>`;
                results.cognition.attack_reasoner.recommendations.slice(0, 5).forEach(r => {
                    html += `<div class="finding-item" style="border-left-color: #6366f1;"><strong>🎯 ${r.action}</strong><br><small>${r.reason}</small><br><small>Priority: ${r.priority} | Confidence: ${Math.round(r.confidence * 100)}%</small></div>`;
                });
            }
            
            document.getElementById('resultsArea').innerHTML = html;
        }
        
        async function loadRecentScans() {
            try {
                const response = await fetch('/api/scan/list');
                const scans = await response.json();
                document.getElementById('totalScans').textContent = scans.length;
                document.getElementById('activeScans').textContent = scans.filter(s => s.status === 'running').length;
            } catch(e) {}
        }
        
        function toggleSidebar() { document.getElementById('sidebar').classList.toggle('open'); }
        
        setInterval(loadRecentScans, 5000);
        loadRecentScans();
    </script>
</body>
</html>'''

with open("interfaces/dashboard/templates/scan_tester_pro.html", "w") as f:
    f.write(html_template)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5002, reload=False)
