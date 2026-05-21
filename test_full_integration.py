"""
اختبار التكامل الشامل - هل كل الملفات مرتبطة وتشتغل؟
"""

import sys
import asyncio
import traceback

RESULTS = {"pass": 0, "fail": 0, "skip": 0}


def check(name, success, detail=""):
    if success:
        RESULTS["pass"] += 1
        print(f"   ✅ {name}")
    else:
        RESULTS["fail"] += 1
        print(f"   ❌ {name} - {detail}")


async def main():
    print("=" * 60)
    print("🔍 فحص التكامل الشامل لجميع مكونات المشروع")
    print("=" * 60)
    
    # ============================================================
    # 1. SCHEMAS
    # ============================================================
    print(f"\n📋 1. Schemas (7 عقود بيانات)")
    
    try:
        from schemas.vulnerability import Vulnerability, Severity, generate_vulnerability_id
        v = Vulnerability(id=generate_vulnerability_id(), type=None, title="test", description="test", url="http://test.com")
        check("vulnerability.py", v is not None)
    except Exception as e: check("vulnerability.py", False, str(e)[:50])
    
    try:
        from schemas.attack_chain import AttackChain, ChainType, COMMON_ATTACK_CHAINS
        check("attack_chain.py", len(COMMON_ATTACK_CHAINS) > 0)
    except Exception as e: check("attack_chain.py", False, str(e)[:50])
    
    try:
        from schemas.world_state import WorldState, ScanPhase, create_initial_state
        ws = create_initial_state("http://test.com")
        check("world_state.py", ws.phase == ScanPhase.INITIALIZING)
    except Exception as e: check("world_state.py", False, str(e)[:50])
    
    try:
        from schemas.payload import Payload, PayloadType, XSS_PAYLOADS, SQLI_PAYLOADS
        check("payload.py", len(XSS_PAYLOADS) > 0 and len(SQLI_PAYLOADS) > 0)
    except Exception as e: check("payload.py", False, str(e)[:50])
    
    try:
        from schemas.decision import Decision, DecisionType, CommonDecisions
        d = CommonDecisions.create_scan_decision("http://test.com")
        check("decision.py", d is not None)
    except Exception as e: check("decision.py", False, str(e)[:50])
    
    try:
        from schemas.agent_message import AgentMessage, MessageType, create_message
        msg = create_message("test", "test", MessageType.COMMAND_SCAN)
        check("agent_message.py", msg is not None)
    except Exception as e: check("agent_message.py", False, str(e)[:50])
    
    try:
        from schemas.telemetry import TelemetryData, MetricPoint, MetricType
        check("telemetry.py", True)
    except Exception as e: check("telemetry.py", False, str(e)[:50])
    
    # ============================================================
    # 2. ORCHESTRATION
    # ============================================================
    print(f"\n🎛️  2. Orchestration (العقل المدبر)")
    
    try:
        from orchestration.orchestrator import Orchestrator, get_orchestrator
        orch = Orchestrator()
        check("orchestrator.py", orch is not None)
    except Exception as e: check("orchestrator.py", False, str(e)[:50])
    
    try:
        from orchestration.smart_orchestrator import SmartOrchestrator
        smart = SmartOrchestrator()
        check("smart_orchestrator.py", smart is not None)
    except Exception as e: check("smart_orchestrator.py", False, str(e)[:50])
    
    try:
        from orchestration.world_state_manager import WorldStateManager
        wsm = WorldStateManager()
        check("world_state_manager.py", wsm is not None)
    except Exception as e: check("world_state_manager.py", False, str(e)[:50])
    
    try:
        from orchestration.messaging.event_bus import EventBus, Event, EventType
        check("event_bus.py", hasattr(EventType, 'VULNERABILITY_FOUND'))
    except Exception as e: check("event_bus.py", False, str(e)[:50])
    
    try:
        from orchestration.task_manager import TaskManager
        check("task_manager.py", True)
    except Exception as e: check("task_manager.py", False, str(e)[:50])
    
    try:
        from orchestration.cache_manager import CacheManager
        check("cache_manager.py", True)
    except Exception as e: check("cache_manager.py", False, str(e)[:50])
    
    # ============================================================
    # 3. SCANNERS
    # ============================================================
    print(f"\n⚔️  3. Scanners (12 فاحص)")
    
    scanners = [
        ("xss_scanner", "XSSScanner"),
        ("sqli_scanner", "SQLiScanner"),
        ("idor_scanner", "IDORScanner"),
        ("rce_scanner", "RCEScanner"),
        ("ssrf_scanner", "SSRFScanner"),
        ("csrf_scanner", "CSRFScanner"),
        ("auth_scanner", "AuthScanner"),
        ("graphql_scanner", "GraphQLScanner"),
        ("api_scanner", "APIScanner"),
    ]
    
    for module_name, class_name in scanners:
        try:
            module = __import__(f"offensive.scanners.{module_name}", fromlist=[class_name])
            cls = getattr(module, class_name)
            instance = cls()
            check(f"{module_name}.py", instance is not None)
        except Exception as e:
            check(f"{module_name}.py", False, str(e)[:50])
    
    try:
        from offensive.scanners.jwt_analyzer import JWTAnalyzer
        check("jwt_analyzer.py", True)
    except Exception as e: check("jwt_analyzer.py", False, str(e)[:50])
    
    try:
        from offensive.scanners.context_aware_scanner import ContextAwareScanner
        check("context_aware_scanner.py", True)
    except Exception as e: check("context_aware_scanner.py", False, str(e)[:50])
    
    try:
        from offensive.scanners.ai_scanner import AIScanner
        check("ai_scanner.py", True)
    except Exception as e: check("ai_scanner.py", False, str(e)[:50])
    
    try:
        from offensive.scanners.adapters import ScannerAdapter, ConfigLoader
        check("adapters.py", True)
    except Exception as e: check("adapters.py", False, str(e)[:50])
    
    try:
        from offensive.scanners.payload_integration import PayloadManager, get_payload_manager
        pm = get_payload_manager()
        check("payload_integration.py", pm is not None)
    except Exception as e: check("payload_integration.py", False, str(e)[:50])
    
    # ============================================================
    # 4. RECON
    # ============================================================
    print(f"\n🔍 4. Recon (8 أدوات استطلاع)")
    
    recon_tools = [
        ("enhanced_crawler", "EnhancedCrawler"),
        ("js_processor", "JSProcessor"),
        ("js_api_discovery", "JSAPIDiscovery"),
        ("api_collector", "APICollector"),
        ("form_extractor", "FormExtractor"),
        ("attack_surface_mapper", "AttackSurfaceMapper"),
        ("site_analyzer", "SiteAnalyzer"),
        ("secrets_scanner", "SecretsScanner"),
    ]
    
    for module_name, class_name in recon_tools:
        try:
            module = __import__(f"offensive.recon.{module_name}", fromlist=[class_name])
            cls = getattr(module, class_name)
            instance = cls()
            check(f"{module_name}.py", instance is not None)
        except Exception as e:
            check(f"{module_name}.py", False, str(e)[:50])
    
    # ============================================================
    # 5. EXPLOITATION
    # ============================================================
    print(f"\n💥 5. Exploitation (أدوات الاستغلال)")
    
    try:
        from offensive.exploitation.auto_exploiter import AutoExploiter
        check("auto_exploiter.py", True)
    except Exception as e: check("auto_exploiter.py", False, str(e)[:50])
    
    # ============================================================
    # 6. INFRASTRUCTURE
    # ============================================================
    print(f"\n🏗️  6. Infrastructure (البنية التحتية)")
    
    try:
        from infrastructure.networking.network_monitor import NetworkMonitor
        check("network_monitor.py", True)
    except Exception as e: check("network_monitor.py", False, str(e)[:50])
    
    try:
        from infrastructure.networking.proxy_manager import ProxyManager
        check("proxy_manager.py", True)
    except Exception as e: check("proxy_manager.py", False, str(e)[:50])
    
    try:
        from infrastructure.networking.rate_controller import RateController
        check("rate_controller.py", True)
    except Exception as e: check("rate_controller.py", False, str(e)[:50])
    
    try:
        from infrastructure.networking.request_router import RequestRouter
        check("request_router.py", True)
    except Exception as e: check("request_router.py", False, str(e)[:50])
    
    try:
        from infrastructure.networking.session_manager import SessionManager
        check("session_manager.py", True)
    except Exception as e: check("session_manager.py", False, str(e)[:50])
    
    try:
        from infrastructure.networking.session_pool import SessionPool
        check("session_pool.py", True)
    except Exception as e: check("session_pool.py", False, str(e)[:50])
    
    try:
        from infrastructure.networking.traffic_analyzer import TrafficAnalyzer
        check("traffic_analyzer.py", True)
    except Exception as e: check("traffic_analyzer.py", False, str(e)[:50])
    
    try:
        from infrastructure.auth.interactive_login import InteractiveLogin
        check("interactive_login.py", True)
    except Exception as e: check("interactive_login.py", False, str(e)[:50])
    
    try:
        from infrastructure.auth.auth_manager import AuthManager
        check("auth_manager.py", True)
    except Exception as e: check("auth_manager.py", False, str(e)[:50])
    
    # ============================================================
    # 7. MODELS
    # ============================================================
    print(f"\n🧠 7. AI Models (نماذج الذكاء الاصطناعي)")
    
    try:
        from models.rl.dqn_agent import DQNAgent, get_dqn_agent
        agent = get_dqn_agent()
        check("dqn_agent.py", agent is not None)
    except Exception as e: check("dqn_agent.py", False, str(e)[:50])
    
    try:
        from models.classifiers.vuln_classifier import VulnerabilityClassifier, get_vuln_classifier
        clf = get_vuln_classifier()
        check("vuln_classifier.py", clf is not None)
    except Exception as e: check("vuln_classifier.py", False, str(e)[:50])
    
    try:
        from models.embeddings.vector_store import SimpleVectorStore
        check("vector_store.py", True)
    except Exception as e: check("vector_store.py", False, str(e)[:50])
    
    try:
        from models.policy_models.scan_policy import ScanPolicyOptimizer
        check("scan_policy.py", True)
    except Exception as e: check("scan_policy.py", False, str(e)[:50])
    
    # ============================================================
    # 8. DATABASE + DATASETS
    # ============================================================
    print(f"\n💾 8. Database + Datasets")
    
    try:
        from database.scan_repository import ScanRepository
        check("scan_repository.py", True)
    except Exception as e: check("scan_repository.py", False, str(e)[:50])
    
    try:
        from database.vuln_repository import VulnerabilityRepository
        check("vuln_repository.py", True)
    except Exception as e: check("vuln_repository.py", False, str(e)[:50])
    
    try:
        from datasets.attack_payloads import XSS_PAYLOADS, SQLI_PAYLOADS, RCE_PAYLOADS
        check("datasets/attack_payloads", len(XSS_PAYLOADS) > 0)
    except Exception as e: check("datasets/attack_payloads", False, str(e)[:50])
    
    try:
        from datasets.exploit_chains import get_chains
        chains = get_chains()
        check("datasets/exploit_chains", len(chains) > 0)
    except Exception as e: check("datasets/exploit_chains", False, str(e)[:50])
    
    try:
        from datasets.waf_patterns import get_wafs
        wafs = get_wafs()
        check("datasets/waf_patterns", len(wafs) > 0)
    except Exception as e: check("datasets/waf_patterns", False, str(e)[:50])
    
    try:
        from datasets.vulnerable_apps import get_applications
        apps = get_applications()
        check("datasets/vulnerable_apps", len(apps) > 0)
    except Exception as e: check("datasets/vulnerable_apps", False, str(e)[:50])
    
    # ============================================================
    # 9. INTERFACES
    # ============================================================
    print(f"\n🌐 9. Interfaces (واجهات المستخدم)")
    
    try:
        from interfaces.cli.cli_runner import CLIRunner
        check("cli_runner.py", True)
    except Exception as e: check("cli_runner.py", False, str(e)[:50])
    
    try:
        from interfaces.cli.terminal_ui import TerminalUI, Color
        check("terminal_ui.py", True)
    except Exception as e: check("terminal_ui.py", False, str(e)[:50])
    
    try:
        from interfaces.cli.command_parser import CommandParser
        check("command_parser.py", True)
    except Exception as e: check("command_parser.py", False, str(e)[:50])
    
    try:
        from interfaces.dashboard.dashboard_server import DashboardDataManager
        check("dashboard_server.py", True)
    except Exception as e: check("dashboard_server.py", False, str(e)[:50])
    
    try:
        from interfaces.dashboard.realtime_monitor import MonitorManager
        check("realtime_monitor.py", True)
    except Exception as e: check("realtime_monitor.py", False, str(e)[:50])
    
    try:
        from interfaces.reporting.report_generator import ReportGenerator
        check("report_generator.py", True)
    except Exception as e: check("report_generator.py", False, str(e)[:50])
    
    try:
        from interfaces.reporting.json_exporter import JSONExporter
        check("json_exporter.py", True)
    except Exception as e: check("json_exporter.py", False, str(e)[:50])
    
    try:
        from interfaces.reporting.pdf_exporter import PDFExporter
        check("pdf_exporter.py", True)
    except Exception as e: check("pdf_exporter.py", False, str(e)[:50])
    
    # ============================================================
    # SUMMARY
    # ============================================================
    print(f"\n{'='*60}")
    print(f"📊 النتيجة النهائية")
    print(f"{'='*60}")
    print(f"   ✅ نجح: {RESULTS['pass']}")
    print(f"   ❌ فشل: {RESULTS['fail']}")
    print(f"   📊 النسبة: {RESULTS['pass']/(RESULTS['pass']+RESULTS['fail'])*100:.0f}%")
    
    if RESULTS['fail'] == 0:
        print(f"\n🎉 كل الملفات مرتبطة وتعمل!")
        print(f"   {RESULTS['pass']} ملف تم فحصهم بنجاح")
    else:
        print(f"\n⚠️  {RESULTS['fail']} ملفات محتاجة إصلاح")


asyncio.run(main())
