# interfaces/dashboard/__init__.py

"""
Dashboard Module - لوحة التحكم والمراقبة
"""

# دوال افتراضية لتجنب أخطاء الاستيراد
dashboard_data = {"stats": {}, "recent_scans": [], "recent_vulnerabilities": [], "system_status": {}}

async def get_stats(): return {}
async def get_scans(limit=50, offset=0): return {"items": [], "total": 0}
async def get_vulnerabilities(limit=50, offset=0): return {"items": [], "total": 0}
async def get_system_status(): return {"cpu": 0, "memory": 0, "disk": 0}
async def update_stats(data): return {}
async def add_scan(scan): return {}
async def add_vulnerability(vuln): return {}

# محاولة استيراد النسخة الأصلية
try:
    from .dashboard_server import app as _app
    app = _app
except ImportError:
    app = None

from .realtime_monitor import (
    MonitorManager, monitor_manager, monitor_websocket,
    emit_scan_started, emit_scan_completed, emit_vulnerability_found,
    emit_attack_started, emit_attack_result, emit_system_alert,
    get_monitor_page
)

from .attack_visualizer import (
    AttackVisualizer, visualizer, get_visualizer_page,
    get_attack_chains, get_graph_data, add_attack_chain,
    record_attack_result, clear_data
)

from .cognitive_visualizer import (
    CognitiveMonitor, cognitive_monitor, cognitive_websocket,
    update_cognitive_state, add_reasoning_step, record_decision,
    get_cognitive_state, get_cognitive_page
)

__all__ = [
    'app', 'dashboard_data', 'get_stats', 'get_scans',
    'get_vulnerabilities', 'get_system_status', 'update_stats',
    'add_scan', 'add_vulnerability',
    'MonitorManager', 'monitor_manager', 'monitor_websocket',
    'emit_scan_started', 'emit_scan_completed', 'emit_vulnerability_found',
    'emit_attack_started', 'emit_attack_result', 'emit_system_alert',
    'get_monitor_page',
    'AttackVisualizer', 'visualizer', 'get_visualizer_page',
    'get_attack_chains', 'get_graph_data', 'add_attack_chain',
    'record_attack_result', 'clear_data',
    'CognitiveMonitor', 'cognitive_monitor', 'cognitive_websocket',
    'update_cognitive_state', 'add_reasoning_step', 'record_decision',
    'get_cognitive_state', 'get_cognitive_page',
]
