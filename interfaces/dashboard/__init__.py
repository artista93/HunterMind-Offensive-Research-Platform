# interfaces/dashboard/__init__.py

"""
Dashboard Module - لوحة التحكم والمراقبة
"""

from .dashboard_server import app, dashboard_data, get_stats, get_scans, get_vulnerabilities, get_system_status, update_stats, add_scan, add_vulnerability
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

# إعادة تسمية app إلى dashboard_app للتوافق
dashboard_app = app

__all__ = [
    'app',
    'dashboard_app',
    'dashboard_data',
    'get_stats',
    'get_scans',
    'get_vulnerabilities',
    'get_system_status',
    'update_stats',
    'add_scan',
    'add_vulnerability',
    'MonitorManager',
    'monitor_manager',
    'monitor_websocket',
    'emit_scan_started',
    'emit_scan_completed',
    'emit_vulnerability_found',
    'emit_attack_started',
    'emit_attack_result',
    'emit_system_alert',
    'get_monitor_page',
    'AttackVisualizer',
    'visualizer',
    'get_visualizer_page',
    'get_attack_chains',
    'get_graph_data',
    'add_attack_chain',
    'record_attack_result',
    'clear_data',
    'CognitiveMonitor',
    'cognitive_monitor',
    'cognitive_websocket',
    'update_cognitive_state',
    'add_reasoning_step',
    'record_decision',
    'get_cognitive_state',
    'get_cognitive_page',
]
