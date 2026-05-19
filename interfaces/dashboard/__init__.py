# interfaces/dashboard/__init__.py

"""
Dashboard Module - لوحة التحكم والمراقبة
"""

from .dashboard_server import app, DashboardDataManager, data_manager

# المراقبة في الوقت الفعلي
from .realtime_monitor import (
    MonitorManager, monitor_manager,
    emit_scan_started, emit_scan_completed, emit_vulnerability_found,
    emit_attack_started, emit_attack_result, emit_system_alert,
    get_monitor_page,
)

# مصور الهجمات
from .attack_visualizer import (
    AttackVisualizer, visualizer,
    get_attack_chains, get_graph_data, add_attack_chain,
    record_attack_result, clear_data,
)

# المراقب المعرفي
from .cognitive_visualizer import (
    CognitiveMonitor, cognitive_monitor,
    update_cognitive_state, add_reasoning_step, record_decision,
    get_cognitive_state, get_cognitive_page,
)

__all__ = [
    'app', 'DashboardDataManager', 'data_manager',
    'MonitorManager', 'monitor_manager',
    'emit_scan_started', 'emit_scan_completed', 'emit_vulnerability_found',
    'emit_attack_started', 'emit_attack_result', 'emit_system_alert',
    'get_monitor_page',
    'AttackVisualizer', 'visualizer',
    'get_attack_chains', 'get_graph_data', 'add_attack_chain',
    'record_attack_result', 'clear_data',
    'CognitiveMonitor', 'cognitive_monitor',
    'update_cognitive_state', 'add_reasoning_step', 'record_decision',
    'get_cognitive_state', 'get_cognitive_page',
]
