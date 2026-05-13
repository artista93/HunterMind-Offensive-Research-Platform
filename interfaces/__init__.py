# interfaces/__init__.py

"""
Interfaces Module - طبقة الواجهات (API, Dashboard, CLI, Reporting)
"""

from . import api
from . import dashboard
from . import cli
from . import reporting

# استيراد من api
from .api import (
    Severity, Confidence, ScanType, AttackType,
    ScanRequest, ScanResponse, ScanResult, Finding,
    AttackRequest, AttackResponse, AttackResult,
    ExploitRequest, ExploitResult,
    app as api_app,
    get_grpc_server,
)

# استيراد من dashboard
from .dashboard import (
    app as dashboard_app,
    monitor_manager, cognitive_monitor,
    get_monitor_page, get_cognitive_page, get_visualizer_page,
)

# استيراد من cli
from .cli import (
    CLIRunner, main as cli_main,
    TerminalUI, Color, get_terminal_ui,
    CommandParser, Command, CommandType, get_command_parser,
)

# استيراد من reporting
from .reporting import (
    ReportGenerator, get_report_generator,
    JSONExporter, get_json_exporter,
    PDFExporter, get_pdf_exporter,
    AttackChainReporter, get_attack_chain_reporter,
)

__all__ = [
    'api',
    'dashboard',
    'cli',
    'reporting',
    # api
    'Severity', 'Confidence', 'ScanType', 'AttackType',
    'ScanRequest', 'ScanResponse', 'ScanResult', 'Finding',
    'AttackRequest', 'AttackResponse', 'AttackResult',
    'ExploitRequest', 'ExploitResult',
    'api_app',
    'get_grpc_server',
    # dashboard
    'dashboard_app',
    'monitor_manager',
    'cognitive_monitor',
    'get_monitor_page',
    'get_cognitive_page',
    'get_visualizer_page',
    # cli
    'CLIRunner', 'cli_main',
    'TerminalUI', 'Color', 'get_terminal_ui',
    'CommandParser', 'Command', 'CommandType', 'get_command_parser',
    # reporting
    'ReportGenerator', 'get_report_generator',
    'JSONExporter', 'get_json_exporter',
    'PDFExporter', 'get_pdf_exporter',
    'AttackChainReporter', 'get_attack_chain_reporter',
]
