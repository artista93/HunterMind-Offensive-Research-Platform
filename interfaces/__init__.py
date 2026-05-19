# interfaces/__init__.py

"""
Interfaces Module - طبقة الواجهات (API, Dashboard, CLI, Reporting)
"""

from . import api
from . import dashboard
from . import cli
from . import reporting

# API
from .api import app as api_app, get_grpc_server

# Dashboard
from .dashboard import app as dashboard_app
from .dashboard.dashboard_server import DashboardDataManager, data_manager

# CLI
from .cli import CLIRunner, main as cli_main, TerminalUI, Color, get_terminal_ui

# Reporting
from .reporting import (
    ReportGenerator, get_report_generator,
    JSONExporter, get_json_exporter,
    PDFExporter, get_pdf_exporter,
    AttackChainReporter, get_attack_chain_reporter,
)

__all__ = [
    'api', 'dashboard', 'cli', 'reporting',
    'api_app', 'get_grpc_server',
    'dashboard_app', 'DashboardDataManager', 'data_manager',
    'CLIRunner', 'cli_main', 'TerminalUI', 'Color', 'get_terminal_ui',
    'ReportGenerator', 'get_report_generator',
    'JSONExporter', 'get_json_exporter',
    'PDFExporter', 'get_pdf_exporter',
    'AttackChainReporter', 'get_attack_chain_reporter',
]
