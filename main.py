#!/usr/bin/env python3
"""
HunterMind - Autonomous Offensive Security Intelligence Platform
Main entry point for the platform
"""

import asyncio
import argparse
import sys
import logging
from pathlib import Path

# إضافة المسار الحالي إلى sys.path
sys.path.insert(0, str(Path(__file__).parent))

from orchestration.orchestrator import Orchestrator
from infrastructure.runtime.lifecycle_manager import get_lifecycle_manager
from infrastructure.runtime.dependency_container import get_dependency_container
from interfaces.cli.terminal_ui import get_terminal_ui

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


async def main():
    """الوظيفة الرئيسية للمنصة"""
    parser = argparse.ArgumentParser(
        description="HunterMind - Autonomous Offensive Security Intelligence Platform"
    )
    parser.add_argument(
        "--mode",
        choices=["cli", "api", "dashboard", "all"],
        default="cli",
        help="Run mode (default: cli)"
    )
    parser.add_argument(
        "--host",
        default="0.0.0.0",
        help="API host (default: 0.0.0.0)"
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8000,
        help="API port (default: 8000)"
    )
    
    args = parser.parse_args()
    
    ui = get_terminal_ui()
    ui.print_banner()
    
    if args.mode == "cli":
        await run_cli()
    elif args.mode == "api":
        await run_api(args.host, args.port)
    elif args.mode == "dashboard":
        await run_dashboard()
    else:  # all
        await run_all(args.host, args.port)


async def run_cli():
    """تشغيل واجهة سطر الأوامر"""
    from interfaces.cli.cli_runner import CLIRunner
    
    ui = get_terminal_ui()
    ui.print_info("Starting CLI mode...")
    
    runner = CLIRunner()
    await runner.interactive_mode()


async def run_api(host: str, port: int):
    """تشغيل خادم API"""
    import uvicorn
    from interfaces.api.fastapi_server import app
    
    ui = get_terminal_ui()
    ui.print_info(f"Starting API server on http://{host}:{port}")
    
    config = uvicorn.Config(app, host=host, port=port, log_level="info")
    server = uvicorn.Server(config)
    await server.serve()


async def run_dashboard():
    """تشغيل لوحة التحكم"""
    import subprocess
    import sys
    
    ui = get_terminal_ui()
    ui.print_info("Starting Dashboard...")
    
    # تشغيل dashboard في عمليات منفصلة
    scripts = [
        "interfaces/dashboard/dashboard_server.py",
        "interfaces/dashboard/realtime_monitor.py",
        "interfaces/dashboard/attack_visualizer.py",
        "interfaces/dashboard/cognitive_visualizer.py"
    ]
    
    processes = []
    for script in scripts:
        proc = subprocess.Popen([sys.executable, script])
        processes.append(proc)
    
    ui.print_success(f"Started {len(processes)} dashboard components")
    ui.print_info("Press Ctrl+C to stop...")
    
    try:
        for proc in processes:
            await asyncio.get_event_loop().run_in_executor(None, proc.wait)
    except KeyboardInterrupt:
        for proc in processes:
            proc.terminate()
        ui.print_info("Dashboard stopped")


async def run_all(host: str, port: int):
    """تشغيل جميع المكونات"""
    import uvicorn
    import subprocess
    import sys
    from interfaces.api.fastapi_server import app
    
    ui = get_terminal_ui()
    ui.print_info("Starting all components...")
    
    # تشغيل API
    api_task = asyncio.create_task(run_api(host, port))
    
    # تشغيل Dashboard
    scripts = [
        "interfaces/dashboard/realtime_monitor.py",
        "interfaces/dashboard/attack_visualizer.py",
        "interfaces/dashboard/cognitive_visualizer.py"
    ]
    
    processes = []
    for script in scripts:
        proc = subprocess.Popen([sys.executable, script])
        processes.append(proc)
    
    ui.print_success("All components started!")
    ui.print_info("Press Ctrl+C to stop...")
    
    try:
        await api_task
    except KeyboardInterrupt:
        for proc in processes:
            proc.terminate()
        ui.print_info("All components stopped")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n👋 Goodbye!")
        sys.exit(0)
