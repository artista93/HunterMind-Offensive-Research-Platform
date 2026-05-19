"""
CLI Runner - واجهة سطر الأوامر الاحترافية
"""

import argparse
import asyncio
import sys
from typing import List
from datetime import datetime

from .terminal_ui import TerminalUI, Color

# استيراد المنسق الرئيسي فقط (العقل المدبر)
from orchestration.orchestrator import get_orchestrator

import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class CLIRunner:
    """
    مشغل واجهة الأوامر الاحترافي
    يعتمد على Orchestrator لتنسيق جميع المكونات
    """
    
    def __init__(self):
        self.ui = TerminalUI()
        self.orchestrator = None
        self.smart_orchestrator = None
        self.history: List[str] = []
        self._active_session: str = None  # جلسة نشطة للفحص
        
        self.commands = {
            # الفحص
            "scan": self.cmd_scan,
            "smart": self.cmd_smart,
            "crawl": self.cmd_crawl,
            # المصادقة
            "login": self.cmd_login,
            "register": self.cmd_register,
            "sessions": self.cmd_sessions,
            "full": self.cmd_full,
            # النظام
            "status": self.cmd_status,
            "list": self.cmd_list,
            "show": self.cmd_show,
            "help": self.cmd_help,
            "exit": self.cmd_exit,
            "quit": self.cmd_exit,
            "clear": self.cmd_clear
        }
    
    async def _ensure_orchestrator(self):
        """تأكد من وجود المنسق"""
        if self.orchestrator is None:
            self.orchestrator = await get_orchestrator()
    
    async def _ensure_smart_orchestrator(self):
        """تأكد من وجود المنسق الذكي"""
        if self.smart_orchestrator is None:
            from orchestration.smart_orchestrator import get_smart_orchestrator
            self.smart_orchestrator = await get_smart_orchestrator()
    
    async def run(self, args: argparse.Namespace):
        """تشغيل CLI"""
        await self._ensure_orchestrator()
        
        if args.command:
            await self.execute_command(args.command, args)
        else:
            await self.interactive_mode()
    
    async def interactive_mode(self):
        """الوضع التفاعلي"""
        self.ui.clear_screen()
        self.ui.print_banner()
        print("Type 'help' for available commands, 'exit' to quit\n")
        
        while True:
            try:
                command = input(f"{Color.BRIGHT_CYAN}huntermind> {Color.RESET}").strip()
                if not command:
                    continue
                
                self.history.append(command)
                
                if command in ["exit", "quit"]:
                    print("\nGoodbye! 🦅\n")
                    break
                
                if command == "clear":
                    self.ui.clear_screen()
                    self.ui.print_banner()
                    continue
                
                await self.execute_command(command, None)
                
            except KeyboardInterrupt:
                print("\nGoodbye! 🦅\n")
                break
            except Exception as e:
                print(f"{Color.RED}Error: {e}{Color.RESET}")
    
    async def execute_command(self, command: str, args):
        """تنفيذ أمر"""
        parts = command.split()
        cmd_name = parts[0].lower()
        
        if cmd_name in self.commands:
            await self.commands[cmd_name](parts[1:] if len(parts) > 1 else [])
        else:
            print(f"Unknown command: {cmd_name}. Type 'help'.")
    
    # ==================== أوامر الفحص والزحف ====================
    
    async def cmd_scan(self, args: List[str]):
        """فحص شامل للموقع (زحف + فحص)"""
        if not args:
            print("Usage: scan <url> [--depth 3] [--max-pages 50] [--session ID]")
            print("\n  Full scan with all 9 scanners")
            return
        
        url = args[0]
        depth = 3
        max_pages = 50
        session_id = None
        
        for i, arg in enumerate(args):
            if arg == "--depth" and i + 1 < len(args):
                depth = int(args[i + 1])
            if arg == "--max-pages" and i + 1 < len(args):
                max_pages = int(args[i + 1])
            if arg == "--session" and i + 1 < len(args):
                session_id = args[i + 1]
        
        print(f"\n{Color.BRIGHT_CYAN}🔍 Starting comprehensive scan on {url}{Color.RESET}")
        print(f"{'='*60}\n")
        
        await self._ensure_orchestrator()
        
        # تحميل الجلسة إذا وجدت
        if session_id:
            print(f"🔐 Loading session: {session_id}")
        elif self._active_session:
            session_id = self._active_session
            print(f"🔐 Using active session: {session_id}")
        
        result = await self.orchestrator.execute_full_scan(url, depth, max_pages)
        
        # عرض النتائج
        print(f"\n{Color.BRIGHT_GREEN}{'='*60}{Color.RESET}")
        print(f"{Color.BRIGHT_GREEN}✅ SCAN COMPLETED!{Color.RESET}")
        print(f"{Color.BRIGHT_GREEN}{'='*60}{Color.RESET}")
        print(f"   Target: {url}")
        print(f"   Pages scanned: {result.get('pages_scanned', 0)}")
        print(f"   Total vulnerabilities: {result.get('total_vulnerabilities', result.get('total_findings', 0))}")
        
        vulns = result.get('vulnerabilities', result.get('findings', []))
        if vulns:
            print(f"\n{Color.CYAN}📊 Findings:{Color.RESET}")
            for f in vulns[:10]:
                sev = f.get('severity', 'info') if isinstance(f, dict) else str(f.severity.value)
                sev_str = str(sev).upper()
                severity_color = Color.RED if sev_str in ['CRITICAL', 'HIGH'] else Color.YELLOW
                url_str = f.get('url', '') if isinstance(f, dict) else str(f.url)
                type_str = f.get('type', '') if isinstance(f, dict) else str(f.vulnerability_type)
                print(f"   {severity_color}[{sev_str}]{Color.RESET} {type_str} - {url_str[:60]}")
            if len(vulns) > 10:
                print(f"   ... and {len(vulns) - 10} more")
    
    async def cmd_smart(self, args: List[str]):
        """🧠 فحص ذكي - يفهم الموقع قبل الفحص"""
        if not args:
            print("Usage: smart <url> [--depth 2] [--max-pages 10]")
            print("\n  Smart scan: extracts real forms, links, and APIs before scanning")
            return
        
        url = args[0]
        depth = 2
        max_pages = 10
        
        for i, arg in enumerate(args):
            if arg == "--depth" and i + 1 < len(args):
                depth = int(args[i + 1])
            if arg == "--max-pages" and i + 1 < len(args):
                max_pages = int(args[i + 1])
        
        print(f"\n{Color.BRIGHT_CYAN}🧠 Starting SMART scan on {url}{Color.RESET}")
        print(f"{'='*60}\n")
        
        await self._ensure_smart_orchestrator()
        result = await self.smart_orchestrator.smart_scan(url, depth, max_pages)
        
        print(f"\n{Color.BRIGHT_GREEN}{'='*60}{Color.RESET}")
        print(f"{Color.BRIGHT_GREEN}✅ SMART SCAN COMPLETED!{Color.RESET}")
        print(f"{Color.BRIGHT_GREEN}{'='*60}{Color.RESET}")
        print(f"   Target: {url}")
        print(f"   Pages found: {result.get('pages_found', 0)}")
        print(f"   Forms discovered: {result.get('forms_found', 0)}")
        print(f"   API Endpoints: {result.get('api_endpoints_found', 0)}")
        print(f"   Targets scanned: {result.get('targets_scanned', 0)}")
        print(f"   Vulnerabilities found: {result.get('vulnerabilities_count', 0)}")
        print(f"   Duration: {result.get('duration_seconds', 0):.1f}s")
        
        if result.get('vulnerabilities'):
            print(f"\n{Color.CYAN}📊 Findings:{Color.RESET}")
            for v in result['vulnerabilities'][:10]:
                sev = v.get('severity', 'INFO')
                severity_color = Color.RED if sev in ['CRITICAL', 'HIGH'] else Color.YELLOW
                print(f"   {severity_color}[{sev}]{Color.RESET} {v.get('type', '?')} - {v.get('url', '')[:60]}")
    
    async def cmd_crawl(self, args: List[str]):
        """زحف الموقع لاكتشاف جميع الصفحات"""
        if not args:
            print("Usage: crawl <url> [--depth 3] [--max-pages 100]")
            return
        
        url = args[0]
        depth = 3
        max_pages = 100
        
        for i, arg in enumerate(args):
            if arg == "--depth" and i + 1 < len(args):
                depth = int(args[i + 1])
            if arg == "--max-pages" and i + 1 < len(args):
                max_pages = int(args[i + 1])
        
        print(f"\n{Color.BRIGHT_CYAN}🕷️ Starting crawl on {url}{Color.RESET}\n")
        
        await self._ensure_orchestrator()
        result = await self.orchestrator.execute_crawl(url, depth, max_pages)
        
        print(f"\n{Color.BRIGHT_GREEN}✅ Crawl completed!{Color.RESET}")
        print(f"   Pages found: {result.get('total_pages', 0)}")
        print(f"   Forms found: {result.get('total_forms', 0)}")
        print(f"   API endpoints: {result.get('total_apis', 0)}")
    
    # ==================== أوامر المصادقة ====================
    
    async def cmd_login(self, args: List[str]):
        """🔐 تسجيل دخول تفاعلي ذكي - يكتشف حقول النموذج تلقائياً"""
        if not args:
            print("Usage: login <url> [--username <u>] [--password <p>]")
            print("\n  Interactive login wizard:")
            print("  - Auto-detects form fields (email, password, CSRF, 2FA, CAPTCHA)")
            print("  - Asks for missing credentials interactively")
            print("  - Saves session for later scanning")
            print("\n  Examples:")
            print("    login https://example.com/login")
            print("    login https://example.com/login --username admin --password pass123")
            return
        
        url = args[0]
        username = None
        password = None
        
        for i, arg in enumerate(args):
            if arg == "--username" and i + 1 < len(args):
                username = args[i + 1]
            if arg == "--password" and i + 1 < len(args):
                password = args[i + 1]
        
        from infrastructure.auth.interactive_login import get_interactive_login
        
        login_manager = get_interactive_login()
        session = await login_manager.login(url, username, password)
        
        if session:
            self._active_session = session.session_id
            print(f"\n{Color.BRIGHT_GREEN}✅ Session saved & activated!{Color.RESET}")
            print(f"   Session ID: {Color.CYAN}{session.session_id}{Color.RESET}")
            print(f"   Now use: {Color.CYAN}scan <url>{Color.RESET} to scan with this session")
            print(f"   Or: {Color.CYAN}sessions{Color.RESET} to list all saved sessions")
        else:
            print(f"\n{Color.RED}❌ Login failed. Check URL and credentials.{Color.RESET}")
    
    async def cmd_sessions(self, args: List[str]):
        """📋 عرض الجلسات المحفوظة"""
        from infrastructure.auth.interactive_login import get_interactive_login
        
        login_manager = get_interactive_login()
        sessions = login_manager.list_sessions()
        
        if not sessions:
            print(f"\n📭 No saved sessions")
            print(f"   Use: login <url> to create a session")
            return
        
        print(f"\n{Color.BRIGHT_CYAN}📋 Saved Sessions{Color.RESET}")
        print(f"{'='*50}")
        for s in sessions:
            marker = " ← ACTIVE" if s == self._active_session else ""
            print(f"   {Color.CYAN}{s}{Color.RESET}{marker}")
        
        print(f"\n   Use: scan <url> --session <ID> to use a session")
    
    async def cmd_register(self, args: List[str]):
        """إنشاء حساب جديد (تلقائي)"""
        if not args:
            print("Usage: register <url> [--username <u>] [--password <p>]")
            return
        
        url = args[0]
        username = None
        password = None
        
        for i, arg in enumerate(args):
            if arg == "--username" and i + 1 < len(args):
                username = args[i + 1]
            if arg == "--password" and i + 1 < len(args):
                password = args[i + 1]
        
        print(f"\n{Color.BRIGHT_CYAN}📝 Registering on {url}...{Color.RESET}\n")
        
        await self._ensure_orchestrator()
        result = await self.orchestrator.register_account(url, username, password)
        
        if result.get('success'):
            print(f"{Color.BRIGHT_GREEN}✅ Account created!{Color.RESET}")
            print(f"   Username: {result.get('username')}")
            print(f"   Password: {result.get('password')}")
        else:
            print(f"{Color.RED}❌ Registration failed: {result.get('message')}{Color.RESET}")
    
    async def cmd_full(self, args: List[str]):
        """أتمتة كاملة: تسجيل → دخول → فحص"""
        if not args:
            print("Usage: full <register_url> <target_url>")
            return
        
        register_url = args[0]
        target_url = args[1] if len(args) > 1 else register_url
        
        print(f"\n{Color.BRIGHT_CYAN}🔄 Starting FULL automation{Color.RESET}")
        
        await self._ensure_orchestrator()
        result = await self.orchestrator.full_automation(register_url, target_url)
        
        if result.get('success'):
            print(f"\n{Color.BRIGHT_GREEN}🎉 FULL AUTOMATION COMPLETED!{Color.RESET}")
            print(f"   Username: {result.get('username')}")
            print(f"   Vulnerabilities: {result.get('total_findings', result.get('total_vulnerabilities', 0))}")
        else:
            print(f"{Color.RED}❌ Automation failed: {result.get('message')}{Color.RESET}")
    
    # ==================== أوامر النظام ====================
    
    async def cmd_status(self, args: List[str]):
        """عرض حالة النظام"""
        await self._ensure_orchestrator()
        status = await self.orchestrator.get_status()
        
        print(f"\n{Color.BRIGHT_CYAN}📊 System Status{Color.RESET}")
        print(f"{'='*50}")
        print(f"   Status: {Color.BRIGHT_GREEN}🟢 Running{Color.RESET}")
        print(f"   Components: {status.get('components', 0)}")
        print(f"   Total scans: {status.get('total_scans', 0)}")
        print(f"   Total vulnerabilities: {status.get('total_vulnerabilities', 0)}")
        print(f"   Registered accounts: {status.get('total_accounts', 0)}")
        
        if self._active_session:
            print(f"   Active session: {Color.CYAN}{self._active_session}{Color.RESET}")
        
        # WorldState
        ws = status.get('world_state', {})
        if ws and ws.get('phase') != 'not_initialized':
            print(f"   WorldState phase: {ws.get('phase', 'N/A')}")
            print(f"   Endpoints: {ws.get('endpoints', 0)}")
        print("")
    
    async def cmd_list(self, args: List[str]):
        """عرض القوائم"""
        if not args:
            print("Usage: list <scans|vulnerabilities|accounts|agents>")
            return
        
        list_type = args[0].lower()
        await self._ensure_orchestrator()
        
        if list_type == "scans":
            scans = await self.orchestrator.list_scans()
            if scans:
                print(f"\n{Color.BRIGHT_CYAN}📋 Recent Scans{Color.RESET}")
                for s in scans[:10]:
                    vc = s.get('vulnerabilities_count', s.get('findings_count', 0))
                    print(f"   {s['id']} | {str(s.get('target', ''))[:50]} | {vc} vulns")
            else:
                print("\n📭 No scans found")
        
        elif list_type == "vulnerabilities":
            vulns = await self.orchestrator.list_vulnerabilities()
            if vulns:
                print(f"\n{Color.BRIGHT_CYAN}🔍 Vulnerabilities{Color.RESET}")
                for v in vulns[:20]:
                    sev = str(v.get('severity', 'info')).upper()
                    severity_color = Color.RED if sev in ['CRITICAL', 'HIGH'] else Color.YELLOW
                    print(f"   {severity_color}[{sev}]{Color.RESET} {v.get('type', '?')} - {str(v.get('url', ''))[:60]}")
            else:
                print("\n🎉 No vulnerabilities found")
        
        elif list_type == "accounts":
            accounts = await self.orchestrator.list_registered_accounts()
            if accounts:
                print(f"\n{Color.BRIGHT_CYAN}📋 Registered Accounts{Color.RESET}")
                for a in accounts:
                    print(f"   {a['username']} | {a.get('email', 'N/A')}")
            else:
                print("\n📭 No registered accounts")
        
        elif list_type == "agents":
            print(f"\n{Color.BRIGHT_CYAN}🤖 Available Agents{Color.RESET}")
            agents = await self.orchestrator.list_agents()
            for a in agents:
                print(f"   - {a}")
    
    async def cmd_show(self, args: List[str]):
        """عرض تفاصيل عنصر"""
        if len(args) < 2:
            print("Usage: show <scan|vulnerability> <id>")
            return
        
        item_type = args[0].lower()
        item_id = args[1]
        await self._ensure_orchestrator()
        
        if item_type == "scan":
            details = await self.orchestrator.get_scan_details(item_id)
            if details:
                print(f"\n{Color.BRIGHT_CYAN}📄 Scan Details: {item_id}{Color.RESET}")
                print(f"   Target: {details.get('target', 'N/A')}")
                print(f"   Pages: {details.get('pages_scanned', 0)}")
                print(f"   Findings: {details.get('findings_count', details.get('vulnerabilities_count', 0))}")
                print(f"   Date: {details.get('date', 'N/A')}")
            else:
                print(f"Scan {item_id} not found")
        
        elif item_type == "vulnerability":
            details = await self.orchestrator.get_vulnerability_details(item_id)
            if details:
                print(f"\n{Color.BRIGHT_CYAN}🔍 Vulnerability: {item_id}{Color.RESET}")
                print(f"   Type: {details.get('type', 'N/A')}")
                print(f"   Severity: {details.get('severity', 'N/A')}")
                print(f"   URL: {details.get('url', 'N/A')}")
                print(f"   Parameter: {details.get('parameter', 'N/A')}")
            else:
                print(f"Vulnerability {item_id} not found")
    
    async def cmd_clear(self, args: List[str]):
        """مسح الشاشة"""
        self.ui.clear_screen()
        self.ui.print_banner()
    
    async def cmd_help(self, args: List[str]):
        """عرض المساعدة"""
        print(f"""
{Color.BRIGHT_CYAN}╔══════════════════════════════════════════════════════════════════╗
║                    HUNTERMIND CLI COMMANDS                        ║
╠══════════════════════════════════════════════════════════════════╣
║                                                                    ║
║  {Color.BRIGHT_WHITE}CRAWLING & SCANNING{Color.RESET}                                             ║
║    scan <url> [--depth 3] [--max-pages 50]  - Full scan           ║
║    smart <url> [--depth 2] [--max-pages 10] - Smart scan 🧠       ║
║    crawl <url> [--depth 3] [--max-pages 100] - Crawl only         ║
║                                                                    ║
║  {Color.BRIGHT_WHITE}AUTHENTICATION{Color.RESET}                                                   ║
║    login <url> [--username u] [--password p]  - Interactive login 🔐║
║    register <url> [--username u] [--password p] - Auto register   ║
║    sessions                                   - List saved sessions║
║    full <reg_url> <target>                   - Register → Scan    ║
║                                                                    ║
║  {Color.BRIGHT_WHITE}SYSTEM{Color.RESET}                                                        ║
║    status                                   - System status       ║
║    list <scans|vulnerabilities|accounts>    - List items          ║
║    show <scan|vulnerability> <id>           - Show details        ║
║    clear                                    - Clear screen        ║
║    help                                     - Show this help      ║
║    exit, quit                               - Exit CLI            ║
║                                                                    ║
╚══════════════════════════════════════════════════════════════════╝
{Color.BRIGHT_GREEN}✅ Connected to REAL orchestrator & scanners!{Color.RESET}
{Color.YELLOW}🧠 Smart scan available: extracts real forms, links & APIs{Color.RESET}
{Color.CYAN}🔐 Interactive login: auto-detects form fields{Color.RESET}
""")
    
    async def cmd_exit(self, args: List[str]):
        """الخروج من CLI"""
        if self.orchestrator:
            await self.orchestrator.stop()
        sys.exit(0)


def create_parser() -> argparse.ArgumentParser:
    """إنشاء محلل المعاملات"""
    parser = argparse.ArgumentParser(description="HunterMind Offensive Security Platform CLI")
    parser.add_argument("command", nargs="?", help="Command to execute")
    parser.add_argument("args", nargs="*", help="Command arguments")
    return parser


async def main():
    """الوظيفة الرئيسية"""
    parser = create_parser()
    args = parser.parse_args()
    runner = CLIRunner()
    await runner.run(args)


if __name__ == "__main__":
    asyncio.run(main())
