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
        self.history: List[str] = []
        
        self.commands = {
            "scan": self.cmd_scan,
            "crawl": self.cmd_crawl,
            "register": self.cmd_register,
            "login": self.cmd_login,
            "full": self.cmd_full,
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
            print("Usage: scan <url> [--depth 3] [--max-pages 50]")
            return
        
        url = args[0]
        depth = 3
        max_pages = 50
        
        for i, arg in enumerate(args):
            if arg == "--depth" and i + 1 < len(args):
                depth = int(args[i + 1])
            if arg == "--max-pages" and i + 1 < len(args):
                max_pages = int(args[i + 1])
        
        print(f"\n{Color.BRIGHT_CYAN}🔍 Starting comprehensive scan on {url}{Color.RESET}")
        print(f"{'='*60}\n")
        
        await self._ensure_orchestrator()
        result = await self.orchestrator.execute_full_scan(url, depth, max_pages)
        
        # عرض النتائج
        print(f"\n{Color.BRIGHT_GREEN}{'='*60}{Color.RESET}")
        print(f"{Color.BRIGHT_GREEN}✅ SCAN COMPLETED!{Color.RESET}")
        print(f"{Color.BRIGHT_GREEN}{'='*60}{Color.RESET}")
        print(f"   Target: {url}")
        print(f"   Pages scanned: {result.get('pages_scanned', 0)}")
        print(f"   Total vulnerabilities: {result.get('total_findings', 0)}")
        
        if result.get('findings'):
            print(f"\n{Color.CYAN}📊 Findings:{Color.RESET}")
            for f in result['findings'][:10]:
                severity_color = Color.RED if f['severity'] in ['critical', 'high'] else Color.YELLOW
                print(f"   {severity_color}[{f['severity'].upper()}]{Color.RESET} {f['type']} - {f['url'][:60]}")
            if len(result['findings']) > 10:
                print(f"   ... and {len(result['findings']) - 10} more")
    
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
    
    # ==================== أوامر التسجيل والمصادقة ====================
    
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
    
    async def cmd_login(self, args: List[str]):
        """تسجيل الدخول بحساب موجود"""
        username = None
        password = None
        
        for i, arg in enumerate(args):
            if arg == "--username" and i + 1 < len(args):
                username = args[i + 1]
            if arg == "--password" and i + 1 < len(args):
                password = args[i + 1]
        
        if not username or not password:
            print("Usage: login --username <u> --password <p>")
            return
        
        print(f"\n{Color.BRIGHT_CYAN}🔐 Logging in as {username}...{Color.RESET}\n")
        
        await self._ensure_orchestrator()
        result = await self.orchestrator.login(username, password)
        
        if result.get('success'):
            print(f"{Color.BRIGHT_GREEN}✅ Login successful!{Color.RESET}")
            print(f"   Session saved for {username}")
        else:
            print(f"{Color.RED}❌ Login failed: {result.get('message')}{Color.RESET}")
    
    async def cmd_full(self, args: List[str]):
        """أتمتة كاملة: تسجيل → دخول → فحص"""
        if not args:
            print("Usage: full <register_url> <target_url>")
            return
        
        register_url = args[0]
        target_url = args[1] if len(args) > 1 else register_url
        
        print(f"\n{Color.BRIGHT_CYAN}🔄 Starting FULL automation{Color.RESET}")
        print(f"{'='*60}\n")
        
        await self._ensure_orchestrator()
        result = await self.orchestrator.full_automation(register_url, target_url)
        
        if result.get('success'):
            print(f"\n{Color.BRIGHT_GREEN}{'='*60}{Color.RESET}")
            print(f"{Color.BRIGHT_GREEN}🎉 FULL AUTOMATION COMPLETED!{Color.RESET}")
            print(f"{Color.BRIGHT_GREEN}{'='*60}{Color.RESET}")
            print(f"   Username: {result.get('username')}")
            print(f"   Password: {result.get('password')}")
            print(f"   Vulnerabilities: {result.get('total_findings', 0)}")
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
        print(f"   Active components: {', '.join(status.get('components_list', [])[:5])}")
        print(f"   Total scans: {status.get('total_scans', 0)}")
        print(f"   Total vulnerabilities: {status.get('total_vulnerabilities', 0)}")
        print(f"   Registered accounts: {status.get('total_accounts', 0)}")
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
                print(f"{'='*80}")
                for s in scans[:10]:
                    print(f"   {s['id']} | {s['target'][:50]} | {s['findings_count']} findings")
            else:
                print("\n📭 No scans found")
        
        elif list_type == "vulnerabilities":
            vulns = await self.orchestrator.list_vulnerabilities()
            if vulns:
                print(f"\n{Color.BRIGHT_CYAN}🔍 Vulnerabilities{Color.RESET}")
                print(f"{'='*80}")
                for v in vulns[:20]:
                    severity_color = Color.RED if v['severity'] in ['critical', 'high'] else Color.YELLOW
                    print(f"   {severity_color}[{v['severity'].upper()}]{Color.RESET} {v['type']} - {v['url'][:60]}")
            else:
                print("\n🎉 No vulnerabilities found")
        
        elif list_type == "accounts":
            accounts = await self.orchestrator.list_registered_accounts()
            if accounts:
                print(f"\n{Color.BRIGHT_CYAN}📋 Registered Accounts{Color.RESET}")
                print(f"{'='*80}")
                for a in accounts:
                    print(f"   {a['username']} | {a['email']} | {a['url'][:40]}")
            else:
                print("\n📭 No registered accounts")
        
        elif list_type == "agents":
            print(f"\n{Color.BRIGHT_CYAN}🤖 Available Agents{Color.RESET}")
            print(f"{'='*40}")
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
                print(f"{'='*50}")
                print(f"   Target: {details.get('target')}")
                print(f"   Pages: {details.get('pages_scanned', 0)}")
                print(f"   Findings: {details.get('findings_count', 0)}")
                print(f"   Date: {details.get('date')}")
            else:
                print(f"Scan {item_id} not found")
        
        elif item_type == "vulnerability":
            details = await self.orchestrator.get_vulnerability_details(item_id)
            if details:
                print(f"\n{Color.BRIGHT_CYAN}🔍 Vulnerability Details: {item_id}{Color.RESET}")
                print(f"{'='*50}")
                print(f"   Type: {details.get('type')}")
                print(f"   Severity: {details.get('severity')}")
                print(f"   URL: {details.get('url')}")
                print(f"   Parameter: {details.get('parameter')}")
                print(f"   Payload: {details.get('payload', 'N/A')[:100]}")
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
║    scan <url> [--depth 3] [--max-pages 50]  - Full scan (crawl + scan)
║    crawl <url> [--depth 3] [--max-pages 100] - Crawl only         ║
║                                                                    ║
║  {Color.BRIGHT_WHITE}REGISTRATION & AUTH{Color.RESET}                                            ║
║    register <url> [--username u] [--password p] - Auto register   ║
║    login --username u --password p            - Login              ║
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
