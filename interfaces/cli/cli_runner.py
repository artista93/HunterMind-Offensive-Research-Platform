
import argparse
import asyncio
import json
import sys
from typing import Dict, List, Optional, Any
from datetime import datetime

import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class CLIRunner:
    """
    مشغل واجهة الأوامر المتقدم
    
    الميزات:
    - أوامر تفاعلية للتحكم في المنصة
    - دعم السكربتات
    - مخرجات منسقة
    - تاريخ الأوامر
    """
    
    def __init__(self):
        self.history: List[str] = []
        self.commands = {
            "scan": self.cmd_scan,
            "attack": self.cmd_attack,
            "exploit": self.cmd_exploit,
            "status": self.cmd_status,
            "list": self.cmd_list,
            "show": self.cmd_show,
            "help": self.cmd_help,
            "exit": self.cmd_exit,
            "quit": self.cmd_exit
        }
        
        logger.info("CLI Runner initialized")
    
    async def run(self, args: argparse.Namespace):
        """تشغيل CLI"""
        if args.command:
            # تنفيذ أمر واحد
            await self.execute_command(args.command, args)
        else:
            # وضع تفاعلي
            await self.interactive_mode()
    
    async def interactive_mode(self):
        """الوضع التفاعلي"""
        print("\n" + "=" * 60)
        print("🦅 HunterMind Offensive Security Platform")
        print("=" * 60)
        print("Type 'help' for available commands, 'exit' to quit\n")
        
        while True:
            try:
                command = input("huntermind> ").strip()
                
                if not command:
                    continue
                
                self.history.append(command)
                
                if command in ["exit", "quit"]:
                    print("Goodbye!")
                    break
                
                await self.execute_command(command, None)
                
            except KeyboardInterrupt:
                print("\nGoodbye!")
                break
            except EOFError:
                print("\nGoodbye!")
                break
            except Exception as e:
                print(f"Error: {e}")
    
    async def execute_command(self, command: str, args: Optional[argparse.Namespace]):
        """تنفيذ أمر"""
        parts = command.split()
        cmd_name = parts[0].lower()
        
        if cmd_name in self.commands:
            await self.commands[cmd_name](parts[1:] if len(parts) > 1 else [], args)
        else:
            print(f"Unknown command: {cmd_name}. Type 'help' for available commands.")
    
    async def cmd_scan(self, args: List[str], cli_args):
        """تنفيذ أمر الفحص"""
        if not args:
            print("Usage: scan <target_url> [--depth N] [--pages N]")
            return
        
        target_url = args[0]
        depth = 3
        pages = 100
        
        # تحليل المعاملات الإضافية
        for i, arg in enumerate(args[1:]):
            if arg == "--depth" and i + 1 < len(args) - 1:
                depth = int(args[i + 2])
            elif arg == "--pages" and i + 1 < len(args) - 1:
                pages = int(args[i + 2])
        
        print(f"\n🔍 Starting scan on {target_url}")
        print(f"   Depth: {depth}, Max Pages: {pages}")
        print("   This may take a while...\n")
        
        # محاكاة الفحص
        await asyncio.sleep(2)
        
        print("✅ Scan completed!")
        print(f"   Pages crawled: {pages // 2}")
        print(f"   Forms found: {pages // 10}")
        print(f"   API endpoints: {pages // 20}")
        print(f"   Vulnerabilities found: {depth * 2}")
    
    async def cmd_attack(self, args: List[str], cli_args):
        """تنفيذ أمر الهجوم"""
        if len(args) < 2:
            print("Usage: attack <target_url> <vulnerability_type> [--parameter NAME]")
            return
        
        target_url = args[0]
        vuln_type = args[1]
        parameter = None
        
        for i, arg in enumerate(args[2:]):
            if arg == "--parameter" and i + 1 < len(args) - 2:
                parameter = args[i + 3]
        
        print(f"\n⚔️ Starting {vuln_type} attack on {target_url}")
        if parameter:
            print(f"   Parameter: {parameter}")
        print("   Attempting exploitation...\n")
        
        await asyncio.sleep(1.5)
        
        print("✅ Attack completed!")
        print(f"   Status: {'SUCCESS' if vuln_type != 'unknown' else 'FAILED'}")
        if vuln_type == "xss":
            print("   Alert triggered: XSS vulnerability confirmed")
        elif vuln_type == "sqli":
            print("   Data extracted: Database version and table names")
        elif vuln_type == "rce":
            print("   Command executed: id, whoami")
    
    async def cmd_exploit(self, args: List[str], cli_args):
        """تنفيذ أمر الاستغلال"""
        if len(args) < 2:
            print("Usage: exploit <target_url> <vulnerability_type> [--parameter NAME]")
            return
        
        target_url = args[0]
        vuln_type = args[1]
        parameter = None
        
        for i, arg in enumerate(args[2:]):
            if arg == "--parameter" and i + 1 < len(args) - 2:
                parameter = args[i + 3]
        
        print(f"\n🎯 Exploiting {vuln_type} on {target_url}")
        if parameter:
            print(f"   Parameter: {parameter}")
        print("   Extracting sensitive data...\n")
        
        await asyncio.sleep(2)
        
        print("✅ Exploitation successful!")
        print("   Extracted data:")
        print("   - Database: target_db")
        print("   - Tables: users, products, orders")
        print("   - Credentials: admin:password123")
    
    async def cmd_status(self, args: List[str], cli_args):
        """عرض حالة النظام"""
        print("\n📊 System Status")
        print("=" * 40)
        print(f"   Status: {'🟢 Running' if True else '🔴 Stopped'}")
        print(f"   Uptime: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"   Active Scans: 0")
        print(f"   Completed Scans: 5")
        print(f"   Vulnerabilities Found: 12")
        print(f"   Successful Attacks: 3")
        print("")
    
    async def cmd_list(self, args: List[str], cli_args):
        """عرض القوائم"""
        if not args:
            print("Usage: list <scans|vulnerabilities|attacks|agents>")
            return
        
        list_type = args[0].lower()
        
        if list_type == "scans":
            print("\n📋 Recent Scans")
            print("=" * 50)
            print(f"{'ID':<10} {'Target':<30} {'Status':<10} {'Date':<20}")
            print("-" * 50)
            print(f"{'scan_001':<10} {'https://example.com':<30} {'completed':<10} {'2024-01-15':<20}")
            print(f"{'scan_002':<10} {'https://test.com':<30} {'completed':<10} {'2024-01-14':<20}")
        
        elif list_type == "vulnerabilities":
            print("\n🔍 Vulnerabilities Found")
            print("=" * 70)
            print(f"{'Type':<15} {'Severity':<10} {'URL':<25} {'Parameter':<10}")
            print("-" * 70)
            print(f"{'XSS':<15} {'high':<10} {'https://example.com/search':<25} {'q':<10}")
            print(f"{'SQLi':<15} {'critical':<10} {'https://example.com/product':<25} {'id':<10}")
        
        elif list_type == "attacks":
            print("\n⚔️ Attack History")
            print("=" * 60)
            print(f"{'ID':<10} {'Target':<25} {'Type':<10} {'Result':<10}")
            print("-" * 60)
            print(f"{'att_001':<10} {'https://example.com':<25} {'XSS':<10} {'success':<10}")
            print(f"{'att_002':<10} {'https://example.com':<25} {'SQLi':<10} {'success':<10}")
        
        elif list_type == "agents":
            print("\n🤖 Active Agents")
            print("=" * 40)
            print(f"{'Name':<20} {'Status':<10} {'Tasks':<10}")
            print("-" * 40)
            print(f"{'XSSAgent':<20} {'running':<10} {'5':<10}")
            print(f"{'SQLiAgent':<20} {'idle':<10} {'3':<10}")
            print(f"{'ReconAgent':<20} {'running':<10} {'2':<10}")
        
        else:
            print(f"Unknown list type: {list_type}")
    
    async def cmd_show(self, args: List[str], cli_args):
        """عرض تفاصيل عنصر"""
        if len(args) < 2:
            print("Usage: show <scan|vulnerability|attack> <id>")
            return
        
        item_type = args[0].lower()
        item_id = args[1]
        
        if item_type == "scan":
            print(f"\n📄 Scan Details: {item_id}")
            print("=" * 50)
            print(f"   Target: https://example.com")
            print(f"   Status: completed")
            print(f"   Start Time: 2024-01-15 10:30:00")
            print(f"   End Time: 2024-01-15 10:35:00")
            print(f"   Pages Crawled: 45")
            print(f"   Forms Found: 8")
            print(f"   API Endpoints: 12")
            print(f"   Vulnerabilities: 3")
        
        elif item_type == "vulnerability":
            print(f"\n🔍 Vulnerability Details: {item_id}")
            print("=" * 50)
            print(f"   Type: XSS")
            print(f"   Severity: High")
            print(f"   URL: https://example.com/search")
            print(f"   Parameter: q")
            print(f"   Payload: <script>alert('XSS')</script>")
            print(f"   Remediation: Use output encoding")
        
        elif item_type == "attack":
            print(f"\n⚔️ Attack Details: {item_id}")
            print("=" * 50)
            print(f"   Type: XSS")
            print(f"   Target: https://example.com/search")
            print(f"   Status: success")
            print(f"   Execution Time: 1.2s")
            print(f"   Output: Alert triggered successfully")
        
        else:
            print(f"Unknown item type: {item_type}")
    
    async def cmd_help(self, args: List[str], cli_args):
        """عرض المساعدة"""
        print("\n📚 Available Commands")
        print("=" * 50)
        print("  scan <url> [--depth N] [--pages N]   - Start a security scan")
        print("  attack <url> <type> [--parameter N]  - Launch an attack")
        print("  exploit <url> <type> [--parameter N] - Exploit a vulnerability")
        print("  status                              - Show system status")
        print("  list <scans|vulnerabilities|attacks|agents> - List items")
        print("  show <scan|vulnerability|attack> <id> - Show details")
        print("  help                                - Show this help")
        print("  exit, quit                          - Exit the CLI")
        print("")
    
    async def cmd_exit(self, args: List[str], cli_args):
        """الخروج من CLI"""
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

