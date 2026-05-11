"""
CLI Runner - مشغل واجهة الأوامر (متصل بالمشروع الحقيقي)
"""

import argparse
import asyncio
import sys
from typing import List
from datetime import datetime

from .terminal_ui import TerminalUI, Color

# استيراد المكونات الحقيقية
from offensive.scanners.xss_scanner import XSSScanner
from offensive.scanners.sqli_scanner import SQLiScanner
from offensive.scanners.idor_scanner import IDORScanner
from offensive.scanners.base_scanner import ScanContext, ScanTarget

import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class CLIRunner:
    """
    مشغل واجهة الأوامر المتصل بالمشروع الحقيقي
    """
    
    def __init__(self):
        self.ui = TerminalUI()
        self.history: List[str] = []
        self.scans = []  # تخزين نتائج الفحوصات الحقيقية
        self.vulnerabilities = []  # تخزين الثغرات الحقيقية
        
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
        
        logger.info("CLI Runner initialized (REAL mode)")
    
    async def run(self, args: argparse.Namespace):
        """تشغيل CLI"""
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
                    print("Goodbye!")
                    break
                
                await self.execute_command(command, None)
                
            except KeyboardInterrupt:
                print("\nGoodbye!")
                break
            except Exception as e:
                print(f"{Color.RED}Error: {e}{Color.RESET}")
    
    async def execute_command(self, command: str, args: argparse.Namespace):
        """تنفيذ أمر"""
        parts = command.split()
        cmd_name = parts[0].lower()
        
        if cmd_name in self.commands:
            await self.commands[cmd_name](parts[1:] if len(parts) > 1 else [], args)
        else:
            print(f"Unknown command: {cmd_name}. Type 'help' for available commands.")
    
    async def cmd_scan(self, args: List[str], cli_args):
        """تنفيذ فحص حقيقي"""
        if not args:
            print("Usage: scan <target_url>")
            return
        
        target_url = args[0]
        
        print(f"\n{Color.BRIGHT_CYAN}🔍 Starting REAL scan on {target_url}{Color.RESET}\n")
        
        # إنشاء سياق الفحص
        context = ScanContext(
            target=ScanTarget(url=target_url, method="GET")
        )
        
        all_findings = []
        
        # 1. فحص XSS
        print(f"   {Color.CYAN}📡 Running XSS Scanner...{Color.RESET}")
        try:
            xss_scanner = XSSScanner()
            xss_findings = await xss_scanner.execute_scan(context)
            all_findings.extend(xss_findings)
            print(f"      ✓ XSS scan complete: {len(xss_findings)} findings")
        except Exception as e:
            print(f"      ❌ XSS scan error: {e}")
        
        # 2. فحص SQLi
        print(f"   {Color.CYAN}💉 Running SQLi Scanner...{Color.RESET}")
        try:
            sqli_scanner = SQLiScanner()
            sqli_findings = await sqli_scanner.execute_scan(context)
            all_findings.extend(sqli_findings)
            print(f"      ✓ SQLi scan complete: {len(sqli_findings)} findings")
        except Exception as e:
            print(f"      ❌ SQLi scan error: {e}")
        
        # 3. فحص IDOR
        print(f"   {Color.CYAN}🔐 Running IDOR Scanner...{Color.RESET}")
        try:
            idor_scanner = IDORScanner()
            idor_findings = await idor_scanner.execute_scan(context)
            all_findings.extend(idor_findings)
            print(f"      ✓ IDOR scan complete: {len(idor_findings)} findings")
        except Exception as e:
            print(f"      ❌ IDOR scan error: {e}")
        
        # حفظ النتائج
        scan_id = f"scan_{len(self.scans)+1:03d}"
        self.scans.append({
            "id": scan_id,
            "target": target_url,
            "status": "completed",
            "date": datetime.now().strftime("%Y-%m-%d"),
            "findings_count": len(all_findings),
            "findings": all_findings
        })
        
        # حفظ الثغرات
        for finding in all_findings:
            self.vulnerabilities.append({
                "type": finding.vulnerability_type,
                "severity": finding.severity.value,
                "url": finding.url,
                "parameter": finding.parameter or "N/A",
                "payload": finding.payload or "N/A"
            })
        
        print(f"\n{Color.BRIGHT_GREEN}✅ Scan completed!{Color.RESET}")
        print(f"   Total vulnerabilities found: {len(all_findings)}")
        
        for finding in all_findings[:5]:
            severity_color = Color.RED if finding.severity.value in ["critical", "high"] else Color.YELLOW
            print(f"   {severity_color}[{finding.severity.value.upper()}]{Color.RESET} {finding.vulnerability_type} - {finding.url}")
    
    async def cmd_attack(self, args: List[str], cli_args):
        """تنفيذ هجوم حقيقي"""
        if len(args) < 2:
            print("Usage: attack <target_url> <vulnerability_type> [--parameter NAME]")
            return
        
        target_url = args[0]
        vuln_type = args[1].lower()
        parameter = None
        
        for i, arg in enumerate(args[2:]):
            if arg == "--parameter" and i + 1 < len(args) - 2:
                parameter = args[i + 3]
        
        print(f"\n{Color.BRIGHT_CYAN}⚔️ Starting REAL {vuln_type} attack on {target_url}{Color.RESET}")
        if parameter:
            print(f"   Parameter: {parameter}")
        print("   Attempting exploitation...\n")
        
        if vuln_type == "xss":
            scanner = XSSScanner()
            params = {parameter: "test"} if parameter else {}
            context = ScanContext(target=ScanTarget(url=target_url, params=params))
            findings = await scanner.execute_scan(context)
            
            if findings:
                print(f"{Color.BRIGHT_GREEN}✅ Attack completed!{Color.RESET}")
                print(f"   Status: SUCCESS")
                print(f"   Vulnerable parameter: {findings[0].parameter}")
            else:
                print(f"{Color.RED}❌ Attack failed!{Color.RESET}")
                print(f"   No XSS vulnerability found")
        
        elif vuln_type == "sqli":
            scanner = SQLiScanner()
            params = {parameter: "1"} if parameter else {}
            context = ScanContext(target=ScanTarget(url=target_url, params=params))
            findings = await scanner.execute_scan(context)
            
            if findings:
                print(f"{Color.BRIGHT_GREEN}✅ Attack completed!{Color.RESET}")
                print(f"   Status: SUCCESS")
                print(f"   Vulnerable parameter: {findings[0].parameter}")
            else:
                print(f"{Color.RED}❌ Attack failed!{Color.RESET}")
                print(f"   No SQL injection vulnerability found")
        
        else:
            print(f"{Color.YELLOW}⚠ Attack type '{vuln_type}' not fully implemented yet{Color.RESET}")
    
    async def cmd_exploit(self, args: List[str], cli_args):
        """استغلال ثغرة"""
        print(f"\n{Color.YELLOW}⚠ Exploitation module in development{Color.RESET}")
    
    async def cmd_status(self, args: List[str], cli_args):
        """عرض حالة النظام"""
        print(f"\n{Color.BRIGHT_CYAN}📊 System Status{Color.RESET}")
        print("=" * 40)
        print(f"   Status: {Color.BRIGHT_GREEN}🟢 Running{Color.RESET}")
        print(f"   Uptime: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"   Scans performed: {len(self.scans)}")
        print(f"   Vulnerabilities found: {len(self.vulnerabilities)}")
        print("")
    
    async def cmd_list(self, args: List[str], cli_args):
        """عرض القوائم"""
        if not args:
            print("Usage: list <scans|vulnerabilities|attacks|agents>")
            return
        
        list_type = args[0].lower()
        
        if list_type == "scans":
            print(f"\n{Color.BRIGHT_CYAN}📋 Recent Scans{Color.RESET}")
            print("=" * 80)
            print(f"{'ID':<12} {'Target':<45} {'Status':<10} {'Findings':<10}")
            print("-" * 80)
            for scan in self.scans[-10:]:
                print(f"{scan['id']:<12} {scan['target'][:44]:<45} {scan['status']:<10} {scan['findings_count']:<10}")
        
        elif list_type == "vulnerabilities":
            print(f"\n{Color.BRIGHT_CYAN}🔍 Vulnerabilities Found{Color.RESET}")
            print("=" * 80)
            print(f"{'Type':<15} {'Severity':<10} {'URL':<40} {'Parameter':<15}")
            print("-" * 80)
            for vuln in self.vulnerabilities[-20:]:
                severity_color = Color.RED if vuln['severity'] in ["critical", "high"] else Color.YELLOW
                print(f"{vuln['type']:<15} {severity_color}{vuln['severity']:<10}{Color.RESET} {vuln['url'][:39]:<40} {vuln['parameter']:<15}")
        
        elif list_type == "agents":
            print(f"\n{Color.BRIGHT_CYAN}🤖 Available Agents{Color.RESET}")
            print("=" * 40)
            print("   - XSSAgent (XSS Scanner)")
            print("   - SQLiAgent (SQL Injection Scanner)")
            print("   - IDORAgent (IDOR Scanner)")
            print("   - ReconAgent (Reconnaissance)")
            print("   - WAFAgent (WAF Detector)")
    
    async def cmd_show(self, args: List[str], cli_args):
        """عرض تفاصيل عنصر"""
        if len(args) < 2:
            print("Usage: show <scan|vulnerability> <id>")
            return
        
        item_type = args[0].lower()
        item_id = args[1]
        
        if item_type == "scan":
            for scan in self.scans:
                if scan['id'] == item_id:
                    print(f"\n{Color.BRIGHT_CYAN}📄 Scan Details: {item_id}{Color.RESET}")
                    print("=" * 50)
                    print(f"   Target: {scan['target']}")
                    print(f"   Status: {scan['status']}")
                    print(f"   Date: {scan['date']}")
                    print(f"   Vulnerabilities: {scan['findings_count']}")
                    print("")
                    return
            
            print(f"Scan {item_id} not found")
        
        elif item_type == "vulnerability":
            for vuln in self.vulnerabilities:
                if vuln.get('id') == item_id:
                    print(f"\n{Color.BRIGHT_CYAN}🔍 Vulnerability Details: {item_id}{Color.RESET}")
                    print("=" * 50)
                    print(f"   Type: {vuln['type']}")
                    print(f"   Severity: {vuln['severity']}")
                    print(f"   URL: {vuln['url']}")
                    print(f"   Parameter: {vuln['parameter']}")
                    print(f"   Payload: {vuln['payload'][:100] if vuln['payload'] else 'N/A'}")
                    print("")
                    return
            
            print(f"Vulnerability {item_id} not found")
    
    async def cmd_help(self, args: List[str], cli_args):
        """عرض المساعدة"""
        print(f"\n{Color.BRIGHT_CYAN}📚 Available Commands{Color.RESET}")
        print("=" * 50)
        print("  scan <url>                         - Start a REAL security scan")
        print("  attack <url> <type> [--parameter]  - Launch a REAL attack")
        print("  status                            - Show system status")
        print("  list <scans|vulnerabilities|agents> - List items")
        print("  show <scan|vulnerability> <id>     - Show details")
        print("  help                              - Show this help")
        print("  exit, quit                        - Exit the CLI")
        print("")
        print(f"{Color.BRIGHT_GREEN}✅ This CLI is connected to REAL scanners!{Color.RESET}")
    
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
