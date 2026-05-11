"""
CLI Runner - مشغل واجهة الأوامر (متصل بالمشروع الحقيقي)
"""

import argparse
import asyncio
import sys
import os
from typing import List, Dict, Any
from datetime import datetime

# إضافة المسار الرئيسي
sys.path.insert(0, '/workspaces/HunterMind_Offensive_Research_Platform')

from .terminal_ui import TerminalUI, Color

# استيراد المكونات الحقيقية
from offensive.scanners.xss_scanner import XSSScanner
from offensive.scanners.sqli_scanner import SQLiScanner
from offensive.scanners.idor_scanner import IDORScanner
from offensive.scanners.base_scanner import ScanContext, ScanTarget
from orchestration.task_manager import TaskManager
from storage.sqlite.persistence import PersistenceManager


class CLIRunner:
    def __init__(self):
        self.ui = TerminalUI()
        self.history = []
        self.task_manager = None
        self.persistence = None
        self._initialized = False
    
    async def _initialize(self):
        """تهيئة المكونات الحقيقية"""
        if self._initialized:
            return
        
        print("🔧 Initializing real components...")
        self.task_manager = TaskManager()
        self.persistence = PersistenceManager()
        await self.task_manager.start()
        self._initialized = True
        print("✅ Components initialized\n")
    
    async def _save_scan_result(self, target: str, findings: list, pages: int):
        """حفظ نتيجة الفحص في قاعدة البيانات"""
        scan_data = {
            "target": target,
            "timestamp": datetime.now().isoformat(),
            "findings_count": len(findings),
            "pages_crawled": pages,
            "findings": findings
        }
        # حفظ في قاعدة البيانات الحقيقية
        if self.persistence:
            await self.persistence.save_scan_result(scan_data)
    
    async def run(self, args):
        if args.command:
            await self.execute_command(args.command, args)
        else:
            await self.interactive_mode()
    
    async def interactive_mode(self):
        await self._initialize()
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
    
    async def execute_command(self, command: str, args):
        parts = command.split()
        cmd = parts[0].lower()
        
        if cmd == "scan":
            await self.cmd_scan(parts[1:])
        elif cmd == "attack":
            await self.cmd_attack(parts[1:])
        elif cmd == "exploit":
            await self.cmd_exploit(parts[1:])
        elif cmd == "status":
            await self.cmd_status()
        elif cmd == "list":
            await self.cmd_list(parts[1:])
        elif cmd == "show":
            await self.cmd_show(parts[1:])
        elif cmd == "help":
            await self.cmd_help()
        else:
            print(f"Unknown command: {cmd}. Type 'help' for available commands.")
    
    async def cmd_scan(self, args: List[str]):
        if not args:
            print("Usage: scan <url> [--depth N] [--pages N]")
            return
        
        target = args[0]
        depth = 3
        pages = 100
        
        for i, arg in enumerate(args):
            if arg == "--depth" and i+1 < len(args):
                depth = int(args[i+1])
            elif arg == "--pages" and i+1 < len(args):
                pages = int(args[i+1])
        
        print(f"\n{Color.BRIGHT_CYAN}🔍 Starting REAL scan on {target}{Color.RESET}")
        print(f"   Depth: {depth}, Max Pages: {pages}\n")
        
        # إنشاء سياق الفحص
        context = ScanContext(
            target=ScanTarget(url=target, method="GET")
        )
        
        all_findings = []
        
        # 1. فحص XSS
        print("   📡 Running XSS Scanner...")
        try:
            xss_scanner = XSSScanner()
            xss_findings = await xss_scanner.execute_scan(context)
            all_findings.extend(xss_findings)
            print(f"      ✓ XSS scan complete: {len(xss_findings)} findings")
        except Exception as e:
            print(f"      ❌ XSS scan error: {e}")
        
        # 2. فحص SQLi
        print("   💉 Running SQLi Scanner...")
        try:
            sqli_scanner = SQLiScanner()
            sqli_findings = await sqli_scanner.execute_scan(context)
            all_findings.extend(sqli_findings)
            print(f"      ✓ SQLi scan complete: {len(sqli_findings)} findings")
        except Exception as e:
            print(f"      ❌ SQLi scan error: {e}")
        
        # 3. فحص IDOR
        print("   🔐 Running IDOR Scanner...")
        try:
            idor_scanner = IDORScanner()
            idor_findings = await idor_scanner.execute_scan(context)
            all_findings.extend(idor_findings)
            print(f"      ✓ IDOR scan complete: {len(idor_findings)} findings")
        except Exception as e:
            print(f"      ❌ IDOR scan error: {e}")
        
        # حفظ النتائج
        await self._save_scan_result(target, all_findings, pages)
        
        print(f"\n{Color.BRIGHT_GREEN}✅ Scan completed!{Color.RESET}")
        print(f"   Total vulnerabilities found: {len(all_findings)}")
        
        for finding in all_findings[:5]:
            severity_color = Color.RED if finding.severity.value == "high" else Color.YELLOW
            print(f"   {severity_color}[{finding.severity.value.upper()}]{Color.RESET} {finding.vulnerability_type} at {finding.url}")
    
    async def cmd_attack(self, args: List[str]):
        if len(args) < 2:
            print("Usage: attack <url> <type> [--parameter NAME]")
            return
        
        target = args[0]
        vuln_type = args[1]
        parameter = None
        
        for i, arg in enumerate(args):
            if arg == "--parameter" and i+1 < len(args):
                parameter = args[i+1]
        
        print(f"\n{Color.BRIGHT_CYAN}⚔️ Starting REAL {vuln_type} attack on {target}{Color.RESET}")
        if parameter:
            print(f"   Parameter: {parameter}\n")
        
        # تنفيذ هجوم حقيقي حسب النوع
        if vuln_type == "xss":
            scanner = XSSScanner()
            context = ScanContext(
                target=ScanTarget(url=target, params={parameter: "test"} if parameter else {})
            )
            findings = await scanner.execute_scan(context)
            
            if findings:
                print(f"{Color.BRIGHT_GREEN}✅ Attack completed!{Color.RESET}")
                print(f"   Status: SUCCESS")
                print(f"   Vulnerable parameter: {findings[0].parameter}")
                print(f"   Example payload: {findings[0].payload[:100] if findings[0].payload else 'N/A'}")
            else:
                print(f"{Color.RED}❌ Attack failed!{Color.RESET}")
                print(f"   No XSS vulnerability found")
        
        elif vuln_type == "sqli":
            scanner = SQLiScanner()
            context = ScanContext(
                target=ScanTarget(url=target, params={parameter: "1"} if parameter else {})
            )
            findings = await scanner.execute_scan(context)
            
            if findings:
                print(f"{Color.BRIGHT_GREEN}✅ Attack completed!{Color.RESET}")
                print(f"   Status: SUCCESS")
                print(f"   Vulnerable parameter: {findings[0].parameter}")
                print(f"   DBMS: {findings[0].metadata.get('dbms', 'Unknown')}")
            else:
                print(f"{Color.RED}❌ Attack failed!{Color.RESET}")
                print(f"   No SQL injection vulnerability found")
        
        else:
            print(f"{Color.YELLOW}⚠ Attack type '{vuln_type}' not fully implemented yet{Color.RESET}")
    
    async def cmd_exploit(self, args: List[str]):
        if len(args) < 2:
            print("Usage: exploit <url> <type> [--parameter NAME]")
            return
        
        target = args[0]
        vuln_type = args[1]
        parameter = args[2] if len(args) > 2 else None
        
        print(f"\n{Color.BRIGHT_CYAN}🎯 Exploiting {vuln_type} on {target}{Color.RESET}")
        if parameter:
            print(f"   Parameter: {parameter}\n")
        
        print(f"{Color.YELLOW}⚠ Exploitation module in development{Color.RESET}")
        print(f"   This feature will be available in the next release")
    
    async def cmd_status(self):
        print(f"\n{Color.BRIGHT_CYAN}📊 System Status{Color.RESET}")
        print("=" * 40)
        print(f"   Status: {Color.BRIGHT_GREEN}🟢 Running{Color.RESET}")
        print(f"   CLI Version: 2.0 (Connected to real components)")
        print(f"   Task Manager: {'✅ Active' if self.task_manager else '❌ Inactive'}")
        print(f"   Persistence: {'✅ Active' if self.persistence else '❌ Inactive'}")
        print("")
    
    async def cmd_list(self, args: List[str]):
        if not args:
            print("Usage: list <scans|vulnerabilities|attacks|agents>")
            return
        
        list_type = args[0].lower()
        
        if list_type == "scans":
            print(f"\n{Color.BRIGHT_CYAN}📋 Recent Scans{Color.RESET}")
            print("   (Use database queries to retrieve real scan history)")
            print("   Feature coming soon...")
        
        elif list_type == "vulnerabilities":
            print(f"\n{Color.BRIGHT_CYAN}🔍 Vulnerabilities Found{Color.RESET}")
            print("   (Results will appear after running scans)")
        
        elif list_type == "agents":
            print(f"\n{Color.BRIGHT_CYAN}🤖 Available Agents{Color.RESET}")
            print("=" * 40)
            print("   - XSSAgent (XSS Scanner)")
            print("   - SQLiAgent (SQL Injection Scanner)")
            print("   - IDORAgent (IDOR Scanner)")
            print("   - ReconAgent (Reconnaissance)")
            print("   - WAFAgent (WAF Detector)")
            print("   - AuthAgent (Authentication Tester)")
    
    async def cmd_show(self, args: List[str]):
        if len(args) < 2:
            print("Usage: show <scan|vulnerability|attack> <id>")
            return
        
        print(f"\n{Color.YELLOW}⚠ Feature coming soon{Color.RESET}")
    
    async def cmd_help(self):
        print(f"\n{Color.BRIGHT_CYAN}📚 Available Commands{Color.RESET}")
        print("=" * 50)
        print("  scan <url> [--depth N] [--pages N]   - Start a REAL security scan")
        print("  attack <url> <type> [--parameter N]  - Launch a REAL attack")
        print("  exploit <url> <type> [--parameter N] - Exploit a vulnerability")
        print("  status                              - Show system status")
        print("  list <scans|vulnerabilities|agents>  - List items")
        print("  help                                - Show this help")
        print("  exit, quit                          - Exit the CLI")
        print("")
        print(f"{Color.BRIGHT_GREEN}Note: This CLI is now connected to REAL components!{Color.RESET}")


def main():
    import asyncio
    runner = CLIRunner()
    asyncio.run(runner.interactive_mode())


if __name__ == "__main__":
    main()
