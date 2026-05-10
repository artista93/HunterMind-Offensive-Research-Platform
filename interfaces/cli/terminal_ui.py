
import sys
import time
from typing import Dict, List, Optional, Any, Callable
from datetime import datetime
from enum import Enum


class Color:
    """ألوان الطرفية"""
    BLACK = '\033[30m'
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    BLUE = '\033[34m'
    MAGENTA = '\033[35m'
    CYAN = '\033[36m'
    WHITE = '\033[37m'
    BRIGHT_BLACK = '\033[90m'
    BRIGHT_RED = '\033[91m'
    BRIGHT_GREEN = '\033[92m'
    BRIGHT_YELLOW = '\033[93m'
    BRIGHT_BLUE = '\033[94m'
    BRIGHT_MAGENTA = '\033[95m'
    BRIGHT_CYAN = '\033[96m'
    BRIGHT_WHITE = '\033[97m'
    RESET = '\033[0m'
    
    # أنماط
    BOLD = '\033[1m'
    DIM = '\033[2m'
    ITALIC = '\033[3m'
    UNDERLINE = '\033[4m'
    BLINK = '\033[5m'
    REVERSE = '\033[7m'
    HIDDEN = '\033[8m'


class ProgressBar:
    """شريط التقدم"""
    
    def __init__(self, total: int, width: int = 50, prefix: str = "", suffix: str = ""):
        self.total = total
        self.width = width
        self.prefix = prefix
        self.suffix = suffix
        self.current = 0
        self.start_time = time.time()
    
    def update(self, current: int, message: str = ""):
        """تحديث شريط التقدم"""
        self.current = min(current, self.total)
        percent = self.current / self.total
        filled = int(self.width * percent)
        bar = "█" * filled + "░" * (self.width - filled)
        
        elapsed = time.time() - self.start_time
        if self.current > 0:
            eta = (elapsed / self.current) * (self.total - self.current)
            eta_str = self._format_time(eta)
        else:
            eta_str = "?"

        sys.stdout.write(f"\r{self.prefix} |{bar}| {percent*100:.1f}% {self.suffix} ETA: {eta_str} {message}")
        sys.stdout.flush()
    
    def finish(self, message: str = ""):
        """إنهاء شريط التقدم"""
        self.update(self.total, message)
        print()
    
    def _format_time(self, seconds: float) -> str:
        """تنسيق الوقت"""
        if seconds < 60:
            return f"{seconds:.0f}s"
        elif seconds < 3600:
            return f"{seconds/60:.0f}m"
        else:
            return f"{seconds/3600:.1f}h"


class Spinner:
    """مؤشر انتظار متحرك"""
    
    def __init__(self, message: str = "Loading"):
        self.message = message
        self.spinner_chars = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
        self.running = False
    
    def start(self):
        """بدء المؤشر"""
        self.running = True
        self._spin()
    
    def stop(self):
        """إيقاف المؤشر"""
        self.running = False
    
    def _spin(self):
        """حركة المؤشر"""
        import threading
        i = 0
        while self.running:
            sys.stdout.write(f"\r{self.spinner_chars[i % len(self.spinner_chars)]} {self.message}...")
            sys.stdout.flush()
            time.sleep(0.1)
            i += 1
        sys.stdout.write("\r" + " " * (len(self.message) + 10) + "\r")


class Table:
    """جدول منسق"""
    
    def __init__(self, headers: List[str], alignments: List[str] = None):
        self.headers = headers
        self.alignments = alignments or ["left"] * len(headers)
        self.rows = []
    
    def add_row(self, row: List[str]):
        """إضافة صف"""
        self.rows.append(row)
    
    def render(self) -> str:
        """عرض الجدول"""
        if not self.rows:
            return "No data"
        
        # حساب عرض الأعمدة
        col_widths = []
        for i, header in enumerate(self.headers):
            width = len(header)
            for row in self.rows:
                if i < len(row):
                    width = max(width, len(str(row[i])))
            col_widths.append(width)
        
        # إنشاء الفاصل
        separator = "+" + "+".join("-" * (w + 2) for w in col_widths) + "+"
        
        # إنشاء الرأس
        result = [separator]
        header_row = "|"
        for i, header in enumerate(self.headers):
            header_row += f" {header:<{col_widths[i]}} |"
        result.append(header_row)
        result.append(separator)
        
        # إنشاء الصفوف
        for row in self.rows:
            row_str = "|"
            for i, cell in enumerate(row):
                if self.alignments[i] == "right":
                    row_str += f" {str(cell):>{col_widths[i]}} |"
                elif self.alignments[i] == "center":
                    row_str += f" {str(cell):^{col_widths[i]}} |"
                else:
                    row_str += f" {str(cell):<{col_widths[i]}} |"
            result.append(row_str)
        
        result.append(separator)
        
        return "\n".join(result)


class TerminalUI:
    """واجهة الطرفية المتقدمة"""
    
    @staticmethod
    def print_header(title: str):
        """طباعة رأس"""
        width = 60
        print("\n" + "=" * width)
        print(f"{Color.BOLD}{Color.CYAN}{title.center(width)}{Color.RESET}")
        print("=" * width + "\n")
    
    @staticmethod
    def print_success(message: str):
        """طباعة رسالة نجاح"""
        print(f"{Color.GREEN}✓ {message}{Color.RESET}")
    
    @staticmethod
    def print_error(message: str):
        """طباعة رسالة خطأ"""
        print(f"{Color.RED}✗ {message}{Color.RESET}")
    
    @staticmethod
    def print_warning(message: str):
        """طباعة رسالة تحذير"""
        print(f"{Color.YELLOW}⚠ {message}{Color.RESET}")
    
    @staticmethod
    def print_info(message: str):
        """طباعة رسالة معلومات"""
        print(f"{Color.BLUE}ℹ {message}{Color.RESET}")
    
    @staticmethod
    def print_progress(message: str):
        """طباعة رسالة تقدم"""
        print(f"{Color.DIM}{message}{Color.RESET}")
    
    @staticmethod
    def print_banner():
        """طباعة الشعار"""
        banner = f"""
{Color.BRIGHT_CYAN}
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║   ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗       ║
║   ██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗      ║
║   ███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝      ║
║   ██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗      ║
║   ██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║      ║
║   ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝      ║
║                                                               ║
║            Offensive Security Intelligence Platform          ║
║                         v1.0.0                               ║
╚═══════════════════════════════════════════════════════════════╝
{Color.RESET}"""
        print(banner)
    
    @staticmethod
    def confirm(prompt: str, default: bool = False) -> bool:
        """طلب تأكيد من المستخدم"""
        suffix = " [Y/n] " if default else " [y/N] "
        response = input(f"{Color.YELLOW}{prompt}{suffix}{Color.RESET}").strip().lower()
        
        if not response:
            return default
        
        return response in ["y", "yes", "Y", "Yes"]
    
    @staticmethod
    def input(prompt: str, default: str = None) -> str:
        """طلب إدخال من المستخدم"""
        if default:
            prompt = f"{prompt} [{default}]"
        
        response = input(f"{Color.CYAN}{prompt}{Color.RESET} ").strip()
        
        if not response and default:
            return default
        
        return response
    
    @staticmethod
    def select(options: List[str], prompt: str = "Select an option") -> int:
        """عرض قائمة اختيار"""
        print(f"\n{Color.BOLD}{prompt}:{Color.RESET}")
        for i, option in enumerate(options, 1):
            print(f"  {i}. {option}")
        
        while True:
            try:
                choice = int(input(f"{Color.CYAN}Enter number (1-{len(options)}): {Color.RESET}"))
                if 1 <= choice <= len(options):
                    return choice - 1
                print(f"{Color.RED}Invalid choice. Please enter 1-{len(options)}.{Color.RESET}")
            except ValueError:
                print(f"{Color.RED}Please enter a valid number.{Color.RESET}")
    
    @staticmethod
    def progress_bar(total: int, prefix: str = "", suffix: str = "") -> ProgressBar:
        """إنشاء شريط تقدم"""
        return ProgressBar(total, prefix=prefix, suffix=suffix)
    
    @staticmethod
    def spinner(message: str = "Loading") -> Spinner:
        """إنشاء مؤشر انتظار"""
        return Spinner(message)
    
    @staticmethod
    def table(headers: List[str], alignments: List[str] = None) -> Table:
        """إنشاء جدول"""
        return Table(headers, alignments)
    
    @staticmethod
    def format_finding(finding: Dict) -> str:
        """تنسيق عرض ثغرة"""
        severity_colors = {
            "critical": Color.RED,
            "high": Color.BRIGHT_RED,
            "medium": Color.YELLOW,
            "low": Color.BLUE,
            "info": Color.CYAN
        }
        
        color = severity_colors.get(finding.get("severity", "info"), Color.WHITE)
        
        return f"{color}[{finding.get('severity', 'INFO').upper()}] {finding.get('type', 'Unknown')}{Color.RESET} at {finding.get('url', 'N/A')}"
    
    @staticmethod
    def format_duration(seconds: float) -> str:
        """تنسيق المدة الزمنية"""
        if seconds < 60:
            return f"{seconds:.1f}s"
        elif seconds < 3600:
            return f"{seconds/60:.1f}m"
        else:
            return f"{seconds/3600:.1f}h"
    
    @staticmethod
    def clear_screen():
        """مسح الشاشة"""
        import os
        os.system('clear' if os.name == 'posix' else 'cls')


# نسخة عالمية
_default_ui = None


def get_terminal_ui() -> TerminalUI:
    """الحصول على نسخة عالمية من واجهة الطرفية"""
    global _default_ui
    if _default_ui is None:
        _default_ui = TerminalUI()
    return _default_ui

