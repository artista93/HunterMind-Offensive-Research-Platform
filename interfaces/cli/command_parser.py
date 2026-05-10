
import re
import shlex
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum


class CommandType(Enum):
    """أنواع الأوامر"""
    SCAN = "scan"
    ATTACK = "attack"
    EXPLOIT = "exploit"
    STATUS = "status"
    LIST = "list"
    SHOW = "show"
    HELP = "help"
    EXIT = "exit"
    CONFIG = "config"
    EXPORT = "export"
    IMPORT = "import"


@dataclass
class Command:
    """أمر محلل"""
    type: CommandType
    args: List[str] = field(default_factory=list)
    options: Dict[str, Any] = field(default_factory=dict)
    raw: str = ""


class CommandParser:
    """
    محلل الأوامر المتقدم
    
    الميزات:
    - تحليل الأوامر والمعاملات
    - دعم الخيارات القصيرة والطويلة
    - التحقق من صحة المعاملات
    - اقتراح أوامر مشابهة
    """
    
    # تعريفات الأوامر
    COMMAND_DEFINITIONS = {
        CommandType.SCAN: {
            "description": "Start a security scan",
            "args": ["target_url"],
            "options": {
                "--depth": {"type": int, "default": 3, "help": "Maximum crawl depth"},
                "--pages": {"type": int, "default": 100, "help": "Maximum pages to crawl"},
                "--quick": {"type": bool, "default": False, "help": "Quick scan mode"},
                "--auth": {"type": str, "default": None, "help": "Authentication token"},
                "--output": {"type": str, "default": None, "help": "Output file"}
            },
            "examples": [
                "scan https://example.com",
                "scan https://example.com --depth 5 --pages 200",
                "scan https://example.com --quick"
            ]
        },
        CommandType.ATTACK: {
            "description": "Launch an attack on a vulnerability",
            "args": ["target_url", "vulnerability_type"],
            "options": {
                "--parameter": {"type": str, "default": None, "help": "Target parameter"},
                "--payload": {"type": str, "default": None, "help": "Custom payload"},
                "--method": {"type": str, "default": "GET", "help": "HTTP method"},
                "--threads": {"type": int, "default": 5, "help": "Number of threads"}
            },
            "examples": [
                "attack https://example.com xss",
                "attack https://example.com sqli --parameter id",
                "attack https://example.com rce --payload 'id'"
            ]
        },
        CommandType.EXPLOIT: {
            "description": "Exploit a vulnerability",
            "args": ["target_url", "vulnerability_type"],
            "options": {
                "--parameter": {"type": str, "default": None, "help": "Target parameter"},
                "--technique": {"type": str, "default": "auto", "help": "Exploit technique"},
                "--output": {"type": str, "default": None, "help": "Output file"}
            },
            "examples": [
                "exploit https://example.com sqli --parameter id",
                "exploit https://example.com rce --technique reverse_shell"
            ]
        },
        CommandType.STATUS: {
            "description": "Show system status",
            "args": [],
            "options": {
                "--verbose": {"type": bool, "default": False, "help": "Verbose output"},
                "--json": {"type": bool, "default": False, "help": "JSON output"}
            },
            "examples": [
                "status",
                "status --verbose",
                "status --json"
            ]
        },
        CommandType.LIST: {
            "description": "List items",
            "args": ["item_type"],
            "options": {
                "--limit": {"type": int, "default": 50, "help": "Maximum items"},
                "--offset": {"type": int, "default": 0, "help": "Offset"},
                "--filter": {"type": str, "default": None, "help": "Filter expression"}
            },
            "examples": [
                "list scans",
                "list vulnerabilities --limit 20",
                "list attacks --filter status=success"
            ]
        },
        CommandType.SHOW: {
            "description": "Show item details",
            "args": ["item_type", "item_id"],
            "options": {},
            "examples": [
                "show scan scan_001",
                "show vulnerability vuln_001"
            ]
        },
        CommandType.CONFIG: {
            "description": "View or set configuration",
            "args": [],
            "options": {
                "--get": {"type": str, "default": None, "help": "Get configuration value"},
                "--set": {"type": str, "default": None, "help": "Set configuration value"},
                "--list": {"type": bool, "default": False, "help": "List all configurations"}
            },
            "examples": [
                "config --list",
                "config --get max_depth",
                "config --set max_depth=5"
            ]
        },
        CommandType.EXPORT: {
            "description": "Export data",
            "args": ["item_type", "output_file"],
            "options": {
                "--format": {"type": str, "default": "json", "help": "Export format"},
                "--filter": {"type": str, "default": None, "help": "Filter expression"}
            },
            "examples": [
                "export scans results.json",
                "export vulnerabilities vulns.json --format json"
            ]
        },
        CommandType.IMPORT: {
            "description": "Import data",
            "args": ["item_type", "input_file"],
            "options": {},
            "examples": [
                "import scans results.json",
                "import vulnerabilities vulns.json"
            ]
        }
    }
    
    def __init__(self):
        self.last_command: Optional[Command] = None
        self.suggestions_enabled = True
    
    def parse(self, input_line: str) -> Optional[Command]:
        """
        تحليل سطر الأوامر
        
        Args:
            input_line: سطر الأوامر
        
        Returns:
            كائن Command أو None
        """
        if not input_line or input_line.strip() == "":
            return None
        
        # تقسيم السطر إلى وحدات
        try:
            parts = shlex.split(input_line.strip())
        except ValueError as e:
            print(f"Parse error: {e}")
            return None
        
        if not parts:
            return None
        
        # تحديد نوع الأمر
        cmd_str = parts[0].lower()
        
        try:
            cmd_type = CommandType(cmd_str)
        except ValueError:
            # أمر غير معروف - اقتراح أوامر مشابهة
            if self.suggestions_enabled:
                self._suggest_commands(cmd_str)
            return None
        
        # استخراج المعاملات والخيارات
        args = []
        options = {}
        i = 1
        
        # الحصول على تعريف الأمر
        cmd_def = self.COMMAND_DEFINITIONS.get(cmd_type, {})
        expected_args = cmd_def.get("args", [])
        
        while i < len(parts):
            part = parts[i]
            
            if part.startswith("--"):
                # خيار طويل
                option_name = part
                
                # التحقق من وجود قيمة
                if i + 1 < len(parts) and not parts[i + 1].startswith("-"):
                    value = parts[i + 1]
                    i += 2
                    
                    # تحويل النوع
                    if option_name in cmd_def.get("options", {}):
                        opt_def = cmd_def["options"][option_name]
                        if opt_def["type"] == int:
                            try:
                                value = int(value)
                            except ValueError:
                                print(f"Invalid value for {option_name}: expected integer")
                                return None
                        elif opt_def["type"] == bool:
                            value = True
                    
                    options[option_name] = value
                else:
                    # خيار بدون قيمة (boolean)
                    options[option_name] = True
                    i += 1
            
            elif part.startswith("-"):
                # خيار قصير (غير مدعوم حالياً)
                print(f"Short options not supported yet. Use --{part[1]}")
                return None
            
            else:
                # معامل عادي
                args.append(part)
                i += 1
        
        # التحقق من عدد المعاملات
        if len(args) < len(expected_args):
            print(f"Missing arguments. Expected: {expected_args}")
            print(f"Usage: {cmd_str} {' '.join(expected_args)}")
            return None
        
        # تطبيق القيم الافتراضية للخيارات
        for opt_name, opt_def in cmd_def.get("options", {}).items():
            if opt_name not in options and "default" in opt_def:
                options[opt_name] = opt_def["default"]
        
        command = Command(
            type=cmd_type,
            args=args,
            options=options,
            raw=input_line
        )
        
        self.last_command = command
        return command
    
    def _suggest_commands(self, unknown_cmd: str):
        """اقتراح أوامر مشابهة"""
        commands = [cmd.value for cmd in CommandType]
        suggestions = []
        
        for cmd in commands:
            if cmd.startswith(unknown_cmd) or unknown_cmd in cmd:
                suggestions.append(cmd)
        
        if suggestions:
            print(f"Unknown command: '{unknown_cmd}'. Did you mean: {', '.join(suggestions)}?")
        else:
            print(f"Unknown command: '{unknown_cmd}'. Type 'help' for available commands.")
    
    def get_command_help(self, cmd_type: CommandType = None) -> str:
        """
        الحصول على مساعدة لأمر معين
        
        Args:
            cmd_type: نوع الأمر (الكل إذا None)
        
        Returns:
            نص المساعدة
        """
        if cmd_type:
            cmd_def = self.COMMAND_DEFINITIONS.get(cmd_type)
            if not cmd_def:
                return f"No help available for {cmd_type.value}"
            
            help_text = f"\n📖 Command: {cmd_type.value}\n"
            help_text += f"   Description: {cmd_def['description']}\n"
            help_text += f"   Usage: {cmd_type.value} {' '.join(cmd_def['args'])}\n"
            
            if cmd_def['options']:
                help_text += "   Options:\n"
                for opt, opt_def in cmd_def['options'].items():
                    help_text += f"     {opt:<15} {opt_def['help']}\n"
            
            if cmd_def['examples']:
                help_text += "   Examples:\n"
                for ex in cmd_def['examples']:
                    help_text += f"     {ex}\n"
            
            return help_text
        
        # مساعدة عامة
        help_text = "\n📚 Available Commands\n"
        help_text += "=" * 40 + "\n"
        
        for cmd_type, cmd_def in self.COMMAND_DEFINITIONS.items():
            help_text += f"  {cmd_type.value:<12} - {cmd_def['description']}\n"
        
        help_text += "\n  Type 'help <command>' for detailed help on a specific command.\n"
        
        return help_text
    
    def validate_command(self, command: Command) -> Tuple[bool, str]:
        """
        التحقق من صحة الأمر
        
        Args:
            command: الأمر المراد التحقق منه
        
        Returns:
            (صحيح, رسالة خطأ)
        """
        cmd_def = self.COMMAND_DEFINITIONS.get(command.type)
        if not cmd_def:
            return False, f"Unknown command: {command.type.value}"
        
        # التحقق من المعاملات المطلوبة
        expected_count = len(cmd_def["args"])
        if len(command.args) < expected_count:
            return False, f"Missing arguments. Expected {expected_count}, got {len(command.args)}"
        
        # التحقق من الخيارات
        for opt_name, opt_value in command.options.items():
            if opt_name not in cmd_def["options"]:
                return False, f"Unknown option: {opt_name}"
            
            opt_def = cmd_def["options"][opt_name]
            if opt_def["type"] == int and not isinstance(opt_value, int):
                return False, f"Option {opt_name} expects an integer"
        
        return True, ""


# نسخة عالمية
_default_parser = None


def get_command_parser() -> CommandParser:
    """الحصول على نسخة عالمية من محلل الأوامر"""
    global _default_parser
    if _default_parser is None:
        _default_parser = CommandParser()
    return _default_parser

