
import os
import sys
import platform
import subprocess
import asyncio
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class ChromiumProfile:
    """ملف تعريف Chromium"""
    name: str
    path: str
    user_data_dir: str
    created_at: str = ""
    last_used: str = ""
    preferences: Dict[str, Any] = field(default_factory=dict)


class ChromiumController:
    """متحكم Chromium المتقدم"""
    
    def __init__(self):
        self._executable_path: Optional[str] = None
        self._user_data_dir: Optional[str] = None
        self._profiles: Dict[str, ChromiumProfile] = {}
        self._current_profile: Optional[str] = None
        self._flags: List[str] = []
        
        # إعدادات الأداء
        self._performance_settings = {
            "disable_gpu": True,
            "disable_extensions": True,
            "disable_plugins": True,
            "disable_images": False,
            "disable_javascript": False,
            "disable_web_security": False,
            "max_connections": 6,
            "memory_limit_mb": 512
        }
    
    def find_chromium(self) -> Optional[str]:
        """البحث عن مسار Chromium في النظام"""
        
        # منصات مختلفة
        system = platform.system()
        
        paths = []
        if system == "Windows":
            paths = [
                "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
                "C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe",
                os.path.expanduser("~\\AppData\\Local\\Google\\Chrome\\Application\\chrome.exe")
            ]
        elif system == "Darwin":  # macOS
            paths = [
                "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
                "/Applications/Chromium.app/Contents/MacOS/Chromium"
            ]
        else:  # Linux
            paths = [
                "/usr/bin/google-chrome",
                "/usr/bin/chromium-browser",
                "/usr/bin/chromium",
                os.path.expanduser("~/.local/bin/chromium")
            ]
        
        # أيضاً مسار Playwright
        try:
            from playwright._impl._driver import compute_driver_executable
            driver_path = compute_driver_executable()
            chromium_path = os.path.join(os.path.dirname(driver_path), "chromium")
            paths.append(chromium_path)
        except:
            pass
        
        for path in paths:
            if os.path.exists(path):
                self._executable_path = path
                return path
        
        # محاولة تشغيل via `which`
        for cmd in ["google-chrome", "chromium-browser", "chromium"]:
            result = subprocess.run(["which", cmd], capture_output=True, text=True)
            if result.returncode == 0:
                self._executable_path = result.stdout.strip()
                return self._executable_path
        
        return None
    
    def set_executable_path(self, path: str):
        """تعيين مسار Chromium يدوياً"""
        if os.path.exists(path):
            self._executable_path = path
        else:
            raise FileNotFoundError(f"Chromium not found at {path}")
    
    def create_user_data_dir(self, name: str) -> str:
        """إنشاء دليل بيانات مستخدم جديد"""
        base_dir = os.path.expanduser(f"~/.huntermind/chromium_profiles/{name}")
        os.makedirs(base_dir, exist_ok=True)
        
        profile = ChromiumProfile(
            name=name,
            path=base_dir,
            user_data_dir=f"--user-data-dir={base_dir}"
        )
        self._profiles[name] = profile
        return base_dir
    
    def get_profile(self, name: str) -> Optional[ChromiumProfile]:
        """الحصول على ملف تعريف"""
        return self._profiles.get(name)
    
    def list_profiles(self) -> List[str]:
        """قائمة ملفات التعريف"""
        return list(self._profiles.keys())
    
    def set_profile(self, name: str):
        """تعيين ملف تعريف نشط"""
        if name in self._profiles:
            self._current_profile = name
    
    def add_flag(self, flag: str):
        """إضافة علامة تشغيل"""
        if flag not in self._flags:
            self._flags.append(flag)
    
    def remove_flag(self, flag: str):
        """إزالة علامة تشغيل"""
        if flag in self._flags:
            self._flags.remove(flag)
    
    def set_performance(self, **kwargs):
        """تعيين إعدادات الأداء"""
        for key, value in kwargs.items():
            if key in self._performance_settings:
                self._performance_settings[key] = value
    
    def get_launch_args(self, extra_args: List[str] = None) -> List[str]:
        """الحصول على معاملات التشغيل الكاملة"""
        
        args = []
        
        # ملف تعريف المستخدم
        if self._current_profile and self._current_profile in self._profiles:
            profile = self._profiles[self._current_profile]
            args.append(profile.user_data_dir)
        else:
            # دليل مؤقت
            import tempfile
            temp_dir = tempfile.mkdtemp()
            args.append(f"--user-data-dir={temp_dir}")
        
        # علامات إضافية
        args.extend(self._flags)
        
        if extra_args:
            args.extend(extra_args)
        
        # ========== علامات الأمان والتخفي ==========
        args.extend([
            "--no-sandbox",
            "--disable-setuid-sandbox",
            "--disable-dev-shm-usage",
            "--disable-gpu",
            "--disable-software-rasterizer",
            "--disable-extensions",
            "--disable-plugins",
            "--disable-default-apps",
            "--disable-sync",
            "--disable-translate",
            "--disable-background-networking",
            "--disable-background-timer-throttling",
            "--disable-backgrounding-occluded-windows",
            "--disable-breakpad",
            "--disable-client-side-phishing-detection",
            "--disable-component-extensions-with-background-pages",
            "--disable-component-update",
            "--disable-domain-reliability",
            "--disable-features=IsolateOrigins,site-per-process",
            "--disable-ipc-flooding-protection",
            "--disable-renderer-backgrounding",
            "--disable-session-crashed-bubble",
            "--disable-site-isolation-trials",
            "--disable-web-security" if self._performance_settings.get("disable_web_security") else "",
        ])
        
        # ========== علامات الأداء ==========
        if self._performance_settings.get("disable_gpu"):
            args.append("--disable-gpu")
        if self._performance_settings.get("disable_extensions"):
            args.append("--disable-extensions")
        if self._performance_settings.get("disable_plugins"):
            args.append("--disable-plugins")
        if self._performance_settings.get("disable_images"):
            args.append("--blink-settings=imagesEnabled=false")
        if self._performance_settings.get("disable_javascript"):
            args.append("--disable-javascript")
        
        # حد الذاكرة
        memory_limit = self._performance_settings.get("memory_limit_mb", 512)
        args.append(f"--max_old_space_size={memory_limit}")
        
        # عدد الاتصالات
        max_conn = self._performance_settings.get("max_connections", 6)
        args.append(f"--max-connections-per-host={max_conn}")
        
        # إزالة العلامات الفارغة
        return [arg for arg in args if arg]
    
    def get_version(self) -> Optional[str]:
        """الحصول على إصدار Chromium"""
        if not self._executable_path:
            return None
        
        try:
            result = subprocess.run(
                [self._executable_path, "--version"],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                return result.stdout.strip()
        except:
            pass
        return None
    
    def is_available(self) -> bool:
        """التحقق من توفر Chromium"""
        return self.find_chromium() is not None
    
    def clean_profiles(self):
        """تنظيف ملفات التعريف القديمة"""
        import shutil
        base_dir = os.path.expanduser("~/.huntermind/chromium_profiles")
        if os.path.exists(base_dir):
            for name in os.listdir(base_dir):
                profile_path = os.path.join(base_dir, name)
                if os.path.isdir(profile_path):
                    # حذف الملفات القديمة (أكثر من 7 أيام)
                    try:
                        import time
                        mtime = os.path.getmtime(profile_path)
                        if time.time() - mtime > 7 * 24 * 3600:
                            shutil.rmtree(profile_path)
                    except:
                        pass
    
    def get_stats(self) -> Dict:
        """إحصائيات المتحكم"""
        return {
            "chromium_available": self.is_available(),
            "chromium_path": self._executable_path,
            "chromium_version": self.get_version(),
            "active_profile": self._current_profile,
            "profiles_count": len(self._profiles),
            "flags_count": len(self._flags),
            "performance_settings": self._performance_settings.copy()
        }


# نسخة عالمية
_default_controller = None


def get_chromium_controller() -> ChromiumController:
    """الحصول على نسخة عالمية من متحكم Chromium"""
    global _default_controller
    if _default_controller is None:
        _default_controller = ChromiumController()
    return _default_controller

