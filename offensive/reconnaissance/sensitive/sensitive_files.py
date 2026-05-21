"""
Sensitive Files Discovery - اكتشاف الملفات الحساسة

يبحث عن:
- ملفات النسخ الاحتياطي (.bak, .zip, .tar.gz, .sql, .dump)
- ملفات التكوين (.env, config.php, wp-config.php, settings.py)
- مستودعات Git (.git/HEAD, .git/config, .git/index)
- لوحات التحكم (/admin, /wp-admin, /phpmyadmin, /pma)
- ملفات السجلات (debug.log, error.log, access.log)
- ملفات البيئة (.env.local, .env.production, .env.backup)
- قواعد البيانات المكشوفة (.sqlite, database.sql, dump.sql)
"""

import asyncio
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime
from urllib.parse import urljoin, urlparse

import httpx
import logging

logger = logging.getLogger(__name__)


@dataclass
class SensitiveFile:
    """ملف حساس مكتشف"""
    url: str
    type: str  # backup, config, git, admin, log, database, env
    status_code: int = 0
    content_preview: str = ""
    content_length: int = 0
    is_accessible: bool = False
    severity: str = "MEDIUM"  # CRITICAL, HIGH, MEDIUM, LOW
    description: str = ""


@dataclass
class SensitiveFilesResult:
    """نتائج البحث عن الملفات الحساسة"""
    target: str
    files_found: List[SensitiveFile] = field(default_factory=list)
    total_files: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    errors: List[str] = field(default_factory=list)


class SensitiveFilesScanner:
    """
    ماسح الملفات الحساسة
    
    يستخدم wordlists مخصصة حسب التقنية
    """
    
    # Wordlists مخصصة
    BACKUP_FILES = [
        "backup.zip", "backup.tar.gz", "backup.sql", "backup.rar",
        "site.zip", "site.tar.gz", "www.zip", "www.tar.gz",
        "backup.zip.bak", "database.sql", "dump.sql", "export.sql",
        "db_backup.sql", "db.sql", "data.sql", "mysql.sql",
        "backup", "old", "archive.zip", "archive.tar.gz",
    ]
    
    CONFIG_FILES = [
        ".env", ".env.local", ".env.production", ".env.backup", ".env.dev",
        ".env.staging", ".env.old", ".env.save",
        "config.php", "config.php.bak", "config.php.old", "config.php.save",
        "wp-config.php", "wp-config.php.bak", "wp-config.php.old",
        "settings.py", "settings.py.bak", "settings.pyc",
        ".htaccess", ".htaccess.bak", ".htpasswd",
        "web.config", "web.config.bak", "app.config",
        "config.yml", "config.yaml", "config.json",
        "application.properties", "application.yml",
        "database.yml", "database.json",
        "credentials.json", "credentials.yml",
        "secrets.yml", "secrets.json",
    ]
    
    GIT_FILES = [
        ".git/HEAD", ".git/config", ".git/index",
        ".git/refs/heads/master", ".git/refs/heads/main",
        ".git/logs/HEAD", ".git/description",
        ".git/packed-refs", ".git/FETCH_HEAD",
        ".git/COMMIT_EDITMSG", ".git/ORIG_HEAD",
        ".svn/entries", ".svn/wc.db",
        ".hg/requires", ".hg/store/",
        ".DS_Store", ".DS_Store?",
    ]
    
    ADMIN_PANELS = [
        "admin", "administrator", "admin.php", "admin.html",
        "wp-admin", "wp-admin/admin-ajax.php", "wp-login.php",
        "phpmyadmin", "pma", "phpMyAdmin", "mysql", "dbadmin",
        "manager/html", "manager/status",
        "jenkins", "jenkins/login",
        "grafana", "grafana/login",
        "cpanel", "webmail", "roundcube", "roundcubemail",
        "django-admin", "admin/login", "user/login",
        "api/admin", "api/docs", "swagger", "swagger-ui.html",
        "graphql", "graphiql", "playground",
        "api/graphql", "api/swagger",
        "console", "dashboard", "portal",
    ]
    
    LOG_FILES = [
        "debug.log", "error.log", "access.log", "server.log",
        "app.log", "application.log", "system.log",
        "wp-content/debug.log", "storage/logs/laravel.log",
        "var/log/error.log", "var/log/access.log",
        "logs/error.log", "logs/access.log",
        "log.txt", "error_log", "debug_log",
    ]
    
    DATABASE_FILES = [
        "database.sqlite", "database.sqlite3", "db.sqlite3",
        "database.db", "data.db", "app.db",
        "database.sql", "dump.sql", "backup.sql",
        "mysql.dump", "postgres.dump",
    ]
    
    # تصنيف الخطورة
    SEVERITY_MAP = {
        "env": "CRITICAL",
        "config": "HIGH",
        "git": "HIGH",
        "database": "CRITICAL",
        "backup": "HIGH",
        "admin": "MEDIUM",
        "log": "MEDIUM",
    }
    
    def __init__(self):
        self._results: Dict[str, SensitiveFilesResult] = {}
        self._client = None
    
    async def _get_client(self) -> httpx.AsyncClient:
        if not self._client:
            self._client = httpx.AsyncClient(
                timeout=10, follow_redirects=False, verify=False,
                headers={"User-Agent": "Mozilla/5.0 (compatible; HunterMind/1.0)"}
            )
        return self._client
    
    async def scan(self, url: str, cms_type: str = "", use_wordlists: bool = True) -> SensitiveFilesResult:
        """
        فحص الملفات الحساسة
        
        Args:
            url: رابط الموقع الأساسي
            cms_type: نوع CMS إذا كان معروفاً (wordpress, drupal, joomla, laravel)
            use_wordlists: استخدام wordlists موسعة
        
        Returns:
            SensitiveFilesResult مع الملفات المكتشفة
        """
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        
        print(f"  🔑 Scanning sensitive files: {base}")
        
        result = SensitiveFilesResult(target=base)
        client = await self._get_client()
        
        # تجميع كل المسارات
        all_paths = []
        all_paths.extend(self.BACKUP_FILES)
        all_paths.extend(self.CONFIG_FILES)
        all_paths.extend(self.GIT_FILES)
        all_paths.extend(self.ADMIN_PANELS)
        all_paths.extend(self.LOG_FILES)
        all_paths.extend(self.DATABASE_FILES)
        
        # إضافة wordlists مخصصة حسب CMS
        if cms_type == "wordpress":
            wp_paths = [
                "wp-content/backup", "wp-content/uploads",
                "wp-content/debug.log", "wp-content/upgrade",
                "wp-json/wp/v2/users", "wp-json/wp/v2/posts",
                "xmlrpc.php", "wp-cron.php", "wp-trackback.php",
            ]
            all_paths.extend(wp_paths)
        elif cms_type == "drupal":
            drupal_paths = [
                "sites/default/settings.php", "sites/default/files",
                "modules/php/php.info", "CHANGELOG.txt",
                "core/CHANGELOG.txt", "update.php",
            ]
            all_paths.extend(drupal_paths)
        elif cms_type == "laravel":
            laravel_paths = [
                "storage/logs/laravel.log", "storage/app",
                "storage/framework", "vendor/phpunit",
                "composer.json", "composer.lock",
                "package.json", "artisan",
            ]
            all_paths.extend(laravel_paths)
        
        # فحص كل مسار
        tasks = []
        for path in all_paths[:100]:  # حد أقصى 100 مسار
            tasks.append(self._check_path(client, base, path, result))
        
        await asyncio.gather(*tasks, return_exceptions=True)
        
        # إحصائيات
        result.total_files = len(result.files_found)
        for f in result.files_found:
            if f.severity == "CRITICAL":
                result.critical_count += 1
            elif f.severity == "HIGH":
                result.high_count += 1
            elif f.severity == "MEDIUM":
                result.medium_count += 1
            else:
                result.low_count += 1
        
        # عرض النتائج
        if result.files_found:
            print(f"     ⚠️  Found {result.total_files} sensitive files!")
            print(f"     🔴 Critical: {result.critical_count} | 🟠 High: {result.high_count} | 🟡 Medium: {result.medium_count}")
            
            # عرض أمثلة
            criticals = [f for f in result.files_found if f.severity == "CRITICAL"]
            for f in criticals[:3]:
                print(f"     🔴 {f.url} ({f.type}) - HTTP {f.status_code}")
        else:
            print(f"     ✅ No sensitive files found")
        
        self._results[base] = result
        return result
    
    async def _check_path(self, client: httpx.AsyncClient, base: str, path: str, result: SensitiveFilesResult):
        """فحص مسار واحد"""
        full_url = urljoin(base, path)
        
        try:
            response = await client.get(full_url)
            status = response.status_code
            
            # بنسجل لو الملف موجود (200) أو محمي (403/401)
            if status in [200, 403, 401, 301, 302]:
                # تحديد نوع الملف
                file_type = self._classify_path(path)
                severity = self.SEVERITY_MAP.get(file_type, "MEDIUM")
                
                # معاينة المحتوى إذا كان 200
                preview = ""
                if status == 200 and response.text:
                    preview = response.text[:200]
                    
                    # لو ملف .env، نتأكد إنه فعلاً environment file
                    if file_type == "env" and "=" not in preview:
                        return  # مش .env حقيقي
                    
                    # لو Git، نتأكد من المحتوى
                    if file_type == "git" and "ref:" not in preview and "[core]" not in preview:
                        return  # مش Git حقيقي
                
                sensitive_file = SensitiveFile(
                    url=full_url,
                    type=file_type,
                    status_code=status,
                    content_preview=preview,
                    content_length=len(response.text) if status == 200 else 0,
                    is_accessible=(status == 200),
                    severity=severity,
                    description=self._get_description(file_type, status),
                )
                
                result.files_found.append(sensitive_file)
        
        except Exception as e:
            logger.debug(f"Check failed for {full_url}: {e}")
    
    def _classify_path(self, path: str) -> str:
        """تصنيف المسار"""
        path_lower = path.lower()
        
        # Git/SVN
        if '.git/' in path_lower or '.svn/' in path_lower or '.hg/' in path_lower:
            return "git"
        
        # Environment files
        if '.env' in path_lower:
            return "env"
        
        # Config files
        if any(kw in path_lower for kw in ['config', 'settings', '.htaccess', 'web.config', 'application.properties']):
            return "config"
        
        # Database files
        if any(kw in path_lower for kw in ['.sql', '.sqlite', '.db', 'dump', 'database']):
            return "database"
        
        # Backup files
        if any(kw in path_lower for kw in ['backup', '.bak', '.zip', '.tar', '.gz', '.rar', '.old', '.save']):
            return "backup"
        
        # Admin panels
        if any(kw in path_lower for kw in ['admin', 'login', 'phpmyadmin', 'pma', 'jenkins', 'grafana', 'cpanel']):
            return "admin"
        
        # Log files
        if any(kw in path_lower for kw in ['.log', 'debug', 'error_log']):
            return "log"
        
        return "other"
    
    def _get_description(self, file_type: str, status: int) -> str:
        """وصف الملف"""
        descriptions = {
            "env": "Environment file with potential secrets and API keys",
            "config": "Configuration file may contain database credentials",
            "git": "Git repository exposed - source code accessible",
            "database": "Database file exposed - data breach risk",
            "backup": "Backup file may contain full source code",
            "admin": "Admin panel accessible",
            "log": "Log file may leak sensitive information",
        }
        
        desc = descriptions.get(file_type, "Sensitive file found")
        
        if status == 403:
            desc += " (restricted but confirms existence)"
        elif status == 401:
            desc += " (authentication required)"
        
        return desc
    
    def get_results(self, url: str) -> Optional[SensitiveFilesResult]:
        return self._results.get(url)
    
    async def close(self):
        if self._client:
            await self._client.aclose()


# نسخة عالمية
_sensitive_scanner = None

def get_sensitive_scanner() -> SensitiveFilesScanner:
    global _sensitive_scanner
    if _sensitive_scanner is None:
        _sensitive_scanner = SensitiveFilesScanner()
    return _sensitive_scanner
