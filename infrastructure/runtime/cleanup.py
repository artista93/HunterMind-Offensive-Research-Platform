
import asyncio
import os
import shutil
import tempfile
import glob
import psutil
from typing import Dict, List, Optional, Any, Callable, Awaitable, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
import logging

logger = logging.getLogger(__name__)


class CleanupTarget(Enum):
    """هدف التنظيف"""
    TEMP_FILES = "temp_files"
    OLD_LOGS = "old_logs"
    CACHE = "cache"
    CHECKPOINTS = "checkpoints"
    ORPHAN_PROCESSES = "orphan_processes"
    ZOMBIE_THREADS = "zombie_threads"
    UNUSED_MEMORY = "unused_memory"
    STOPPED_CONTAINERS = "stopped_containers"
    DANGLING_IMAGES = "dangling_images"
    OLD_SESSIONS = "old_sessions"


class CleanupStrategy(Enum):
    """استراتيجية التنظيف"""
    DELETE = "delete"
    ARCHIVE = "archive"
    COMPRESS = "compress"
    TRUNCATE = "truncate"


@dataclass
class CleanupRule:
    """قاعدة تنظيف"""
    target: CleanupTarget
    strategy: CleanupStrategy
    max_age_hours: int
    max_size_mb: Optional[int] = None
    paths: List[str] = field(default_factory=list)
    patterns: List[str] = field(default_factory=list)
    enabled: bool = True


@dataclass
class CleanupReport:
    """تقرير التنظيف"""
    timestamp: datetime
    rules_executed: int
    space_freed_mb: float
    items_removed: int
    errors: List[str]
    details: Dict[str, Any]


class CleanupManager:
    """
    مدير التنظيف المتقدم
    
    الميزات:
    - تنظيف تلقائي للملفات المؤقتة والسجلات القديمة
    - إدارة نقاط التفتيش القديمة
    - تنظيف العمليات اليتيمة (orphan processes)
    - تنظيف ذاكرة التخزين المؤقت
    - مراقبة المساحة وإطلاق التنبيهات
    - تقارير التنظيف الدورية
    - تكامل مع نظام الملفات والحاويات
    """
    
    def __init__(
        self,
        cleanup_interval: int = 3600,  # ساعة واحدة
        auto_cleanup: bool = True,
        dry_run: bool = False
    ):
        self._cleanup_interval = cleanup_interval
        self._auto_cleanup = auto_cleanup
        self._dry_run = dry_run
        
        # قواعد التنظيف
        self._rules: List[CleanupRule] = []
        self._setup_default_rules()
        
        # سجل التنظيف
        self._cleanup_reports: List[CleanupReport] = []
        self._last_cleanup: Optional[datetime] = None
        
        # مكونات التشغيل
        self._cleanup_task: Optional[asyncio.Task] = None
        self._running = False
        self._lock = asyncio.Lock()
        
        # إحصائيات
        self._stats = {
            "total_cleanups": 0,
            "total_space_freed_mb": 0.0,
            "total_items_removed": 0,
            "last_cleanup_time": None,
            "last_cleanup_space_mb": 0.0
        }
        
        # الحالة
        self._disk_usage_warning_threshold = 80.0  # %
        self._disk_usage_critical_threshold = 90.0  # %
        
        logger.info(f"CleanupManager initialized (interval={cleanup_interval}s, auto_cleanup={auto_cleanup})")
    
    def _setup_default_rules(self):
        """إعداد قواعد التنظيف الافتراضية"""
        # ملفات مؤقتة
        self._rules.append(CleanupRule(
            target=CleanupTarget.TEMP_FILES,
            strategy=CleanupStrategy.DELETE,
            max_age_hours=24,
            paths=["/tmp", "/var/tmp"],
            patterns=["*.tmp", "*.temp", "tmp_*", "temp_*"]
        ))
        
        # سجلات قديمة (أكثر من 7 أيام)
        self._rules.append(CleanupRule(
            target=CleanupTarget.OLD_LOGS,
            strategy=CleanupStrategy.ARCHIVE,
            max_age_hours=168,  # 7 أيام
            paths=["./logs", "./telemetry/logs"],
            patterns=["*.log", "*.log.*"]
        ))
        
        # ذاكرة التخزين المؤقت (أكثر من 24 ساعة)
        self._rules.append(CleanupRule(
            target=CleanupTarget.CACHE,
            strategy=CleanupStrategy.DELETE,
            max_age_hours=24,
            paths=["./cache", "./.cache"],
            patterns=["*"]
        ))
        
        # نقاط التفتيش القديمة (أكثر من 7 أيام، احتفظ بآخر 5)
        self._rules.append(CleanupRule(
            target=CleanupTarget.CHECKPOINTS,
            strategy=CleanupStrategy.DELETE,
            max_age_hours=168,
            paths=["./checkpoints"],
            patterns=["*.pkl", "*.json"]
        ))
        
        # حاويات متوقفة (Docker)
        self._rules.append(CleanupRule(
            target=CleanupTarget.STOPPED_CONTAINERS,
            strategy=CleanupStrategy.DELETE,
            max_age_hours=0,  # فورية
            paths=[]
        ))
    
    def add_rule(self, rule: CleanupRule):
        """إضافة قاعدة تنظيف مخصصة"""
        self._rules.append(rule)
        logger.info(f"Added cleanup rule: {rule.target.value}")
    
    def remove_rule(self, target: CleanupTarget):
        """إزالة قاعدة تنظيف"""
        self._rules = [r for r in self._rules if r.target != target]
        logger.info(f"Removed cleanup rule: {target.value}")
    
    async def start(self):
        """بدء التنظيف التلقائي"""
        if self._running:
            return
        
        self._running = True
        
        if self._auto_cleanup:
            self._cleanup_task = asyncio.create_task(self._cleanup_loop())
        
        logger.info("CleanupManager started")
    
    async def stop(self):
        """إيقاف التنظيف"""
        if not self._running:
            return
        
        self._running = False
        
        if self._cleanup_task:
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass
        
        logger.info("CleanupManager stopped")
    
    async def _cleanup_loop(self):
        """حلقة التنظيف الدورية"""
        while self._running:
            await asyncio.sleep(self._cleanup_interval)
            
            try:
                if self._auto_cleanup:
                    report = await self.run_cleanup()
                    
                    # فحص استخدام القرص
                    await self._check_disk_usage()
                    
                    logger.info(f"Auto cleanup completed: freed {report.space_freed_mb:.1f}MB, removed {report.items_removed} items")
                    
            except Exception as e:
                logger.error(f"Cleanup loop error: {e}")
    
    async def run_cleanup(self, specific_target: Optional[CleanupTarget] = None) -> CleanupReport:
        """
        تنفيذ التنظيف
        
        Args:
            specific_target: تنظيف هدف محدد فقط (اختياري)
        
        Returns:
            تقرير التنظيف
        """
        start_time = datetime.now()
        space_freed = 0.0
        items_removed = 0
        errors = []
        details = {}
        
        rules_to_run = [r for r in self._rules if r.enabled]
        if specific_target:
            rules_to_run = [r for r in rules_to_run if r.target == specific_target]
        
        logger.info(f"Running cleanup with {len(rules_to_run)} rules (dry_run={self._dry_run})")
        
        for rule in rules_to_run:
            try:
                result = await self._execute_rule(rule)
                space_freed += result.get("space_freed_mb", 0)
                items_removed += result.get("items_removed", 0)
                details[rule.target.value] = result
                
                if result.get("errors"):
                    errors.extend(result["errors"])
                    
            except Exception as e:
                error_msg = f"Rule {rule.target.value} failed: {e}"
                logger.error(error_msg)
                errors.append(error_msg)
        
        report = CleanupReport(
            timestamp=datetime.now(),
            rules_executed=len(rules_to_run),
            space_freed_mb=space_freed,
            items_removed=items_removed,
            errors=errors,
            details=details
        )
        
        async with self._lock:
            self._cleanup_reports.append(report)
            if len(self._cleanup_reports) > 100:
                self._cleanup_reports.pop(0)
        
        # تحديث الإحصائيات
        self._stats["total_cleanups"] += 1
        self._stats["total_space_freed_mb"] += space_freed
        self._stats["total_items_removed"] += items_removed
        self._stats["last_cleanup_time"] = datetime.now().isoformat()
        self._stats["last_cleanup_space_mb"] = space_freed
        self._last_cleanup = datetime.now()
        
        return report
    
    async def _execute_rule(self, rule: CleanupRule) -> Dict[str, Any]:
        """تنفيذ قاعدة تنظيف واحدة"""
        result = {
            "space_freed_mb": 0.0,
            "items_removed": 0,
            "errors": []
        }
        
        if rule.target == CleanupTarget.TEMP_FILES:
            result = await self._cleanup_temp_files(rule)
        
        elif rule.target == CleanupTarget.OLD_LOGS:
            result = await self._cleanup_old_logs(rule)
        
        elif rule.target == CleanupTarget.CACHE:
            result = await self._cleanup_cache(rule)
        
        elif rule.target == CleanupTarget.CHECKPOINTS:
            result = await self._cleanup_checkpoints(rule)
        
        elif rule.target == CleanupTarget.ORPHAN_PROCESSES:
            result = await self._cleanup_orphan_processes()
        
        elif rule.target == CleanupTarget.STOPPED_CONTAINERS:
            result = await self._cleanup_stopped_containers()
        
        elif rule.target == CleanupTarget.OLD_SESSIONS:
            result = await self._cleanup_old_sessions(rule)
        
        return result
    
    async def _cleanup_temp_files(self, rule: CleanupRule) -> Dict[str, Any]:
        """تنظيف الملفات المؤقتة"""
        result = {"space_freed_mb": 0.0, "items_removed": 0, "errors": []}
        cutoff_time = datetime.now() - timedelta(hours=rule.max_age_hours)
        
        for base_path in rule.paths:
            if not os.path.exists(base_path):
                continue
            
            for pattern in rule.patterns:
                search_pattern = os.path.join(base_path, pattern)
                
                for filepath in glob.glob(search_pattern, recursive=True):
                    try:
                        stat = os.stat(filepath)
                        mtime = datetime.fromtimestamp(stat.st_mtime)
                        
                        if mtime < cutoff_time:
                            size_mb = stat.st_size / (1024 * 1024)
                            
                            if not self._dry_run:
                                if os.path.isdir(filepath):
                                    shutil.rmtree(filepath)
                                else:
                                    os.remove(filepath)
                            
                            result["space_freed_mb"] += size_mb
                            result["items_removed"] += 1
                            
                    except Exception as e:
                        result["errors"].append(f"Failed to clean {filepath}: {e}")
        
        return result
    
    async def _cleanup_old_logs(self, rule: CleanupRule) -> Dict[str, Any]:
        """تنظيف السجلات القديمة"""
        result = {"space_freed_mb": 0.0, "items_removed": 0, "errors": []}
        cutoff_time = datetime.now() - timedelta(hours=rule.max_age_hours)
        
        for base_path in rule.paths:
            if not os.path.exists(base_path):
                continue
            
            for pattern in rule.patterns:
                search_pattern = os.path.join(base_path, pattern)
                
                for filepath in glob.glob(search_pattern):
                    try:
                        stat = os.stat(filepath)
                        mtime = datetime.fromtimestamp(stat.st_mtime)
                        
                        if mtime < cutoff_time:
                            size_mb = stat.st_size / (1024 * 1024)
                            
                            if not self._dry_run:
                                if rule.strategy == CleanupStrategy.ARCHIVE:
                                    # ضغط بدلاً من الحذف المباشر
                                    archive_path = f"{filepath}.gz"
                                    import gzip
                                    with open(filepath, 'rb') as f_in:
                                        with gzip.open(archive_path, 'wb') as f_out:
                                            f_out.writelines(f_in)
                                    os.remove(filepath)
                                else:
                                    os.remove(filepath)
                            
                            result["space_freed_mb"] += size_mb
                            result["items_removed"] += 1
                            
                    except Exception as e:
                        result["errors"].append(f"Failed to clean {filepath}: {e}")
        
        return result
    
    async def _cleanup_cache(self, rule: CleanupRule) -> Dict[str, Any]:
        """تنظيف ذاكرة التخزين المؤقت"""
        result = {"space_freed_mb": 0.0, "items_removed": 0, "errors": []}
        cutoff_time = datetime.now() - timedelta(hours=rule.max_age_hours)
        
        for base_path in rule.paths:
            if not os.path.exists(base_path):
                continue
            
            # تنظيف ذاكرة التخزين المؤقت في الذاكرة
            import gc
            collected = gc.collect()
            result["items_removed"] += collected
            logger.debug(f"Garbage collector freed {collected} objects")
            
            # تنظيف الملفات
            for filepath in glob.glob(os.path.join(base_path, "*")):
                try:
                    stat = os.stat(filepath)
                    mtime = datetime.fromtimestamp(stat.st_mtime)
                    
                    if mtime < cutoff_time:
                        size_mb = stat.st_size / (1024 * 1024)
                        
                        if not self._dry_run:
                            if os.path.isdir(filepath):
                                shutil.rmtree(filepath)
                            else:
                                os.remove(filepath)
                        
                        result["space_freed_mb"] += size_mb
                        result["items_removed"] += 1
                        
                except Exception as e:
                    result["errors"].append(f"Failed to clean {filepath}: {e}")
        
        return result
    
    async def _cleanup_checkpoints(self, rule: CleanupRule) -> Dict[str, Any]:
        """تنظيف نقاط التفتيش القديمة"""
        result = {"space_freed_mb": 0.0, "items_removed": 0, "errors": []}
        
        for base_path in rule.paths:
            if not os.path.exists(base_path):
                continue
            
            # جمع جميع نقاط التفتيش
            checkpoints = []
            for pattern in rule.patterns:
                for filepath in glob.glob(os.path.join(base_path, pattern)):
                    stat = os.stat(filepath)
                    checkpoints.append((filepath, stat.st_mtime, stat.st_size))
            
            # ترتيب حسب التاريخ (الأحدث أولاً)
            checkpoints.sort(key=lambda x: x[1], reverse=True)
            
            # الاحتفاظ بآخر 5 نقاط فقط
            for filepath, mtime, size in checkpoints[5:]:
                if not self._dry_run:
                    os.remove(filepath)
                
                result["space_freed_mb"] += size / (1024 * 1024)
                result["items_removed"] += 1
        
        return result
    
    async def _cleanup_orphan_processes(self) -> Dict[str, Any]:
        """تنظيف العمليات اليتيمة"""
        result = {"space_freed_mb": 0.0, "items_removed": 0, "errors": []}
        
        try:
            current_process = psutil.Process()
            children = current_process.children(recursive=True)
            
            for child in children:
                try:
                    # العمليات المنتهية ولكن لم يتم جمعها (zombie)
                    if child.status() == psutil.STATUS_ZOMBIE:
                        if not self._dry_run:
                            child.wait(timeout=1)
                        result["items_removed"] += 1
                        logger.debug(f"Cleaned zombie process: {child.pid}")
                    
                    # العمليات اليتيمة (الأصل مات)
                    elif child.parent() != current_process:
                        if not self._dry_run:
                            child.terminate()
                            try:
                                child.wait(timeout=5)
                            except psutil.TimeoutExpired:
                                child.kill()
                        result["items_removed"] += 1
                        logger.debug(f"Cleaned orphan process: {child.pid}")
                        
                except Exception as e:
                    result["errors"].append(f"Failed to clean process {child.pid}: {e}")
            
        except Exception as e:
            result["errors"].append(f"Process cleanup error: {e}")
        
        return result
    
    async def _cleanup_stopped_containers(self) -> Dict[str, Any]:
        """تنظيف الحاويات المتوقفة (Docker)"""
        result = {"space_freed_mb": 0.0, "items_removed": 0, "errors": []}
        
        try:
            import docker
            client = docker.from_env()
            
            # حاويات متوقفة
            containers = client.containers.list(all=True, filters={"status": "exited"})
            
            for container in containers:
                if not self._dry_run:
                    container.remove()
                result["items_removed"] += 1
                logger.debug(f"Cleaned stopped container: {container.name}")
            
            # صور غير مستخدمة (dangling)
            images = client.images.list(filters={"dangling": True})
            for image in images:
                if not self._dry_run:
                    client.images.remove(image.id)
                result["items_removed"] += 1
                logger.debug(f"Cleaned dangling image: {image.id[:12]}")
                
        except ImportError:
            logger.debug("Docker not available, skipping container cleanup")
        except Exception as e:
            result["errors"].append(f"Docker cleanup error: {e}")
        
        return result
    
    async def _cleanup_old_sessions(self, rule: CleanupRule) -> Dict[str, Any]:
        """تنظيف الجلسات القديمة"""
        result = {"space_freed_mb": 0.0, "items_removed": 0, "errors": []}
        cutoff_time = datetime.now() - timedelta(hours=rule.max_age_hours)
        
        # هذا يعتمد على نظام إدارة الجلسات الخاص بالمنصة
        # سيتم تنفيذه لاحقاً مع تكامل SessionManager
        
        return result
    
    async def _check_disk_usage(self):
        """فحص استخدام القرص وإطلاق تنبيهات"""
        try:
            disk = psutil.disk_usage('/')
            usage_percent = disk.percent
            
            if usage_percent >= self._disk_usage_critical_threshold:
                logger.critical(f"Critical disk usage: {usage_percent:.1f}% (threshold: {self._disk_usage_critical_threshold}%)")
                
                # تنظيف طارئ
                if self._auto_cleanup:
                    logger.warning("Running emergency cleanup due to critical disk usage")
                    await self.run_cleanup(CleanupTarget.TEMP_FILES)
                    await self.run_cleanup(CleanupTarget.OLD_LOGS)
                    
            elif usage_percent >= self._disk_usage_warning_threshold:
                logger.warning(f"High disk usage: {usage_percent:.1f}% (threshold: {self._disk_usage_warning_threshold}%)")
                
        except Exception as e:
            logger.error(f"Disk usage check failed: {e}")
    
    async def get_cleanup_reports(self, limit: int = 10) -> List[Dict]:
        """الحصول على تقارير التنظيف الأخيرة"""
        async with self._lock:
            reports = self._cleanup_reports[-limit:]
            
            return [
                {
                    "timestamp": r.timestamp.isoformat(),
                    "rules_executed": r.rules_executed,
                    "space_freed_mb": r.space_freed_mb,
                    "items_removed": r.items_removed,
                    "errors": r.errors,
                    "details": r.details
                }
                for r in reports
            ]
    
    async def estimate_cleanup_space(self) -> float:
        """تقدير المساحة التي سيتم تحريرها (بدون تنفيذ فعلي)"""
        original_dry_run = self._dry_run
        self._dry_run = True
        
        try:
            report = await self.run_cleanup()
            return report.space_freed_mb
        finally:
            self._dry_run = original_dry_run
    
    async def get_stats(self) -> Dict:
        """الحصول على إحصائيات التنظيف"""
        disk = psutil.disk_usage('/')
        
        return {
            **self._stats,
            "running": self._running,
            "auto_cleanup": self._auto_cleanup,
            "dry_run": self._dry_run,
            "rules_count": len(self._rules),
            "current_disk_usage": {
                "percent": disk.percent,
                "free_gb": disk.free / (1024**3),
                "used_gb": disk.used / (1024**3),
                "total_gb": disk.total / (1024**3)
            },
            "disk_warning_threshold": self._disk_usage_warning_threshold,
            "disk_critical_threshold": self._disk_usage_critical_threshold
        }
    
    async def emergency_cleanup(self) -> CleanupReport:
        """تنظيف طارئ فوري"""
        logger.warning("Running emergency cleanup")
        
        # تنظيف الأهداف الأكثر أهمية فقط
        emergency_targets = [
            CleanupTarget.TEMP_FILES,
            CleanupTarget.OLD_LOGS,
            CleanupTarget.CACHE,
            CleanupTarget.ORPHAN_PROCESSES,
            CleanupTarget.STOPPED_CONTAINERS
        ]
        
        total_space = 0.0
        total_items = 0
        
        for target in emergency_targets:
            report = await self.run_cleanup(target)
            total_space += report.space_freed_mb
            total_items += report.items_removed
        
        logger.info(f"Emergency cleanup completed: freed {total_space:.1f}MB, removed {total_items} items")
        
        # إرجاع تقرير مجمع
        return CleanupReport(
            timestamp=datetime.now(),
            rules_executed=len(emergency_targets),
            space_freed_mb=total_space,
            items_removed=total_items,
            errors=[],
            details={"emergency": True}
        )


# نسخة عالمية
_default_manager = None


async def get_cleanup_manager() -> CleanupManager:
    """الحصول على نسخة عالمية من مدير التنظيف"""
    global _default_manager
    if _default_manager is None:
        _default_manager = CleanupManager()
        await _default_manager.start()
    return _default_manager

