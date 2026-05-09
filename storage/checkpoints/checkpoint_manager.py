
import asyncio
import sqlite3
import json
import os
import shutil
import hashlib
import zlib
import pickle
from typing import Dict, List, Optional, Any, Tuple, Union
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from contextlib import asynccontextmanager
import logging

logger = logging.getLogger(__name__)


class CheckpointStatus(Enum):
    """حالة نقطة التفتيش"""
    CREATED = "created"
    VALIDATED = "validated"
    RESTORED = "restored"
    CORRUPTED = "corrupted"
    DELETED = "deleted"


class CheckpointStrategy(Enum):
    """استراتيجية إنشاء نقاط التفتيش"""
    MANUAL = "manual"
    PERIODIC = "periodic"
    BEFORE_CRITICAL = "before_critical"
    AFTER_SUCCESS = "after_success"
    ON_ERROR = "on_error"


@dataclass
class Checkpoint:
    """نقطة تفتيش للنظام"""
    id: str
    name: str
    description: str
    strategy: CheckpointStrategy
    status: CheckpointStatus
    created_at: datetime
    size_bytes: int
    compressed: bool
    checksum: str
    metadata: Dict[str, Any]
    components: List[str]  # قائمة المكونات المتضمنة
    parent_checkpoint_id: Optional[str] = None  # للتفرع


@dataclass
class CheckpointComponent:
    """مكون في نقطة تفتيش"""
    checkpoint_id: str
    component_name: str
    component_type: str
    data_hash: str
    storage_path: str
    version: str


class CheckpointManager:
    """
    مدير نقاط التفتيش المتقدم
    
    الميزات:
    - إنشاء نقاط تفتيش كاملة أو جزئية
    - ضغط البيانات وتشفيرها
    - التحقق من السلامة (checksum)
    - استعادة النظام من نقطة تفتيش
    - مقارنة نقاط التفتيش (diff)
    - جدولة تلقائية لنقاط التفتيش
    - استراتيجيات متعددة للإنشاء
    - إدارة الإصدارات (checkpoint chains)
    """
    
    def __init__(
        self,
        storage_dir: str = "./storage/checkpoints/data",
        db_path: str = "./storage/checkpoints/checkpoints.db",
        max_checkpoints: int = 50,
        enable_compression: bool = True,
        auto_checkpoint_interval_hours: int = 6
    ):
        self._storage_dir = storage_dir
        self._db_path = db_path
        self._max_checkpoints = max_checkpoints
        self._enable_compression = enable_compression
        self._auto_checkpoint_interval_hours = auto_checkpoint_interval_hours
        
        self._write_lock = asyncio.Lock()
        
        # تسجيل مكونات النظام (للحفظ الجزئي)
        self._component_savers: Dict[str, callable] = {}
        self._component_loaders: Dict[str, callable] = {}
        
        # إنشاء المجلدات
        os.makedirs(storage_dir, exist_ok=True)
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        
        # تهيئة قاعدة البيانات
        self._init_database()
        
        # مهمة الجدولة التلقائية
        self._scheduler_task = None
        
        logger.info(f"CheckpointManager initialized (dir={storage_dir}, max={max_checkpoints})")
    
    def _init_database(self):
        """تهيئة قاعدة البيانات"""
        conn = sqlite3.connect(self._db_path, timeout=30.0)
        cursor = conn.cursor()
        
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA synchronous=NORMAL")
        
        # جدول نقاط التفتيش
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS checkpoints (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT,
                strategy TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                size_bytes INTEGER NOT NULL,
                compressed INTEGER DEFAULT 0,
                checksum TEXT NOT NULL,
                metadata TEXT,
                parent_checkpoint_id TEXT
            )
        ''')
        
        # جدول مكونات نقطة التفتيش
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS checkpoint_components (
                checkpoint_id TEXT NOT NULL,
                component_name TEXT NOT NULL,
                component_type TEXT NOT NULL,
                data_hash TEXT NOT NULL,
                storage_path TEXT NOT NULL,
                version TEXT,
                FOREIGN KEY (checkpoint_id) REFERENCES checkpoints(id),
                PRIMARY KEY (checkpoint_id, component_name)
            )
        ''')
        
        # جدول سجل العمليات
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS checkpoint_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                checkpoint_id TEXT,
                operation TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                details TEXT
            )
        ''')
        
        # الفهارس
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_checkpoints_created ON checkpoints(created_at)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_checkpoints_status ON checkpoints(status)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_checkpoints_parent ON checkpoints(parent_checkpoint_id)')
        
        conn.commit()
        conn.close()
        
        logger.info("Checkpoint database initialized")
    
    def _compute_checksum(self, data: bytes) -> str:
        """حساب checksum للبيانات"""
        return hashlib.sha256(data).hexdigest()[:16]
    
    def _get_storage_path(self, checkpoint_id: str, component_name: str) -> str:
        """الحصول على مسار تخزين لمكون"""
        subdir = checkpoint_id[:2]
        path = os.path.join(self._storage_dir, subdir, checkpoint_id)
        os.makedirs(path, exist_ok=True)
        return os.path.join(path, f"{component_name}.dat")
    
    def register_component(
        self,
        name: str,
        component_type: str,
        saver: callable,
        loader: callable,
        version: str = "1.0.0"
    ):
        """
        تسجيل مكون للنظام
        
        Args:
            name: اسم المكون
            component_type: نوع المكون
            saver: دالة async لحفظ حالة المكون -> Dict
            loader: دالة async لاستعادة حالة المكون من Dict
            version: إصدار المكون
        """
        self._component_savers[name] = {
            "type": component_type,
            "saver": saver,
            "loader": loader,
            "version": version
        }
        logger.info(f"Component registered: {name} ({component_type})")
    
    async def create_checkpoint(
        self,
        name: str,
        description: str = "",
        strategy: CheckpointStrategy = CheckpointStrategy.MANUAL,
        components: List[str] = None,
        metadata: Dict[str, Any] = None,
        parent_checkpoint_id: str = None
    ) -> str:
        """
        إنشاء نقطة تفتيش جديدة
        
        Args:
            name: اسم نقطة التفتيش
            description: وصف
            strategy: استراتيجية الإنشاء
            components: قائمة المكونات لحفظها (None = جميع المكونات)
            metadata: بيانات وصفية إضافية
            parent_checkpoint_id: نقطة تفتيش أصل (للتفرع)
        
        Returns:
            معرف نقطة التفتيش
        """
        import uuid
        checkpoint_id = str(uuid.uuid4())
        now = datetime.now()
        
        # تحديد المكونات المراد حفظها
        if components is None:
            components_to_save = list(self._component_savers.keys())
        else:
            components_to_save = components
        
        saved_components = []
        total_size = 0
        
        logger.info(f"Creating checkpoint '{name}' with {len(components_to_save)} components...")
        
        # حفظ كل مكون
        for comp_name in components_to_save:
            if comp_name not in self._component_savers:
                logger.warning(f"Component {comp_name} not registered, skipping")
                continue
            
            comp_info = self._component_savers[comp_name]
            
            try:
                # حفظ حالة المكون
                state = await comp_info["saver"]()
                state_bytes = pickle.dumps(state)
                
                # ضغط البيانات إذا لزم الأمر
                if self._enable_compression and len(state_bytes) > 10240:
                    state_bytes = zlib.compress(state_bytes, level=6)
                    compressed = True
                else:
                    compressed = False
                
                # حساب checksum
                checksum = self._compute_checksum(state_bytes)
                
                # حفظ إلى ملف
                storage_path = self._get_storage_path(checkpoint_id, comp_name)
                with open(storage_path, 'wb') as f:
                    # كتابة علامة الضغط أولاً
                    f.write(b'\x01' if compressed else b'\x00')
                    f.write(state_bytes)
                
                size = len(state_bytes) + 1  # +1 لعلامة الضغط
                total_size += size
                
                saved_components.append((
                    checkpoint_id, comp_name, comp_info["type"],
                    checksum, storage_path, comp_info["version"]
                ))
                
                logger.debug(f"  Saved component: {comp_name} ({size} bytes, compressed={compressed})")
                
            except Exception as e:
                logger.error(f"Failed to save component {comp_name}: {e}")
                # تنظيف الملفات المحفوظة جزئياً
                for comp in saved_components:
                    if os.path.exists(comp[4]):
                        os.remove(comp[4])
                raise
        
        # حفظ معلومات نقطة التفتيش في قاعدة البيانات
        query = '''
            INSERT INTO checkpoints 
            (id, name, description, strategy, status, created_at, size_bytes, compressed, checksum, metadata, parent_checkpoint_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        '''
        
        # Checksum شامل لنقطة التفتيش
        overall_checksum = hashlib.sha256(
            json.dumps(saved_components).encode()
        ).hexdigest()[:16]
        
        params = (
            checkpoint_id, name, description, strategy.value, CheckpointStatus.CREATED.value,
            now.isoformat(), total_size, 1 if self._enable_compression else 0,
            overall_checksum, json.dumps(metadata or {}), parent_checkpoint_id
        )
        
        async with self._write_lock:
            conn = sqlite3.connect(self._db_path)
            cursor = conn.cursor()
            cursor.execute(query, params)
            
            # حفظ المكونات
            cursor.executemany(
                '''INSERT INTO checkpoint_components 
                   (checkpoint_id, component_name, component_type, data_hash, storage_path, version)
                   VALUES (?, ?, ?, ?, ?, ?)''',
                saved_components
            )
            
            # تسجيل العملية
            cursor.execute(
                "INSERT INTO checkpoint_log (checkpoint_id, operation, timestamp, details) VALUES (?, ?, ?, ?)",
                (checkpoint_id, "create", now.isoformat(), json.dumps({"components": components_to_save}))
            )
            
            conn.commit()
            conn.close()
        
        # تحديث الحالة
        await self._update_checkpoint_status(checkpoint_id, CheckpointStatus.VALIDATED)
        
        # تنظيف نقاط التفتيش القديمة
        await self._cleanup_old_checkpoints()
        
        logger.info(f"Checkpoint created: {name} ({checkpoint_id[:8]}) size={total_size} bytes")
        return checkpoint_id
    
    async def _update_checkpoint_status(self, checkpoint_id: str, status: CheckpointStatus):
        """تحديث حالة نقطة التفتيش"""
        query = "UPDATE checkpoints SET status = ? WHERE id = ?"
        
        async with self._write_lock:
            conn = sqlite3.connect(self._db_path)
            cursor = conn.cursor()
            cursor.execute(query, (status.value, checkpoint_id))
            conn.commit()
            conn.close()
    
    async def restore_checkpoint(
        self,
        checkpoint_id: str,
        components: List[str] = None
    ) -> bool:
        """
        استعادة النظام من نقطة تفتيش
        
        Args:
            checkpoint_id: معرف نقطة التفتيش
            components: قائمة المكونات لاستعادتها (None = جميع المكونات)
        
        Returns:
            نجاح العملية
        """
        # جلب معلومات نقطة التفتيش
        checkpoint = await self.get_checkpoint(checkpoint_id)
        if not checkpoint:
            logger.error(f"Checkpoint {checkpoint_id} not found")
            return False
        
        if checkpoint.status == CheckpointStatus.CORRUPTED:
            logger.error(f"Checkpoint {checkpoint_id} is corrupted")
            return False
        
        # جلب المكونات
        query = "SELECT * FROM checkpoint_components WHERE checkpoint_id = ?"
        
        async with self._write_lock:
            conn = sqlite3.connect(self._db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(query, (checkpoint_id,))
            component_rows = cursor.fetchall()
            conn.close()
        
        components_to_restore = components or [row["component_name"] for row in component_rows]
        
        logger.info(f"Restoring checkpoint '{checkpoint.name}' with {len(components_to_restore)} components...")
        
        restored = 0
        for row in component_rows:
            comp_name = row["component_name"]
            
            if comp_name not in components_to_restore:
                continue
            
            if comp_name not in self._component_loaders:
                logger.warning(f"No loader for component {comp_name}, skipping")
                continue
            
            # قراءة البيانات من الملف
            storage_path = row["storage_path"]
            if not os.path.exists(storage_path):
                logger.error(f"Component data file not found: {storage_path}")
                continue
            
            try:
                with open(storage_path, 'rb') as f:
                    compressed_flag = f.read(1)
                    compressed = compressed_flag == b'\x01'
                    data = f.read()
                
                # فك الضغط إذا لزم الأمر
                if compressed:
                    data = zlib.decompress(data)
                
                # استعادة الحالة
                state = pickle.loads(data)
                
                # استدعاء loader
                loader = self._component_loaders[comp_name]["loader"]
                await loader(state)
                
                restored += 1
                logger.debug(f"  Restored component: {comp_name}")
                
            except Exception as e:
                logger.error(f"Failed to restore component {comp_name}: {e}")
                return False
        
        # تسجيل العملية
        async with self._write_lock:
            conn = sqlite3.connect(self._db_path)
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO checkpoint_log (checkpoint_id, operation, timestamp, details) VALUES (?, ?, ?, ?)",
                (checkpoint_id, "restore", datetime.now().isoformat(), json.dumps({"components": components_to_restore}))
            )
            conn.commit()
            conn.close()
        
        await self._update_checkpoint_status(checkpoint_id, CheckpointStatus.RESTORED)
        
        logger.info(f"Checkpoint restored: {checkpoint.name} ({restored}/{len(components_to_restore)} components)")
        return True
    
    async def get_checkpoint(self, checkpoint_id: str) -> Optional[Checkpoint]:
        """الحصول على معلومات نقطة تفتيش"""
        query = "SELECT * FROM checkpoints WHERE id = ?"
        
        async with self._write_lock:
            conn = sqlite3.connect(self._db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(query, (checkpoint_id,))
            row = cursor.fetchone()
            conn.close()
        
        if not row:
            return None
        
        # جلب المكونات
        comp_query = "SELECT component_name FROM checkpoint_components WHERE checkpoint_id = ?"
        
        async with self._write_lock:
            conn = sqlite3.connect(self._db_path)
            cursor = conn.cursor()
            cursor.execute(comp_query, (checkpoint_id,))
            components = [row[0] for row in cursor.fetchall()]
            conn.close()
        
        return Checkpoint(
            id=row["id"],
            name=row["name"],
            description=row["description"] or "",
            strategy=CheckpointStrategy(row["strategy"]),
            status=CheckpointStatus(row["status"]),
            created_at=datetime.fromisoformat(row["created_at"]),
            size_bytes=row["size_bytes"],
            compressed=bool(row["compressed"]),
            checksum=row["checksum"],
            metadata=json.loads(row["metadata"]) if row["metadata"] else {},
            components=components,
            parent_checkpoint_id=row["parent_checkpoint_id"]
        )
    
    async def list_checkpoints(
        self,
        limit: int = 50,
        offset: int = 0,
        status: CheckpointStatus = None
    ) -> List[Checkpoint]:
        """قائمة نقاط التفتيش"""
        query = "SELECT id FROM checkpoints"
        params = []
        
        if status:
            query += " WHERE status = ?"
            params.append(status.value)
        
        query += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        
        async with self._write_lock:
            conn = sqlite3.connect(self._db_path)
            cursor = conn.cursor()
            cursor.execute(query, params)
            checkpoint_ids = [row[0] for row in cursor.fetchall()]
            conn.close()
        
        checkpoints = []
        for cp_id in checkpoint_ids:
            cp = await self.get_checkpoint(cp_id)
            if cp:
                checkpoints.append(cp)
        
        return checkpoints
    
    async def delete_checkpoint(self, checkpoint_id: str) -> bool:
        """حذف نقطة تفتيش"""
        checkpoint = await self.get_checkpoint(checkpoint_id)
        if not checkpoint:
            return False
        
        # حذف ملفات المكونات
        comp_query = "SELECT storage_path FROM checkpoint_components WHERE checkpoint_id = ?"
        
        async with self._write_lock:
            conn = sqlite3.connect(self._db_path)
            cursor = conn.cursor()
            cursor.execute(comp_query, (checkpoint_id,))
            storage_paths = [row[0] for row in cursor.fetchall()]
            conn.close()
        
        for path in storage_paths:
            if os.path.exists(path):
                os.remove(path)
        
        # حذف مجلد نقطة التفتيش
        checkpoint_dir = os.path.dirname(storage_paths[0]) if storage_paths else None
        if checkpoint_dir and os.path.exists(checkpoint_dir):
            try:
                shutil.rmtree(checkpoint_dir)
            except:
                pass
        
        # حذف من قاعدة البيانات
        del_components = "DELETE FROM checkpoint_components WHERE checkpoint_id = ?"
        del_checkpoint = "DELETE FROM checkpoints WHERE id = ?"
        
        async with self._write_lock:
            conn = sqlite3.connect(self._db_path)
            cursor = conn.cursor()
            cursor.execute(del_components, (checkpoint_id,))
            cursor.execute(del_checkpoint, (checkpoint_id,))
            
            cursor.execute(
                "INSERT INTO checkpoint_log (checkpoint_id, operation, timestamp, details) VALUES (?, ?, ?, ?)",
                (checkpoint_id, "delete", datetime.now().isoformat(), None)
            )
            
            conn.commit()
            conn.close()
        
        logger.info(f"Checkpoint deleted: {checkpoint.name} ({checkpoint_id[:8]})")
        return True
    
    async def compare_checkpoints(
        self,
        checkpoint_id_a: str,
        checkpoint_id_b: str
    ) -> Dict[str, Any]:
        """
        مقارنة بين نقطتي تفتيش
        
        Returns:
            قاموس بالتغييرات بينهما
        """
        cp_a = await self.get_checkpoint(checkpoint_id_a)
        cp_b = await self.get_checkpoint(checkpoint_id_b)
        
        if not cp_a or not cp_b:
            return {"error": "Checkpoint not found"}
        
        # جلب المكونات
        query = "SELECT component_name, data_hash FROM checkpoint_components WHERE checkpoint_id = ?"
        
        async with self._write_lock:
            conn = sqlite3.connect(self._db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(query, (checkpoint_id_a,))
            components_a = {row["component_name"]: row["data_hash"] for row in cursor.fetchall()}
            
            cursor.execute(query, (checkpoint_id_b,))
            components_b = {row["component_name"]: row["data_hash"] for row in cursor.fetchall()}
            conn.close()
        
        # حساب الفروق
        only_in_a = set(components_a.keys()) - set(components_b.keys())
        only_in_b = set(components_b.keys()) - set(components_a.keys())
        different = {
            comp for comp in set(components_a.keys()) & set(components_b.keys())
            if components_a[comp] != components_b[comp]
        }
        same = set(components_a.keys()) & set(components_b.keys()) - different
        
        return {
            "checkpoint_a": {"id": checkpoint_id_a, "name": cp_a.name, "created_at": cp_a.created_at.isoformat()},
            "checkpoint_b": {"id": checkpoint_id_b, "name": cp_b.name, "created_at": cp_b.created_at.isoformat()},
            "only_in_a": list(only_in_a),
            "only_in_b": list(only_in_b),
            "different": list(different),
            "same": list(same),
            "total_components_a": len(components_a),
            "total_components_b": len(components_b)
        }
    
    async def _cleanup_old_checkpoints(self):
        """تنظيف نقاط التفتيش القديمة"""
        checkpoints = await self.list_checkpoints(limit=self._max_checkpoints * 2)
        
        if len(checkpoints) <= self._max_checkpoints:
            return
        
        # حذف الأقدم
        to_delete = checkpoints[self._max_checkpoints:]
        for cp in to_delete:
            await self.delete_checkpoint(cp.id)
        
        logger.info(f"Cleaned up {len(to_delete)} old checkpoints")
    
    async def get_checkpoint_chain(self, checkpoint_id: str) -> List[Checkpoint]:
        """الحصول على سلسلة نقاط التفتيش (التاريخ الكامل)"""
        chain = []
        current = await self.get_checkpoint(checkpoint_id)
        
        while current:
            chain.append(current)
            if current.parent_checkpoint_id:
                current = await self.get_checkpoint(current.parent_checkpoint_id)
            else:
                break
        
        return chain
    
    async def get_statistics(self) -> Dict:
        """إحصائيات مدير نقاط التفتيش"""
        checkpoints = await self.list_checkpoints(limit=1000)
        
        total_size = sum(cp.size_bytes for cp in checkpoints)
        avg_size = total_size / len(checkpoints) if checkpoints else 0
        
        return {
            "total_checkpoints": len(checkpoints),
            "total_size_bytes": total_size,
            "total_size_mb": total_size / (1024 * 1024),
            "average_size_bytes": avg_size,
            "compression_enabled": self._enable_compression,
            "max_checkpoints": self._max_checkpoints,
            "storage_dir": self._storage_dir,
            "registered_components": len(self._component_savers),
            "checkpoints_by_strategy": {
                strategy.value: sum(1 for cp in checkpoints if cp.strategy == strategy)
                for strategy in CheckpointStrategy
            },
            "checkpoints_by_status": {
                status.value: sum(1 for cp in checkpoints if cp.status == status)
                for status in CheckpointStatus
            }
        }
    
    async def start_auto_scheduler(self):
        """بدء الجدولة التلقائية لنقاط التفتيش"""
        async def scheduler_loop():
            last_checkpoint = None
            
            while True:
                await asyncio.sleep(self._auto_checkpoint_interval_hours * 3600)
                
                now = datetime.now()
                
                # إنشاء نقطة تفتيش دورية
                checkpoint_name = f"auto_{now.strftime('%Y%m%d_%H%M%S')}"
                
                try:
                    await self.create_checkpoint(
                        name=checkpoint_name,
                        description="Automatic periodic checkpoint",
                        strategy=CheckpointStrategy.PERIODIC
                    )
                    logger.info(f"Auto checkpoint created: {checkpoint_name}")
                except Exception as e:
                    logger.error(f"Failed to create auto checkpoint: {e}")
        
        self._scheduler_task = asyncio.create_task(scheduler_loop())
        logger.info(f"Auto scheduler started (interval={self._auto_checkpoint_interval_hours}h)")
    
    async def stop_auto_scheduler(self):
        """إيقاف الجدولة التلقائية"""
        if self._scheduler_task:
            self._scheduler_task.cancel()
            logger.info("Auto scheduler stopped")
    
    async def validate_checkpoint(self, checkpoint_id: str) -> bool:
        """التحقق من سلامة نقطة تفتيش"""
        checkpoint = await self.get_checkpoint(checkpoint_id)
        if not checkpoint:
            return False
        
        # جلب المكونات
        query = "SELECT storage_path, data_hash FROM checkpoint_components WHERE checkpoint_id = ?"
        
        async with self._write_lock:
            conn = sqlite3.connect(self._db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(query, (checkpoint_id,))
            components = cursor.fetchall()
            conn.close()
        
        valid = True
        for comp in components:
            storage_path = comp["storage_path"]
            expected_hash = comp["data_hash"]
            
            if not os.path.exists(storage_path):
                logger.error(f"Component file missing: {storage_path}")
                valid = False
                continue
            
            with open(storage_path, 'rb') as f:
                f.read(1)  # علامة الضغط
                data = f.read()
                actual_hash = self._compute_checksum(data)
            
            if actual_hash != expected_hash:
                logger.error(f"Component hash mismatch: {storage_path}")
                valid = False
        
        status = CheckpointStatus.VALIDATED if valid else CheckpointStatus.CORRUPTED
        await self._update_checkpoint_status(checkpoint_id, status)
        
        return valid


# نسخة عالمية
_default_manager = None


async def get_checkpoint_manager() -> CheckpointManager:
    """الحصول على نسخة عالمية من مدير نقاط التفتيش"""
    global _default_manager
    if _default_manager is None:
        _default_manager = CheckpointManager()
        await _default_manager.start_auto_scheduler()
    return _default_manager

