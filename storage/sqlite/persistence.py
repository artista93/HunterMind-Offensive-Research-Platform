
import asyncio
import sqlite3
import json
import pickle
import zlib
import hashlib
import os
from typing import Dict, List, Optional, Any, Tuple, Union
from dataclasses import dataclass, field, asdict
from datetime import datetime
from contextlib import asynccontextmanager
import logging

logger = logging.getLogger(__name__)

# محاولة استخدام orjson
try:
    import orjson
    def fast_json_dumps(obj):
        return orjson.dumps(obj).decode('utf-8')
    def fast_json_loads(s):
        return orjson.loads(s) if s else {}
    USING_ORJSON = True
except ImportError:
    USING_ORJSON = False
    def fast_json_dumps(obj):
        return json.dumps(obj, default=str)
    def fast_json_loads(s):
        return json.loads(s) if s else {}


@dataclass
class PersistedState:
    """حالة مستمرة للنظام"""
    id: str
    name: str
    state_type: str  # agent, orchestrator, cognitive
    data: Dict[str, Any]
    version: str
    checksum: str
    created_at: datetime
    updated_at: datetime
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Snapshot:
    """لقطة كاملة للنظام"""
    id: str
    name: str
    timestamp: datetime
    states: List[PersistedState]
    metadata: Dict[str, Any]
    size_bytes: int
    compressed: bool


class PersistenceManager:
    """
    نظام الثباتية المتقدم
    
    الميزات:
    - حفظ واستعادة حالة المكونات
    - لقطات كاملة للنظام (Snapshots)
    - ضغط البيانات
    - التحقق من السلامة (Checksum)
    - إصدارات الحالة (Versioning)
    - استعادة نقطة زمنية (Point-in-time recovery)
    - دعم المعاملات (Transactions)
    """
    
    def __init__(self, db_path: str = "./storage/sqlite/persistence.db", backup_dir: str = "./backups"):
        self._db_path = db_path
        self._backup_dir = backup_dir
        self._write_lock = asyncio.Lock()
        
        # إنشاء المجلدات
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        os.makedirs(backup_dir, exist_ok=True)
        
        # تهيئة قاعدة البيانات
        self._init_database()
        
        # ذاكرة مؤقتة
        self._state_cache: Dict[str, PersistedState] = {}
        self._cache_ttl = 300  # 5 دقائق
        self._last_cache_update: Dict[str, datetime] = {}
        
        logger.info(f"PersistenceManager initialized (db={db_path}, backup_dir={backup_dir})")
    
    def _init_database(self):
        """تهيئة قاعدة البيانات"""
        conn = sqlite3.connect(self._db_path, timeout=30.0)
        cursor = conn.cursor()
        
        # تفعيل WAL mode
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA synchronous=NORMAL")
        
        # جدول الحالات المستمرة
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS persisted_states (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                state_type TEXT NOT NULL,
                data TEXT NOT NULL,
                version TEXT NOT NULL,
                checksum TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                metadata TEXT
            )
        ''')
        
        # جدول اللقطات
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS snapshots (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                compressed INTEGER DEFAULT 0,
                size_bytes INTEGER DEFAULT 0,
                metadata TEXT
            )
        ''')
        
        # جدول علاقة اللقطات بالحالات
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS snapshot_states (
                snapshot_id TEXT NOT NULL,
                state_id TEXT NOT NULL,
                FOREIGN KEY (snapshot_id) REFERENCES snapshots(id),
                FOREIGN KEY (state_id) REFERENCES persisted_states(id),
                PRIMARY KEY (snapshot_id, state_id)
            )
        ''')
        
        # جدول سجل العمليات (لـ audit)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS persistence_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                operation TEXT NOT NULL,
                target_id TEXT,
                target_type TEXT,
                timestamp TEXT NOT NULL,
                details TEXT
            )
        ''')
        
        # الفهارس
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_persisted_states_type ON persisted_states(state_type)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_persisted_states_name ON persisted_states(name)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_snapshots_timestamp ON snapshots(timestamp)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_persistence_log_timestamp ON persistence_log(timestamp)')
        
        conn.commit()
        conn.close()
        
        logger.info("Persistence database initialized")
    
    def _compute_checksum(self, data: Dict[str, Any]) -> str:
        """حساب checksum للبيانات"""
        data_str = fast_json_dumps(data)
        return hashlib.sha256(data_str.encode()).hexdigest()[:16]
    
    def _compress_data(self, data: Dict[str, Any]) -> Tuple[bytes, bool]:
        """ضغط البيانات إذا كانت كبيرة"""
        data_str = fast_json_dumps(data)
        data_bytes = data_str.encode()
        
        if len(data_bytes) > 10240:  # > 10KB
            compressed = zlib.compress(data_bytes, level=6)
            return compressed, True
        return data_bytes, False
    
    def _decompress_data(self, data_bytes: bytes, compressed: bool) -> Dict[str, Any]:
        """فك ضغط البيانات"""
        if compressed:
            data_bytes = zlib.decompress(data_bytes)
        data_str = data_bytes.decode()
        return fast_json_loads(data_str)
    
    async def _log_operation(self, operation: str, target_id: str = None, target_type: str = None, details: Dict = None):
        """تسجيل عملية في سجل التدقيق"""
        query = '''
            INSERT INTO persistence_log (operation, target_id, target_type, timestamp, details)
            VALUES (?, ?, ?, ?, ?)
        '''
        params = (
            operation, target_id, target_type, datetime.now().isoformat(),
            fast_json_dumps(details) if details else None
        )
        
        async with self._write_lock:
            conn = sqlite3.connect(self._db_path)
            cursor = conn.cursor()
            cursor.execute(query, params)
            conn.commit()
            conn.close()
    
    async def save_state(
        self,
        name: str,
        state_type: str,
        data: Dict[str, Any],
        version: str = "1.0.0",
        metadata: Dict = None
    ) -> str:
        """
        حفظ حالة مكون
        
        Returns:
            معرف الحالة
        """
        import uuid
        state_id = str(uuid.uuid4())
        now = datetime.now().isoformat()
        checksum = self._compute_checksum(data)
        
        data_compressed, compressed = self._compress_data(data)
        
        query = '''
            INSERT OR REPLACE INTO persisted_states 
            (id, name, state_type, data, version, checksum, created_at, updated_at, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        '''
        
        params = (
            state_id, name, state_type, data_compressed, version, checksum, now, now,
            fast_json_dumps(metadata) if metadata else None
        )
        
        async with self._write_lock:
            conn = sqlite3.connect(self._db_path)
            cursor = conn.cursor()
            cursor.execute(query, params)
            conn.commit()
            conn.close()
        
        # تحديث الذاكرة المؤقتة
        state = PersistedState(
            id=state_id, name=name, state_type=state_type, data=data,
            version=version, checksum=checksum,
            created_at=datetime.fromisoformat(now),
            updated_at=datetime.fromisoformat(now),
            metadata=metadata or {}
        )
        self._state_cache[state_id] = state
        self._last_cache_update[state_id] = datetime.now()
        
        await self._log_operation("save_state", state_id, state_type, {"name": name, "version": version})
        logger.info(f"State saved: {name} ({state_type}) id={state_id[:8]}")
        
        return state_id
    
    async def load_state(self, state_id: str) -> Optional[PersistedState]:
        """
        تحميل حالة من قاعدة البيانات
        
        Args:
            state_id: معرف الحالة
        
        Returns:
            كائن PersistedState أو None
        """
        # التحقق من الذاكرة المؤقتة
        if state_id in self._state_cache:
            cache_time = self._last_cache_update.get(state_id)
            if cache_time and (datetime.now() - cache_time).total_seconds() < self._cache_ttl:
                return self._state_cache[state_id]
        
        query = "SELECT * FROM persisted_states WHERE id = ?"
        
        async with self._write_lock:
            conn = sqlite3.connect(self._db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(query, (state_id,))
            row = cursor.fetchone()
            conn.close()
        
        if not row:
            return None
        
        # فك ضغط البيانات
        data = self._decompress_data(row["data"], isinstance(row["data"], bytes))
        
        state = PersistedState(
            id=row["id"],
            name=row["name"],
            state_type=row["state_type"],
            data=data,
            version=row["version"],
            checksum=row["checksum"],
            created_at=datetime.fromisoformat(row["created_at"]),
            updated_at=datetime.fromisoformat(row["updated_at"]),
            metadata=fast_json_loads(row["metadata"]) if row["metadata"] else {}
        )
        
        # التحقق من السلامة
        expected_checksum = self._compute_checksum(data)
        if state.checksum != expected_checksum:
            logger.error(f"Checksum mismatch for state {state_id}! Expected {state.checksum}, got {expected_checksum}")
            return None
        
        # تحديث الذاكرة المؤقتة
        self._state_cache[state_id] = state
        self._last_cache_update[state_id] = datetime.now()
        
        return state
    
    async def load_latest_state(self, name: str, state_type: str) -> Optional[PersistedState]:
        """تحميل أحدث حالة لاسم ونوع معينين"""
        query = '''
            SELECT id FROM persisted_states 
            WHERE name = ? AND state_type = ?
            ORDER BY updated_at DESC
            LIMIT 1
        '''
        
        async with self._write_lock:
            conn = sqlite3.connect(self._db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(query, (name, state_type))
            row = cursor.fetchone()
            conn.close()
        
        if not row:
            return None
        
        return await self.load_state(row["id"])
    
    async def list_states(self, state_type: str = None, name: str = None) -> List[Dict]:
        """قائمة الحالات المحفوظة"""
        query = "SELECT id, name, state_type, version, created_at, updated_at FROM persisted_states"
        params = []
        conditions = []
        
        if state_type:
            conditions.append("state_type = ?")
            params.append(state_type)
        
        if name:
            conditions.append("name = ?")
            params.append(name)
        
        if conditions:
            query += " WHERE " + " AND ".join(conditions)
        
        query += " ORDER BY updated_at DESC"
        
        async with self._write_lock:
            conn = sqlite3.connect(self._db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(query, tuple(params))
            rows = cursor.fetchall()
            conn.close()
        
        return [dict(row) for row in rows]
    
    async def delete_state(self, state_id: str) -> bool:
        """حذف حالة"""
        query = "DELETE FROM persisted_states WHERE id = ?"
        
        async with self._write_lock:
            conn = sqlite3.connect(self._db_path)
            cursor = conn.cursor()
            cursor.execute(query, (state_id,))
            conn.commit()
            affected = cursor.rowcount
            conn.close()
        
        if affected > 0:
            self._state_cache.pop(state_id, None)
            self._last_cache_update.pop(state_id, None)
            await self._log_operation("delete_state", state_id)
            logger.info(f"State deleted: {state_id[:8]}")
            return True
        
        return False
    
    async def create_snapshot(self, name: str, metadata: Dict = None) -> str:
        """
        إنشاء لقطة كاملة للنظام
        
        تشمل جميع الحالات الحالية
        """
        import uuid
        snapshot_id = str(uuid.uuid4())
        now = datetime.now()
        
        # جلب جميع الحالات
        states = await self.list_states()
        
        snapshot = Snapshot(
            id=snapshot_id,
            name=name,
            timestamp=now,
            states=[],
            metadata=metadata or {},
            size_bytes=0,
            compressed=False
        )
        
        # حفظ اللقطة في قاعدة البيانات
        query_snapshot = '''
            INSERT INTO snapshots (id, name, timestamp, metadata)
            VALUES (?, ?, ?, ?)
        '''
        
        async with self._write_lock:
            conn = sqlite3.connect(self._db_path)
            cursor = conn.cursor()
            cursor.execute(query_snapshot, (snapshot_id, name, now.isoformat(), fast_json_dumps(metadata or {})))
            
            # ربط الحالات باللقطة
            for state in states:
                cursor.execute(
                    "INSERT INTO snapshot_states (snapshot_id, state_id) VALUES (?, ?)",
                    (snapshot_id, state["id"])
                )
            
            conn.commit()
            conn.close()
        
        # حفظ نسخة منفصلة من اللقطة (للـ restore السريع)
        await self._save_snapshot_to_file(snapshot_id)
        
        await self._log_operation("create_snapshot", snapshot_id, "snapshot", {"name": name})
        logger.info(f"Snapshot created: {name} ({snapshot_id[:8]}) with {len(states)} states")
        
        return snapshot_id
    
    async def _save_snapshot_to_file(self, snapshot_id: str):
        """حفظ لقطة إلى ملف للاستعادة السريعة"""
        # جلب جميع الحالات المرتبطة باللقطة
        query = '''
            SELECT ps.* FROM persisted_states ps
            JOIN snapshot_states ss ON ps.id = ss.state_id
            WHERE ss.snapshot_id = ?
        '''
        
        async with self._write_lock:
            conn = sqlite3.connect(self._db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(query, (snapshot_id,))
            rows = cursor.fetchall()
            conn.close()
        
        states = []
        for row in rows:
            data = self._decompress_data(row["data"], isinstance(row["data"], bytes))
            states.append({
                "id": row["id"],
                "name": row["name"],
                "state_type": row["state_type"],
                "data": data,
                "version": row["version"],
                "checksum": row["checksum"]
            })
        
        snapshot_data = {
            "snapshot_id": snapshot_id,
            "timestamp": datetime.now().isoformat(),
            "states": states
        }
        
        data_compressed, compressed = self._compress_data(snapshot_data)
        
        # حفظ إلى ملف
        filepath = os.path.join(self._backup_dir, f"{snapshot_id}.snap")
        with open(filepath, "wb") as f:
            # كتابة علامة ضغط
            f.write(b'\x01' if compressed else b'\x00')
            f.write(data_compressed)
        
        # تحديث الحجم في قاعدة البيانات
        size_bytes = os.path.getsize(filepath)
        query_update = "UPDATE snapshots SET size_bytes = ?, compressed = ? WHERE id = ?"
        
        async with self._write_lock:
            conn = sqlite3.connect(self._db_path)
            cursor = conn.cursor()
            cursor.execute(query_update, (size_bytes, 1 if compressed else 0, snapshot_id))
            conn.commit()
            conn.close()
        
        logger.info(f"Snapshot saved to file: {filepath} ({size_bytes} bytes)")
    
    async def restore_snapshot(self, snapshot_id: str) -> bool:
        """
        استعادة لقطة كاملة للنظام
        
        يحذف الحالة الحالية ويستبدلها باللقطة
        """
        # جلب اللقطة
        query = "SELECT * FROM snapshots WHERE id = ?"
        
        async with self._write_lock:
            conn = sqlite3.connect(self._db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(query, (snapshot_id,))
            snapshot_row = cursor.fetchone()
            
            if not snapshot_row:
                conn.close()
                return False
            
            # جلب الحالات المرتبطة
            cursor.execute('''
                SELECT ps.* FROM persisted_states ps
                JOIN snapshot_states ss ON ps.id = ss.state_id
                WHERE ss.snapshot_id = ?
            ''', (snapshot_id,))
            state_rows = cursor.fetchall()
            conn.close()
        
        # استعادة الحالات
        for row in state_rows:
            data = self._decompress_data(row["data"], isinstance(row["data"], bytes))
            
            # تحديث الحالة (upsert)
            await self.save_state(
                name=row["name"],
                state_type=row["state_type"],
                data=data,
                version=row["version"],
                metadata=fast_json_loads(row["metadata"]) if row["metadata"] else {}
            )
        
        await self._log_operation("restore_snapshot", snapshot_id, "snapshot")
        logger.info(f"Snapshot restored: {snapshot_id[:8]}")
        
        return True
    
    async def list_snapshots(self) -> List[Dict]:
        """قائمة اللقطات المحفوظة"""
        query = '''
            SELECT id, name, timestamp, size_bytes, compressed, metadata
            FROM snapshots
            ORDER BY timestamp DESC
        '''
        
        async with self._write_lock:
            conn = sqlite3.connect(self._db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(query)
            rows = cursor.fetchall()
            conn.close()
        
        return [dict(row) for row in rows]
    
    async def delete_snapshot(self, snapshot_id: str) -> bool:
        """حذف لقطة"""
        # حذف من قاعدة البيانات
        query_snapshot = "DELETE FROM snapshots WHERE id = ?"
        query_relations = "DELETE FROM snapshot_states WHERE snapshot_id = ?"
        
        async with self._write_lock:
            conn = sqlite3.connect(self._db_path)
            cursor = conn.cursor()
            cursor.execute(query_relations, (snapshot_id,))
            cursor.execute(query_snapshot, (snapshot_id,))
            conn.commit()
            affected = cursor.rowcount
            conn.close()
        
        # حذف ملف اللقطة
        filepath = os.path.join(self._backup_dir, f"{snapshot_id}.snap")
        if os.path.exists(filepath):
            os.remove(filepath)
        
        if affected > 0:
            await self._log_operation("delete_snapshot", snapshot_id, "snapshot")
            logger.info(f"Snapshot deleted: {snapshot_id[:8]}")
            return True
        
        return False
    
    async def export_state(self, state_id: str, filepath: str) -> bool:
        """تصدير حالة إلى ملف"""
        state = await self.load_state(state_id)
        if not state:
            return False
        
        export_data = {
            "version": "1.0",
            "exported_at": datetime.now().isoformat(),
            "state": asdict(state)
        }
        
        with open(filepath, "w") as f:
            json.dump(export_data, f, indent=2, default=str)
        
        logger.info(f"State exported to {filepath}")
        return True
    
    async def import_state(self, filepath: str) -> Optional[str]:
        """استيراد حالة من ملف"""
        with open(filepath, "r") as f:
            import_data = json.load(f)
        
        state_data = import_data.get("state")
        if not state_data:
            logger.error("Invalid import file")
            return None
        
        # إعادة إنشاء الحالة
        state_id = await self.save_state(
            name=state_data["name"],
            state_type=state_data["state_type"],
            data=state_data["data"],
            version=state_data.get("version", "1.0.0"),
            metadata=state_data.get("metadata", {})
        )
        
        logger.info(f"State imported from {filepath}")
        return state_id
    
    async def cleanup_old_snapshots(self, keep_last: int = 10):
        """تنظيف اللقطات القديمة (الاحتفاظ بآخر N)"""
        snapshots = await self.list_snapshots()
        
        if len(snapshots) <= keep_last:
            return
        
        to_delete = snapshots[keep_last:]
        for snapshot in to_delete:
            await self.delete_snapshot(snapshot["id"])
        
        logger.info(f"Cleaned {len(to_delete)} old snapshots")
    
    async def get_statistics(self) -> Dict:
        """إحصائيات نظام الثباتية"""
        states = await self.list_states()
        snapshots = await self.list_snapshots()
        
        # حساب الحجم الإجمالي
        total_size = 0
        for snapshot in snapshots:
            total_size += snapshot.get("size_bytes", 0)
        
        return {
            "total_states": len(states),
            "total_snapshots": len(snapshots),
            "total_backup_size_mb": total_size / (1024 * 1024),
            "cache_hits": len(self._state_cache),
            "backup_dir": self._backup_dir,
            "states_by_type": {
                t: sum(1 for s in states if s.get("state_type") == t)
                for t in set(s.get("state_type") for s in states)
            }
        }
    
    async def clear_cache(self):
        """مسح الذاكرة المؤقتة"""
        self._state_cache.clear()
        self._last_cache_update.clear()
        logger.info("Persistence cache cleared")
    
    async def vacuum(self):
        """إعادة بناء قاعدة البيانات لتحسين الأداء"""
        async with self._write_lock:
            conn = sqlite3.connect(self._db_path)
            cursor = conn.cursor()
            cursor.execute("VACUUM")
            conn.commit()
            conn.close()
        
        logger.info("Database vacuum completed")


# نسخة عالمية
_default_manager = None


async def get_persistence_manager() -> PersistenceManager:
    """الحصول على نسخة عالمية من مدير الثباتية"""
    global _default_manager
    if _default_manager is None:
        _default_manager = PersistenceManager()
    return _default_manager

