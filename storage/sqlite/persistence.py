import asyncio
import sqlite3
import json
import zlib
import hashlib
import os
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from datetime import datetime
import logging

from storage.base_storage import BaseStorage, StorageType, StorageStatus, StorageStats

logger = logging.getLogger(__name__)


def fast_json_dumps(obj):
    return json.dumps(obj, default=str)


def fast_json_loads(s):
    return json.loads(s) if s else {}


@dataclass
class PersistedState:
    id: str
    name: str
    state_type: str
    data: Dict[str, Any]
    version: str
    checksum: str
    created_at: datetime
    updated_at: datetime
    metadata: Dict[str, Any] = field(default_factory=dict)


class PersistenceManager(BaseStorage):
    """
    مدير الثباتية المتقدم - يطبق واجهة BaseStorage
    """
    
    def __init__(self, db_path: str = "./storage/sqlite/persistence.db", backup_dir: str = "./backups"):
        super().__init__(name="PersistenceManager", storage_type=StorageType.SQLITE)
        self._db_path = db_path
        self._backup_dir = backup_dir
        self._write_lock = asyncio.Lock()
        self._is_memory_db = (db_path == ':memory:')
        
        # إنشاء المجلدات فقط إذا لم تكن قاعدة بيانات في الذاكرة
        if not self._is_memory_db:
            db_dir = os.path.dirname(db_path)
            if db_dir:
                os.makedirs(db_dir, exist_ok=True)
            os.makedirs(backup_dir, exist_ok=True)
        
        # ذاكرة مؤقتة
        self._state_cache: Dict[str, PersistedState] = {}
        
        # تهيئة قاعدة البيانات
        self._initialized = False
        
        logger.info(f"PersistenceManager initialized (db={db_path}, memory={self._is_memory_db})")
    
    async def initialize(self) -> bool:
        """تهيئة قاعدة البيانات"""
        if self._initialized:
            return True
        
        try:
            self._init_database()
            self._initialized = True
            self._status = StorageStatus.ACTIVE
            logger.info("PersistenceManager initialized successfully")
            return True
        except Exception as e:
            logger.error(f"Failed to initialize PersistenceManager: {e}")
            self._status = StorageStatus.ERROR
            return False
    
    def _init_database(self):
        """تهيئة قاعدة البيانات وإنشاء جميع الجداول"""
        conn = sqlite3.connect(self._db_path, timeout=30.0)
        cursor = conn.cursor()
        
        # تفعيل الإعدادات
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA synchronous=NORMAL")
        
        # إنشاء جدول الحالات المستمرة (مع عمود compressed)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS persisted_states (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                state_type TEXT NOT NULL,
                data BLOB NOT NULL,
                version TEXT NOT NULL,
                checksum TEXT NOT NULL,
                compressed INTEGER DEFAULT 0,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                metadata TEXT
            )
        ''')
        
        # إضافة عمود compressed إذا كان موجوداً في الإصدارات القديمة
        try:
            cursor.execute("ALTER TABLE persisted_states ADD COLUMN compressed INTEGER DEFAULT 0")
        except sqlite3.OperationalError:
            pass  # العمود موجود بالفعل
        
        # إنشاء جدول اللقطات
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
        
        # إنشاء جدول علاقة اللقطات بالحالات
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS snapshot_states (
                snapshot_id TEXT NOT NULL,
                state_id TEXT NOT NULL,
                FOREIGN KEY (snapshot_id) REFERENCES snapshots(id),
                FOREIGN KEY (state_id) REFERENCES persisted_states(id),
                PRIMARY KEY (snapshot_id, state_id)
            )
        ''')
        
        # إنشاء جدول سجل العمليات
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
        
        conn.commit()
        conn.close()
        logger.info("Database initialized")
    
    def _get_connection(self):
        """الحصول على اتصال بقاعدة البيانات"""
        return sqlite3.connect(self._db_path, timeout=30.0)
    
    def _compute_checksum(self, data: Dict[str, Any]) -> str:
        data_str = fast_json_dumps(data)
        return hashlib.sha256(data_str.encode()).hexdigest()[:16]
    
    def _compress_data(self, data: Dict[str, Any]) -> Tuple[bytes, bool]:
        data_str = fast_json_dumps(data)
        data_bytes = data_str.encode()
        
        # ضغط فقط إذا كان الحجم كبيراً (> 1KB)
        if len(data_bytes) > 1024:
            try:
                compressed = zlib.compress(data_bytes, level=6)
                return compressed, True
            except Exception:
                return data_bytes, False
        return data_bytes, False
    
    def _decompress_data(self, data_bytes: bytes, compressed: bool) -> Dict[str, Any]:
        try:
            if compressed:
                data_bytes = zlib.decompress(data_bytes)
            data_str = data_bytes.decode()
            return fast_json_loads(data_str)
        except (zlib.error, UnicodeDecodeError, json.JSONDecodeError) as e:
            # محاولة فك الضغط مباشرة إذا فشل
            try:
                data_str = data_bytes.decode()
                return fast_json_loads(data_str)
            except Exception:
                logger.error(f"Failed to decompress data: {e}")
                return {}
    
    async def save(self, key: str, data: Any, metadata: Dict = None) -> bool:
        """حفظ بيانات"""
        import uuid
        state_id = str(uuid.uuid4())
        now = datetime.now().isoformat()
        
        # تحويل البيانات إلى قاموس إذا لم تكن كذلك
        if not isinstance(data, dict):
            data = {"value": data}
        
        checksum = self._compute_checksum(data)
        data_bytes, compressed = self._compress_data(data)
        
        query = '''
            INSERT OR REPLACE INTO persisted_states 
            (id, name, state_type, data, version, checksum, compressed, created_at, updated_at, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        '''
        
        params = (
            state_id, key, "general", data_bytes, "1.0.0", checksum,
            1 if compressed else 0, now, now,
            fast_json_dumps(metadata) if metadata else None
        )
        
        async with self._write_lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute(query, params)
            conn.commit()
            conn.close()
        
        state = PersistedState(
            id=state_id, name=key, state_type="general", data=data,
            version="1.0.0", checksum=checksum,
            created_at=datetime.fromisoformat(now),
            updated_at=datetime.fromisoformat(now),
            metadata=metadata or {}
        )
        self._state_cache[state_id] = state
        
        logger.debug(f"State saved: {key} (compressed={compressed})")
        return True
    
    async def load(self, key: str) -> Optional[Any]:
        """تحميل بيانات"""
        query = "SELECT data, compressed FROM persisted_states WHERE name = ?"
        
        async with self._write_lock:
            conn = self._get_connection()
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(query, (key,))
            row = cursor.fetchone()
            conn.close()
        
        if not row:
            return None
        
        data_bytes = row["data"]
        compressed = bool(row["compressed"])
        
        data = self._decompress_data(data_bytes, compressed)
        
        # إذا كانت البيانات تحتوي على مفتاح "value"، نستخرج القيمة فقط
        if isinstance(data, dict) and "value" in data and len(data) == 1:
            return data["value"]
        
        return data
    
    async def delete(self, key: str) -> bool:
        """حذف بيانات"""
        query = "DELETE FROM persisted_states WHERE name = ?"
        
        async with self._write_lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute(query, (key,))
            conn.commit()
            affected = cursor.rowcount
            conn.close()
        
        if affected > 0:
            # إزالة من الذاكرة المؤقتة
            for sid, state in list(self._state_cache.items()):
                if state.name == key:
                    del self._state_cache[sid]
                    break
            logger.debug(f"State deleted: {key}")
            return True
        
        return False
    
    async def list_keys(self, prefix: str = None, limit: int = 100) -> List[str]:
        """قائمة المفاتيح"""
        query = "SELECT name FROM persisted_states"
        params = []
        
        if prefix:
            query += " WHERE name LIKE ?"
            params.append(f"{prefix}%")
        
        query += " LIMIT ?"
        params.append(limit)
        
        async with self._write_lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute(query, params)
            rows = cursor.fetchall()
            conn.close()
        
        return [row[0] for row in rows]
    
    async def exists(self, key: str) -> bool:
        """التحقق من وجود بيانات"""
        query = "SELECT COUNT(*) FROM persisted_states WHERE name = ?"
        
        async with self._write_lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute(query, (key,))
            count = cursor.fetchone()[0]
            conn.close()
        
        return count > 0
    
    async def search(self, query: Dict[str, Any], limit: int = 50) -> List[Any]:
        """بحث متقدم في البيانات"""
        if "name" in query:
            keys = await self.list_keys(prefix=query["name"], limit=limit)
            results = []
            for key in keys:
                data = await self.load(key)
                if data:
                    results.append(data)
            return results
        return []
    
    async def get_stats(self) -> StorageStats:
        """الحصول على إحصائيات نظام التخزين"""
        keys = await self.list_keys(limit=10000)
        total_items = len(keys)
        
        # الحصول على معلومات قاعدة البيانات
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT page_count * page_size FROM pragma_page_count(), pragma_page_size()")
        row = cursor.fetchone()
        total_size = row[0] if row else 0
        conn.close()
        
        return StorageStats(
            total_items=total_items,
            total_size_bytes=total_size,
            status=self._status,
            last_accessed=datetime.now(),
            created_at=self._created_at,
            metadata={
                "db_path": self._db_path,
                "is_memory": self._is_memory_db,
                "cache_size": len(self._state_cache)
            }
        )
    
    async def health_check(self) -> bool:
        """فحص صحة نظام التخزين"""
        try:
            test_key = "_health_check"
            await self.save(test_key, {"test": True})
            data = await self.load(test_key)
            await self.delete(test_key)
            return data is not None
        except Exception as e:
            logger.error(f"Health check failed: {e}")
            return False
    
    async def clear(self) -> bool:
        """مسح جميع البيانات"""
        query = "DELETE FROM persisted_states"
        
        async with self._write_lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute(query)
            conn.commit()
            conn.close()
        
        self._state_cache.clear()
        logger.info("All states cleared")
        return True
    
    async def close(self):
        """إغلاق نظام التخزين وتنظيف الموارد"""
        self._state_cache.clear()
        self._initialized = False
        logger.info("PersistenceManager closed")
    
    async def save_state(self, name: str, state_type: str, data: Dict[str, Any], version: str = "1.0.0", metadata: Dict = None) -> str:
        """حفظ حالة (متوافق مع الواجهة القديمة)"""
        await self.save(name, data, metadata)
        return name
    
    async def load_state(self, state_id: str) -> Optional[PersistedState]:
        """تحميل حالة (متوافق مع الواجهة القديمة)"""
        data = await self.load(state_id)
        if data:
            return PersistedState(
                id=state_id,
                name=state_id,
                state_type="general",
                data=data,
                version="1.0.0",
                checksum="",
                created_at=datetime.now(),
                updated_at=datetime.now()
            )
        return None
    
    async def list_states(self, state_type: str = None, name: str = None) -> List[Dict]:
        """قائمة الحالات (متوافق مع الواجهة القديمة)"""
        keys = await self.list_keys(prefix=name, limit=100)
        return [{"id": k, "name": k, "state_type": state_type or "general"} for k in keys]
    
    async def delete_state(self, state_id: str) -> bool:
        """حذف حالة (متوافق مع الواجهة القديمة)"""
        return await self.delete(state_id)
    
    async def get_statistics_legacy(self) -> Dict:
        """إحصائيات قديمة للتوافق"""
        stats = await self.get_stats()
        return {
            "total_states": stats.total_items,
            "cache_hits": len(self._state_cache),
            "is_memory_db": self._is_memory_db,
            "states_by_type": {"general": stats.total_items}
        }


# نسخة عالمية
_default_manager = None


async def get_persistence_manager() -> PersistenceManager:
    """الحصول على نسخة عالمية من مدير الثباتية"""
    global _default_manager
    if _default_manager is None:
        _default_manager = PersistenceManager()
        await _default_manager.initialize()
    return _default_manager
