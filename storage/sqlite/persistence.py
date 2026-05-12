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


class PersistenceManager:
    
    def __init__(self, db_path: str = "./storage/sqlite/persistence.db", backup_dir: str = "./backups"):
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
        
        # تهيئة قاعدة البيانات والجداول
        self._initialize_database()
        
        logger.info(f"PersistenceManager initialized (db={db_path}, memory={self._is_memory_db})")
    
    def _initialize_database(self):
        """تهيئة قاعدة البيانات وإنشاء جميع الجداول"""
        conn = sqlite3.connect(self._db_path, timeout=30.0)
        cursor = conn.cursor()
        
        # تفعيل الإعدادات
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA synchronous=NORMAL")
        
        # إنشاء جدول الحالات المستمرة
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS persisted_states (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                state_type TEXT NOT NULL,
                data BLOB NOT NULL,
                version TEXT NOT NULL,
                checksum TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                metadata TEXT
            )
        ''')
        
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
        
        # إنشاء الفهارس
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_persisted_states_type ON persisted_states(state_type)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_persisted_states_name ON persisted_states(name)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_snapshots_timestamp ON snapshots(timestamp)')
        
        conn.commit()
        
        # التحقق من إنشاء الجدول
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='persisted_states'")
        result = cursor.fetchone()
        if result:
            logger.info("✅ Table 'persisted_states' created successfully")
        else:
            logger.error("❌ Failed to create table 'persisted_states'")
        
        conn.close()
    
    def _get_connection(self):
        """الحصول على اتصال بقاعدة البيانات"""
        return sqlite3.connect(self._db_path, timeout=30.0)
    
    def _compute_checksum(self, data: Dict[str, Any]) -> str:
        data_str = fast_json_dumps(data)
        return hashlib.sha256(data_str.encode()).hexdigest()[:16]
    
    def _compress_data(self, data: Dict[str, Any]) -> Tuple[bytes, bool]:
        data_str = fast_json_dumps(data)
        data_bytes = data_str.encode()
        
        if len(data_bytes) > 10240:
            compressed = zlib.compress(data_bytes, level=6)
            return compressed, True
        return data_bytes, False
    
    def _decompress_data(self, data_bytes: bytes, compressed: bool) -> Dict[str, Any]:
        if compressed:
            data_bytes = zlib.decompress(data_bytes)
        data_str = data_bytes.decode()
        return fast_json_loads(data_str)
    
    async def save_state(
        self,
        name: str,
        state_type: str,
        data: Dict[str, Any],
        version: str = "1.0.0",
        metadata: Dict = None
    ) -> str:
        import uuid
        state_id = str(uuid.uuid4())
        now = datetime.now().isoformat()
        checksum = self._compute_checksum(data)
        
        data_compressed, _ = self._compress_data(data)
        
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
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute(query, params)
            conn.commit()
            conn.close()
        
        state = PersistedState(
            id=state_id, name=name, state_type=state_type, data=data,
            version=version, checksum=checksum,
            created_at=datetime.fromisoformat(now),
            updated_at=datetime.fromisoformat(now),
            metadata=metadata or {}
        )
        self._state_cache[state_id] = state
        
        logger.info(f"State saved: {name} ({state_type}) id={state_id[:8]}")
        return state_id
    
    async def load_state(self, state_id: str) -> Optional[PersistedState]:
        if state_id in self._state_cache:
            return self._state_cache[state_id]
        
        query = "SELECT * FROM persisted_states WHERE id = ?"
        
        async with self._write_lock:
            conn = self._get_connection()
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(query, (state_id,))
            row = cursor.fetchone()
            conn.close()
        
        if not row:
            return None
        
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
        
        self._state_cache[state_id] = state
        return state
    
    async def list_states(self, state_type: str = None, name: str = None) -> List[Dict]:
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
            conn = self._get_connection()
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(query, tuple(params))
            rows = cursor.fetchall()
            conn.close()
        
        return [dict(row) for row in rows]
    
    async def delete_state(self, state_id: str) -> bool:
        query = "DELETE FROM persisted_states WHERE id = ?"
        
        async with self._write_lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute(query, (state_id,))
            conn.commit()
            affected = cursor.rowcount
            conn.close()
        
        if affected > 0:
            self._state_cache.pop(state_id, None)
            logger.info(f"State deleted: {state_id[:8]}")
            return True
        
        return False
    
    async def get_statistics(self) -> Dict:
        states = await self.list_states()
        
        return {
            "total_states": len(states),
            "cache_hits": len(self._state_cache),
            "is_memory_db": self._is_memory_db,
            "states_by_type": {
                t: sum(1 for s in states if s.get("state_type") == t)
                for t in set(s.get("state_type") for s in states)
            }
        }
    
    async def clear_cache(self):
        self._state_cache.clear()
        logger.info("Persistence cache cleared")


_default_manager = None


async def get_persistence_manager() -> PersistenceManager:
    global _default_manager
    if _default_manager is None:
        _default_manager = PersistenceManager()
    return _default_manager
