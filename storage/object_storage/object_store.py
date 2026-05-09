
import asyncio
import sqlite3
import json
import os
import shutil
import hashlib
import zlib
from typing import Dict, List, Optional, Any, BinaryIO, Tuple, Union
from dataclasses import dataclass, field
from datetime import datetime
from contextlib import asynccontextmanager
import logging

logger = logging.getLogger(__name__)


class StorageBackend:
    """أنواع التخزين الخلفية"""
    LOCAL = "local"
    S3 = "s3"  # مستقبلي
    MINIO = "minio"  # مستقبلي


@dataclass
class StoredObject:
    """كائن مخزن"""
    id: str
    name: str
    content_type: str  # MIME type
    size_bytes: int
    hash_sha256: str
    compressed: bool
    original_size_bytes: int
    storage_backend: str
    storage_path: str
    metadata: Dict[str, Any]
    created_at: datetime
    updated_at: datetime
    expires_at: Optional[datetime] = None
    access_count: int = 0
    last_accessed: Optional[datetime] = None


@dataclass
class ObjectChunk:
    """جزء من كائن كبير (للتخزين المتجزئ)"""
    object_id: str
    chunk_index: int
    size_bytes: int
    hash_sha256: str
    storage_path: str


class ObjectStore:
    """
    مخزن الكائنات المتقدم
    
    الميزات:
    - تخزين الملفات الكبيرة (payloads, logs, snapshots)
    - ضغط تلقائي
    - تخزين متجزئ (chunking) للملفات الكبيرة جداً
    - صلاحية زمنية (TTL) مع تنظيف تلقائي
    - إحصائيات الوصول (access tracking)
    - تصنيف وتنظيم بالعلامات (tags)
    - دعم التخزين المحلي و S3 لاحقاً
    """
    
    def __init__(
        self,
        storage_dir: str = "./storage/object_storage/data",
        db_path: str = "./storage/object_storage/objects.db",
        chunk_size_mb: int = 10,  # حجم الجزء بالـ MB
        enable_compression: bool = True,
        auto_cleanup_days: int = 30
    ):
        self._storage_dir = storage_dir
        self._db_path = db_path
        self._chunk_size_bytes = chunk_size_mb * 1024 * 1024
        self._enable_compression = enable_compression
        self._auto_cleanup_days = auto_cleanup_days
        
        self._write_lock = asyncio.Lock()
        
        # إنشاء المجلدات
        os.makedirs(storage_dir, exist_ok=True)
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        
        # تهيئة قاعدة البيانات
        self._init_database()
        
        # بدء مهمة التنظيف التلقائي
        self._cleanup_task = None
        
        logger.info(f"ObjectStore initialized (dir={storage_dir}, chunk_size={chunk_size_mb}MB)")
    
    def _init_database(self):
        """تهيئة قاعدة البيانات"""
        conn = sqlite3.connect(self._db_path, timeout=30.0)
        cursor = conn.cursor()
        
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA synchronous=NORMAL")
        
        # جدول الكائنات
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS objects (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                content_type TEXT NOT NULL,
                size_bytes INTEGER NOT NULL,
                hash_sha256 TEXT NOT NULL,
                compressed INTEGER DEFAULT 0,
                original_size_bytes INTEGER,
                storage_backend TEXT DEFAULT 'local',
                storage_path TEXT NOT NULL,
                metadata TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                expires_at TEXT,
                access_count INTEGER DEFAULT 0,
                last_accessed TEXT
            )
        ''')
        
        # جدول الأجزاء (للملفات الكبيرة)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS object_chunks (
                object_id TEXT NOT NULL,
                chunk_index INTEGER NOT NULL,
                size_bytes INTEGER NOT NULL,
                hash_sha256 TEXT NOT NULL,
                storage_path TEXT NOT NULL,
                PRIMARY KEY (object_id, chunk_index)
            )
        ''')
        
        # جدول العلامات (tags)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS object_tags (
                object_id TEXT NOT NULL,
                tag TEXT NOT NULL,
                PRIMARY KEY (object_id, tag)
            )
        ''')
        
        # جدول الإصدارات (versioning)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS object_versions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                object_id TEXT NOT NULL,
                version INTEGER NOT NULL,
                storage_path TEXT NOT NULL,
                size_bytes INTEGER NOT NULL,
                hash_sha256 TEXT NOT NULL,
                created_at TEXT NOT NULL,
                UNIQUE(object_id, version)
            )
        ''')
        
        # الفهارس
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_objects_name ON objects(name)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_objects_content_type ON objects(content_type)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_objects_created ON objects(created_at)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_objects_expires ON objects(expires_at)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_tags_tag ON object_tags(tag)')
        
        conn.commit()
        conn.close()
        
        logger.info("Object database initialized")
    
    def _compute_hash(self, data: bytes) -> str:
        """حساب SHA-256 للبيانات"""
        return hashlib.sha256(data).hexdigest()
    
    def _get_storage_path(self, object_id: str) -> str:
        """الحصول على مسار التخزين لكائن"""
        # استخدام مجلدات فرعية لتجنب كثرة الملفات
        subdir = object_id[:2]
        path = os.path.join(self._storage_dir, subdir)
        os.makedirs(path, exist_ok=True)
        return os.path.join(path, f"{object_id}.dat")
    
    def _get_chunk_path(self, object_id: str, chunk_index: int) -> str:
        """الحصول على مسار تخزين جزء"""
        subdir = object_id[:2]
        path = os.path.join(self._storage_dir, subdir, "chunks")
        os.makedirs(path, exist_ok=True)
        return os.path.join(path, f"{object_id}_{chunk_index}.chunk")
    
    async def put(
        self,
        name: str,
        data: Union[bytes, BinaryIO, str],
        content_type: str = "application/octet-stream",
        metadata: Dict[str, Any] = None,
        tags: List[str] = None,
        ttl_seconds: int = None,
        compress: bool = None
    ) -> str:
        """
        تخزين كائن جديد
        
        Args:
            name: اسم الكائن
            data: البيانات (bytes, file object, أو مسار ملف)
            content_type: نوع المحتوى MIME
            metadata: بيانات وصفية
            tags: علامات للتصنيف
            ttl_seconds: مدة الصلاحية بالثواني
            compress: ضغط البيانات (تجاوز الإعداد الافتراضي)
        
        Returns:
            معرف الكائن
        """
        import uuid
        object_id = str(uuid.uuid4())
        now = datetime.now()
        
        # قراءة البيانات
        if isinstance(data, str) and os.path.exists(data):
            # مسار ملف
            with open(data, 'rb') as f:
                file_data = f.read()
        elif isinstance(data, bytes):
            file_data = data
        elif hasattr(data, 'read'):
            # file-like object
            file_data = data.read()
        else:
            file_data = data.encode() if isinstance(data, str) else bytes(data)
        
        original_size = len(file_data)
        
        # ضغط البيانات
        use_compression = compress if compress is not None else self._enable_compression
        if use_compression and original_size > 1024:  # ضغط فقط إذا كان أكبر من 1KB
            compressed_data = zlib.compress(file_data, level=6)
            if len(compressed_data) < original_size * 0.9:  # فقط إذا كان الضغط فعالاً
                file_data = compressed_data
                compressed = True
            else:
                compressed = False
        else:
            compressed = False
        
        size = len(file_data)
        file_hash = self._compute_hash(file_data)
        
        # تحديد ما إذا كان التخزين متجزئاً
        if size > self._chunk_size_bytes * 2:
            # تخزين متجزئ للملفات الكبيرة
            await self._store_chunked(object_id, file_data, now)
            storage_path = f"chunked:{object_id}"
        else:
            # تخزين عادي
            storage_path = self._get_storage_path(object_id)
            with open(storage_path, 'wb') as f:
                f.write(file_data)
        
        expires_at = (now + datetime.timedelta(seconds=ttl_seconds)) if ttl_seconds else None
        
        query = '''
            INSERT INTO objects 
            (id, name, content_type, size_bytes, hash_sha256, compressed, original_size_bytes,
             storage_backend, storage_path, metadata, created_at, updated_at, expires_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        '''
        
        params = (
            object_id, name, content_type, size, file_hash,
            1 if compressed else 0, original_size if compressed else None,
            StorageBackend.LOCAL, storage_path,
            json.dumps(metadata or {}), now.isoformat(), now.isoformat(),
            expires_at.isoformat() if expires_at else None
        )
        
        async with self._write_lock:
            conn = sqlite3.connect(self._db_path)
            cursor = conn.cursor()
            cursor.execute(query, params)
            
            # إضافة العلامات
            if tags:
                for tag in tags:
                    cursor.execute(
                        "INSERT INTO object_tags (object_id, tag) VALUES (?, ?)",
                        (object_id, tag)
                    )
            
            conn.commit()
            conn.close()
        
        logger.info(f"Object stored: {name} ({size} bytes, compressed={compressed}) id={object_id[:8]}")
        return object_id
    
    async def _store_chunked(self, object_id: str, data: bytes, now: datetime):
        """تخزين كائن كبير بشكل متجزئ"""
        chunks = []
        total_chunks = (len(data) + self._chunk_size_bytes - 1) // self._chunk_size_bytes
        
        for i in range(total_chunks):
            start = i * self._chunk_size_bytes
            end = min(start + self._chunk_size_bytes, len(data))
            chunk_data = data[start:end]
            chunk_hash = self._compute_hash(chunk_data)
            chunk_path = self._get_chunk_path(object_id, i)
            
            with open(chunk_path, 'wb') as f:
                f.write(chunk_data)
            
            chunks.append((object_id, i, len(chunk_data), chunk_hash, chunk_path))
        
        conn = sqlite3.connect(self._db_path)
        cursor = conn.cursor()
        cursor.executemany(
            "INSERT INTO object_chunks (object_id, chunk_index, size_bytes, hash_sha256, storage_path) VALUES (?, ?, ?, ?, ?)",
            chunks
        )
        conn.commit()
        conn.close()
        
        logger.debug(f"Object chunked: {object_id[:8]} into {total_chunks} chunks")
    
    async def get(self, object_id: str) -> Optional[Tuple[bytes, StoredObject]]:
        """
        استرجاع كائن
        
        Returns:
            (data, object_info) أو None
        """
        # جلب معلومات الكائن
        query = "SELECT * FROM objects WHERE id = ?"
        
        async with self._write_lock:
            conn = sqlite3.connect(self._db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(query, (object_id,))
            row = cursor.fetchone()
            conn.close()
        
        if not row:
            return None
        
        # إنشاء كائن المعلومات
        obj = StoredObject(
            id=row["id"],
            name=row["name"],
            content_type=row["content_type"],
            size_bytes=row["size_bytes"],
            hash_sha256=row["hash_sha256"],
            compressed=bool(row["compressed"]),
            original_size_bytes=row["original_size_bytes"] or row["size_bytes"],
            storage_backend=row["storage_backend"],
            storage_path=row["storage_path"],
            metadata=json.loads(row["metadata"]) if row["metadata"] else {},
            created_at=datetime.fromisoformat(row["created_at"]),
            updated_at=datetime.fromisoformat(row["updated_at"]),
            expires_at=datetime.fromisoformat(row["expires_at"]) if row["expires_at"] else None,
            access_count=row["access_count"],
            last_accessed=datetime.fromisoformat(row["last_accessed"]) if row["last_accessed"] else None
        )
        
        # قراءة البيانات
        if obj.storage_path.startswith("chunked:"):
            # تخزين متجزئ
            data = await self._get_chunked(obj.id)
        else:
            # تخزين عادي
            with open(obj.storage_path, 'rb') as f:
                data = f.read()
        
        # فك الضغط إذا لزم الأمر
        if obj.compressed:
            data = zlib.decompress(data)
        
        # تحديث إحصائيات الوصول
        await self._update_access_stats(object_id)
        
        return data, obj
    
    async def _get_chunked(self, object_id: str) -> bytes:
        """استرجاع كائن متجزئ"""
        query = "SELECT * FROM object_chunks WHERE object_id = ? ORDER BY chunk_index"
        
        async with self._write_lock:
            conn = sqlite3.connect(self._db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(query, (object_id,))
            rows = cursor.fetchall()
            conn.close()
        
        data_parts = []
        for row in rows:
            with open(row["storage_path"], 'rb') as f:
                data_parts.append(f.read())
        
        return b''.join(data_parts)
    
    async def _update_access_stats(self, object_id: str):
        """تحديث إحصائيات الوصول"""
        query = '''
            UPDATE objects 
            SET access_count = access_count + 1, last_accessed = ?
            WHERE id = ?
        '''
        
        async with self._write_lock:
            conn = sqlite3.connect(self._db_path)
            cursor = conn.cursor()
            cursor.execute(query, (datetime.now().isoformat(), object_id))
            conn.commit()
            conn.close()
    
    async def delete(self, object_id: str) -> bool:
        """حذف كائن"""
        # جلب معلومات الكائن
        obj_info = await self.get_metadata(object_id)
        if not obj_info:
            return False
        
        # حذف الملفات
        if obj_info.storage_path.startswith("chunked:"):
            # حذف الأجزاء
            query = "SELECT storage_path FROM object_chunks WHERE object_id = ?"
            async with self._write_lock:
                conn = sqlite3.connect(self._db_path)
                cursor = conn.cursor()
                cursor.execute(query, (object_id,))
                rows = cursor.fetchall()
                for row in rows:
                    if os.path.exists(row[0]):
                        os.remove(row[0])
                conn.close()
        else:
            # حذف ملف واحد
            if os.path.exists(obj_info.storage_path):
                os.remove(obj_info.storage_path)
        
        # حذف من قاعدة البيانات
        query_obj = "DELETE FROM objects WHERE id = ?"
        query_tags = "DELETE FROM object_tags WHERE object_id = ?"
        query_chunks = "DELETE FROM object_chunks WHERE object_id = ?"
        
        async with self._write_lock:
            conn = sqlite3.connect(self._db_path)
            cursor = conn.cursor()
            cursor.execute(query_obj, (object_id,))
            cursor.execute(query_tags, (object_id,))
            cursor.execute(query_chunks, (object_id,))
            conn.commit()
            conn.close()
        
        logger.info(f"Object deleted: {obj_info.name} ({object_id[:8]})")
        return True
    
    async def get_metadata(self, object_id: str) -> Optional[StoredObject]:
        """الحصول على معلومات كائن بدون تحميل البيانات"""
        query = "SELECT * FROM objects WHERE id = ?"
        
        async with self._write_lock:
            conn = sqlite3.connect(self._db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(query, (object_id,))
            row = cursor.fetchone()
            conn.close()
        
        if not row:
            return None
        
        return StoredObject(
            id=row["id"],
            name=row["name"],
            content_type=row["content_type"],
            size_bytes=row["size_bytes"],
            hash_sha256=row["hash_sha256"],
            compressed=bool(row["compressed"]),
            original_size_bytes=row["original_size_bytes"] or row["size_bytes"],
            storage_backend=row["storage_backend"],
            storage_path=row["storage_path"],
            metadata=json.loads(row["metadata"]) if row["metadata"] else {},
            created_at=datetime.fromisoformat(row["created_at"]),
            updated_at=datetime.fromisoformat(row["updated_at"]),
            expires_at=datetime.fromisoformat(row["expires_at"]) if row["expires_at"] else None,
            access_count=row["access_count"],
            last_accessed=datetime.fromisoformat(row["last_accessed"]) if row["last_accessed"] else None
        )
    
    async def list_objects(
        self,
        prefix: str = None,
        content_type: str = None,
        tags: List[str] = None,
        limit: int = 100,
        offset: int = 0
    ) -> List[StoredObject]:
        """قائمة الكائنات مع تصفية"""
        query = "SELECT * FROM objects WHERE 1=1"
        params = []
        
        if prefix:
            query += " AND name LIKE ?"
            params.append(f"{prefix}%")
        
        if content_type:
            query += " AND content_type = ?"
            params.append(content_type)
        
        if tags:
            # البحث عن الكائنات التي تحمل جميع العلامات
            for tag in tags:
                query += f" AND id IN (SELECT object_id FROM object_tags WHERE tag = ?)"
                params.append(tag)
        
        query += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        
        async with self._write_lock:
            conn = sqlite3.connect(self._db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(query, params)
            rows = cursor.fetchall()
            conn.close()
        
        return [
            StoredObject(
                id=row["id"],
                name=row["name"],
                content_type=row["content_type"],
                size_bytes=row["size_bytes"],
                hash_sha256=row["hash_sha256"],
                compressed=bool(row["compressed"]),
                original_size_bytes=row["original_size_bytes"] or row["size_bytes"],
                storage_backend=row["storage_backend"],
                storage_path=row["storage_path"],
                metadata=json.loads(row["metadata"]) if row["metadata"] else {},
                created_at=datetime.fromisoformat(row["created_at"]),
                updated_at=datetime.fromisoformat(row["updated_at"]),
                expires_at=datetime.fromisoformat(row["expires_at"]) if row["expires_at"] else None,
                access_count=row["access_count"],
                last_accessed=datetime.fromisoformat(row["last_accessed"]) if row["last_accessed"] else None
            )
            for row in rows
        ]
    
    async def add_tags(self, object_id: str, tags: List[str]):
        """إضافة علامات لكائن"""
        async with self._write_lock:
            conn = sqlite3.connect(self._db_path)
            cursor = conn.cursor()
            for tag in tags:
                cursor.execute(
                    "INSERT OR IGNORE INTO object_tags (object_id, tag) VALUES (?, ?)",
                    (object_id, tag)
                )
            conn.commit()
            conn.close()
    
    async def remove_tags(self, object_id: str, tags: List[str]):
        """إزالة علامات من كائن"""
        async with self._write_lock:
            conn = sqlite3.connect(self._db_path)
            cursor = conn.cursor()
            for tag in tags:
                cursor.execute(
                    "DELETE FROM object_tags WHERE object_id = ? AND tag = ?",
                    (object_id, tag)
                )
            conn.commit()
            conn.close()
    
    async def get_tags(self, object_id: str) -> List[str]:
        """الحصول على علامات كائن"""
        query = "SELECT tag FROM object_tags WHERE object_id = ?"
        
        async with self._write_lock:
            conn = sqlite3.connect(self._db_path)
            cursor = conn.cursor()
            cursor.execute(query, (object_id,))
            rows = cursor.fetchall()
            conn.close()
        
        return [row[0] for row in rows]
    
    async def cleanup_expired(self) -> int:
        """حذف الكائنات منتهية الصلاحية"""
        now = datetime.now().isoformat()
        query = "SELECT id FROM objects WHERE expires_at IS NOT NULL AND expires_at < ?"
        
        async with self._write_lock:
            conn = sqlite3.connect(self._db_path)
            cursor = conn.cursor()
            cursor.execute(query, (now,))
            expired_ids = [row[0] for row in cursor.fetchall()]
            conn.close()
        
        deleted = 0
        for object_id in expired_ids:
            if await self.delete(object_id):
                deleted += 1
        
        logger.info(f"Cleaned up {deleted} expired objects")
        return deleted
    
    async def get_statistics(self) -> Dict:
        """إحصائيات المخزن"""
        queries = {
            "total_objects": "SELECT COUNT(*) as count FROM objects",
            "total_size_bytes": "SELECT SUM(size_bytes) as total FROM objects",
            "total_compressed_size_bytes": "SELECT SUM(size_bytes) as total FROM objects WHERE compressed = 1",
            "total_objects_by_type": "SELECT content_type, COUNT(*) as count FROM objects GROUP BY content_type",
            "most_accessed": "SELECT name, access_count FROM objects ORDER BY access_count DESC LIMIT 10"
        }
        
        stats = {}
        
        async with self._write_lock:
            conn = sqlite3.connect(self._db_path)
            conn.row_factory = sqlite3.Row
            
            for key, query in queries.items():
                cursor = conn.cursor()
                cursor.execute(query)
                rows = cursor.fetchall()
                
                if key == "total_objects_by_type":
                    stats[key] = [dict(row) for row in rows]
                elif key == "most_accessed":
                    stats[key] = [dict(row) for row in rows]
                else:
                    stats[key] = rows[0][0] if rows else 0
            
            conn.close()
        
        stats["storage_dir"] = self._storage_dir
        stats["chunk_size_mb"] = self._chunk_size_bytes / (1024 * 1024)
        stats["compression_enabled"] = self._enable_compression
        
        return stats
    
    async def start_auto_cleanup(self, interval_hours: int = 24):
        """بدء التنظيف التلقائي"""
        async def cleanup_loop():
            while True:
                await asyncio.sleep(interval_hours * 3600)
                await self.cleanup_expired()
        
        self._cleanup_task = asyncio.create_task(cleanup_loop())
        logger.info(f"Auto cleanup started (interval={interval_hours}h)")
    
    async def stop_auto_cleanup(self):
        """إيقاف التنظيف التلقائي"""
        if self._cleanup_task:
            self._cleanup_task.cancel()
            logger.info("Auto cleanup stopped")


# نسخة عالمية
_default_store = None


async def get_object_store() -> ObjectStore:
    """الحصول على نسخة عالمية من مخزن الكائنات"""
    global _default_store
    if _default_store is None:
        _default_store = ObjectStore()
        await _default_store.start_auto_cleanup()
    return _default_store

