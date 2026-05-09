
import json
import sqlite3
import asyncio
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

from .payload_generator import Payload, PayloadType, EncodingType, get_payload_generator
from .payload_mutator import get_payload_mutator
from .payload_encoder import get_payload_encoder
from .payload_ranker import get_payload_ranker

import logging

logger = logging.getLogger(__name__)


class PayloadStatus(Enum):
    """حالة الحمولة"""
    ACTIVE = "active"
    DEPRECATED = "deprecated"
    EXPERIMENTAL = "experimental"
    BROKEN = "broken"


@dataclass
class PayloadEntry:
    """إدخال في مكتبة الحمولات"""
    id: str
    name: str
    type: PayloadType
    payload: str
    encoding: Optional[EncodingType]
    status: PayloadStatus
    tags: List[str]
    metadata: Dict[str, Any]
    created_at: datetime
    updated_at: datetime
    success_count: int = 0
    fail_count: int = 0
    rating: float = 0.0


class PayloadLibrary:
    """
    مكتبة الحمولات المركزية
    
    الميزات:
    - تخزين وإدارة الحمولات في قاعدة بيانات SQLite
    - تصنيف حسب النوع والوسوم
    - بحث متقدم في الحمولات
    - استيراد وتصدير الحمولات
    - تحديث إحصائيات النجاح والفشل
    - تكامل مع مولد الحمولات ومشفرها
    """
    
    def __init__(self, db_path: str = "./offensive/payloads/library.db"):
        self._db_path = db_path
        self._lock = asyncio.Lock()
        
        # تهيئة قاعدة البيانات
        self._init_database()
        
        # تهيئة المكونات الأخرى
        self._generator = get_payload_generator()
        self._mutator = get_payload_mutator()
        self._encoder = get_payload_encoder()
        self._ranker = get_payload_ranker()
        
        logger.info(f"PayloadLibrary initialized (db={db_path})")
    
    def _init_database(self):
        """تهيئة قاعدة البيانات"""
        import os
        os.makedirs(os.path.dirname(self._db_path), exist_ok=True)
        
        conn = sqlite3.connect(self._db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS payloads (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                type TEXT NOT NULL,
                payload TEXT NOT NULL,
                encoding TEXT,
                status TEXT DEFAULT 'active',
                tags TEXT,
                metadata TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                success_count INTEGER DEFAULT 0,
                fail_count INTEGER DEFAULT 0,
                rating REAL DEFAULT 0
            )
        ''')
        
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_payloads_type ON payloads(type)
        ''')
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_payloads_status ON payloads(status)
        ''')
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_payloads_rating ON payloads(rating DESC)
        ''')
        
        conn.commit()
        conn.close()
        
        logger.info("Payload library database initialized")
    
    async def add_payload(
        self,
        name: str,
        payload_type: PayloadType,
        payload: str,
        encoding: Optional[EncodingType] = None,
        tags: List[str] = None,
        metadata: Dict[str, Any] = None,
        status: PayloadStatus = PayloadStatus.ACTIVE
    ) -> str:
        """
        إضافة حمولة جديدة إلى المكتبة
        
        Returns:
            معرف الحمولة
        """
        import uuid
        payload_id = str(uuid.uuid4())
        now = datetime.now().isoformat()
        
        async with self._lock:
            conn = sqlite3.connect(self._db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO payloads 
                (id, name, type, payload, encoding, status, tags, metadata, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                payload_id, name, payload_type.value, payload,
                encoding.value if encoding else None,
                status.value,
                json.dumps(tags or []),
                json.dumps(metadata or {}),
                now, now
            ))
            
            conn.commit()
            conn.close()
        
        logger.info(f"Added payload to library: {name} ({payload_type.value})")
        return payload_id
    
    async def get_payload(self, payload_id: str) -> Optional[PayloadEntry]:
        """الحصول على حمولة من المكتبة"""
        async with self._lock:
            conn = sqlite3.connect(self._db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM payloads WHERE id = ?", (payload_id,))
            row = cursor.fetchone()
            conn.close()
        
        if not row:
            return None
        
        return PayloadEntry(
            id=row["id"],
            name=row["name"],
            type=PayloadType(row["type"]),
            payload=row["payload"],
            encoding=EncodingType(row["encoding"]) if row["encoding"] else None,
            status=PayloadStatus(row["status"]),
            tags=json.loads(row["tags"]),
            metadata=json.loads(row["metadata"]),
            created_at=datetime.fromisoformat(row["created_at"]),
            updated_at=datetime.fromisoformat(row["updated_at"]),
            success_count=row["success_count"],
            fail_count=row["fail_count"],
            rating=row["rating"]
        )
    
    async def update_payload_stats(self, payload_id: str, success: bool):
        """
        تحديث إحصائيات الحمولة
        
        Args:
            payload_id: معرف الحمولة
            success: هل نجحت الحمولة؟
        """
        async with self._lock:
            conn = sqlite3.connect(self._db_path)
            cursor = conn.cursor()
            
            if success:
                cursor.execute('''
                    UPDATE payloads 
                    SET success_count = success_count + 1,
                        rating = (success_count + 1.0) / (success_count + fail_count + 1) * 10,
                        updated_at = ?
                    WHERE id = ?
                ''', (datetime.now().isoformat(), payload_id))
            else:
                cursor.execute('''
                    UPDATE payloads 
                    SET fail_count = fail_count + 1,
                        rating = success_count / (success_count + fail_count + 1.0) * 10,
                        updated_at = ?
                    WHERE id = ?
                ''', (datetime.now().isoformat(), payload_id))
            
            conn.commit()
            conn.close()
        
        # تحديث في ranking system
        self._ranker.record_success(payload_id, success)
    
    async def search_payloads(
        self,
        payload_type: Optional[PayloadType] = None,
        tags: List[str] = None,
        min_rating: float = 0.0,
        status: PayloadStatus = PayloadStatus.ACTIVE,
        limit: int = 100,
        offset: int = 0
    ) -> List[PayloadEntry]:
        """
        البحث عن حمولات في المكتبة
        
        Args:
            payload_type: نوع الحمولة
            tags: قائمة بالوسوم
            min_rating: الحد الأدنى للتقييم
            status: حالة الحمولة
            limit: عدد النتائج
            offset: الإزاحة
        """
        query = "SELECT * FROM payloads WHERE status = ?"
        params = [status.value]
        
        if payload_type:
            query += " AND type = ?"
            params.append(payload_type.value)
        
        if min_rating > 0:
            query += " AND rating >= ?"
            params.append(min_rating)
        
        if tags:
            for tag in tags:
                query += " AND tags LIKE ?"
                params.append(f'%"{tag}"%')
        
        query += " ORDER BY rating DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        
        async with self._lock:
            conn = sqlite3.connect(self._db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(query, params)
            rows = cursor.fetchall()
            conn.close()
        
        return [
            PayloadEntry(
                id=row["id"],
                name=row["name"],
                type=PayloadType(row["type"]),
                payload=row["payload"],
                encoding=EncodingType(row["encoding"]) if row["encoding"] else None,
                status=PayloadStatus(row["status"]),
                tags=json.loads(row["tags"]),
                metadata=json.loads(row["metadata"]),
                created_at=datetime.fromisoformat(row["created_at"]),
                updated_at=datetime.fromisoformat(row["updated_at"]),
                success_count=row["success_count"],
                fail_count=row["fail_count"],
                rating=row["rating"]
            )
            for row in rows
        ]
    
    async def get_top_payloads(
        self,
        payload_type: Optional[PayloadType] = None,
        limit: int = 10
    ) -> List[PayloadEntry]:
        """الحصول على أفضل الحمولات حسب التقييم"""
        return await self.search_payloads(
            payload_type=payload_type,
            min_rating=0,
            status=PayloadStatus.ACTIVE,
            limit=limit
        )
    
    async def generate_and_store_payloads(self):
        """توليد حمولات جديدة وتخزينها في المكتبة"""
        logger.info("Generating payloads...")
        
        # توليد جميع أنواع الحمولات
        all_payloads = await self._generator.generate_all_payloads()
        
        count = 0
        for payload_type, payloads in all_payloads.items():
            for payload in payloads:
                # التحقق من عدم وجود الحمولة بالفعل
                existing = await self.search_payloads(
                    payload_type=payload_type,
                    limit=1
                )
                
                if not existing or not any(p.payload == payload.payload for p in existing):
                    await self.add_payload(
                        name=payload.name,
                        payload_type=payload_type,
                        payload=payload.payload,
                        encoding=payload.encoding,
                        tags=payload.tags,
                        metadata=payload.metadata,
                        status=PayloadStatus.ACTIVE
                    )
                    count += 1
        
        logger.info(f"Generated and stored {count} new payloads")
        return count
    
    async def export_to_json(self, filepath: str):
        """تصدير المكتبة إلى ملف JSON"""
        payloads = await self.search_payloads(limit=10000)
        
        export_data = {
            "exported_at": datetime.now().isoformat(),
            "total_payloads": len(payloads),
            "payloads": [
                {
                    "id": p.id,
                    "name": p.name,
                    "type": p.type.value,
                    "payload": p.payload,
                    "encoding": p.encoding.value if p.encoding else None,
                    "tags": p.tags,
                    "metadata": p.metadata,
                    "rating": p.rating
                }
                for p in payloads
            ]
        }
        
        with open(filepath, 'w') as f:
            json.dump(export_data, f, indent=2)
        
        logger.info(f"Exported {len(payloads)} payloads to {filepath}")
    
    async def import_from_json(self, filepath: str):
        """استيراد حمولات من ملف JSON"""
        with open(filepath, 'r') as f:
            data = json.load(f)
        
        count = 0
        for payload_data in data.get("payloads", []):
            # التحقق من الوجود المسبق
            existing = await self.search_payloads(limit=1)
            
            payload_type = PayloadType(payload_data["type"])
            encoding = EncodingType(payload_data["encoding"]) if payload_data.get("encoding") else None
            
            if not existing or not any(p.payload == payload_data["payload"] for p in existing):
                await self.add_payload(
                    name=payload_data["name"],
                    payload_type=payload_type,
                    payload=payload_data["payload"],
                    encoding=encoding,
                    tags=payload_data.get("tags", []),
                    metadata=payload_data.get("metadata", {}),
                    status=PayloadStatus.ACTIVE
                )
                count += 1
        
        logger.info(f"Imported {count} payloads from {filepath}")
    
    async def delete_payload(self, payload_id: str) -> bool:
        """حذف حمولة من المكتبة"""
        async with self._lock:
            conn = sqlite3.connect(self._db_path)
            cursor = conn.cursor()
            cursor.execute("DELETE FROM payloads WHERE id = ?", (payload_id,))
            affected = cursor.rowcount
            conn.commit()
            conn.close()
        
        if affected > 0:
            logger.info(f"Deleted payload: {payload_id}")
            return True
        
        return False
    
    async def get_statistics(self) -> Dict:
        """إحصائيات المكتبة"""
        async with self._lock:
            conn = sqlite3.connect(self._db_path)
            cursor = conn.cursor()
            
            # إجمالي الحمولات
            cursor.execute("SELECT COUNT(*) FROM payloads")
            total = cursor.fetchone()[0]
            
            # حسب النوع
            cursor.execute("SELECT type, COUNT(*) FROM payloads GROUP BY type")
            by_type = {row[0]: row[1] for row in cursor.fetchall()}
            
            # حسب الحالة
            cursor.execute("SELECT status, COUNT(*) FROM payloads GROUP BY status")
            by_status = {row[0]: row[1] for row in cursor.fetchall()}
            
            # متوسط التقييم
            cursor.execute("SELECT AVG(rating) FROM payloads")
            avg_rating = cursor.fetchone()[0] or 0
            
            conn.close()
        
        return {
            "total_payloads": total,
            "by_type": by_type,
            "by_status": by_status,
            "avg_rating": avg_rating,
            "generator_stats": self._generator.get_statistics() if hasattr(self._generator, 'get_statistics') else {},
            "encoder_stats": self._encoder.get_statistics() if hasattr(self._encoder, 'get_statistics') else {},
            "ranker_stats": self._ranker.get_statistics() if hasattr(self._ranker, 'get_statistics') else {}
        }


# نسخة عالمية
_default_library = None


async def get_payload_library() -> PayloadLibrary:
    """الحصول على نسخة عالمية من مكتبة الحمولات"""
    global _default_library
    if _default_library is None:
        _default_library = PayloadLibrary()
        # توليد الحمولات الأولية في الخلفية
        asyncio.create_task(_default_library.generate_and_store_payloads())
    return _default_library

