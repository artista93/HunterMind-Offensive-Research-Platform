
import asyncio
import sqlite3
import json
import struct
import numpy as np
from typing import Dict, List, Optional, Any, Tuple, Union
from dataclasses import dataclass, field
from datetime import datetime
from contextlib import asynccontextmanager
import logging

# محاولة استيراد FAISS للبحث السريع
try:
    import faiss
    FAISS_AVAILABLE = True
except ImportError:
    FAISS_AVAILABLE = False
    logger.warning("FAISS not available, vector search will be O(N)")

# محاولة استيراد Annoy للبحث التقريبي
try:
    from annoy import AnnoyIndex
    ANNOY_AVAILABLE = True
except ImportError:
    ANNOY_AVAILABLE = False

logger = logging.getLogger(__name__)


@dataclass
class VectorDocument:
    """وثيقة متجهة"""
    id: str
    vector: List[float]
    metadata: Dict[str, Any]
    text: Optional[str] = None
    embedding_model: str = "default"
    created_at: datetime = field(default_factory=datetime.now)


@dataclass
class SearchResult:
    """نتيجة بحث"""
    document: VectorDocument
    score: float  # مسافة أو تشابه
    rank: int


class HNSWIndex:
    """
    فهرس HNSW للبحث المتجهي السريع
    
    يستخدم FAISS إذا كان متاحاً، وإلا يستخدم Annoy
    """
    
    def __init__(self, dimension: int, index_type: str = "cosine"):
        self._dimension = dimension
        self._index_type = index_type
        self._documents: Dict[int, VectorDocument] = {}
        self._id_counter = 0
        
        if FAISS_AVAILABLE:
            # FAISS للبحث الدقيق
            if index_type == "cosine":
                # للتشابه cosine، نستخدم L2 بعد التطبيع
                self._index = faiss.IndexFlatIP(dimension)
                self._normalize = True
            else:
                self._index = faiss.IndexFlatL2(dimension)
                self._normalize = False
            self._faiss_index = True
            
        elif ANNOY_AVAILABLE:
            # Annoy للبحث التقريبي (أسرع للبيانات الكبيرة)
            metric = "angular" if index_type == "cosine" else "euclidean"
            self._index = AnnoyIndex(dimension, metric)
            self._faiss_index = False
            self._annoy_index = True
            self._built = False
            
        else:
            # بحث خطي (fallback)
            self._index = None
            self._faiss_index = False
            self._annoy_index = False
        
        logger.info(f"HNSWIndex initialized (dim={dimension}, type={index_type}, faiss={FAISS_AVAILABLE})")
    
    def add(self, vector: List[float], document: VectorDocument) -> int:
        """إضافة متجه إلى الفهرس"""
        vec = np.array(vector, dtype=np.float32)
        
        if self._faiss_index:
            if self._normalize:
                vec = vec / (np.linalg.norm(vec) + 1e-8)
            self._index.add(vec.reshape(1, -1))
            
        elif self._annoy_index:
            self._index.add_item(self._id_counter, vec)
            self._built = False
            
        self._documents[self._id_counter] = document
        self._id_counter += 1
        
        return self._id_counter - 1
    
    def search(self, query: List[float], k: int = 10) -> List[Tuple[float, VectorDocument]]:
        """البحث عن أقرب المتجهات"""
        query_vec = np.array(query, dtype=np.float32)
        
        if self._faiss_index:
            if self._normalize:
                query_vec = query_vec / (np.linalg.norm(query_vec) + 1e-8)
            
            if self._index.ntotal == 0:
                return []
            
            distances, indices = self._index.search(query_vec.reshape(1, -1), min(k, self._index.ntotal))
            
            results = []
            for dist, idx in zip(distances[0], indices[0]):
                if idx != -1 and idx in self._documents:
                    # تحويل المسافة إلى تشابه
                    if self._index_type == "cosine":
                        score = float(dist)  # IP عالية = تشابه عالي
                    else:
                        score = 1.0 / (1.0 + float(dist))  # تحويل L2 إلى تشابه
                    results.append((score, self._documents[idx]))
            
            return sorted(results, key=lambda x: x[0], reverse=True)
        
        elif self._annoy_index:
            if not self._built:
                self._index.build(10)  # 10 trees
                self._built = True
            
            indices, distances = self._index.get_nns_by_vector(
                query_vec, k, include_distances=True
            )
            
            results = []
            for idx, dist in zip(indices, distances):
                if idx in self._documents:
                    if self._index_type == "cosine":
                        score = 1.0 - (dist / 2)  # Angular distance -> cosine similarity
                    else:
                        score = 1.0 / (1.0 + dist)
                    results.append((score, self._documents[idx]))
            
            return sorted(results, key=lambda x: x[0], reverse=True)
        
        else:
            # بحث خطي O(N) - fallback
            results = []
            for idx, doc in self._documents.items():
                doc_vec = np.array(doc.vector, dtype=np.float32)
                
                if self._index_type == "cosine":
                    # Cosine similarity
                    norm_q = np.linalg.norm(query_vec)
                    norm_d = np.linalg.norm(doc_vec)
                    if norm_q > 0 and norm_d > 0:
                        similarity = np.dot(query_vec, doc_vec) / (norm_q * norm_d)
                    else:
                        similarity = 0.0
                    score = similarity
                else:
                    # Euclidean distance
                    distance = np.linalg.norm(query_vec - doc_vec)
                    score = 1.0 / (1.0 + distance)
                
                results.append((score, doc))
            
            results.sort(key=lambda x: x[0], reverse=True)
            return results[:k]
    
    def count(self) -> int:
        """عدد المتجهات في الفهرس"""
        return len(self._documents)
    
    def clear(self):
        """مسح الفهرس"""
        self._documents.clear()
        self._id_counter = 0
        
        if self._faiss_index:
            self._index.reset()
        elif self._annoy_index:
            self._index = AnnoyIndex(self._dimension, "angular" if self._index_type == "cosine" else "euclidean")
            self._built = False


class VectorStore:
    """
    مخزن المتجهات المتقدم
    
    الميزات:
    - تخزين واسترجاع المتجهات مع بيانات وصفية
    - البحث الدلالي (semantic search)
    - فهارس متعددة (FAISS / Annoy / Linear)
    - دمج البيانات (merge) وإعادة الفهرسة
    - تصدير واستيراد المتجهات
    """
    
    def __init__(
        self,
        db_path: str = "./storage/vector_db/vectors.db",
        dimension: int = 768,  # الحجم الافتراضي لـ embeddings
        index_type: str = "cosine",  # cosine, euclidean
        use_hnsw: bool = True
    ):
        self._db_path = db_path
        self._dimension = dimension
        self._index_type = index_type
        self._use_hnsw = use_hnsw
        
        self._write_lock = asyncio.Lock()
        
        # الفهرس في الذاكرة
        self._index = HNSWIndex(dimension, index_type) if use_hnsw else None
        self._documents: Dict[str, VectorDocument] = {}
        
        # إنشاء المجلد
        import os
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        
        # تهيئة قاعدة البيانات
        self._init_database()
        
        # تحميل المتجهات من قاعدة البيانات
        asyncio.create_task(self._load_vectors())
        
        logger.info(f"VectorStore initialized (dim={dimension}, type={index_type}, hnsw={use_hnsw})")
    
    def _init_database(self):
        """تهيئة قاعدة البيانات"""
        conn = sqlite3.connect(self._db_path, timeout=30.0)
        cursor = conn.cursor()
        
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA synchronous=NORMAL")
        
        # جدول المتجهات
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS vectors (
                id TEXT PRIMARY KEY,
                vector BLOB NOT NULL,
                metadata TEXT,
                text TEXT,
                embedding_model TEXT,
                created_at TEXT NOT NULL
            )
        ''')
        
        # جدول المجموعات (collections)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS collections (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT,
                dimension INTEGER,
                created_at TEXT NOT NULL
            )
        ''')
        
        # جدول علاقة المتجهات بالمجموعات
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS collection_vectors (
                collection_id TEXT NOT NULL,
                vector_id TEXT NOT NULL,
                FOREIGN KEY (collection_id) REFERENCES collections(id),
                FOREIGN KEY (vector_id) REFERENCES vectors(id),
                PRIMARY KEY (collection_id, vector_id)
            )
        ''')
        
        # الفهارس
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_vectors_model ON vectors(embedding_model)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_vectors_created ON vectors(created_at)')
        
        conn.commit()
        conn.close()
        
        logger.info("Vector database initialized")
    
    async def _load_vectors(self):
        """تحميل المتجهات من قاعدة البيانات إلى الذاكرة"""
        query = "SELECT * FROM vectors"
        
        async with self._write_lock:
            conn = sqlite3.connect(self._db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(query)
            rows = cursor.fetchall()
            conn.close()
        
        for row in rows:
            # فك ضغط المتجه
            vector_bytes = row["vector"]
            vector = list(struct.unpack(f'{len(vector_bytes)//4}f', vector_bytes))
            
            doc = VectorDocument(
                id=row["id"],
                vector=vector,
                metadata=json.loads(row["metadata"]) if row["metadata"] else {},
                text=row["text"],
                embedding_model=row["embedding_model"],
                created_at=datetime.fromisoformat(row["created_at"])
            )
            
            self._documents[doc.id] = doc
            
            if self._index:
                self._index.add(vector, doc)
        
        logger.info(f"Loaded {len(self._documents)} vectors from database")
    
    async def add_vector(
        self,
        vector: List[float],
        metadata: Dict[str, Any] = None,
        text: str = None,
        embedding_model: str = "default",
        collection_id: str = None
    ) -> str:
        """
        إضافة متجه إلى المخزن
        
        Args:
            vector: المتجه (قائمة من الأعداد العشرية)
            metadata: بيانات وصفية
            text: النص الأصلي (اختياري)
            embedding_model: اسم نموذج التضمين
            collection_id: معرف المجموعة (اختياري)
        
        Returns:
            معرف المتجه
        """
        import uuid
        doc_id = str(uuid.uuid4())
        now = datetime.now().isoformat()
        
        # التحقق من أبعاد المتجه
        if len(vector) != self._dimension:
            raise ValueError(f"Vector dimension mismatch: expected {self._dimension}, got {len(vector)}")
        
        # تحويل المتجه إلى bytes
        vector_bytes = struct.pack(f'{len(vector)}f', *vector)
        
        query = '''
            INSERT INTO vectors (id, vector, metadata, text, embedding_model, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
        '''
        
        params = (
            doc_id, vector_bytes,
            json.dumps(metadata) if metadata else None,
            text, embedding_model, now
        )
        
        async with self._write_lock:
            conn = sqlite3.connect(self._db_path)
            cursor = conn.cursor()
            cursor.execute(query, params)
            
            # إضافة إلى المجموعة إذا تم تحديدها
            if collection_id:
                cursor.execute(
                    "INSERT INTO collection_vectors (collection_id, vector_id) VALUES (?, ?)",
                    (collection_id, doc_id)
                )
            
            conn.commit()
            conn.close()
        
        # إضافة إلى الذاكرة
        doc = VectorDocument(
            id=doc_id,
            vector=vector,
            metadata=metadata or {},
            text=text,
            embedding_model=embedding_model,
            created_at=datetime.fromisoformat(now)
        )
        self._documents[doc_id] = doc
        
        if self._index:
            self._index.add(vector, doc)
        
        logger.debug(f"Vector added: {doc_id[:8]}")
        return doc_id
    
    async def add_vectors_batch(self, vectors: List[Tuple[List[float], Dict, str]]) -> List[str]:
        """
        إضافة مجموعة من المتجهات دفعة واحدة
        
        Args:
            vectors: قائمة من (vector, metadata, text)
        
        Returns:
            قائمة المعرفات
        """
        ids = []
        
        async with self._write_lock:
            conn = sqlite3.connect(self._db_path)
            cursor = conn.cursor()
            
            for vector, metadata, text in vectors:
                import uuid
                doc_id = str(uuid.uuid4())
                now = datetime.now().isoformat()
                
                if len(vector) != self._dimension:
                    logger.warning(f"Skipping vector with wrong dimension: {len(vector)}")
                    continue
                
                vector_bytes = struct.pack(f'{len(vector)}f', *vector)
                
                cursor.execute(
                    "INSERT INTO vectors (id, vector, metadata, text, created_at) VALUES (?, ?, ?, ?, ?)",
                    (doc_id, vector_bytes, json.dumps(metadata), text, now)
                )
                
                ids.append(doc_id)
                
                # إضافة إلى الذاكرة
                doc = VectorDocument(
                    id=doc_id,
                    vector=vector,
                    metadata=metadata,
                    text=text,
                    created_at=datetime.fromisoformat(now)
                )
                self._documents[doc_id] = doc
                
                if self._index:
                    self._index.add(vector, doc)
            
            conn.commit()
            conn.close()
        
        logger.info(f"Batch added {len(ids)} vectors")
        return ids
    
    async def search(
        self,
        query_vector: List[float],
        top_k: int = 10,
        filter_metadata: Dict[str, Any] = None,
        min_score: float = 0.0
    ) -> List[SearchResult]:
        """
        البحث عن متجهات مشابهة
        
        Args:
            query_vector: متجه الاستعلام
            top_k: عدد النتائج
            filter_metadata: تصفية حسب البيانات الوصفية
            min_score: الحد الأدنى للتشابه
        
        Returns:
            قائمة بنتائج البحث
        """
        if len(query_vector) != self._dimension:
            raise ValueError(f"Query vector dimension mismatch: expected {self._dimension}, got {len(query_vector)}")
        
        if self._index and not filter_metadata:
            # بحث سريع باستخدام الفهرس
            results = self._index.search(query_vector, top_k * 2)  # *2 للتصفية
            
            filtered_results = []
            for score, doc in results:
                if score < min_score:
                    continue
                
                if filter_metadata:
                    # تطبيق التصفية
                    match = all(
                        doc.metadata.get(key) == value
                        for key, value in filter_metadata.items()
                    )
                    if not match:
                        continue
                
                filtered_results.append(SearchResult(
                    document=doc,
                    score=score,
                    rank=len(filtered_results) + 1
                ))
                
                if len(filtered_results) >= top_k:
                    break
            
            return filtered_results
        
        else:
            # بحث خطي مع التصفية
            query_vec = np.array(query_vector, dtype=np.float32)
            results = []
            
            for doc in self._documents.values():
                if filter_metadata:
                    match = all(
                        doc.metadata.get(key) == value
                        for key, value in filter_metadata.items()
                    )
                    if not match:
                        continue
                
                doc_vec = np.array(doc.vector, dtype=np.float32)
                
                if self._index_type == "cosine":
                    norm_q = np.linalg.norm(query_vec)
                    norm_d = np.linalg.norm(doc_vec)
                    if norm_q > 0 and norm_d > 0:
                        similarity = np.dot(query_vec, doc_vec) / (norm_q * norm_d)
                    else:
                        similarity = 0.0
                    score = similarity
                else:
                    distance = np.linalg.norm(query_vec - doc_vec)
                    score = 1.0 / (1.0 + distance)
                
                if score >= min_score:
                    results.append((score, doc))
            
            results.sort(key=lambda x: x[0], reverse=True)
            
            return [
                SearchResult(document=doc, score=score, rank=i+1)
                for i, (score, doc) in enumerate(results[:top_k])
            ]
    
    async def get_vector(self, vector_id: str) -> Optional[VectorDocument]:
        """الحصول على متجه بالمعرف"""
        return self._documents.get(vector_id)
    
    async def delete_vector(self, vector_id: str) -> bool:
        """حذف متجه"""
        if vector_id not in self._documents:
            return False
        
        query = "DELETE FROM vectors WHERE id = ?"
        
        async with self._write_lock:
            conn = sqlite3.connect(self._db_path)
            cursor = conn.cursor()
            cursor.execute(query, (vector_id,))
            conn.commit()
            conn.close()
        
        del self._documents[vector_id]
        
        # إعادة بناء الفهرس (بسيط)
        if self._index:
            self._index.clear()
            for doc in self._documents.values():
                self._index.add(doc.vector, doc)
        
        logger.debug(f"Vector deleted: {vector_id[:8]}")
        return True
    
    async def create_collection(self, name: str, description: str = None) -> str:
        """إنشاء مجموعة جديدة"""
        import uuid
        collection_id = str(uuid.uuid4())
        now = datetime.now().isoformat()
        
        query = '''
            INSERT INTO collections (id, name, description, dimension, created_at)
            VALUES (?, ?, ?, ?, ?)
        '''
        
        params = (collection_id, name, description, self._dimension, now)
        
        async with self._write_lock:
            conn = sqlite3.connect(self._db_path)
            cursor = conn.cursor()
            cursor.execute(query, params)
            conn.commit()
            conn.close()
        
        logger.info(f"Collection created: {name} ({collection_id[:8]})")
        return collection_id
    
    async def add_to_collection(self, vector_id: str, collection_id: str) -> bool:
        """إضافة متجه إلى مجموعة"""
        if vector_id not in self._documents:
            return False
        
        query = "INSERT OR IGNORE INTO collection_vectors (collection_id, vector_id) VALUES (?, ?)"
        
        async with self._write_lock:
            conn = sqlite3.connect(self._db_path)
            cursor = conn.cursor()
            cursor.execute(query, (collection_id, vector_id))
            conn.commit()
            conn.close()
        
        return True
    
    async def get_collection_vectors(self, collection_id: str) -> List[VectorDocument]:
        """الحصول على جميع متجهات مجموعة"""
        query = '''
            SELECT vector_id FROM collection_vectors
            WHERE collection_id = ?
        '''
        
        async with self._write_lock:
            conn = sqlite3.connect(self._db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(query, (collection_id,))
            rows = cursor.fetchall()
            conn.close()
        
        return [self._documents[row["vector_id"]] for row in rows if row["vector_id"] in self._documents]
    
    async def rebuild_index(self):
        """إعادة بناء الفهرس (للاستخدام مع Annoy بعد الإضافات الكبيرة)"""
        if not self._index:
            return
        
        self._index.clear()
        for doc in self._documents.values():
            self._index.add(doc.vector, doc)
        
        logger.info(f"Index rebuilt with {self._index.count()} vectors")
    
    async def get_statistics(self) -> Dict:
        """إحصائيات المخزن"""
        return {
            "total_vectors": len(self._documents),
            "dimension": self._dimension,
            "index_type": self._index_type,
            "use_hnsw": self._use_hnsw,
            "faiss_available": FAISS_AVAILABLE,
            "annoy_available": ANNOY_AVAILABLE,
            "index_size": self._index.count() if self._index else 0,
            "collections": await self._get_collection_count()
        }
    
    async def _get_collection_count(self) -> int:
        """عدد المجموعات"""
        query = "SELECT COUNT(*) as count FROM collections"
        
        async with self._write_lock:
            conn = sqlite3.connect(self._db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(query)
            row = cursor.fetchone()
            conn.close()
        
        return row["count"] if row else 0
    
    async def export_vectors(self, filepath: str):
        """تصدير جميع المتجهات إلى ملف"""
        export_data = {
            "dimension": self._dimension,
            "index_type": self._index_type,
            "vectors": [
                {
                    "id": doc.id,
                    "vector": doc.vector,
                    "metadata": doc.metadata,
                    "text": doc.text,
                    "embedding_model": doc.embedding_model,
                    "created_at": doc.created_at.isoformat()
                }
                for doc in self._documents.values()
            ]
        }
        
        with open(filepath, "w") as f:
            json.dump(export_data, f, indent=2)
        
        logger.info(f"Exported {len(self._documents)} vectors to {filepath}")
    
    async def import_vectors(self, filepath: str):
        """استيراد متجهات من ملف"""
        with open(filepath, "r") as f:
            import_data = json.load(f)
        
        # التحقق من التوافق
        if import_data.get("dimension") != self._dimension:
            logger.warning(f"Dimension mismatch: file={import_data.get('dimension')}, store={self._dimension}")
        
        # استيراد المتجهات
        for vec_data in import_data.get("vectors", []):
            await self.add_vector(
                vector=vec_data["vector"],
                metadata=vec_data.get("metadata", {}),
                text=vec_data.get("text"),
                embedding_model=vec_data.get("embedding_model", "default")
            )
        
        logger.info(f"Imported {len(import_data.get('vectors', []))} vectors from {filepath}")


# نسخة عالمية
_default_store = None


async def get_vector_store() -> VectorStore:
    """الحصول على نسخة عالمية من مخزن المتجهات"""
    global _default_store
    if _default_store is None:
        _default_store = VectorStore()
    return _default_store

