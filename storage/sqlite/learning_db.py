
import sqlite3
import json
import asyncio
import random
import math
import struct
from typing import Dict, List, Optional, Any, Tuple, Union
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from contextlib import asynccontextmanager
import logging

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

# محاولة استيراد FAISS للبحث المتجهي
try:
    import faiss
    import numpy as np
    FAISS_AVAILABLE = True
except ImportError:
    FAISS_AVAILABLE = False
    logger.warning("FAISS not available, embedding search will be O(N)")

logger = logging.getLogger(__name__)


@dataclass
class Experience:
    """تجربة تعلم"""
    id: Optional[int]
    state: Dict[str, Any]
    action: str
    reward: float
    next_state: Dict[str, Any]
    done: bool
    agent_name: str
    timestamp: datetime
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class RLTransition:
    """انتقال RL مع دعم priority"""
    id: Optional[int]
    state: List[float]
    action: int
    reward: float
    next_state: List[float]
    done: bool
    agent_name: str
    priority: float = 1.0
    td_error: float = 0.0
    episode_id: Optional[int] = None
    created_at: datetime = field(default_factory=datetime.now)


@dataclass
class Episode:
    """حلقة تعلم كاملة"""
    id: Optional[int]
    agent_name: str
    episode_number: int
    total_reward: float
    steps: int
    epsilon: float
    loss: float
    start_time: datetime
    end_time: Optional[datetime] = None
    metadata: Dict = field(default_factory=dict)


class RunningStats:
    """
    إحصائيات تشغيلية باستخدام خوارزمية Welford
    لحساب mean و std بشكل تدريجي بدون تخزين جميع القيم
    """
    
    def __init__(self):
        self.n = 0
        self.mean = 0.0
        self.M2 = 0.0  # مجموع مربعات الفروق
    
    def update(self, x: float):
        """تحديث الإحصائيات بقيمة جديدة"""
        self.n += 1
        delta = x - self.mean
        self.mean += delta / self.n
        delta2 = x - self.mean
        self.M2 += delta * delta2
    
    def get_mean(self) -> float:
        return self.mean if self.n > 0 else 0.0
    
    def get_std(self) -> float:
        return math.sqrt(self.M2 / self.n) if self.n > 1 else 1.0
    
    def normalize(self, x: float) -> float:
        """تطبيع القيمة باستخدام mean و std الحاليين"""
        std = self.get_std()
        if std < 1e-6:
            return 0.0
        return (x - self.mean) / std


class ConnectionPool:
    """
    تجمع اتصالات SQLite محسن مع دعم async
    """
    
    def __init__(self, db_path: str, max_connections: int = 10, enable_wal: bool = True):
        self._db_path = db_path
        self._max_connections = max_connections
        self._enable_wal = enable_wal
        
        self._pool = asyncio.Queue(maxsize=max_connections)
        self._write_lock = asyncio.Lock()
        self._closed = False
        
        # إنشاء المجلد
        import os
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        
        # تهيئة قاعدة البيانات
        self._init_database()
        
        # ملء التجمع
        for _ in range(max_connections):
            conn = self._create_connection()
            self._pool.put_nowait(conn)
        
        logger.info(f"ConnectionPool initialized: {db_path} (max_conn={max_connections})")
    
    def _create_connection(self) -> sqlite3.Connection:
        """إنشاء اتصال جديد مع الإعدادات المثلى"""
        conn = sqlite3.connect(self._db_path, timeout=30.0, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        
        if self._enable_wal:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.execute("PRAGMA cache_size=-20000")  # 20MB cache
            conn.execute("PRAGMA temp_store=MEMORY")
            conn.execute("PRAGMA mmap_size=268435456")  # 256MB mmap
        
        return conn
    
    def _init_database(self):
        """تهيئة قاعدة البيانات"""
        conn = self._create_connection()
        cursor = conn.cursor()
        
        # جداول قاعدة البيانات (نفس الهيكل السابق)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS rl_transitions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                agent_name TEXT NOT NULL,
                state TEXT NOT NULL,
                action INTEGER NOT NULL,
                reward REAL NOT NULL,
                next_state TEXT NOT NULL,
                done INTEGER NOT NULL,
                priority REAL DEFAULT 1.0,
                td_error REAL DEFAULT 0.0,
                episode_id INTEGER,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS episodes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                agent_name TEXT NOT NULL,
                episode_number INTEGER NOT NULL,
                total_reward REAL DEFAULT 0,
                steps INTEGER DEFAULT 0,
                epsilon REAL DEFAULT 1.0,
                loss REAL DEFAULT 0,
                start_time TEXT NOT NULL,
                end_time TEXT,
                metadata TEXT,
                UNIQUE(agent_name, episode_number)
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS learning_stats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                agent_name TEXT NOT NULL,
                episode INTEGER,
                total_reward REAL,
                avg_reward REAL,
                steps INTEGER,
                epsilon REAL,
                loss REAL,
                timestamp TEXT NOT NULL,
                UNIQUE(agent_name, episode)
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS successful_attacks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                attack_chain TEXT NOT NULL,
                target_type TEXT NOT NULL,
                success_rate REAL,
                embedding BLOB,
                metadata TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS target_network_sync (
                agent_name TEXT PRIMARY KEY,
                last_sync_time TEXT NOT NULL,
                sync_count INTEGER DEFAULT 0,
                current_step INTEGER DEFAULT 0
            )
        ''')
        
        # الفهارس المحسنة
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_rl_agent ON rl_transitions(agent_name)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_rl_priority ON rl_transitions(priority DESC)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_rl_created ON rl_transitions(created_at)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_rl_episode ON rl_transitions(episode_id)')
        
        conn.commit()
        conn.close()
        
        logger.info("Database initialized with WAL mode")
    
    async def acquire(self) -> sqlite3.Connection:
        """الحصول على اتصال من التجمع"""
        if self._closed:
            raise RuntimeError("Connection pool is closed")
        return await self._pool.get()
    
    async def release(self, conn: sqlite3.Connection):
        """إعادة اتصال إلى التجمع"""
        if not self._closed:
            await self._pool.put(conn)
        else:
            conn.close()
    
    @asynccontextmanager
    async def connection(self):
        """سياق للاتصال"""
        conn = await self.acquire()
        try:
            yield conn
        finally:
            await self.release(conn)
    
    async def execute_write(self, query: str, params: tuple = ()) -> int:
        """تنفيذ عملية كتابة"""
        async with self._write_lock:
            async with self.connection() as conn:
                cursor = conn.cursor()
                cursor.execute(query, params)
                conn.commit()
                return cursor.lastrowid
    
    async def execute_read(self, query: str, params: tuple = ()) -> List[Dict]:
        """تنفيذ عملية قراءة"""
        async with self.connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            rows = cursor.fetchall()
            return [dict(row) for row in rows]
    
    async def execute_many(self, query: str, params_list: List[tuple]) -> int:
        """تنفيذ معاملات متعددة دفعة واحدة"""
        if not params_list:
            return 0
        
        async with self._write_lock:
            async with self.connection() as conn:
                cursor = conn.cursor()
                cursor.executemany(query, params_list)
                conn.commit()
                return cursor.rowcount
    
    async def close(self):
        """إغلاق جميع الاتصالات"""
        self._closed = True
        while not self._pool.empty():
            conn = await self._pool.get()
            conn.close()
        logger.info("ConnectionPool closed")


class VectorIndex:
    """
    فهرس متجهي للبحث السريع عن الهجمات المشابهة
    يدعم FAISS إذا كان متاحاً، وإلا يقع back إلى البحث الخطي
    """
    
    def __init__(self, dimension: int = 512):
        self._dimension = dimension
        self._embeddings: List[np.ndarray] = []
        self._metadata: List[Dict] = []
        
        if FAISS_AVAILABLE:
            self._index = faiss.IndexFlatL2(dimension)
            self._faiss_available = True
        else:
            self._index = None
            self._faiss_available = False
            logger.warning("FAISS not available, using linear search")
    
    def add(self, embedding: List[float], metadata: Dict):
        """إضافة متجه إلى الفهرس"""
        import numpy as np
        vec = np.array(embedding, dtype=np.float32).reshape(1, -1)
        
        if self._faiss_available:
            self._index.add(vec)
        
        self._embeddings.append(vec[0])
        self._metadata.append(metadata)
    
    def search(self, query: List[float], k: int = 10) -> List[Tuple[float, Dict]]:
        """البحث عن أقرب المتجهات"""
        import numpy as np
        query_vec = np.array(query, dtype=np.float32).reshape(1, -1)
        
        if self._faiss_available and self._index.ntotal > 0:
            distances, indices = self._index.search(query_vec, min(k, self._index.ntotal))
            results = []
            for dist, idx in zip(distances[0], indices[0]):
                if idx >= 0 and idx < len(self._metadata):
                    results.append((float(dist), self._metadata[idx]))
            return results
        else:
            # بحث خطي O(N) - fallback
            results = []
            for vec, meta in zip(self._embeddings, self._metadata):
                dist = np.linalg.norm(query_vec - vec.reshape(1, -1))
                results.append((float(dist), meta))
            results.sort(key=lambda x: x[0])
            return results[:k]


class LearningDatabase:
    """
    قاعدة بيانات التعلم المتقدمة
    
    الميزات:
    - Connection pooling حقيقي
    - Running stats لـ reward normalization (خوارزمية Welford)
    - Stochastic sampling مع نافذة متكيفة log(N)
    - FAISS للبحث المتجهي السريع
    - Batch updates للأولويات
    """
    
    def __init__(
        self,
        db_path: str = "./storage/sqlite/learning.db",
        max_replay_buffer_size: int = 100000,
        replay_buffer_ttl_days: int = 7,
        embedding_dimension: int = 512
    ):
        self._pool = ConnectionPool(db_path, max_connections=10)
        self._max_replay_buffer_size = max_replay_buffer_size
        self._replay_buffer_ttl_days = replay_buffer_ttl_days
        
        # Running stats لكل وكيل (خوارزمية Welford)
        self._reward_stats: Dict[str, RunningStats] = {}
        
        # فهرس متجهي للهجمات الناجحة
        self._vector_index = VectorIndex(embedding_dimension)
        
        # ذاكرة مؤقتة لآخر N انتقالات لكل وكيل (لتسريع sampling)
        self._recent_transitions_cache: Dict[str, List[Dict]] = {}
        self._cache_size = 10000
        
        logger.info(f"LearningDatabase initialized (max_buffer={max_replay_buffer_size}, faiss={FAISS_AVAILABLE})")
    
    async def _get_transition_count(self, agent_name: str) -> int:
        """الحصول على عدد الانتقالات لوكيل معين"""
        query = "SELECT COUNT(*) as count FROM rl_transitions WHERE agent_name = ?"
        rows = await self._pool.execute_read(query, (agent_name,))
        return rows[0]["count"] if rows else 0
    
    async def _cleanup_old_transitions(self, agent_name: str):
        """تنظيف الانتقالات القديمة"""
        cutoff = (datetime.now() - timedelta(days=self._replay_buffer_ttl_days)).isoformat()
        query = '''
            DELETE FROM rl_transitions 
            WHERE agent_name = ? AND created_at < ?
        '''
        await self._pool.execute_write(query, (agent_name, cutoff))
    
    async def _enforce_buffer_size(self, agent_name: str):
        """تطبيق الحد الأقصى لحجم replay buffer"""
        count = await self._get_transition_count(agent_name)
        if count <= self._max_replay_buffer_size:
            return
        
        to_delete = count - self._max_replay_buffer_size
        query = '''
            DELETE FROM rl_transitions 
            WHERE id IN (
                SELECT id FROM rl_transitions 
                WHERE agent_name = ?
                ORDER BY created_at ASC
                LIMIT ?
            )
        '''
        await self._pool.execute_write(query, (agent_name, to_delete))
        logger.debug(f"Enforced buffer size for {agent_name}: deleted {to_delete} old transitions")
    
    async def _get_dynamic_window_size(self, agent_name: str) -> int:
        """حجم نافذة متكيف: sqrt(N) أو 10000 أيهما أكبر"""
        count = await self._get_transition_count(agent_name)
        # dynamic window = min(sqrt(N), 50000)
        window = max(int(math.sqrt(count)), 1000)
        return min(window, 50000)
    
    async def update_running_stats(self, agent_name: str, reward: float):
        """تحديث الإحصائيات التشغيلية (خوارزمية Welford)"""
        if agent_name not in self._reward_stats:
            self._reward_stats[agent_name] = RunningStats()
        
        self._reward_stats[agent_name].update(reward)
    
    async def normalize_reward(self, agent_name: str, reward: float) -> float:
        """تطبيع المكافأة باستخدام إحصائيات Welford (بدون query)"""
        if agent_name not in self._reward_stats:
            return reward  # أول مرة، لا تطبيع
        
        return self._reward_stats[agent_name].normalize(reward)
    
    async def store_rl_transition(self, transition: RLTransition, batch: bool = False) -> int:
        """تخزين انتقال RL مع تطبيع المكافأة"""
        # تحديث الإحصائيات التشغيلية
        await self.update_running_stats(transition.agent_name, transition.reward)
        
        # تطبيع المكافأة
        normalized_reward = await self.normalize_reward(transition.agent_name, transition.reward)
        
        # تنظيف قديم
        await self._cleanup_old_transitions(transition.agent_name)
        
        # تطبيق حجم buffer
        await self._enforce_buffer_size(transition.agent_name)
        
        query = '''
            INSERT INTO rl_transitions 
            (agent_name, state, action, reward, next_state, done, priority, td_error, episode_id, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        '''
        
        params = (
            transition.agent_name,
            fast_json_dumps(transition.state),
            transition.action,
            normalized_reward,
            fast_json_dumps(transition.next_state),
            1 if transition.done else 0,
            transition.priority,
            transition.td_error,
            transition.episode_id,
            datetime.now().isoformat()
        )
        
        return await self._pool.execute_write(query, params)
    
    async def update_batch_priorities(self, updates: List[Tuple[int, float]]):
        """
        تحديث دفعة من الأولويات (لـ batch updates)
        يستخدم execute_many لتحسين الأداء
        """
        if not updates:
            return
        
        query = "UPDATE rl_transitions SET priority = ?, td_error = ? WHERE id = ?"
        params_list = [(abs(td) + 0.01, td, tid) for tid, td in updates]
        await self._pool.execute_many(query, params_list)
    
    async def sample_transitions_stochastic(
        self,
        agent_name: str,
        batch_size: int = 32,
        alpha: float = 0.6,
        beta: float = 0.4
    ) -> Tuple[List[RLTransition], List[float]]:
        """
        أخذ عينات عشوائية مرجحة مع نافذة متكيفة
        """
        total_count = await self._get_transition_count(agent_name)
        
        if total_count < batch_size:
            return [], []
        
        # نافذة متكيفة حسب حجم البيانات
        window_size = await self._get_dynamic_window_size(agent_name)
        window_start = random.randint(0, max(0, total_count - window_size))
        
        query = '''
            SELECT * FROM rl_transitions 
            WHERE agent_name = ?
            ORDER BY created_at
            LIMIT ? OFFSET ?
        '''
        rows = await self._pool.execute_read(query, (agent_name, window_size, window_start))
        
        if not rows:
            return [], []
        
        # حساب الاحتمالات
        priorities = [row["priority"] ** alpha for row in rows]
        total_priority = sum(priorities)
        
        if total_priority == 0:
            probabilities = [1.0 / len(rows)] * len(rows)
        else:
            probabilities = [p / total_priority for p in priorities]
        
        # أخذ عينات مرجحة
        indices = random.choices(range(len(rows)), weights=probabilities, k=batch_size)
        
        # حساب importance sampling weights
        n = len(rows)
        weights = [(n * probabilities[i]) ** (-beta) for i in indices]
        max_weight = max(weights) if weights else 1.0
        weights = [w / max_weight for w in weights]
        
        transitions = []
        for i, idx in enumerate(indices):
            row = rows[idx]
            transitions.append(RLTransition(
                id=row["id"],
                state=fast_json_loads(row["state"]),
                action=row["action"],
                reward=row["reward"],
                next_state=fast_json_loads(row["next_state"]),
                done=bool(row["done"]),
                agent_name=row["agent_name"],
                priority=row["priority"],
                td_error=row["td_error"],
                episode_id=row["episode_id"],
                created_at=datetime.fromisoformat(row["created_at"]) if row["created_at"] else datetime.now()
            ))
        
        return transitions, weights
    
    async def store_successful_attack(
        self,
        attack_chain: Dict[str, Any],
        target_type: str,
        success_rate: float,
        embedding: List[float] = None,
        metadata: Dict = None
    ) -> int:
        """تخزين هجوم ناجح وإضافته إلى الفهرس المتجهي"""
        query = '''
            INSERT INTO successful_attacks 
            (attack_chain, target_type, success_rate, embedding, metadata)
            VALUES (?, ?, ?, ?, ?)
        '''
        
        embedding_bytes = None
        if embedding:
            embedding_bytes = struct.pack(f'{len(embedding)}f', *embedding)
        
        params = (
            fast_json_dumps(attack_chain),
            target_type,
            success_rate,
            embedding_bytes,
            fast_json_dumps(metadata) if metadata else None
        )
        
        attack_id = await self._pool.execute_write(query, params)
        
        # إضافة إلى الفهرس المتجهي للبحث السريع
        if embedding:
            self._vector_index.add(embedding, {
                "id": attack_id,
                "attack_chain": attack_chain,
                "target_type": target_type,
                "success_rate": success_rate
            })
        
        return attack_id
    
    async def find_similar_attacks(
        self,
        query_embedding: List[float],
        top_k: int = 10
    ) -> List[Dict]:
        """البحث عن هجمات مشابهة باستخدام الفهرس المتجهي"""
        return self._vector_index.search(query_embedding, top_k)
    
    async def get_learning_stats(self, agent_name: str, last_n_episodes: int = 100) -> List[Dict]:
        """الحصول على إحصائيات التعلم"""
        query = '''
            SELECT * FROM learning_stats 
            WHERE agent_name = ?
            ORDER BY episode DESC
            LIMIT ?
        '''
        return await self._pool.execute_read(query, (agent_name, last_n_episodes))
    
    async def start_episode(
        self,
        agent_name: str,
        episode_number: int,
        epsilon: float = 1.0,
        metadata: Dict = None
    ) -> int:
        """بدء حلقة تعلم جديدة"""
        query = '''
            INSERT INTO episodes 
            (agent_name, episode_number, epsilon, start_time, metadata)
            VALUES (?, ?, ?, ?, ?)
        '''
        params = (
            agent_name, episode_number, epsilon,
            datetime.now().isoformat(),
            fast_json_dumps(metadata) if metadata else None
        )
        return await self._pool.execute_write(query, params)
    
    async def end_episode(
        self,
        agent_name: str,
        episode_number: int,
        total_reward: float,
        steps: int,
        loss: float = 0.0
    ):
        """إنهاء حلقة تعلم"""
        query = '''
            UPDATE episodes 
            SET total_reward = ?, steps = ?, loss = ?, end_time = ?
            WHERE agent_name = ? AND episode_number = ?
        '''
        params = (
            total_reward, steps, loss, datetime.now().isoformat(),
            agent_name, episode_number
        )
        await self._pool.execute_write(query, params)
        
        # تحديث الإحصائيات
        stats = await self.get_learning_stats(agent_name, last_n_episodes=100)
        avg_reward = sum(s["total_reward"] for s in stats) / len(stats) if stats else total_reward
        
        query_stats = '''
            INSERT OR REPLACE INTO learning_stats 
            (agent_name, episode, total_reward, avg_reward, steps, loss, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        '''
        params_stats = (
            agent_name, episode_number, total_reward, avg_reward, steps, loss,
            datetime.now().isoformat()
        )
        await self._pool.execute_write(query_stats, params_stats)
    
    async def get_statistics(self) -> Dict:
        """الحصول على إحصائيات قاعدة البيانات"""
        queries = {
            "rl_transitions_count": "SELECT COUNT(*) as count FROM rl_transitions",
            "episodes_count": "SELECT COUNT(*) as count FROM episodes",
            "learning_stats_count": "SELECT COUNT(*) as count FROM learning_stats",
            "successful_attacks_count": "SELECT COUNT(*) as count FROM successful_attacks",
            "agents": "SELECT DISTINCT agent_name FROM rl_transitions"
        }
        
        stats = {}
        for key, query in queries.items():
            rows = await self._pool.execute_read(query)
            if key == "agents":
                stats[key] = [row["agent_name"] for row in rows]
            else:
                stats[key] = rows[0]["count"] if rows else 0
        
        stats["json_library"] = "orjson" if USING_ORJSON else "json"
        stats["faiss_available"] = FAISS_AVAILABLE
        stats["max_buffer_size"] = self._max_replay_buffer_size
        stats["buffer_ttl_days"] = self._replay_buffer_ttl_days
        stats["reward_stats"] = {
            agent: {"n": stats.n, "mean": stats.mean, "std": stats.get_std()}
            for agent, stats in self._reward_stats.items()
        }
        
        return stats
    
    async def close(self):
        """إغلاق قاعدة البيانات"""
        await self._pool.close()
        logger.info("LearningDatabase closed")


# نسخة عالمية
_default_db = None


async def get_learning_database() -> LearningDatabase:
    global _default_db
    if _default_db is None:
        _default_db = LearningDatabase()
    return _default_db

