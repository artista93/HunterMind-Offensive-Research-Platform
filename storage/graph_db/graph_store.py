
import asyncio
import sqlite3
import json
from typing import Dict, List, Optional, Any, Tuple, Set
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from collections import defaultdict
import logging

logger = logging.getLogger(__name__)


class EdgeType(Enum):
    """أنواع العلاقات في الرسم البياني"""
    # علاقات عامة
    CONTAINS = "contains"
    DEPENDS_ON = "depends_on"
    RELATES_TO = "relates_to"
    
    # علاقات هجومية
    LEADS_TO = "leads_to"
    EXPLOITS = "exploits"
    BYPASSES = "bypasses"
    TRIGGERS = "triggers"
    
    # علاقات معرفية
    IS_A = "is_a"
    INSTANCE_OF = "instance_of"
    SIMILAR_TO = "similar_to"
    
    # علاقات ثغرات
    HAS_VULNERABILITY = "has_vulnerability"
    AFFECTS = "affects"
    MITIGATES = "mitigates"


@dataclass
class GraphNode:
    """عقدة في الرسم البياني"""
    id: str
    label: str
    type: str  # vulnerability, attack, technique, target, etc.
    properties: Dict[str, Any]
    created_at: datetime
    updated_at: datetime
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class GraphEdge:
    """علاقة بين عقدتين"""
    id: str
    source_id: str
    target_id: str
    type: EdgeType
    weight: float  # 0-1, قوة العلاقة
    properties: Dict[str, Any]
    created_at: datetime
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class GraphPath:
    """مسار في الرسم البياني"""
    nodes: List[GraphNode]
    edges: List[GraphEdge]
    total_weight: float
    length: int


class GraphStore:
    """
    مخزن الرسم البياني المتقدم
    
    الميزات:
    - تخزين العقد والعلاقات
    - البحث عن المسارات بين العقد
    - تحليل الهجمات (attack graph analysis)
    - اكتشاف الأنماط (pattern detection)
    - خوارزميات الرسم البياني (BFS, DFS, Dijkstra)
    - تصدير بصيغ متعددة (GraphML, JSON)
    """
    
    def __init__(self, db_path: str = "./storage/graph_db/graph.db"):
        self._db_path = db_path
        self._write_lock = asyncio.Lock()
        
        # ذاكرة مؤقتة
        self._nodes_cache: Dict[str, GraphNode] = {}
        self._edges_cache: Dict[str, GraphEdge] = {}
        self._adjacency_cache: Dict[str, List[GraphEdge]] = defaultdict(list)
        
        # إنشاء المجلد
        import os
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        
        # تهيئة قاعدة البيانات
        self._init_database()
        
        # تحميل البيانات إلى الذاكرة المؤقتة
        asyncio.create_task(self._load_cache())
        
        logger.info(f"GraphStore initialized (db={db_path})")
    
    def _init_database(self):
        """تهيئة قاعدة البيانات"""
        conn = sqlite3.connect(self._db_path, timeout=30.0)
        cursor = conn.cursor()
        
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA synchronous=NORMAL")
        
        # جدول العقد
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS nodes (
                id TEXT PRIMARY KEY,
                label TEXT NOT NULL,
                type TEXT NOT NULL,
                properties TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                metadata TEXT
            )
        ''')
        
        # جدول العلاقات
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS edges (
                id TEXT PRIMARY KEY,
                source_id TEXT NOT NULL,
                target_id TEXT NOT NULL,
                type TEXT NOT NULL,
                weight REAL DEFAULT 1.0,
                properties TEXT,
                created_at TEXT NOT NULL,
                metadata TEXT,
                FOREIGN KEY (source_id) REFERENCES nodes(id),
                FOREIGN KEY (target_id) REFERENCES nodes(id)
            )
        ''')
        
        # جدول الفهارس للنص الكامل
        cursor.execute('''
            CREATE VIRTUAL TABLE IF NOT EXISTS nodes_fts USING fts5(
                id, label, type, properties
            )
        ''')
        
        # الفهارس
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_nodes_type ON nodes(type)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_edges_source ON edges(source_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_edges_target ON edges(target_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_edges_type ON edges(type)')
        
        conn.commit()
        conn.close()
        
        logger.info("Graph database initialized")
    
    async def _load_cache(self):
        """تحميل البيانات إلى الذاكرة المؤقتة"""
        # تحميل العقد
        query_nodes = "SELECT * FROM nodes"
        
        async with self._write_lock:
            conn = sqlite3.connect(self._db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(query_nodes)
            node_rows = cursor.fetchall()
            
            for row in node_rows:
                node = GraphNode(
                    id=row["id"],
                    label=row["label"],
                    type=row["type"],
                    properties=json.loads(row["properties"]) if row["properties"] else {},
                    created_at=datetime.fromisoformat(row["created_at"]),
                    updated_at=datetime.fromisoformat(row["updated_at"]),
                    metadata=json.loads(row["metadata"]) if row["metadata"] else {}
                )
                self._nodes_cache[node.id] = node
            
            # تحميل العلاقات
            query_edges = "SELECT * FROM edges"
            cursor.execute(query_edges)
            edge_rows = cursor.fetchall()
            
            for row in edge_rows:
                edge = GraphEdge(
                    id=row["id"],
                    source_id=row["source_id"],
                    target_id=row["target_id"],
                    type=EdgeType(row["type"]),
                    weight=row["weight"],
                    properties=json.loads(row["properties"]) if row["properties"] else {},
                    created_at=datetime.fromisoformat(row["created_at"]),
                    metadata=json.loads(row["metadata"]) if row["metadata"] else {}
                )
                self._edges_cache[edge.id] = edge
                self._adjacency_cache[edge.source_id].append(edge)
            
            conn.close()
        
        logger.info(f"Loaded {len(self._nodes_cache)} nodes and {len(self._edges_cache)} edges")
    
    async def add_node(
        self,
        label: str,
        node_type: str,
        properties: Dict[str, Any] = None,
        metadata: Dict[str, Any] = None
    ) -> str:
        """
        إضافة عقدة جديدة
        
        Returns:
            معرف العقدة
        """
        import uuid
        node_id = str(uuid.uuid4())
        now = datetime.now().isoformat()
        
        query = '''
            INSERT INTO nodes (id, label, type, properties, created_at, updated_at, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        '''
        
        params = (
            node_id, label, node_type,
            json.dumps(properties) if properties else None,
            now, now,
            json.dumps(metadata) if metadata else None
        )
        
        async with self._write_lock:
            conn = sqlite3.connect(self._db_path)
            cursor = conn.cursor()
            cursor.execute(query, params)
            
            # تحديث فهرس النص الكامل
            cursor.execute(
                "INSERT INTO nodes_fts (id, label, type, properties) VALUES (?, ?, ?, ?)",
                (node_id, label, node_type, json.dumps(properties) if properties else None)
            )
            
            conn.commit()
            conn.close()
        
        # تحديث الذاكرة المؤقتة
        node = GraphNode(
            id=node_id,
            label=label,
            type=node_type,
            properties=properties or {},
            created_at=datetime.fromisoformat(now),
            updated_at=datetime.fromisoformat(now),
            metadata=metadata or {}
        )
        self._nodes_cache[node_id] = node
        
        logger.debug(f"Node added: {label} ({node_type}) id={node_id[:8]}")
        return node_id
    
    async def add_edge(
        self,
        source_id: str,
        target_id: str,
        edge_type: EdgeType,
        weight: float = 1.0,
        properties: Dict[str, Any] = None,
        metadata: Dict[str, Any] = None
    ) -> str:
        """
        إضافة علاقة بين عقدتين
        
        Args:
            source_id: معرف العقدة المصدر
            target_id: معرف العقدة الهدف
            edge_type: نوع العلاقة
            weight: وزن العلاقة (0-1)
        """
        # التحقق من وجود العقد
        if source_id not in self._nodes_cache:
            raise ValueError(f"Source node {source_id} not found")
        if target_id not in self._nodes_cache:
            raise ValueError(f"Target node {target_id} not found")
        
        import uuid
        edge_id = str(uuid.uuid4())
        now = datetime.now().isoformat()
        
        query = '''
            INSERT INTO edges (id, source_id, target_id, type, weight, properties, created_at, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        '''
        
        params = (
            edge_id, source_id, target_id, edge_type.value, weight,
            json.dumps(properties) if properties else None,
            now,
            json.dumps(metadata) if metadata else None
        )
        
        async with self._write_lock:
            conn = sqlite3.connect(self._db_path)
            cursor = conn.cursor()
            cursor.execute(query, params)
            conn.commit()
            conn.close()
        
        # تحديث الذاكرة المؤقتة
        edge = GraphEdge(
            id=edge_id,
            source_id=source_id,
            target_id=target_id,
            type=edge_type,
            weight=weight,
            properties=properties or {},
            created_at=datetime.fromisoformat(now),
            metadata=metadata or {}
        )
        self._edges_cache[edge_id] = edge
        self._adjacency_cache[source_id].append(edge)
        
        logger.debug(f"Edge added: {source_id[:8]} -{edge_type.value}-> {target_id[:8]}")
        return edge_id
    
    async def get_node(self, node_id: str) -> Optional[GraphNode]:
        """الحصول على عقدة بالمعرف"""
        return self._nodes_cache.get(node_id)
    
    async def get_edge(self, edge_id: str) -> Optional[GraphEdge]:
        """الحصول على علاقة بالمعرف"""
        return self._edges_cache.get(edge_id)
    
    async def get_neighbors(
        self,
        node_id: str,
        edge_type: Optional[EdgeType] = None
    ) -> List[Tuple[GraphNode, GraphEdge]]:
        """الحصول على جيران العقدة"""
        neighbors = []
        
        for edge in self._adjacency_cache.get(node_id, []):
            if edge_type and edge.type != edge_type:
                continue
            
            target = self._nodes_cache.get(edge.target_id)
            if target:
                neighbors.append((target, edge))
        
        return neighbors
    
    async def find_path(
        self,
        start_id: str,
        end_id: str,
        max_depth: int = 10
    ) -> Optional[GraphPath]:
        """
        البحث عن مسار بين عقدتين باستخدام BFS
        
        Args:
            start_id: معرف العقدة البداية
            end_id: معرف العقدة النهاية
            max_depth: أقصى عمق للبحث
        
        Returns:
            المسار أو None
        """
        if start_id not in self._nodes_cache or end_id not in self._nodes_cache:
            return None
        
        # BFS
        queue = [(start_id, [start_id], [], 1.0)]
        visited = {start_id}
        
        while queue:
            current_id, path_nodes, path_edges, total_weight = queue.pop(0)
            
            if len(path_nodes) > max_depth:
                continue
            
            for edge in self._adjacency_cache.get(current_id, []):
                neighbor_id = edge.target_id
                
                if neighbor_id == end_id:
                    # وجدنا المسار
                    complete_nodes = [self._nodes_cache[nid] for nid in path_nodes + [neighbor_id]]
                    complete_edges = path_edges + [edge]
                    return GraphPath(
                        nodes=complete_nodes,
                        edges=complete_edges,
                        total_weight=total_weight * edge.weight,
                        length=len(complete_edges)
                    )
                
                if neighbor_id not in visited:
                    visited.add(neighbor_id)
                    queue.append((
                        neighbor_id,
                        path_nodes + [neighbor_id],
                        path_edges + [edge],
                        total_weight * edge.weight
                    ))
        
        return None
    
    async def find_all_paths(
        self,
        start_id: str,
        end_id: str,
        max_depth: int = 5
    ) -> List[GraphPath]:
        """البحث عن جميع المسارات بين عقدتين"""
        if start_id not in self._nodes_cache or end_id not in self._nodes_cache:
            return []
        
        paths = []
        
        def dfs(current_id, path_nodes, path_edges, total_weight):
            if len(path_nodes) > max_depth:
                return
            
            for edge in self._adjacency_cache.get(current_id, []):
                neighbor_id = edge.target_id
                
                if neighbor_id in path_nodes:
                    continue  # تجنب الدورات
                
                if neighbor_id == end_id:
                    complete_nodes = [self._nodes_cache[nid] for nid in path_nodes + [neighbor_id]]
                    complete_edges = path_edges + [edge]
                    paths.append(GraphPath(
                        nodes=complete_nodes,
                        edges=complete_edges,
                        total_weight=total_weight * edge.weight,
                        length=len(complete_edges)
                    ))
                else:
                    dfs(neighbor_id, path_nodes + [neighbor_id], path_edges + [edge], total_weight * edge.weight)
        
        dfs(start_id, [start_id], [], 1.0)
        
        # ترتيب حسب الوزن (أعلى أولاً)
        paths.sort(key=lambda p: p.total_weight, reverse=True)
        return paths
    
    async def get_attack_chains(
        self,
        target_type: str = None,
        min_success_rate: float = 0.0
    ) -> List[GraphPath]:
        """
        الحصول على سلاسل هجومية
        
        يبحث عن مسارات من نقطة دخول إلى هدف
        """
        # العثور على عقد الهجوم المحتملة
        attack_nodes = [
            node for node in self._nodes_cache.values()
            if node.type == "attack" or node.type == "vulnerability"
        ]
        
        target_nodes = [
            node for node in self._nodes_cache.values()
            if node.type == "target"
        ]
        
        if target_type:
            target_nodes = [n for n in target_nodes if n.properties.get("type") == target_type]
        
        attack_chains = []
        
        for attack_node in attack_nodes:
            for target_node in target_nodes:
                path = await self.find_path(attack_node.id, target_node.id)
                if path and path.total_weight >= min_success_rate:
                    attack_chains.append(path)
        
        # ترتيب حسب الوزن (أعلى احتمالية نجاح أولاً)
        attack_chains.sort(key=lambda p: p.total_weight, reverse=True)
        return attack_chains
    
    async def detect_patterns(self, min_support: int = 2) -> List[Dict]:
        """
        اكتشاف الأنماط المتكررة في الرسم البياني
        
        باستخدام خوارزمية اكتشاف الأنماط البسيطة (Apriori-like)
        """
        patterns = []
        
        # جمع جميع العلاقات الفريدة
        edge_counts = defaultdict(int)
        for edge in self._edges_cache.values():
            key = f"{edge.source_id}:{edge.type.value}:{edge.target_id}"
            edge_counts[key] += 1
        
        # الأنماط المتكررة (مثلثات بسيطة)
        # هذا مبسط - يمكن توسيعه ليشمل أنماط أكثر تعقيداً
        
        return patterns
    
    async def search_by_label(self, query: str, limit: int = 50) -> List[GraphNode]:
        """البحث عن عقد حسب التسمية (نص كامل)"""
        # استخدام فهرس FTS5 للبحث السريع
        sql_query = '''
            SELECT id FROM nodes_fts 
            WHERE nodes_fts MATCH ? 
            ORDER BY rank
            LIMIT ?
        '''
        
        async with self._write_lock:
            conn = sqlite3.connect(self._db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(sql_query, (f"label:{query}* OR type:{query}*", limit))
            rows = cursor.fetchall()
            conn.close()
        
        return [self._nodes_cache[row["id"]] for row in rows if row["id"] in self._nodes_cache]
    
    async def update_node(self, node_id: str, properties: Dict[str, Any] = None, metadata: Dict[str, Any] = None) -> bool:
        """تحديث عقدة"""
        if node_id not in self._nodes_cache:
            return False
        
        now = datetime.now().isoformat()
        
        # جلب البيانات الحالية
        node = self._nodes_cache[node_id]
        
        # تحديث الخصائص
        if properties:
            node.properties.update(properties)
        if metadata:
            node.metadata.update(metadata)
        
        node.updated_at = datetime.fromisoformat(now)
        
        query = '''
            UPDATE nodes 
            SET properties = ?, metadata = ?, updated_at = ?
            WHERE id = ?
        '''
        
        params = (
            json.dumps(node.properties),
            json.dumps(node.metadata),
            now,
            node_id
        )
        
        async with self._write_lock:
            conn = sqlite3.connect(self._db_path)
            cursor = conn.cursor()
            cursor.execute(query, params)
            
            # تحديث فهرس النص الكامل
            cursor.execute(
                "UPDATE nodes_fts SET properties = ? WHERE id = ?",
                (json.dumps(node.properties), node_id)
            )
            
            conn.commit()
            conn.close()
        
        return True
    
    async def delete_node(self, node_id: str, cascade: bool = True) -> bool:
        """
        حذف عقدة
        
        Args:
            node_id: معرف العقدة
            cascade: حذف العلاقات المرتبطة أيضاً
        """
        if node_id not in self._nodes_cache:
            return False
        
        if cascade:
            # حذف جميع العلاقات المرتبطة
            edge_ids_to_delete = [
                edge.id for edge in self._edges_cache.values()
                if edge.source_id == node_id or edge.target_id == node_id
            ]
            
            for edge_id in edge_ids_to_delete:
                await self.delete_edge(edge_id)
        
        query = "DELETE FROM nodes WHERE id = ?"
        
        async with self._write_lock:
            conn = sqlite3.connect(self._db_path)
            cursor = conn.cursor()
            cursor.execute(query, (node_id,))
            cursor.execute("DELETE FROM nodes_fts WHERE id = ?", (node_id,))
            conn.commit()
            conn.close()
        
        # إزالة من الذاكرة المؤقتة
        del self._nodes_cache[node_id]
        
        logger.debug(f"Node deleted: {node_id[:8]}")
        return True
    
    async def delete_edge(self, edge_id: str) -> bool:
        """حذف علاقة"""
        if edge_id not in self._edges_cache:
            return False
        
        query = "DELETE FROM edges WHERE id = ?"
        
        async with self._write_lock:
            conn = sqlite3.connect(self._db_path)
            cursor = conn.cursor()
            cursor.execute(query, (edge_id,))
            conn.commit()
            conn.close()
        
        # إزالة من الذاكرة المؤقتة
        edge = self._edges_cache[edge_id]
        del self._edges_cache[edge_id]
        
        # إزالة من قائمة الجوار
        if edge.source_id in self._adjacency_cache:
            self._adjacency_cache[edge.source_id] = [
                e for e in self._adjacency_cache[edge.source_id]
                if e.id != edge_id
            ]
        
        logger.debug(f"Edge deleted: {edge_id[:8]}")
        return True
    
    async def get_statistics(self) -> Dict:
        """إحصائيات الرسم البياني"""
        # درجة العقد
        degrees = defaultdict(int)
        for edge in self._edges_cache.values():
            degrees[edge.source_id] += 1
        
        if degrees:
            avg_degree = sum(degrees.values()) / len(degrees)
            max_degree = max(degrees.values())
        else:
            avg_degree = 0
            max_degree = 0
        
        return {
            "total_nodes": len(self._nodes_cache),
            "total_edges": len(self._edges_cache),
            "node_types": {
                t: sum(1 for n in self._nodes_cache.values() if n.type == t)
                for t in set(n.type for n in self._nodes_cache.values())
            },
            "edge_types": {
                t.value: sum(1 for e in self._edges_cache.values() if e.type == t)
                for t in EdgeType
            },
            "avg_degree": avg_degree,
            "max_degree": max_degree,
            "density": (2 * len(self._edges_cache)) / (len(self._nodes_cache) * (len(self._nodes_cache) - 1)) if len(self._nodes_cache) > 1 else 0
        }
    
    async def export_to_json(self, filepath: str):
        """تصدير الرسم البياني إلى JSON"""
        export_data = {
            "nodes": [
                {
                    "id": node.id,
                    "label": node.label,
                    "type": node.type,
                    "properties": node.properties,
                    "created_at": node.created_at.isoformat(),
                    "metadata": node.metadata
                }
                for node in self._nodes_cache.values()
            ],
            "edges": [
                {
                    "id": edge.id,
                    "source": edge.source_id,
                    "target": edge.target_id,
                    "type": edge.type.value,
                    "weight": edge.weight,
                    "properties": edge.properties,
                    "created_at": edge.created_at.isoformat()
                }
                for edge in self._edges_cache.values()
            ],
            "statistics": await self.get_statistics()
        }
        
        with open(filepath, "w") as f:
            json.dump(export_data, f, indent=2)
        
        logger.info(f"Graph exported to {filepath}")


# نسخة عالمية
_default_store = None


async def get_graph_store() -> GraphStore:
    """الحصول على نسخة عالمية من مخزن الرسم البياني"""
    global _default_store
    if _default_store is None:
        _default_store = GraphStore()
    return _default_store

