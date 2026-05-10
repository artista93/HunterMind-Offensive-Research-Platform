
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from collections import defaultdict

import logging

logger = logging.getLogger(__name__)


@dataclass
class KGNode:
    """عقدة في الرسم البياني المعرفي"""
    id: str
    type: str
    name: str
    properties: Dict[str, Any]
    created_at: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class KGEdge:
    """علاقة بين عقدتين"""
    source: str
    target: str
    relation: str
    weight: float = 1.0
    properties: Dict[str, Any] = field(default_factory=dict)


class KnowledgeGraph:
    """
    الرسم البياني المعرفي المتقدم
    
    الميزات:
    - تخزين المعرفة كعقد وعلاقات
    - استعلامات متقدمة
    - استدلال على العلاقات
    - كشف الأنماط
    """
    
    def __init__(self):
        self._nodes: Dict[str, KGNode] = {}
        self._edges: List[KGEdge] = []
        self._adjacency: Dict[str, List[KGEdge]] = defaultdict(list)
        self._reverse_adjacency: Dict[str, List[KGEdge]] = defaultdict(list)
        
        logger.info("KnowledgeGraph initialized")
    
    async def add_node(
        self,
        node_id: str,
        node_type: str,
        name: str,
        properties: Dict = None,
        metadata: Dict = None
    ):
        """
        إضافة عقدة جديدة
        
        Args:
            node_id: معرف العقدة
            node_type: نوع العقدة
            name: اسم العقدة
            properties: خصائص العقدة
            metadata: بيانات إضافية
        """
        if node_id in self._nodes:
            logger.warning(f"Node {node_id} already exists")
            return
        
        node = KGNode(
            id=node_id,
            type=node_type,
            name=name,
            properties=properties or {},
            metadata=metadata or {}
        )
        
        self._nodes[node_id] = node
        
        logger.debug(f"Node added: {node_id} ({node_type})")
    
    async def add_edge(
        self,
        source: str,
        target: str,
        relation: str,
        weight: float = 1.0,
        properties: Dict = None
    ) -> bool:
        """
        إضافة علاقة بين عقدتين
        
        Args:
            source: معرف العقدة المصدر
            target: معرف العقدة الهدف
            relation: نوع العلاقة
            weight: وزن العلاقة
            properties: خصائص إضافية
        
        Returns:
            نجاح العملية
        """
        if source not in self._nodes or target not in self._nodes:
            logger.warning(f"Source or target node not found: {source} -> {target}")
            return False
        
        edge = KGEdge(
            source=source,
            target=target,
            relation=relation,
            weight=weight,
            properties=properties or {}
        )
        
        self._edges.append(edge)
        self._adjacency[source].append(edge)
        self._reverse_adjacency[target].append(edge)
        
        logger.debug(f"Edge added: {source} -{relation}-> {target}")
        return True
    
    async def get_node(self, node_id: str) -> Optional[KGNode]:
        """الحصول على عقدة بالمعرف"""
        return self._nodes.get(node_id)
    
    async def get_nodes_by_type(self, node_type: str) -> List[KGNode]:
        """الحصول على جميع العقد من نوع معين"""
        return [node for node in self._nodes.values() if node.type == node_type]
    
    async def get_neighbors(
        self,
        node_id: str,
        relation: str = None,
        direction: str = "outgoing"
    ) -> List[Tuple[KGNode, KGEdge]]:
        """
        الحصول على جيران عقدة معينة
        
        Args:
            node_id: معرف العقدة
            relation: نوع العلاقة (اختياري)
            direction: اتجاه العلاقة (outgoing/incoming/both)
        
        Returns:
            قائمة بالجيران والعلاقات
        """
        neighbors = []
        
        # outgoing edges
        if direction in ["outgoing", "both"]:
            for edge in self._adjacency.get(node_id, []):
                if relation is None or edge.relation == relation:
                    target_node = self._nodes.get(edge.target)
                    if target_node:
                        neighbors.append((target_node, edge))
        
        # incoming edges
        if direction in ["incoming", "both"]:
            for edge in self._reverse_adjacency.get(node_id, []):
                if relation is None or edge.relation == relation:
                    source_node = self._nodes.get(edge.source)
                    if source_node:
                        neighbors.append((source_node, edge))
        
        return neighbors
    
    async def query(
        self,
        start_node: str,
        max_depth: int = 3,
        relation_filter: str = None
    ) -> List[List[Tuple[KGNode, KGEdge]]]:
        """
        استعلام BFS على الرسم البياني
        
        Args:
            start_node: معرف عقدة البداية
            max_depth: أقصى عمق
            relation_filter: تصفية العلاقات
        
        Returns:
            قائمة بالمسارات
        """
        if start_node not in self._nodes:
            return []
        
        paths = []
        queue = [(start_node, [])]
        visited = set()
        
        while queue and len(paths) < 100:
            current, path = queue.pop(0)
            
            if current in visited:
                continue
            
            visited.add(current)
            
            # استكشاف الجيران
            for edge in self._adjacency.get(current, []):
                if relation_filter and edge.relation != relation_filter:
                    continue
                
                new_path = path + [(self._nodes[current], edge)]
                paths.append(new_path + [(self._nodes[edge.target], None)])
                
                if len(new_path) < max_depth:
                    queue.append((edge.target, new_path))
        
        return paths[:100]
    
    async def find_path(
        self,
        source: str,
        target: str,
        max_depth: int = 5
    ) -> Optional[List[Tuple[KGNode, KGEdge]]]:
        """
        البحث عن مسار بين عقدتين
        
        Args:
            source: معرف عقدة البداية
            target: معرف عقدة النهاية
            max_depth: أقصى عمق
        
        Returns:
            المسار أو None
        """
        if source not in self._nodes or target not in self._nodes:
            return None
        
        queue = [(source, [])]
        visited = {source}
        
        while queue:
            current, path = queue.pop(0)
            
            if current == target:
                return path
            
            if len(path) >= max_depth:
                continue
            
            for edge in self._adjacency.get(current, []):
                if edge.target not in visited:
                    visited.add(edge.target)
                    new_path = path + [(self._nodes[current], edge)]
                    queue.append((edge.target, new_path))
        
        return None
    
    async def get_statistics(self) -> Dict:
        """إحصائيات الرسم البياني"""
        total_nodes = len(self._nodes)
        total_edges = len(self._edges)
        
        # توزيع أنواع العقد
        node_types = {}
        for node in self._nodes.values():
            node_types[node.type] = node_types.get(node.type, 0) + 1
        
        # توزيع أنواع العلاقات
        edge_relations = {}
        for edge in self._edges:
            edge_relations[edge.relation] = edge_relations.get(edge.relation, 0) + 1
        
        # درجة العقد
        degrees = {}
        for node_id in self._nodes:
            degrees[node_id] = len(self._adjacency.get(node_id, []))
        
        avg_degree = sum(degrees.values()) / len(degrees) if degrees else 0
        
        return {
            "total_nodes": total_nodes,
            "total_edges": total_edges,
            "node_types": node_types,
            "edge_relations": edge_relations,
            "average_degree": avg_degree,
            "max_degree": max(degrees.values()) if degrees else 0,
            "density": (2 * total_edges) / (total_nodes * (total_nodes - 1)) if total_nodes > 1 else 0
        }

