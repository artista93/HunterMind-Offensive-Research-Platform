
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from collections import defaultdict, deque

import logging

logger = logging.getLogger(__name__)


@dataclass
class GraphNode:
    """عقدة في الرسم البياني"""
    id: str
    type: str
    properties: Dict[str, Any]
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class GraphEdge:
    """علاقة بين عقدتين"""
    source: str
    target: str
    relation: str
    weight: float = 1.0
    properties: Dict[str, Any] = field(default_factory=dict)


@dataclass
class GraphPattern:
    """نمط في الرسم البياني"""
    nodes: List[GraphNode]
    edges: List[GraphEdge]
    frequency: int
    support: float
    metadata: Dict[str, Any] = field(default_factory=dict)


class GraphReasoner:
    """
    مفكر الرسوم البيانية المتقدم
    
    الميزات:
    - تحليل الرسوم البيانية المعرفية
    - اكتشاف الأنماط المتكررة
    - حساب مركزية العقد
    - اكتشاف المجتمعات
    - استخراج المسارات الحرجة
    """
    
    def __init__(self):
        self._nodes: Dict[str, GraphNode] = {}
        self._edges: List[GraphEdge] = []
        self._adjacency: Dict[str, List[GraphEdge]] = defaultdict(list)
        self._reverse_adjacency: Dict[str, List[GraphEdge]] = defaultdict(list)
        
        self._patterns: List[GraphPattern] = []
        
        logger.info("GraphReasoner initialized")
    
    async def add_node(
        self,
        node_id: str,
        node_type: str,
        properties: Dict = None
    ):
        """إضافة عقدة إلى الرسم البياني"""
        node = GraphNode(
            id=node_id,
            type=node_type,
            properties=properties or {}
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
    ):
        """إضافة علاقة بين عقدتين"""
        if source not in self._nodes or target not in self._nodes:
            logger.warning(f"Source or target node not found: {source} -> {target}")
            return
        
        edge = GraphEdge(
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
    
    async def find_patterns(self, min_support: int = 2) -> List[GraphPattern]:
        """
        اكتشاف الأنماط المتكررة في الرسم البياني
        
        Args:
            min_support: الحد الأدنى لدعم النمط
        
        Returns:
            قائمة بالأنماط المكتشفة
        """
        patterns = []
        
        # تجميع العقد حسب النوع
        nodes_by_type = defaultdict(list)
        for node in self._nodes.values():
            nodes_by_type[node.type].append(node)
        
        # البحث عن أنماط ثنائية (علاقات متكررة)
        relation_counts = defaultdict(int)
        for edge in self._edges:
            key = f"{self._nodes[edge.source].type}-{edge.relation}-{self._nodes[edge.target].type}"
            relation_counts[key] += 1
        
        for key, count in relation_counts.items():
            if count >= min_support:
                # تحليل النمط
                parts = key.split('-')
                source_type, relation, target_type = parts
                
                # إنشاء عقد وهمية للنمط
                source_node = GraphNode(
                    id=f"pattern_source",
                    type=source_type,
                    properties={}
                )
                target_node = GraphNode(
                    id=f"pattern_target",
                    type=target_type,
                    properties={}
                )
                edge = GraphEdge(
                    source="pattern_source",
                    target="pattern_target",
                    relation=relation
                )
                
                pattern = GraphPattern(
                    nodes=[source_node, target_node],
                    edges=[edge],
                    frequency=count,
                    support=count / len(self._edges) if self._edges else 0
                )
                
                patterns.append(pattern)
        
        self._patterns = patterns
        
        logger.info(f"Found {len(patterns)} patterns")
        return patterns
    
    async def calculate_centrality(self) -> Dict[str, float]:
        """
        حساب مركزية العقد (درجة الأهمية)
        
        Returns:
            قاموس بمركزية كل عقدة
        """
        centrality = {}
        
        for node_id in self._nodes:
            # درجة العقد
            degree = len(self._adjacency.get(node_id, [])) + len(self._reverse_adjacency.get(node_id, []))
            
            # وزن العلاقات
            total_weight = sum(e.weight for e in self._adjacency.get(node_id, []))
            total_weight += sum(e.weight for e in self._reverse_adjacency.get(node_id, []))
            
            # مركزية مركبة
            centrality[node_id] = degree * 0.5 + total_weight * 0.5
        
        # تطبيع
        max_centrality = max(centrality.values()) if centrality else 1
        for node_id in centrality:
            centrality[node_id] /= max_centrality
        
        return centrality
    
    async def find_communities(self) -> List[List[str]]:
        """
        اكتشاف المجتمعات (تجميع العقد) باستخدام خوارزمية BFS
        
        Returns:
            قائمة بالمجتمعات (كل مجتمع قائمة بالعقد)
        """
        visited = set()
        communities = []
        
        for node_id in self._nodes:
            if node_id not in visited:
                # BFS للعثور على المجتمع
                community = []
                queue = deque([node_id])
                visited.add(node_id)
                
                while queue:
                    current = queue.popleft()
                    community.append(current)
                    
                    for edge in self._adjacency.get(current, []):
                        if edge.target not in visited:
                            visited.add(edge.target)
                            queue.append(edge.target)
                    
                    for edge in self._reverse_adjacency.get(current, []):
                        if edge.source not in visited:
                            visited.add(edge.source)
                            queue.append(edge.source)
                
                communities.append(community)
        
        return communities
    
    async def find_critical_paths(
        self,
        start_type: str = None,
        end_type: str = None,
        max_depth: int = 5
    ) -> List[List[GraphEdge]]:
        """
        البحث عن المسارات الحرجة في الرسم البياني
        
        Args:
            start_type: نوع عقدة البداية
            end_type: نوع عقدة النهاية
            max_depth: أقصى عمق
        
        Returns:
            قائمة بالمسارات (كل مسار قائمة بالعلاقات)
        """
        # العثور على عقد البداية والنهاية
        start_nodes = [n for n in self._nodes.values() if not start_type or n.type == start_type]
        end_nodes = [n for n in self._nodes.values() if not end_type or n.type == end_type]
        
        paths = []
        
        for start in start_nodes:
            for end in end_nodes:
                if start.id == end.id:
                    continue
                
                # BFS للبحث عن مسار
                queue = [(start.id, [], 0)]
                visited = {start.id}
                
                while queue:
                    current, path, depth = queue.pop(0)
                    
                    if depth >= max_depth:
                        continue
                    
                    if current == end.id:
                        paths.append(path)
                        continue
                    
                    for edge in self._adjacency.get(current, []):
                        if edge.target not in visited:
                            visited.add(edge.target)
                            queue.append((edge.target, path + [edge], depth + 1))
        
        # ترتيب حسب الطول (أقصر أولاً)
        paths.sort(key=lambda x: len(x))
        
        return paths
    
    async def get_node_neighbors(
        self,
        node_id: str,
        relation: str = None
    ) -> List[Tuple[GraphNode, GraphEdge]]:
        """الحصول على جيران عقدة معينة"""
        neighbors = []
        
        for edge in self._adjacency.get(node_id, []):
            if relation is None or edge.relation == relation:
                target_node = self._nodes.get(edge.target)
                if target_node:
                    neighbors.append((target_node, edge))
        
        return neighbors
    
    async def get_graph_summary(self) -> Dict:
        """ملخص الرسم البياني"""
        centrality = await self.calculate_centrality()
        communities = await self.find_communities()
        
        return {
            "total_nodes": len(self._nodes),
            "total_edges": len(self._edges),
            "node_types": {
                node.type: len([n for n in self._nodes.values() if n.type == node.type])
                for node in self._nodes.values()
            },
            "relation_types": {
                edge.relation: len([e for e in self._edges if e.relation == edge.relation])
                for edge in self._edges
            },
            "average_degree": (2 * len(self._edges)) / len(self._nodes) if self._nodes else 0,
            "density": (2 * len(self._edges)) / (len(self._nodes) * (len(self._nodes) - 1)) if len(self._nodes) > 1 else 0,
            "communities_count": len(communities),
            "top_central_nodes": sorted(centrality.items(), key=lambda x: x[1], reverse=True)[:5]
        }
    
    async def get_statistics(self) -> Dict:
        """إحصائيات المفكر"""
        return {
            "total_nodes": len(self._nodes),
            "total_edges": len(self._edges),
            "patterns_found": len(self._patterns),
            "communities_found": len(await self.find_communities()),
            "density": (2 * len(self._edges)) / (len(self._nodes) * (len(self._nodes) - 1)) if len(self._nodes) > 1 else 0
        }

