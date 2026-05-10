
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from collections import deque, defaultdict

import logging

logger = logging.getLogger(__name__)


@dataclass
class GraphNode:
    """عقدة في رسم بياني التنفيذ"""
    id: str
    name: str
    dependencies: List[str]
    status: str = "pending"
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    result: Any = None
    error: Optional[str] = None


class ExecutionGraph:
    """
    رسم بياني للتنفيذ المتقدم
    
    الميزات:
    - تمثيل المهام والتبعيات كرسم بياني
    - اكتشاف الدورات
    - الترتيب الطوبولوجي
    - تنفيذ متوازي للمهام المستقلة
    """
    
    def __init__(self):
        self.nodes: Dict[str, GraphNode] = {}
        self.adjacency: Dict[str, List[str]] = defaultdict(list)
        self.reverse_adjacency: Dict[str, List[str]] = defaultdict(list)
        
        logger.info("ExecutionGraph initialized")
    
    def add_node(self, node_id: str, name: str, dependencies: List[str] = None):
        """
        إضافة عقدة جديدة
        
        Args:
            node_id: معرف العقدة
            name: اسم العقدة
            dependencies: قائمة التبعيات
        """
        if node_id in self.nodes:
            logger.warning(f"Node {node_id} already exists")
            return
        
        node = GraphNode(
            id=node_id,
            name=name,
            dependencies=dependencies or []
        )
        
        self.nodes[node_id] = node
        
        # تحديث علاقات الجوار
        for dep in node.dependencies:
            self.adjacency[dep].append(node_id)
            self.reverse_adjacency[node_id].append(dep)
        
        logger.debug(f"Node added: {name} ({node_id})")
    
    def detect_cycles(self) -> List[List[str]]:
        """
        اكتشاف الدورات في الرسم البياني
        
        Returns:
            قائمة بالدورات المكتشفة
        """
        visited = set()
        rec_stack = set()
        cycles = []
        
        def dfs(node: str, path: List[str]) -> bool:
            visited.add(node)
            rec_stack.add(node)
            path.append(node)
            
            for neighbor in self.adjacency.get(node, []):
                if neighbor not in visited:
                    if dfs(neighbor, path):
                        return True
                elif neighbor in rec_stack:
                    # تم اكتشاف دورة
                    cycle_start = path.index(neighbor)
                    cycles.append(path[cycle_start:] + [neighbor])
                    return True
            
            rec_stack.remove(node)
            path.pop()
            return False
        
        for node in self.nodes:
            if node not in visited:
                dfs(node, [])
        
        return cycles
    
    def topological_sort(self) -> List[str]:
        """
        ترتيب طوبولوجي للعقد
        
        Returns:
            قائمة بالعقد بالترتيب الصحيح
        """
        # حساب درجات الدخول
        in_degree = {node: 0 for node in self.nodes}
        for node in self.nodes:
            for neighbor in self.adjacency.get(node, []):
                in_degree[neighbor] += 1
        
        # قائمة انتظار للعقد بدون تبعيات
        queue = deque([node for node, degree in in_degree.items() if degree == 0])
        sorted_nodes = []
        
        while queue:
            node = queue.popleft()
            sorted_nodes.append(node)
            
            for neighbor in self.adjacency.get(node, []):
                in_degree[neighbor] -= 1
                if in_degree[neighbor] == 0:
                    queue.append(neighbor)
        
        if len(sorted_nodes) != len(self.nodes):
            raise ValueError("Graph contains cycles")
        
        return sorted_nodes
    
    def get_parallel_groups(self) -> List[List[str]]:
        """
        تجميع العقد التي يمكن تنفيذها بشكل متوازي
        
        Returns:
            قائمة بمجموعات العقد المتوازية
        """
        sorted_nodes = self.topological_sort()
        groups = []
        processed = set()
        
        for node in sorted_nodes:
            if node in processed:
                continue
            
            # تجميع العقد التي ليس لها تبعيات متبادلة
            group = [node]
            processed.add(node)
            
            for other in sorted_nodes:
                if other in processed:
                    continue
                
                # التحقق من عدم وجود تبعيات بين node و other
                if (other not in self.reverse_adjacency.get(node, []) and
                    node not in self.reverse_adjacency.get(other, [])):
                    group.append(other)
                    processed.add(other)
            
            groups.append(group)
        
        return groups
    
    def get_critical_path(self) -> List[str]:
        """
        الحصول على المسار الحرج (أطول مسار)
        
        Returns:
            قائمة بالعقد في المسار الحرج
        """
        # ترتيب طوبولوجي
        sorted_nodes = self.topological_sort()
        
        # حساب أطول مسار
        longest_path = {node: 1 for node in self.nodes}
        predecessor = {node: None for node in self.nodes}
        
        for node in sorted_nodes:
            for neighbor in self.adjacency.get(node, []):
                if longest_path[node] + 1 > longest_path[neighbor]:
                    longest_path[neighbor] = longest_path[node] + 1
                    predecessor[neighbor] = node
        
        # العثور على نهاية أطول مسار
        end_node = max(longest_path, key=longest_path.get)
        
        # بناء المسار
        path = []
        current = end_node
        while current is not None:
            path.insert(0, current)
            current = predecessor[current]
        
        return path
    
    def update_status(self, node_id: str, status: str, result: Any = None, error: str = None):
        """
        تحديث حالة عقدة
        
        Args:
            node_id: معرف العقدة
            status: الحالة الجديدة
            result: نتيجة التنفيذ
            error: رسالة خطأ
        """
        if node_id not in self.nodes:
            logger.warning(f"Node {node_id} not found")
            return
        
        node = self.nodes[node_id]
        node.status = status
        
        if status == "running":
            node.start_time = datetime.now()
        elif status in ["completed", "failed"]:
            node.end_time = datetime.now()
        
        if result is not None:
            node.result = result
        
        if error is not None:
            node.error = error
        
        logger.debug(f"Node {node.name} status updated to {status}")
    
    def get_ready_nodes(self) -> List[GraphNode]:
        """
        الحصول على العقد الجاهزة للتنفيذ
        
        Returns:
            قائمة بالعقد الجاهزة
        """
        ready = []
        
        for node in self.nodes.values():
            if node.status != "pending":
                continue
            
            # التحقق من اكتمال جميع التبعيات
            deps_complete = all(
                self.nodes[dep].status == "completed"
                for dep in node.dependencies if dep in self.nodes
            )
            
            if deps_complete:
                ready.append(node)
        
        return ready
    
    def get_statistics(self) -> Dict:
        """إحصائيات الرسم البياني"""
        total_nodes = len(self.nodes)
        completed = len([n for n in self.nodes.values() if n.status == "completed"])
        failed = len([n for n in self.nodes.values() if n.status == "failed"])
        
        cycles = self.detect_cycles()
        
        return {
            "total_nodes": total_nodes,
            "completed_nodes": completed,
            "failed_nodes": failed,
            "pending_nodes": total_nodes - completed - failed,
            "completion_rate": completed / total_nodes if total_nodes > 0 else 0,
            "cycles_detected": len(cycles),
            "parallel_groups": len(self.get_parallel_groups()),
            "critical_path_length": len(self.get_critical_path())
        }

