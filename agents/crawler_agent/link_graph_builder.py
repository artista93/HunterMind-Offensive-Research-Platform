
import json
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from collections import defaultdict, deque
from enum import Enum

import logging

logger = logging.getLogger(__name__)


class LinkType(Enum):
    """نوع الرابط"""
    INTERNAL = "internal"
    EXTERNAL = "external"
    STATIC = "static"  # صور، CSS، JS
    API = "api"
    FORM = "form"
    DOWNLOAD = "download"


@dataclass
class Link:
    """رابط بين الصفحات"""
    source: str
    target: str
    link_type: LinkType
    anchor_text: Optional[str] = None
    depth: int = 0
    discovered_at: datetime = field(default_factory=datetime.now)


@dataclass
class PageNode:
    """عقدة صفحة في الرسم البياني"""
    url: str
    title: str
    depth: int
    status_code: int
    content_type: str
    discovered_at: datetime
    incoming_links: List[str] = field(default_factory=list)
    outgoing_links: List[Link] = field(default_factory=list)
    forms: List[Dict] = field(default_factory=list)
    api_endpoints: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


class LinkGraphBuilder:
    """
    بناء رسم بياني للروابط
    
    الميزات:
    - بناء رسم بياني للروابط بين الصفحات
    - تحليل بنية الموقع
    - اكتشاف الصفحات المعزولة
    - العثور على أقصر المسارات
    - تحليل التأثير (page rank)
    - اكتشاف الحلقات (cycles)
    """
    
    def __init__(self):
        self._nodes: Dict[str, PageNode] = {}
        self._links: List[Link] = []
        self._build_time: Optional[datetime] = None
        
        logger.info("LinkGraphBuilder initialized")
    
    def add_page(
        self,
        url: str,
        title: str,
        depth: int,
        status_code: int,
        content_type: str,
        links: List[str] = None,
        forms: List[Dict] = None,
        api_endpoints: List[str] = None
    ) -> PageNode:
        """
        إضافة صفحة إلى الرسم البياني
        
        Args:
            url: رابط الصفحة
            title: عنوان الصفحة
            depth: العمق
            status_code: كود الحالة
            content_type: نوع المحتوى
            links: قائمة الروابط
            forms: قائمة النماذج
            api_endpoints: قائمة واجهات API
        
        Returns:
            عقدة الصفحة
        """
        # إنشاء العقدة
        node = PageNode(
            url=url,
            title=title,
            depth=depth,
            status_code=status_code,
            content_type=content_type,
            discovered_at=datetime.now(),
            forms=forms or [],
            api_endpoints=api_endpoints or []
        )
        
        self._nodes[url] = node
        
        # إضافة الروابط الخارجة
        if links:
            for target_url in links:
                link_type = self._classify_link(url, target_url)
                link = Link(
                    source=url,
                    target=target_url,
                    link_type=link_type,
                    depth=depth + 1
                )
                node.outgoing_links.append(link)
                self._links.append(link)
                
                # إضافة الرابط الوارد للعقدة الهدف
                if target_url in self._nodes:
                    self._nodes[target_url].incoming_links.append(url)
        
        logger.debug(f"Added page: {url} (depth={depth}, links={len(links or [])})")
        return node
    
    def _classify_link(self, source: str, target: str) -> LinkType:
        """تصنيف نوع الرابط"""
        from urllib.parse import urlparse
        
        source_parsed = urlparse(source)
        target_parsed = urlparse(target)
        
        # روابط API
        if "/api/" in target or target.endswith(".json") or target.endswith(".yaml"):
            return LinkType.API
        
        # ملفات ثابتة
        static_extensions = ['.jpg', '.jpeg', '.png', '.gif', '.svg', '.css', '.js', '.ico']
        if any(target.lower().endswith(ext) for ext in static_extensions):
            return LinkType.STATIC
        
        # روابط تحميل
        download_extensions = ['.pdf', '.zip', '.tar', '.gz', '.exe', '.msi', '.dmg']
        if any(target.lower().endswith(ext) for ext in download_extensions):
            return LinkType.DOWNLOAD
        
        # روابط خارجية
        if source_parsed.netloc != target_parsed.netloc and target_parsed.netloc:
            return LinkType.EXTERNAL
        
        return LinkType.INTERNAL
    
    def get_node(self, url: str) -> Optional[PageNode]:
        """الحصول على عقدة بالرابط"""
        return self._nodes.get(url)
    
    def get_all_nodes(self) -> List[PageNode]:
        """الحصول على جميع العقد"""
        return list(self._nodes.values())
    
    def get_internal_links(self) -> List[Link]:
        """الحصول على الروابط الداخلية فقط"""
        return [l for l in self._links if l.link_type == LinkType.INTERNAL]
    
    def get_external_links(self) -> List[Link]:
        """الحصول على الروابط الخارجية فقط"""
        return [l for l in self._links if l.link_type == LinkType.EXTERNAL]
    
    def get_orphan_pages(self) -> List[str]:
        """
        الحصول على الصفحات المعزولة (لا توجد روابط واردة إليها)
        
        Returns:
            قائمة بالروابط المعزولة
        """
        orphans = []
        for url, node in self._nodes.items():
            if not node.incoming_links and node.depth > 0:
                orphans.append(url)
        return orphans
    
    def find_cycles(self) -> List[List[str]]:
        """
        اكتشاف الحلقات (cycles) في الرسم البياني
        
        Returns:
            قائمة بالمسارات الدائرية
        """
        cycles = []
        visited = set()
        path_stack = []
        
        def dfs(node: str, path: List[str]):
            if node in path_stack:
                # تم اكتشاف حلقة
                cycle_start = path_stack.index(node)
                cycle = path_stack[cycle_start:] + [node]
                cycles.append(cycle)
                return
            
            if node in visited:
                return
            
            visited.add(node)
            path_stack.append(node)
            
            if node in self._nodes:
                for link in self._nodes[node].outgoing_links:
                    if link.link_type == LinkType.INTERNAL:
                        dfs(link.target, path)
            
            path_stack.pop()
        
        for url in self._nodes:
            dfs(url, [])
        
        return cycles
    
    def find_shortest_path(self, start_url: str, end_url: str) -> Optional[List[str]]:
        """
        العثور على أقصر مسار بين صفحتين (BFS)
        
        Args:
            start_url: رابط البداية
            end_url: رابط النهاية
        
        Returns:
            قائمة بالروابط أو None
        """
        if start_url not in self._nodes or end_url not in self._nodes:
            return None
        
        queue = deque([(start_url, [start_url])])
        visited = {start_url}
        
        while queue:
            current, path = queue.popleft()
            
            if current == end_url:
                return path
            
            if current in self._nodes:
                for link in self._nodes[current].outgoing_links:
                    if link.link_type == LinkType.INTERNAL and link.target not in visited:
                        visited.add(link.target)
                        queue.append((link.target, path + [link.target]))
        
        return None
    
    def calculate_page_rank(self, damping: float = 0.85, iterations: int = 100) -> Dict[str, float]:
        """
        حساب Page Rank للصفحات
        
        Args:
            damping: معامل التخميد
            iterations: عدد التكرارات
        
        Returns:
            قاموس بالصفحات وأوزان Page Rank
        """
        nodes = list(self._nodes.keys())
        n = len(nodes)
        
        if n == 0:
            return {}
        
        # تهيئة الرتب
        ranks = {url: 1.0 / n for url in nodes}
        
        # بناء مصفوفة الارتباطات
        outgoing_counts = {}
        for url, node in self._nodes.items():
            internal_links = [l.target for l in node.outgoing_links if l.link_type == LinkType.INTERNAL]
            outgoing_counts[url] = len(internal_links)
        
        # خوارزمية Page Rank
        for _ in range(iterations):
            new_ranks = {}
            for url in nodes:
                rank_sum = 0.0
                # جمع الرتب من الصفحات التي تشير إلى هذه الصفحة
                for other_url, node in self._nodes.items():
                    if url in [l.target for l in node.outgoing_links if l.link_type == LinkType.INTERNAL]:
                        rank_sum += ranks[other_url] / max(outgoing_counts[other_url], 1)
                
                new_ranks[url] = (1 - damping) / n + damping * rank_sum
            
            ranks = new_ranks
        
        return ranks
    
    def get_page_importance(self) -> List[Tuple[str, float]]:
        """
        الحصول على ترتيب الصفحات حسب الأهمية
        
        Returns:
            قائمة مرتبة (رابط, درجة الأهمية)
        """
        page_rank = self.calculate_page_rank()
        
        # دمج مع معاملات إضافية
        importance = {}
        for url, rank in page_rank.items():
            node = self._nodes[url]
            # أهمية إضافية للصفحات ذات المحتوى الغني
            content_score = min(len(node.title) / 50, 1.0)
            # أهمية للصفحات التي تستقبل روابط كثيرة
            incoming_score = min(len(node.incoming_links) / 10, 1.0)
            
            importance[url] = rank * 0.5 + content_score * 0.25 + incoming_score * 0.25
        
        # ترتيب تنازلي
        sorted_pages = sorted(importance.items(), key=lambda x: x[1], reverse=True)
        return sorted_pages
    
    def get_entry_points(self) -> List[str]:
        """
        الحصول على نقاط الدخول (الصفحات ذات العمق 0 أو 1)
        
        Returns:
            قائمة بنقاط الدخول
        """
        entry_points = []
        for url, node in self._nodes.items():
            if node.depth <= 1:
                entry_points.append(url)
        return entry_points
    
    def get_isolated_subgraphs(self) -> List[List[str]]:
        """
        اكتشاف المكونات المعزولة في الرسم البياني
        
        Returns:
            قائمة بالمكونات (كل مكون قائمة بالروابط)
        """
        visited = set()
        components = []
        
        def bfs(start: str) -> List[str]:
            queue = deque([start])
            component = []
            
            while queue:
                current = queue.popleft()
                if current in visited:
                    continue
                
                visited.add(current)
                component.append(current)
                
                if current in self._nodes:
                    for link in self._nodes[current].outgoing_links:
                        if link.link_type == LinkType.INTERNAL and link.target in self._nodes and link.target not in visited:
                            queue.append(link.target)
                    
                    for incoming in self._nodes[current].incoming_links:
                        if incoming in self._nodes and incoming not in visited:
                            queue.append(incoming)
            
            return component
        
        for url in self._nodes:
            if url not in visited:
                component = bfs(url)
                if len(component) > 1:
                    components.append(component)
        
        return components
    
    def get_statistics(self) -> Dict:
        """إحصائيات الرسم البياني"""
        nodes = self._nodes
        links = self._links
        
        if not nodes:
            return {"total_pages": 0}
        
        # إحصائيات الروابط
        internal_links = len(self.get_internal_links())
        external_links = len(self.get_external_links())
        
        # إحصائيات الصفحات
        avg_outgoing = sum(len(n.outgoing_links) for n in nodes.values()) / len(nodes)
        avg_incoming = sum(len(n.incoming_links) for n in nodes.values()) / len(nodes)
        
        # توزيع الأعماق
        depths = {}
        for node in nodes.values():
            depths[node.depth] = depths.get(node.depth, 0) + 1
        
        # الصفحات المعزولة
        orphans = self.get_orphan_pages()
        
        # الحلقات
        cycles = self.find_cycles()
        
        return {
            "total_pages": len(nodes),
            "total_links": len(links),
            "internal_links": internal_links,
            "external_links": external_links,
            "avg_outgoing_links": avg_outgoing,
            "avg_incoming_links": avg_incoming,
            "max_depth": max((n.depth for n in nodes.values()), default=0),
            "depth_distribution": depths,
            "orphan_pages": len(orphans),
            "cycles_found": len(cycles),
            "isolated_components": len(self.get_isolated_subgraphs()),
            "entry_points": len(self.get_entry_points())
        }
    
    def export_to_json(self, filepath: str):
        """تصدير الرسم البياني إلى JSON"""
        export_data = {
            "timestamp": datetime.now().isoformat(),
            "statistics": self.get_statistics(),
            "nodes": [
                {
                    "url": node.url,
                    "title": node.title,
                    "depth": node.depth,
                    "incoming_links_count": len(node.incoming_links),
                    "outgoing_links_count": len(node.outgoing_links),
                    "forms_count": len(node.forms),
                    "api_count": len(node.api_endpoints)
                }
                for node in self._nodes.values()
            ],
            "links": [
                {
                    "source": link.source,
                    "target": link.target,
                    "type": link.link_type.value,
                    "depth": link.depth
                }
                for link in self._links[:1000]  # حد أقصى 1000 رابط
            ]
        }
        
        with open(filepath, 'w') as f:
            json.dump(export_data, f, indent=2)
        
        logger.info(f"Graph exported to {filepath}")
    
    def clear(self):
        """مسح الرسم البياني"""
        self._nodes.clear()
        self._links.clear()
        self._build_time = None
        logger.info("Graph cleared")

