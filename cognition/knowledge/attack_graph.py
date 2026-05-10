
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from collections import defaultdict

from .knowledge_graph import KnowledgeGraph, KGNode, KGEdge

import logging

logger = logging.getLogger(__name__)


@dataclass
class AttackPath:
    """مسار هجومي"""
    nodes: List[KGNode]
    edges: List[KGEdge]
    total_risk: float
    length: int
    entry_point: str
    target: str


class AttackGraph(KnowledgeGraph):
    """
    رسم بياني للهجمات المتقدم
    
    الميزات:
    - تمثيل مسارات الهجوم
    - حساب المخاطر للمسارات
    - اكتشاف نقاط الدخول
    - تحليل أضعف مسار
    """
    
    def __init__(self):
        super().__init__()
        
        # إضافة أنواع خاصة بالهجمات
        self._vulnerability_nodes: Dict[str, List[str]] = defaultdict(list)
        self._entry_points: Set[str] = set()
        self._targets: Set[str] = set()
        
        logger.info("AttackGraph initialized")
    
    async def add_vulnerability(
        self,
        vuln_id: str,
        name: str,
        severity: str,
        cve_id: str = None,
        properties: Dict = None
    ):
        """
        إضافة ثغرة كعقدة في الرسم البياني
        
        Args:
            vuln_id: معرف الثغرة
            name: اسم الثغرة
            severity: شدة الثغرة (critical, high, medium, low)
            cve_id: معرف CVE (اختياري)
            properties: خصائص إضافية
        """
        node_properties = {
            "severity": severity,
            "cve_id": cve_id,
            **(properties or {})
        }
        
        await self.add_node(
            node_id=vuln_id,
            node_type="vulnerability",
            name=name,
            properties=node_properties
        )
        
        self._vulnerability_nodes[severity].append(vuln_id)
        
        logger.debug(f"Vulnerability added: {name} ({severity})")
    
    async def add_attack_step(
        self,
        from_vuln: str,
        to_vuln: str,
        relation: str,
        weight: float = 1.0,
        properties: Dict = None
    ) -> bool:
        """
        إضافة خطوة هجومية (علاقة بين ثغرتين)
        
        Args:
            from_vuln: معرف الثغرة المصدر
            to_vuln: معرف الثغرة الهدف
            relation: نوع العلاقة (leads_to, exploits, bypasses)
            weight: وزن العلاقة (احتمالية النجاح)
            properties: خصائص إضافية
        
        Returns:
            نجاح العملية
        """
        return await self.add_edge(
            source=from_vuln,
            target=to_vuln,
            relation=relation,
            weight=weight,
            properties=properties
        )
    
    async def set_entry_point(self, node_id: str):
        """تعيين نقطة دخول للهجوم"""
        if node_id in self._nodes:
            self._entry_points.add(node_id)
            logger.debug(f"Entry point set: {node_id}")
    
    async def set_target(self, node_id: str):
        """تعيين هدف للهجوم"""
        if node_id in self._nodes:
            self._targets.add(node_id)
            logger.debug(f"Target set: {node_id}")
    
    async def find_attack_paths(
        self,
        max_depth: int = 5,
        min_success_rate: float = 0.0
    ) -> List[AttackPath]:
        """
        البحث عن جميع مسارات الهجوم الممكنة
        
        Args:
            max_depth: أقصى عمق
            min_success_rate: الحد الأدنى لمعدل النجاح
        
        Returns:
            قائمة بالمسارات الهجومية
        """
        paths = []
        
        for entry in self._entry_points:
            for target in self._targets:
                # البحث عن مسار بين نقطة الدخول والهدف
                path_edges = await self.find_path(entry, target, max_depth)
                
                if path_edges:
                    nodes = [edge[0] for edge in path_edges] + [self._nodes[target]]
                    edges = [edge[1] for edge in path_edges]
                    
                    # حساب المخاطر الإجمالية
                    total_risk = await self._calculate_path_risk(nodes, edges)
                    
                    if total_risk >= min_success_rate:
                        paths.append(AttackPath(
                            nodes=nodes,
                            edges=edges,
                            total_risk=total_risk,
                            length=len(edges),
                            entry_point=entry,
                            target=target
                        ))
        
        # ترتيب حسب المخاطر (الأعلى أولاً)
        paths.sort(key=lambda x: x.total_risk, reverse=True)
        
        return paths
    
    async def _calculate_path_risk(
        self,
        nodes: List[KGNode],
        edges: List[KGEdge]
    ) -> float:
        """
        حساب المخاطر الكلية لمسار هجومي
        
        Args:
            nodes: العقد في المسار
            edges: العلاقات في المسار
        
        Returns:
            نسبة المخاطر (0-1)
        """
        # عوامل الخطر
        severity_weights = {
            "critical": 1.0,
            "high": 0.8,
            "medium": 0.5,
            "low": 0.3
        }
        
        # حساب متوسط شدة الثغرات
        total_severity = 0.0
        for node in nodes:
            severity = node.properties.get("severity", "low")
            total_severity += severity_weights.get(severity, 0.2)
        
        avg_severity = total_severity / len(nodes) if nodes else 0
        
        # حساب متوسط وزن العلاقات
        total_weight = sum(edge.weight for edge in edges) if edges else 0
        avg_weight = total_weight / len(edges) if edges else 1.0
        
        # المخاطر الكلية
        risk = avg_severity * avg_weight
        
        return min(risk, 1.0)
    
    async def get_critical_paths(self, threshold: float = 0.7) -> List[AttackPath]:
        """
        الحصول على المسارات الحرجة (عالية المخاطر)
        
        Args:
            threshold: عتبة المخاطر
        
        Returns:
            قائمة بالمسارات الحرجة
        """
        all_paths = await self.find_attack_paths()
        return [p for p in all_paths if p.total_risk >= threshold]
    
    async def get_weakest_link(self) -> Optional[Tuple[KGNode, float]]:
        """
        تحديد أضعف حلقة في الرسم البياني للهجمات
        
        Returns:
            (العقدة, درجة الضعف)
        """
        weakest_node = None
        lowest_risk = 1.0
        
        for node in self._nodes.values():
            if node.type == "vulnerability":
                severity_weights = {
                    "critical": 1.0,
                    "high": 0.8,
                    "medium": 0.5,
                    "low": 0.3
                }
                risk = severity_weights.get(node.properties.get("severity", "low"), 0.2)
                
                if risk < lowest_risk:
                    lowest_risk = risk
                    weakest_node = node
        
        return (weakest_node, lowest_risk) if weakest_node else None
    
    async def get_attack_statistics(self) -> Dict:
        """إحصائيات الهجمات"""
        base_stats = await self.get_statistics()
        
        paths = await self.find_attack_paths()
        
        return {
            **base_stats,
            "attack_specific": {
                "total_entry_points": len(self._entry_points),
                "total_targets": len(self._targets),
                "attack_paths_found": len(paths),
                "critical_paths": len([p for p in paths if p.total_risk >= 0.7]),
                "average_path_risk": sum(p.total_risk for p in paths) / len(paths) if paths else 0,
                "vulnerabilities_by_severity": {
                    severity: len(nodes)
                    for severity, nodes in self._vulnerability_nodes.items()
                }
            }
        }

